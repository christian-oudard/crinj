package main

import (
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	_ "modernc.org/sqlite"
)

// Request injection engine and access control. Data structures and pure
// functions live here. Application against an http.Request is done in the
// gateway layer.

// InjectionKind discriminates the variants of Injection.
type InjectionKind int

const (
	InjectSetHeader InjectionKind = iota
	InjectSetHeaderSQLite
	InjectRemoveHeader
	InjectSetQueryParam
	InjectSetQueryParamSQLite
)

// Injection is a single action to apply to a request. The fields used depend
// on Kind. This is a flat struct rather than an interface because every code
// path that consumes it switches on Kind already.
type Injection struct {
	Kind InjectionKind

	// SetHeader / SetHeaderSQLite / RemoveHeader / SetQueryParam / SetQueryParamSQLite
	Name string

	// SetHeader / SetQueryParam (already formatted at config-load time).
	Value string

	// SetHeaderSQLite / SetQueryParamSQLite
	DBPath string
	Query  string
	Format *string
}

// InjectionRule is one resolved [[host.inject]] block.
type InjectionRule struct {
	PathPattern string
	Ports       []uint16 // empty = any port
	Injections  []Injection
}

// PortMatches reports whether the rule applies to the given port.
// port == -1 means "no port in the authority"; the rule matches only if it
// has no port restriction.
func (r *InjectionRule) PortMatches(port int) bool {
	if len(r.Ports) == 0 {
		return true
	}
	if port < 0 {
		return false
	}
	for _, p := range r.Ports {
		if int(p) == port {
			return true
		}
	}
	return false
}

// AccessVerb is `block` or `allow`.
type AccessVerb int

const (
	AccessBlock AccessVerb = iota
	AccessAllow
)

func (v AccessVerb) String() string {
	switch v {
	case AccessBlock:
		return "block"
	case AccessAllow:
		return "allow"
	}
	return fmt.Sprintf("AccessVerb(%d)", int(v))
}

// AccessEntry is one line of an access list.
type AccessEntry struct {
	Verb        AccessVerb
	PathPattern string
}

// parseAccess parses a multi-line access string into ordered entries. Empty
// lines and `#` comment lines are ignored. Validates natural order: a broader
// pattern must not appear after a narrower one it would dominate.
func parseAccess(s string) ([]AccessEntry, error) {
	var entries []AccessEntry
	for lineno, raw := range strings.Split(s, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		verbStr, path := splitFirstWhitespace(line)
		path = strings.TrimSpace(path)
		var verb AccessVerb
		switch verbStr {
		case "block":
			verb = AccessBlock
		case "allow":
			verb = AccessAllow
		default:
			return nil, fmt.Errorf("access line %d: unknown verb %q (expected `block` or `allow`)", lineno+1, verbStr)
		}
		if path == "" {
			return nil, fmt.Errorf("access line %d: missing path after %s", lineno+1, verbStr)
		}
		entries = append(entries, AccessEntry{Verb: verb, PathPattern: path})
	}
	if err := validateNaturalOrder(entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// splitFirstWhitespace returns (head, tail). If no whitespace is present,
// tail is empty.
func splitFirstWhitespace(s string) (string, string) {
	for i, r := range s {
		if unicode.IsSpace(r) {
			return s[:i], s[i:]
		}
	}
	return s, ""
}

// validateNaturalOrder enforces the rule that a broader entry must not appear
// after a narrower one it dominates.
func validateNaturalOrder(entries []AccessEntry) error {
	for j := range entries {
		for i := 0; i < j; i++ {
			a := entries[i]
			b := entries[j]
			if a.PathPattern == b.PathPattern {
				continue
			}
			if isSupersetOf(b.PathPattern, a.PathPattern) {
				return fmt.Errorf(
					"access: entry %d (%s %s) is broader than earlier entry %d (%s %s); put broader patterns first",
					j+1, b.Verb, b.PathPattern,
					i+1, a.Verb, a.PathPattern,
				)
			}
		}
	}
	return nil
}

// evaluateAccess returns the verb of the last matching entry, or (0, false)
// when nothing matches (default allow).
func evaluateAccess(path string, entries []AccessEntry) (AccessVerb, bool) {
	var result AccessVerb
	matched := false
	for _, e := range entries {
		if globMatches(path, e.PathPattern) {
			result = e.Verb
			matched = true
		}
	}
	return result, matched
}

// ── SQLite resolution ───────────────────────────────────────────────────

// resolveSQLite queries a SQLite database for a single value and applies the
// optional format string. Both TEXT and BLOB columns are accepted; the byte
// payload must be valid UTF-8.
func resolveSQLite(dbPath, query string, format *string) (string, error) {
	raw, err := resolveSQLiteInner(dbPath, query)
	if err != nil {
		return "", fmt.Errorf("sqlite injection from %s: %w", dbPath, err)
	}
	if format != nil {
		return strings.ReplaceAll(*format, "{}", raw), nil
	}
	return raw, nil
}

func resolveSQLiteInner(dbPath, query string) (string, error) {
	dsn := "file:" + url.PathEscape(dbPath) + "?mode=ro&_pragma=busy_timeout(1000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return "", err
	}
	defer db.Close()
	var b []byte
	if err := db.QueryRow(query).Scan(&b); err != nil {
		return "", err
	}
	if !utf8.Valid(b) {
		return "", fmt.Errorf("sqlite value is not valid UTF-8")
	}
	return string(b), nil
}

// ── Injection application ───────────────────────────────────────────────

// applyInjections applies header-related injection rules to the request
// headers. Returns the count of actions applied. Misconfigured static
// injections (invalid header names) are logged and skipped; sqlite
// resolution failures bubble up as errors so the caller can refuse the
// request rather than forward without the credential.
func applyInjections(headers http.Header, requestPath string, rules []InjectionRule) (int, error) {
	count := 0
	for i := range rules {
		rule := &rules[i]
		if !globMatches(requestPath, rule.PathPattern) {
			continue
		}
		for _, inj := range rule.Injections {
			switch inj.Kind {
			case InjectSetHeader:
				if !isValidHeaderName(inj.Name) || !isValidHeaderValue(inj.Value) {
					slog.Warn("injection skipped: invalid header name or value",
						"header", inj.Name)
					continue
				}
				if len(headers.Values(inj.Name)) == 0 {
					continue
				}
				headers.Set(inj.Name, inj.Value)
				count++
			case InjectSetHeaderSQLite:
				if !isValidHeaderName(inj.Name) {
					continue
				}
				if len(headers.Values(inj.Name)) == 0 {
					continue
				}
				value, err := resolveSQLite(inj.DBPath, inj.Query, inj.Format)
				if err != nil {
					return 0, err
				}
				if !isValidHeaderValue(value) {
					return 0, fmt.Errorf("sqlite-resolved value is not a valid header value")
				}
				headers.Set(inj.Name, value)
				count++
			case InjectRemoveHeader:
				if !isValidHeaderName(inj.Name) {
					continue
				}
				if len(headers.Values(inj.Name)) > 0 {
					headers.Del(inj.Name)
					count++
				}
			case InjectSetQueryParam, InjectSetQueryParamSQLite:
				// applied by applyQueryInjections
			}
		}
	}
	return count, nil
}

// applyQueryInjections applies query-param injection rules to a URL
// path+query string. Returns the modified path+query and the count of
// injections applied. Only injects when the parameter name already exists
// in the request (placeholder enforcement).
func applyQueryInjections(pathAndQuery string, rules []InjectionRule) (string, int, error) {
	var path, existingQuery string
	if i := strings.Index(pathAndQuery, "?"); i >= 0 {
		path = pathAndQuery[:i]
		existingQuery = pathAndQuery[i+1:]
	} else {
		path = pathAndQuery
	}

	existing := map[string]bool{}
	if existingQuery != "" {
		for _, pair := range strings.Split(existingQuery, "&") {
			name := pair
			if eq := strings.Index(pair, "="); eq >= 0 {
				name = pair[:eq]
			}
			existing[name] = true
		}
	}

	type kv struct{ name, value string }
	var paramsToSet []kv
	for i := range rules {
		rule := &rules[i]
		if !globMatches(path, rule.PathPattern) {
			continue
		}
		for _, inj := range rule.Injections {
			switch inj.Kind {
			case InjectSetQueryParam:
				if existing[inj.Name] {
					paramsToSet = append(paramsToSet, kv{inj.Name, inj.Value})
				}
			case InjectSetQueryParamSQLite:
				if existing[inj.Name] {
					value, err := resolveSQLite(inj.DBPath, inj.Query, inj.Format)
					if err != nil {
						return "", 0, err
					}
					paramsToSet = append(paramsToSet, kv{inj.Name, value})
				}
			}
		}
	}

	if len(paramsToSet) == 0 {
		return pathAndQuery, 0, nil
	}

	injectNames := map[string]bool{}
	for _, p := range paramsToSet {
		injectNames[p.name] = true
	}

	var parts []string
	if existingQuery != "" {
		for _, pair := range strings.Split(existingQuery, "&") {
			name := pair
			if eq := strings.Index(pair, "="); eq >= 0 {
				name = pair[:eq]
			}
			if !injectNames[name] {
				parts = append(parts, pair)
			}
		}
	}
	for _, p := range paramsToSet {
		parts = append(parts, percentEncode(p.name)+"="+percentEncode(p.value))
	}

	return path + "?" + strings.Join(parts, "&"), len(paramsToSet), nil
}

// isValidHeaderName reports whether s is a valid RFC 7230 token (per the
// chars allowed in HeaderName::from_bytes).
func isValidHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9':
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+',
			'-', '.', '^', '_', '`', '|', '~':
			continue
		}
		return false
	}
	return true
}

// isValidHeaderValue accepts visible ASCII (0x20–0x7E) plus HTAB. Matches
// hyper's HeaderValue::from_str minimum.
func isValidHeaderValue(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\t' {
			continue
		}
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// percentEncode percent-encodes a query parameter name or value.
// RFC 3986 unreserved chars pass through; everything else is %XX.
func percentEncode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z',
			c >= 'a' && c <= 'z',
			c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			const hex = "0123456789ABCDEF"
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0xf])
		}
	}
	return b.String()
}
