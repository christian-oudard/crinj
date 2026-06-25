package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// Load host config from a TOML file.
//
// Parses the file at startup, resolves source references into in-memory
// values, validates access-control natural order, and produces ResolvedHost
// values used by the runtime.

// ── TOML schema ─────────────────────────────────────────────────────────

type tomlConfig struct {
	Host []tomlHostEntry `toml:"host"`
}

// tomlHostEntry mirrors a single [[host]] entry. Field tags use kebab-case to
// match the Rust serde renames.
//
// Canonical field order: domain, no-check-certificate, access, source, inject.
type tomlHostEntry struct {
	Domain             string            `toml:"domain"`
	NoCheckCertificate bool              `toml:"no-check-certificate"`
	Access             *string           `toml:"access"`
	Source             *string           `toml:"source"`
	Inject             []tomlInjectEntry `toml:"inject"`
	OAuth              *tomlHostOAuth    `toml:"oauth"`
}

// tomlHostOAuth mirrors the [host.oauth] table. The [[host]] it sits under is
// the resource host; the token endpoint (token-host/token-path) is
// auto-intercepted. token-host defaults to the resource domain. A host family
// that shares one login is a single wildcard domain. See SPEC.md.
type tomlHostOAuth struct {
	TokenHost *string `toml:"token-host"`
	TokenPath *string `toml:"token-path"`
}

// tomlInjectEntry mirrors a single [[host.inject]] entry.
//
// Canonical field order: url-path, ports, source, source-path, source-sqlite,
// source-sqlite-query, value, header/query-param/remove-header, format.
type tomlInjectEntry struct {
	URLPath           *string  `toml:"url-path"`
	Ports             []uint16 `toml:"ports"`
	Source            *string  `toml:"source"`
	SourcePath        *string  `toml:"source-path"`
	SourceSQLite      *string  `toml:"source-sqlite"`
	SourceSQLiteQuery *string  `toml:"source-sqlite-query"`
	Value             *string  `toml:"value"`
	Header            *string  `toml:"header"`
	QueryParam        *string  `toml:"query-param"`
	RemoveHeader      *string  `toml:"remove-header"`
	Format            *string  `toml:"format"`
}

// ── Resolved types ──────────────────────────────────────────────────────

// ResolvedHost is a fully resolved host entry ready for runtime matching.
type ResolvedHost struct {
	HostPattern        string
	NoCheckCertificate bool
	Access             []AccessEntry
	InjectionRules     []InjectionRule
}

// ── Loading ─────────────────────────────────────────────────────────────

// load parses the config TOML file and resolves all source file references.
//
// File-backed sources (`source` / `source-path` / `source-sqlite`) are not yet
// implemented; only inline `value` resolves correctly.
func load(path string) ([]ResolvedHost, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}
	var cfg tomlConfig
	if err := toml.Unmarshal(content, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	resolved := make([]ResolvedHost, 0, len(cfg.Host))
	var fatal []error
	for i := range cfg.Host {
		h, err := resolveHost(&cfg.Host[i], path)
		if err != nil {
			if isSecretUnavailable(err) {
				slog.Warn("skipping host: secret not available",
					"domain", cfg.Host[i].Domain, "error", err)
				continue
			}
			fatal = append(fatal, err)
			continue
		}
		resolved = append(resolved, *h)
	}
	if len(fatal) > 0 {
		var sb strings.Builder
		fmt.Fprintf(&sb, "%d host config error(s) in %s:", len(fatal), path)
		for _, e := range fatal {
			fmt.Fprintf(&sb, "\n  - %v", e)
		}
		return nil, fmt.Errorf("%s", sb.String())
	}

	// Auto-intercept the token endpoint of each [host.oauth]. Without a
	// synthesized entry the token host would tunnel through unintercepted,
	// carrying the real tokens. The resource host already has its own [[host]]
	// (oauth is nested under it); only the token host can be implicit.
	chains, err := parseOAuthChains(&cfg)
	if err != nil {
		return nil, fmt.Errorf("in %s: %w", path, err)
	}
	declared := make(map[string]bool, len(resolved))
	for i := range resolved {
		declared[resolved[i].HostPattern] = true
	}
	for _, ch := range chains {
		if declared[ch.TokenHost] {
			continue
		}
		declared[ch.TokenHost] = true
		resolved = append(resolved, ResolvedHost{HostPattern: ch.TokenHost})
	}

	if err := validateHostSpecificity(resolved); err != nil {
		return nil, err
	}
	return resolved, nil
}

// loadOAuth parses the [host.oauth] blocks into chains. Read separately from
// load so the host rules can reload on SIGHUP without disturbing the live token
// vault.
func loadOAuth(path string) ([]OAuthChain, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}
	var cfg tomlConfig
	if err := toml.Unmarshal(content, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	chains, err := parseOAuthChains(&cfg)
	if err != nil {
		return nil, fmt.Errorf("in %s: %w", path, err)
	}
	return chains, nil
}

// parseOAuthChains turns each [host.oauth] block into one chain: the resource
// host is the [[host]] it sits under, token-host defaults to that domain, and
// token-path is required.
func parseOAuthChains(cfg *tomlConfig) ([]OAuthChain, error) {
	var chains []OAuthChain
	for i := range cfg.Host {
		entry := &cfg.Host[i]
		o := entry.OAuth
		if o == nil {
			continue
		}
		if o.TokenPath == nil {
			return nil, fmt.Errorf("host %q: [host.oauth] requires token-path", entry.Domain)
		}
		tokenHost := entry.Domain
		if o.TokenHost != nil {
			tokenHost = *o.TokenHost
		}
		chains = append(chains, OAuthChain{
			TokenHost: tokenHost,
			TokenPath: *o.TokenPath,
			Resource:  entry.Domain,
		})
	}
	return chains, nil
}

// resolveHost builds a fully resolved host. Any failure causes the caller to
// either skip the host with a warning (secret-unavailable) or report a fatal
// schema error.
func resolveHost(entry *tomlHostEntry, configPath string) (*ResolvedHost, error) {
	var access []AccessEntry
	if entry.Access != nil {
		a, err := parseAccess(*entry.Access)
		if err != nil {
			return nil, fmt.Errorf("host %q in %s: %w", entry.Domain, configPath, err)
		}
		access = a
	}
	rules, err := resolveHostInjects(entry, configPath)
	if err != nil {
		return nil, err
	}
	return &ResolvedHost{
		HostPattern:        entry.Domain,
		NoCheckCertificate: entry.NoCheckCertificate,
		Access:             access,
		InjectionRules:     rules,
	}, nil
}

func resolveHostInjects(entry *tomlHostEntry, configPath string) ([]InjectionRule, error) {
	rules := make([]InjectionRule, 0, len(entry.Inject))
	for i := range entry.Inject {
		ie := &entry.Inject[i]
		injection, err := resolveInjection(ie, entry.Source, entry.Domain, configPath)
		if err != nil {
			return nil, err
		}
		urlPath := "*"
		if ie.URLPath != nil {
			urlPath = *ie.URLPath
		}
		rules = append(rules, InjectionRule{
			PathPattern: urlPath,
			Ports:       ie.Ports,
			Injections:  []Injection{injection},
		})
	}
	return rules, nil
}

func resolveInjection(entry *tomlInjectEntry, fallbackSource *string, domain, configPath string) (Injection, error) {
	if entry.RemoveHeader != nil {
		return Injection{Kind: InjectRemoveHeader, Name: *entry.RemoveHeader}, nil
	}
	if entry.SourceSQLite != nil || entry.SourceSQLiteQuery != nil {
		return resolveSQLiteInjection(entry, domain, configPath)
	}
	if entry.Header != nil {
		raw, err := resolveValue(entry, fallbackSource, domain, configPath)
		if err != nil {
			return Injection{}, err
		}
		return Injection{
			Kind:  InjectSetHeader,
			Name:  *entry.Header,
			Value: formatValue(raw, entry.Format),
		}, nil
	}
	if entry.QueryParam != nil {
		raw, err := resolveValue(entry, fallbackSource, domain, configPath)
		if err != nil {
			return Injection{}, err
		}
		return Injection{
			Kind:  InjectSetQueryParam,
			Name:  *entry.QueryParam,
			Value: formatValue(raw, entry.Format),
		}, nil
	}
	return Injection{}, fmt.Errorf(
		"inject entry for domain %q in %s must have `header`, `query-param`, or `remove-header`",
		domain, configPath)
}

// resolveSQLiteInjection validates a source-sqlite inject entry and resolves
// its database path. The actual query runs at request time; this only sanity-
// checks the config and file permissions.
func resolveSQLiteInjection(entry *tomlInjectEntry, domain, configPath string) (Injection, error) {
	if entry.SourceSQLite == nil {
		return Injection{}, fmt.Errorf(
			"inject entry for domain %q in %s: `source-sqlite-query` requires `source-sqlite`",
			domain, configPath)
	}
	if entry.SourceSQLiteQuery == nil {
		return Injection{}, fmt.Errorf(
			"inject entry for domain %q in %s: `source-sqlite` requires `source-sqlite-query`",
			domain, configPath)
	}
	if entry.Source != nil || entry.Value != nil || entry.SourcePath != nil {
		return Injection{}, fmt.Errorf(
			"inject entry for domain %q in %s: `source-sqlite` cannot be combined with `source`, `source-path`, or `value`",
			domain, configPath)
	}
	dbPath := resolveSourcePath(*entry.SourceSQLite, configPath)
	// Validate perms only; missing/empty files are acceptable at load time.
	// A populated file with bad perms is a fatal emergency.
	if _, err := validateSecretFile(dbPath); err != nil {
		return Injection{}, err
	}
	if entry.Header != nil {
		return Injection{
			Kind:   InjectSetHeaderSQLite,
			Name:   *entry.Header,
			DBPath: dbPath,
			Query:  *entry.SourceSQLiteQuery,
			Format: entry.Format,
		}, nil
	}
	if entry.QueryParam != nil {
		return Injection{
			Kind:   InjectSetQueryParamSQLite,
			Name:   *entry.QueryParam,
			DBPath: dbPath,
			Query:  *entry.SourceSQLiteQuery,
			Format: entry.Format,
		}, nil
	}
	return Injection{}, fmt.Errorf(
		"inject entry for domain %q in %s: `source-sqlite` inject entry must have `header` or `query-param`",
		domain, configPath)
}

// resolveValue produces the raw credential value before any format substitution.
// source-path extraction is not yet implemented.
func resolveValue(entry *tomlInjectEntry, fallbackSource *string, domain, configPath string) (string, error) {
	if entry.Value != nil {
		return *entry.Value, nil
	}
	source := entry.Source
	if source == nil {
		source = fallbackSource
	}
	if source != nil {
		expanded := resolveSourcePath(*source, configPath)
		state, err := validateSecretFile(expanded)
		if err != nil {
			return "", err
		}
		switch state {
		case secretMissing:
			return "", &errSecretUnavailable{
				msg: fmt.Sprintf("secret file %s does not exist (for domain %q)", expanded, domain),
			}
		case secretEmpty:
			return "", &errSecretUnavailable{
				msg: fmt.Sprintf("secret file %s is empty (for domain %q)", expanded, domain),
			}
		}
		raw, err := os.ReadFile(expanded)
		if err != nil {
			return "", fmt.Errorf("reading source %s (for domain %q) referenced from %s: %w",
				expanded, domain, configPath, err)
		}
		if entry.SourcePath != nil {
			v, err := extractPath(string(raw), *entry.SourcePath, expanded)
			if err != nil {
				return "", fmt.Errorf(
					"extracting source-path %q from %s (for domain %q): %w",
					*entry.SourcePath, expanded, domain, err)
			}
			return v, nil
		}
		return strings.TrimSpace(string(raw)), nil
	}
	return "", fmt.Errorf(
		"inject entry for domain %q in %s has neither `value` nor `source`",
		domain, configPath)
}

// secretState classifies a secret file's load-time state.
type secretState int

const (
	secretMissing secretState = iota
	secretEmpty
	secretPopulated
)

// errSecretUnavailable marks a failure caused by a host's secret being missing
// or empty. The loader treats this as "key not provided yet" — warn and skip
// the host — rather than a fatal schema error.
type errSecretUnavailable struct{ msg string }

func (e *errSecretUnavailable) Error() string { return e.msg }

func isSecretUnavailable(err error) bool {
	var u *errSecretUnavailable
	return errors.As(err, &u)
}

// validateSecretFile inspects a secret file. Empty/missing files are
// non-fatal; a populated file with group/world-readable permissions is an
// emergency (the secret has already leaked) and we refuse to load.
func validateSecretFile(path string) (secretState, error) {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return secretMissing, nil
	}
	if err != nil {
		return 0, fmt.Errorf("stat'ing secret file %s: %w", path, err)
	}
	empty := info.Size() == 0
	mode := info.Mode().Perm()
	if mode&0o077 != 0 && !empty {
		return 0, fmt.Errorf(
			"secret file %s has mode %o — must not be group/world-accessible (chmod 600)",
			path, mode)
	}
	if empty {
		return secretEmpty, nil
	}
	return secretPopulated, nil
}

// expandTilde expands a leading `~` to the user's $HOME.
func expandTilde(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home := os.Getenv("HOME"); home != "" {
			return filepath.Join(home, strings.TrimPrefix(p, "~/"))
		}
	}
	return p
}

// extractPath dispatches on file extension and walks a dot-separated path
// through a JSON or TOML value.
func extractPath(content, path, file string) (string, error) {
	ext := strings.ToLower(filepath.Ext(file))
	switch ext {
	case ".json":
		return extractJSONPath(content, path)
	case ".toml":
		return extractTOMLPath(content, path)
	case "":
		return "", fmt.Errorf("source file has no extension, cannot determine format for source-path")
	default:
		return "", fmt.Errorf("unsupported source file extension %q, expected .json or .toml", ext)
	}
}

func extractJSONPath(content, path string) (string, error) {
	var root any
	if err := json.Unmarshal([]byte(content), &root); err != nil {
		return "", fmt.Errorf("source file is not valid JSON: %w", err)
	}
	return walkPath(root, path, true)
}

func extractTOMLPath(content, path string) (string, error) {
	var root any
	if err := toml.Unmarshal([]byte(content), &root); err != nil {
		return "", fmt.Errorf("source file is not valid TOML: %w", err)
	}
	return walkPath(root, path, false)
}

// walkPath descends through a decoded JSON/TOML tree along a dot-separated
// path. Numeric segments index into arrays; everything else looks up keys.
// Strings at the leaf are returned as-is; other types are formatted as JSON
// (Rust's serde_json::Value::to_string equivalent for the JSON case; for
// TOML the fallback path is rare in practice).
func walkPath(root any, path string, jsonFmt bool) (string, error) {
	cur := root
	for _, seg := range strings.Split(path, ".") {
		if idx, err := strconv.Atoi(seg); err == nil {
			arr, ok := cur.([]any)
			if !ok || idx < 0 || idx >= len(arr) {
				return "", fmt.Errorf("%q not found (full path: %q)", seg, path)
			}
			cur = arr[idx]
			continue
		}
		obj, ok := cur.(map[string]any)
		if !ok {
			return "", fmt.Errorf("%q not found (full path: %q)", seg, path)
		}
		v, present := obj[seg]
		if !present {
			return "", fmt.Errorf("%q not found (full path: %q)", seg, path)
		}
		cur = v
	}
	if s, ok := cur.(string); ok {
		return s, nil
	}
	if jsonFmt {
		b, err := json.Marshal(cur)
		if err != nil {
			return "", fmt.Errorf("formatting leaf value: %w", err)
		}
		return string(b), nil
	}
	return fmt.Sprintf("%v", cur), nil
}

// ── Runtime resolution ──────────────────────────────────────────────────

// ResolveResult is what runtime resolution produces for a CONNECT authority.
type ResolveResult struct {
	Intercept          bool
	NoCheckCertificate bool
	Access             []AccessEntry
	InjectionRules     []InjectionRule
}

// resolveHosts finds the most-specific host entry matching the CONNECT
// authority and returns its access list plus port-filtered injection rules.
// `host` is the raw CONNECT authority, e.g. "example.com:443".
func resolveHosts(host string, hosts []ResolvedHost) ResolveResult {
	hostname, port := splitHostPort(host)

	bestIdx := -1
	var bestSpec specificity
	for i := range hosts {
		if !globMatches(hostname, hosts[i].HostPattern) {
			continue
		}
		spec := patternSpecificity(hosts[i].HostPattern)
		if bestIdx < 0 || spec.moreSpecificThan(bestSpec) {
			bestIdx = i
			bestSpec = spec
		}
	}
	if bestIdx < 0 {
		return ResolveResult{}
	}
	h := &hosts[bestIdx]
	var rules []InjectionRule
	for i := range h.InjectionRules {
		if h.InjectionRules[i].PortMatches(port) {
			rules = append(rules, h.InjectionRules[i])
		}
	}
	return ResolveResult{
		Intercept:          true,
		NoCheckCertificate: h.NoCheckCertificate,
		Access:             h.Access,
		InjectionRules:     rules,
	}
}

// splitHostPort splits a "host:port" authority into hostname and numeric
// port. port == -1 means no port present (or unparseable). Bracketed IPv6
// authorities like "[::1]:443" are handled.
func splitHostPort(s string) (string, int) {
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return s, -1
		}
		host := s[1:end]
		rest := s[end+1:]
		if !strings.HasPrefix(rest, ":") {
			return host, -1
		}
		p, err := strconv.Atoi(rest[1:])
		if err != nil {
			return host, -1
		}
		return host, p
	}
	colon := strings.LastIndex(s, ":")
	if colon < 0 {
		return s, -1
	}
	p, err := strconv.Atoi(s[colon+1:])
	if err != nil {
		return s, -1
	}
	return s[:colon], p
}

// resolveSourcePath turns a config-relative source reference into an absolute
// filesystem path. Absolute (`/...`) and home-relative (`~/...`) paths pass
// through (with tilde expansion); bare names resolve to a `secrets/` directory
// next to the config file.
func resolveSourcePath(source, configPath string) string {
	if strings.HasPrefix(source, "/") || strings.HasPrefix(source, "~/") {
		return expandTilde(source)
	}
	dir := filepath.Dir(configPath)
	if dir == "" {
		dir = "."
	}
	return filepath.Join(dir, "secrets", source)
}

// formatValue applies the format string. `{}` is replaced with the raw value.
func formatValue(raw string, format *string) string {
	if format == nil {
		return raw
	}
	return strings.ReplaceAll(*format, "{}", raw)
}

// validateHostSpecificity errors if two host entries have identical patterns.
func validateHostSpecificity(hosts []ResolvedHost) error {
	for i := range hosts {
		for j := i + 1; j < len(hosts); j++ {
			if hosts[i].HostPattern == hosts[j].HostPattern {
				return fmt.Errorf("duplicate host domain %q (entries %d and %d)",
					hosts[i].HostPattern, i+1, j+1)
			}
		}
	}
	return nil
}
