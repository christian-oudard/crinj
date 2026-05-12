package main

import (
	"database/sql"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeRule is the Go counterpart of the Rust test helper.
func makeRule(pathPattern string, injections []Injection) InjectionRule {
	return InjectionRule{
		PathPattern: pathPattern,
		Injections:  injections,
	}
}

func setHeader(name, value string) Injection {
	return Injection{Kind: InjectSetHeader, Name: name, Value: value}
}

func removeHeader(name string) Injection {
	return Injection{Kind: InjectRemoveHeader, Name: name}
}

func setQueryParam(name, value string) Injection {
	return Injection{Kind: InjectSetQueryParam, Name: name, Value: value}
}

func TestParseAccessBasic(t *testing.T) {
	entries, err := parseAccess("block *\nallow /v1/*\nblock /v1/admin/*")
	if err != nil {
		t.Fatalf("parseAccess: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("len=%d want 3", len(entries))
	}
	if entries[0].Verb != AccessBlock || entries[0].PathPattern != "*" {
		t.Errorf("entry 0: %+v", entries[0])
	}
	if entries[2].Verb != AccessBlock || entries[2].PathPattern != "/v1/admin/*" {
		t.Errorf("entry 2: %+v", entries[2])
	}
}

func TestParseAccessSingleLine(t *testing.T) {
	entries, err := parseAccess("block *")
	if err != nil {
		t.Fatalf("parseAccess: %v", err)
	}
	if len(entries) != 1 || entries[0].Verb != AccessBlock {
		t.Errorf("got %+v", entries)
	}
}

func TestParseAccessIgnoresBlanksAndComments(t *testing.T) {
	entries, err := parseAccess(`
# top-level block
block *

# allow API
allow /v1/*
`)
	if err != nil {
		t.Fatalf("parseAccess: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("got %d entries, want 2", len(entries))
	}
}

func TestParseAccessUnknownVerb(t *testing.T) {
	_, err := parseAccess("deny /v1/*")
	if err == nil || !strings.Contains(err.Error(), "unknown verb") {
		t.Errorf("want unknown verb error, got %v", err)
	}
}

func TestParseAccessMissingPath(t *testing.T) {
	_, err := parseAccess("block")
	if err == nil || !strings.Contains(err.Error(), "missing path") {
		t.Errorf("want missing path error, got %v", err)
	}
}

func TestParseAccessUnnaturalOrder(t *testing.T) {
	_, err := parseAccess("allow /v1/*\nblock *")
	if err == nil || !strings.Contains(err.Error(), "broader than earlier") {
		t.Errorf("want broader-than-earlier error, got %v", err)
	}
}

func TestParseAccessNestedUnnatural(t *testing.T) {
	_, err := parseAccess("block /v1/admin/*\nallow /v1/*")
	if err == nil || !strings.Contains(err.Error(), "broader than earlier") {
		t.Errorf("want broader-than-earlier error, got %v", err)
	}
}

func TestParseAccessDisjointAnyOrder(t *testing.T) {
	if _, err := parseAccess("block /v1/*\nallow /v2/*"); err != nil {
		t.Errorf("disjoint order 1: %v", err)
	}
	if _, err := parseAccess("allow /v2/*\nblock /v1/*"); err != nil {
		t.Errorf("disjoint order 2: %v", err)
	}
}

func TestEvalEmptyListReturnsNone(t *testing.T) {
	if _, ok := evaluateAccess("/v1/foo", nil); ok {
		t.Error("expected no match on empty list")
	}
}

func TestEvalBlockAll(t *testing.T) {
	entries, _ := parseAccess("block *")
	v, ok := evaluateAccess("/anything", entries)
	if !ok || v != AccessBlock {
		t.Errorf("got (%v,%v) want (Block,true)", v, ok)
	}
}

func TestEvalLastMatchWins(t *testing.T) {
	entries, _ := parseAccess("block *\nallow /v1/*")
	if v, ok := evaluateAccess("/v1/foo", entries); !ok || v != AccessAllow {
		t.Errorf("/v1/foo: got (%v,%v)", v, ok)
	}
	if v, ok := evaluateAccess("/v2/foo", entries); !ok || v != AccessBlock {
		t.Errorf("/v2/foo: got (%v,%v)", v, ok)
	}
}

func TestEvalNestedBlockAfterAllow(t *testing.T) {
	entries, _ := parseAccess("block *\nallow /v1/*\nblock /v1/admin/*")
	cases := []struct {
		path string
		want AccessVerb
	}{
		{"/v1/admin/x", AccessBlock},
		{"/v1/users", AccessAllow},
		{"/anything", AccessBlock},
	}
	for _, c := range cases {
		v, ok := evaluateAccess(c.path, entries)
		if !ok || v != c.want {
			t.Errorf("%s: got (%v,%v) want %v", c.path, v, ok, c.want)
		}
	}
}

func TestPortMatches(t *testing.T) {
	r := InjectionRule{Ports: nil}
	if !r.PortMatches(443) || !r.PortMatches(-1) {
		t.Error("empty ports must match anything (incl. unspecified)")
	}
	r2 := InjectionRule{Ports: []uint16{8443}}
	if !r2.PortMatches(8443) {
		t.Error("8443 should match")
	}
	if r2.PortMatches(443) {
		t.Error("443 should not match")
	}
	if r2.PortMatches(-1) {
		t.Error("unspecified port should not match a port-restricted rule")
	}
}

// ── SQLite test helpers ────────────────────────────────────────────────

func createTestDB(t *testing.T, dir string) string {
	t.Helper()
	dbPath := filepath.Join(dir, "test.sqlite")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if _, err := db.Exec(`
		CREATE TABLE cache (key TEXT PRIMARY KEY, value TEXT);
		INSERT INTO cache VALUES ('cookie', 'session_abc123');
	`); err != nil {
		t.Fatalf("init db: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	if err := os.Chmod(dbPath, 0o600); err != nil {
		t.Fatalf("chmod db: %v", err)
	}
	return dbPath
}

func strPtr(s string) *string { return &s }

// ── applyInjections ────────────────────────────────────────────────────

func TestInjectSetHeaderReplacesPlaceholder(t *testing.T) {
	headers := http.Header{}
	headers.Set("accept", "application/json")
	headers.Set("x-api-key", "PLACEHOLDER")

	rules := []InjectionRule{makeRule("*", []Injection{setHeader("x-api-key", "sk-ant-123")})}
	count, err := applyInjections(headers, "/v1/messages", rules)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("count=%d want 1", count)
	}
	if got := headers.Get("x-api-key"); got != "sk-ant-123" {
		t.Errorf("x-api-key=%q", got)
	}
	if got := headers.Get("accept"); got != "application/json" {
		t.Errorf("accept=%q", got)
	}
}

func TestInjectSetHeaderSkipsWhenNoPlaceholder(t *testing.T) {
	headers := http.Header{}
	headers.Set("accept", "application/json")

	rules := []InjectionRule{makeRule("*", []Injection{setHeader("x-api-key", "sk-ant-123")})}
	count, err := applyInjections(headers, "/v1/messages", rules)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("count=%d want 0", count)
	}
	if headers.Get("x-api-key") != "" {
		t.Error("x-api-key should not be set without placeholder")
	}
}

func TestInjectRemoveHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("authorization", "Bearer token")

	rules := []InjectionRule{makeRule("*", []Injection{removeHeader("authorization")})}
	count, err := applyInjections(headers, "/", rules)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("count=%d want 1", count)
	}
	if headers.Get("authorization") != "" {
		t.Error("authorization should have been removed")
	}
}

func TestInjectPathMismatchSkipsRule(t *testing.T) {
	headers := http.Header{}
	headers.Set("x-api-key", "PLACEHOLDER")

	rules := []InjectionRule{makeRule("/v1/*", []Injection{setHeader("x-api-key", "sk-ant-123")})}
	count, err := applyInjections(headers, "/v2/messages", rules)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("count=%d want 0", count)
	}
	if headers.Get("x-api-key") != "PLACEHOLDER" {
		t.Errorf("x-api-key=%q (should be untouched)", headers.Get("x-api-key"))
	}
}

func TestInjectMultipleRulesDifferentPaths(t *testing.T) {
	headers := http.Header{}
	headers.Set("x-api-key", "PLACEHOLDER")

	rules := []InjectionRule{
		makeRule("/v1/*", []Injection{setHeader("x-api-key", "key-v1")}),
		makeRule("/v2/*", []Injection{setHeader("x-api-key", "key-v2")}),
	}
	count, err := applyInjections(headers, "/v1/messages", rules)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("count=%d want 1", count)
	}
	if got := headers.Get("x-api-key"); got != "key-v1" {
		t.Errorf("x-api-key=%q want key-v1", got)
	}
}

// ── applyQueryInjections ───────────────────────────────────────────────

func TestQueryInjectSkipsWhenNoPlaceholder(t *testing.T) {
	rules := []InjectionRule{makeRule("*", []Injection{setQueryParam("api_key", "abc123")})}
	result, count, err := applyQueryInjections("/fred/series", rules)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 || result != "/fred/series" {
		t.Errorf("got (%q,%d)", result, count)
	}
}

func TestQueryInjectReplacesPlaceholder(t *testing.T) {
	rules := []InjectionRule{makeRule("*", []Injection{setQueryParam("api_key", "abc123")})}
	result, count, err := applyQueryInjections("/fred/series?api_key=PLACEHOLDER&series_id=GDP", rules)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("count=%d want 1", count)
	}
	if !strings.Contains(result, "series_id=GDP") {
		t.Errorf("missing series_id=GDP: %s", result)
	}
	if !strings.Contains(result, "api_key=abc123") {
		t.Errorf("missing api_key=abc123: %s", result)
	}
	if strings.Contains(result, "PLACEHOLDER") {
		t.Errorf("placeholder still present: %s", result)
	}
}

func TestQueryInjectEncodesSpecialChars(t *testing.T) {
	rules := []InjectionRule{makeRule("*", []Injection{setQueryParam("q", "hello world&more")})}
	result, _, err := applyQueryInjections("/search?q=PLACEHOLDER", rules)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, "q=hello%20world%26more") {
		t.Errorf("encoding wrong: %s", result)
	}
}

// ── SQLite injection ───────────────────────────────────────────────────

func TestSQLiteHeaderInjectionReplacesPlaceholder(t *testing.T) {
	dir := t.TempDir()
	dbPath := createTestDB(t, dir)

	headers := http.Header{}
	headers.Set("cookie", "PLACEHOLDER")

	rules := []InjectionRule{makeRule("*", []Injection{{
		Kind:   InjectSetHeaderSQLite,
		Name:   "cookie",
		DBPath: dbPath,
		Query:  "SELECT value FROM cache WHERE key = 'cookie'",
		Format: strPtr("_yhlsoft_user={}"),
	}})}

	count, err := applyInjections(headers, "/api/data", rules)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("count=%d want 1", count)
	}
	if got := headers.Get("cookie"); got != "_yhlsoft_user=session_abc123" {
		t.Errorf("cookie=%q", got)
	}
}

func TestSQLiteHeaderInjectionSkipsWhenNoPlaceholder(t *testing.T) {
	dir := t.TempDir()
	dbPath := createTestDB(t, dir)

	headers := http.Header{} // no cookie present

	rules := []InjectionRule{makeRule("*", []Injection{{
		Kind:   InjectSetHeaderSQLite,
		Name:   "cookie",
		DBPath: dbPath,
		Query:  "SELECT value FROM cache WHERE key = 'cookie'",
	}})}

	count, err := applyInjections(headers, "/api/data", rules)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("count=%d want 0", count)
	}
}

func TestSQLiteHeaderInjectionFailsLoudlyOnMissingDB(t *testing.T) {
	headers := http.Header{}
	headers.Set("cookie", "PLACEHOLDER")

	rules := []InjectionRule{makeRule("*", []Injection{{
		Kind:   InjectSetHeaderSQLite,
		Name:   "cookie",
		DBPath: "/nonexistent/test.sqlite",
		Query:  "SELECT value FROM cache WHERE key = 'cookie'",
	}})}

	_, err := applyInjections(headers, "/api/data", rules)
	if err == nil || !strings.Contains(err.Error(), "sqlite injection") {
		t.Errorf("want sqlite-injection error, got %v", err)
	}
	// Placeholder must remain intact so the request is not forwarded with the dummy value.
	if got := headers.Get("cookie"); got != "PLACEHOLDER" {
		t.Errorf("placeholder mutated: cookie=%q", got)
	}
}

func TestSQLiteQueryParamInjection(t *testing.T) {
	dir := t.TempDir()
	dbPath := createTestDB(t, dir)

	rules := []InjectionRule{makeRule("*", []Injection{{
		Kind:   InjectSetQueryParamSQLite,
		Name:   "token",
		DBPath: dbPath,
		Query:  "SELECT value FROM cache WHERE key = 'cookie'",
	}})}

	result, count, err := applyQueryInjections("/api/data?token=PLACEHOLDER&foo=bar", rules)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("count=%d", count)
	}
	if !strings.Contains(result, "token=session_abc123") {
		t.Errorf("missing token=session_abc123: %s", result)
	}
	if !strings.Contains(result, "foo=bar") {
		t.Errorf("missing foo=bar: %s", result)
	}
}

func TestSQLiteReadsUpdatedValue(t *testing.T) {
	dir := t.TempDir()
	dbPath := createTestDB(t, dir)

	// Update after initial creation; query should see the new value.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE cache SET value = 'new_session_xyz' WHERE key = 'cookie'"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	headers := http.Header{}
	headers.Set("cookie", "PLACEHOLDER")

	rules := []InjectionRule{makeRule("*", []Injection{{
		Kind:   InjectSetHeaderSQLite,
		Name:   "cookie",
		DBPath: dbPath,
		Query:  "SELECT value FROM cache WHERE key = 'cookie'",
	}})}

	count, err := applyInjections(headers, "/", rules)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("count=%d", count)
	}
	if got := headers.Get("cookie"); got != "new_session_xyz" {
		t.Errorf("cookie=%q", got)
	}
}

func TestSQLiteHeaderInjectionReadsBlobColumn(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "blob.sqlite")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE cache (key TEXT PRIMARY KEY, data BLOB NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO cache VALUES (?, ?)", "cookie", []byte("session_from_blob")); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if err := os.Chmod(dbPath, 0o600); err != nil {
		t.Fatal(err)
	}

	headers := http.Header{}
	headers.Set("cookie", "PLACEHOLDER")

	rules := []InjectionRule{makeRule("*", []Injection{{
		Kind:   InjectSetHeaderSQLite,
		Name:   "cookie",
		DBPath: dbPath,
		Query:  "SELECT data FROM cache WHERE key = 'cookie'",
	}})}

	count, err := applyInjections(headers, "/", rules)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("count=%d", count)
	}
	if got := headers.Get("cookie"); got != "session_from_blob" {
		t.Errorf("cookie=%q", got)
	}
}

func TestPercentEncodeUnreserved(t *testing.T) {
	if got := percentEncode("AZaz09-_.~"); got != "AZaz09-_.~" {
		t.Errorf("unreserved should pass through, got %q", got)
	}
}

func TestPercentEncodeReserved(t *testing.T) {
	if got := percentEncode("hello world&more"); got != "hello%20world%26more" {
		t.Errorf("got %q", got)
	}
}
