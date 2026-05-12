package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeFileMode(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
}

// ── splitHostPort ──────────────────────────────────────────────────────

func TestSplitHostPortBasic(t *testing.T) {
	cases := []struct {
		s    string
		host string
		port int
	}{
		{"example.com:443", "example.com", 443},
		{"example.com:8443", "example.com", 8443},
	}
	for _, c := range cases {
		h, p := splitHostPort(c.s)
		if h != c.host || p != c.port {
			t.Errorf("splitHostPort(%q)=(%q,%d) want (%q,%d)", c.s, h, p, c.host, c.port)
		}
	}
}

func TestSplitHostPortNoPort(t *testing.T) {
	h, p := splitHostPort("example.com")
	if h != "example.com" || p != -1 {
		t.Errorf("got (%q,%d)", h, p)
	}
}

func TestSplitHostPortIPv6(t *testing.T) {
	cases := []struct {
		s    string
		host string
		port int
	}{
		{"[::1]:443", "::1", 443},
		{"[2001:db8::1]:8080", "2001:db8::1", 8080},
	}
	for _, c := range cases {
		h, p := splitHostPort(c.s)
		if h != c.host || p != c.port {
			t.Errorf("splitHostPort(%q)=(%q,%d) want (%q,%d)", c.s, h, p, c.host, c.port)
		}
	}
}

func TestSplitHostPortIPv6NoPort(t *testing.T) {
	h, p := splitHostPort("[::1]")
	if h != "::1" || p != -1 {
		t.Errorf("got (%q,%d)", h, p)
	}
}

// ── resolveHosts ───────────────────────────────────────────────────────

// hostFixture returns a ResolvedHost mirroring the Rust test helper.
func hostFixture(pattern string) ResolvedHost {
	return ResolvedHost{
		HostPattern: pattern,
		InjectionRules: []InjectionRule{{
			PathPattern: "*",
			Injections: []Injection{{
				Kind:  InjectSetHeader,
				Name:  "x-api-key",
				Value: "sk-123",
			}},
		}},
	}
}

func TestResolveExactDomain(t *testing.T) {
	hosts := []ResolvedHost{hostFixture("api.example.com")}
	if !resolveHosts("api.example.com:443", hosts).Intercept {
		t.Error("api.example.com should intercept")
	}
	if resolveHosts("other.com:443", hosts).Intercept {
		t.Error("other.com should not intercept")
	}
}

func TestResolveWildcardDomain(t *testing.T) {
	hosts := []ResolvedHost{hostFixture("*.example.com")}
	if !resolveHosts("api.example.com:443", hosts).Intercept {
		t.Error("api.example.com should intercept")
	}
	if !resolveHosts("a.b.example.com:443", hosts).Intercept {
		t.Error("a.b.example.com should intercept")
	}
	if resolveHosts("example.com:443", hosts).Intercept {
		t.Error("bare example.com should not intercept")
	}
}

func TestResolveMiddleWildcardDomain(t *testing.T) {
	hosts := []ResolvedHost{hostFixture("http-intake.logs*.datadoghq.com")}
	cases := []struct {
		auth string
		want bool
	}{
		{"http-intake.logs.datadoghq.com:443", true},
		{"http-intake.logs.us5.datadoghq.com:443", true},
		{"api.datadoghq.com:443", false},
	}
	for _, c := range cases {
		if got := resolveHosts(c.auth, hosts).Intercept; got != c.want {
			t.Errorf("%s: intercept=%v want %v", c.auth, got, c.want)
		}
	}
}

func TestResolveMostSpecificWins(t *testing.T) {
	specific := hostFixture("api.datadoghq.com")
	specific.InjectionRules[0].Injections[0].Value = "specific"
	wildcard := hostFixture("*.datadoghq.com")
	wildcard.Access = []AccessEntry{{Verb: AccessBlock, PathPattern: "*"}}
	wildcard.InjectionRules = nil

	hosts := []ResolvedHost{wildcard, specific}
	r := resolveHosts("api.datadoghq.com:443", hosts)
	if !r.Intercept {
		t.Fatal("expected intercept")
	}
	if len(r.Access) != 0 {
		t.Errorf("expected specific host's empty access, got %+v", r.Access)
	}
	if len(r.InjectionRules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(r.InjectionRules))
	}
}

func TestResolveWildcardWinsWhenSpecificDoesntMatch(t *testing.T) {
	specific := hostFixture("api.datadoghq.com")
	wildcard := hostFixture("*.datadoghq.com")
	wildcard.Access = []AccessEntry{{Verb: AccessBlock, PathPattern: "*"}}
	wildcard.InjectionRules = nil

	hosts := []ResolvedHost{wildcard, specific}
	r := resolveHosts("http-intake.logs.datadoghq.com:443", hosts)
	if !r.Intercept {
		t.Fatal("expected intercept")
	}
	if len(r.Access) != 1 || r.Access[0].Verb != AccessBlock {
		t.Errorf("expected wildcard's block access, got %+v", r.Access)
	}
}

func TestResolveRulePortFilter(t *testing.T) {
	h := hostFixture("35.194.69.156")
	h.InjectionRules[0].Ports = []uint16{8443}
	hosts := []ResolvedHost{h}
	if n := len(resolveHosts("35.194.69.156:8443", hosts).InjectionRules); n != 1 {
		t.Errorf(":8443 rules=%d want 1", n)
	}
	if n := len(resolveHosts("35.194.69.156:443", hosts).InjectionRules); n != 0 {
		t.Errorf(":443 rules=%d want 0", n)
	}
}

func TestResolveRuleNoPortMatchesAny(t *testing.T) {
	hosts := []ResolvedHost{hostFixture("api.example.com")}
	if n := len(resolveHosts("api.example.com:443", hosts).InjectionRules); n != 1 {
		t.Errorf(":443 rules=%d want 1", n)
	}
	if n := len(resolveHosts("api.example.com:8443", hosts).InjectionRules); n != 1 {
		t.Errorf(":8443 rules=%d want 1", n)
	}
}

func TestResolvePropagatesAccess(t *testing.T) {
	h := hostFixture("api.example.com")
	access, _ := parseAccess("block *\nallow /v1/*")
	h.Access = access
	r := resolveHosts("api.example.com:443", []ResolvedHost{h})
	if len(r.Access) != 2 {
		t.Errorf("access=%d want 2", len(r.Access))
	}
}

func TestResolvePropagatesNoCheckCertificate(t *testing.T) {
	h := hostFixture("10.0.0.1")
	h.NoCheckCertificate = true
	r := resolveHosts("10.0.0.1:8443", []ResolvedHost{h})
	if !r.NoCheckCertificate {
		t.Error("no-check-certificate not propagated")
	}
}

func TestLoadEmptyConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, "")
	hosts, err := load(cfg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(hosts) != 0 {
		t.Errorf("expected empty, got %d hosts", len(hosts))
	}
}

func TestLoadMultipleHosts(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, `
[[host]]
domain = "api.anthropic.com"
[[host.inject]]
header = "x-api-key"
value = "sk-ant"

[[host]]
domain = "huggingface.co"
[[host.inject]]
header = "authorization"
value = "Bearer hf-tok"
`)
	hosts, err := load(cfg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("len=%d want 2", len(hosts))
	}
	if hosts[0].HostPattern != "api.anthropic.com" {
		t.Errorf("host[0]=%q", hosts[0].HostPattern)
	}
	if hosts[1].HostPattern != "huggingface.co" {
		t.Errorf("host[1]=%q", hosts[1].HostPattern)
	}
}

func TestLoadDuplicateDomainErrors(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, `
[[host]]
domain = "api.example.com"
[[host.inject]]
header = "x-api-key"
value = "first"

[[host]]
domain = "api.example.com"
[[host.inject]]
header = "x-api-key"
value = "second"
`)
	_, err := load(cfg)
	if err == nil || !strings.Contains(err.Error(), "duplicate host") {
		t.Errorf("want duplicate-host error, got %v", err)
	}
}

func TestLoadSingleRuleHeader(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, `
[[host]]
domain = "api.anthropic.com"
[[host.inject]]
header = "x-api-key"
value = "sk-inline-123"
`)
	hosts, err := load(cfg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	inj := hosts[0].InjectionRules[0].Injections[0]
	if inj.Kind != InjectSetHeader || inj.Name != "x-api-key" || inj.Value != "sk-inline-123" {
		t.Errorf("got %+v", inj)
	}
}

func TestLoadRemoveHeader(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, `
[[host]]
domain = "example.com"
[[host.inject]]
remove-header = "authorization"
`)
	hosts, err := load(cfg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	inj := hosts[0].InjectionRules[0].Injections[0]
	if inj.Kind != InjectRemoveHeader || inj.Name != "authorization" {
		t.Errorf("got %+v", inj)
	}
}

func TestLoadFormatWithInlineValue(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, `
[[host]]
domain = "huggingface.co"
[[host.inject]]
header = "authorization"
value = "hf_abc123"
format = "Bearer {}"
`)
	hosts, err := load(cfg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	inj := hosts[0].InjectionRules[0].Injections[0]
	if inj.Value != "Bearer hf_abc123" {
		t.Errorf("value=%q", inj.Value)
	}
}

func TestLoadAccessMultiline(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, `
[[host]]
domain = "api.anthropic.com"
access = """
block *
allow /v1/*
"""
[[host.inject]]
header = "x-api-key"
value = "sk-ant"
`)
	hosts, err := load(cfg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(hosts[0].Access) != 2 ||
		hosts[0].Access[0].Verb != AccessBlock ||
		hosts[0].Access[1].Verb != AccessAllow {
		t.Errorf("access=%+v", hosts[0].Access)
	}
}

func TestLoadAccessSingleLine(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, `
[[host]]
domain = "telemetry.example.com"
access = "block *"
`)
	hosts, err := load(cfg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(hosts[0].Access) != 1 || hosts[0].Access[0].Verb != AccessBlock {
		t.Errorf("access=%+v", hosts[0].Access)
	}
	if len(hosts[0].InjectionRules) != 0 {
		t.Errorf("expected no injection rules, got %d", len(hosts[0].InjectionRules))
	}
}

func TestLoadAccessUnnaturalOrderErrors(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, `
[[host]]
domain = "api.example.com"
access = """
allow /v1/*
block *
"""
[[host.inject]]
header = "x-api-key"
value = "sk"
`)
	_, err := load(cfg)
	if err == nil || !strings.Contains(err.Error(), "broader than earlier") {
		t.Errorf("want broader-than-earlier error, got %v", err)
	}
}

func TestLoadRulePorts(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, `
[[host]]
domain = "35.194.69.156"
[[host.inject]]
ports = [8443]
header = "authorization"
value = "Bearer tok"
`)
	hosts, err := load(cfg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	ports := hosts[0].InjectionRules[0].Ports
	if len(ports) != 1 || ports[0] != 8443 {
		t.Errorf("ports=%v", ports)
	}
}

func TestLoadRuleWithoutActionFails(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, `
[[host]]
domain = "example.com"
[[host.inject]]
value = "whatever"
`)
	_, err := load(cfg)
	if err == nil || !strings.Contains(err.Error(), "header") {
		t.Errorf("want missing-action error containing 'header', got %v", err)
	}
}

func TestLoadCollectsMultipleSchemaErrors(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, `
[[host]]
domain = "a.example.com"
[[host.inject]]
value = "x"

[[host]]
domain = "b.example.com"
[[host.inject]]
value = "y"
`)
	_, err := load(cfg)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "a.example.com") {
		t.Errorf("missing a.example.com: %s", msg)
	}
	if !strings.Contains(msg, "b.example.com") {
		t.Errorf("missing b.example.com: %s", msg)
	}
}

func TestLoadSourceFromFile(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.key")
	writeFile(t, secret, "sk-from-file-456\n")

	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, fmt.Sprintf(`
[[host]]
domain = "api.anthropic.com"
[[host.inject]]
source = "%s"
header = "x-api-key"
`, secret))

	hosts, err := load(cfg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	inj := hosts[0].InjectionRules[0].Injections[0]
	if inj.Value != "sk-from-file-456" {
		t.Errorf("value=%q (expected trimmed file content)", inj.Value)
	}
}

func TestLoadFormatWithFileSource(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "token.key")
	writeFile(t, secret, "hf_abc123\n")

	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, fmt.Sprintf(`
[[host]]
domain = "huggingface.co"
[[host.inject]]
source = "%s"
header = "authorization"
format = "Bearer {}"
`, secret))

	hosts, err := load(cfg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if v := hosts[0].InjectionRules[0].Injections[0].Value; v != "Bearer hf_abc123" {
		t.Errorf("value=%q", v)
	}
}

func TestLoadQueryParamFromFile(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "fred.key")
	writeFile(t, secret, "MY_API_KEY\n")

	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, fmt.Sprintf(`
[[host]]
domain = "api.stlouisfed.org"
[[host.inject]]
source = "%s"
query-param = "api_key"
`, secret))

	hosts, err := load(cfg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	inj := hosts[0].InjectionRules[0].Injections[0]
	if inj.Kind != InjectSetQueryParam || inj.Name != "api_key" || inj.Value != "MY_API_KEY" {
		t.Errorf("got %+v", inj)
	}
}

func TestLoadMissingSecretFileSkipsHost(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, fmt.Sprintf(`
[[host]]
domain = "broken.example.com"
[[host.inject]]
header = "x-api-key"
source = "%s/does-not-exist"

[[host]]
domain = "ok.example.com"
[[host.inject]]
header = "x-api-key"
value = "sk-good"
`, dir))

	hosts, err := load(cfg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(hosts) != 1 || hosts[0].HostPattern != "ok.example.com" {
		t.Errorf("got %+v", hosts)
	}
}

func TestLoadEmptySecretWithBadPermsSkipsHost(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.key")
	writeFileMode(t, secret, "", 0o644)

	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, fmt.Sprintf(`
[[host]]
domain = "example.com"
[[host.inject]]
source = "%s"
header = "x-api-key"
`, secret))

	hosts, err := load(cfg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(hosts) != 0 {
		t.Errorf("expected empty (host skipped), got %+v", hosts)
	}
}

func TestLoadPopulatedWorldReadableSecretFails(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.key")
	writeFileMode(t, secret, "sk-test\n", 0o644)

	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, fmt.Sprintf(`
[[host]]
domain = "example.com"
[[host.inject]]
source = "%s"
header = "x-api-key"
`, secret))

	_, err := load(cfg)
	if err == nil || !strings.Contains(err.Error(), "must not be group/world-accessible") {
		t.Errorf("want bad-perms error, got %v", err)
	}
}

func TestLoadRelativeSourceResolvesToSecretsDir(t *testing.T) {
	dir := t.TempDir()
	secretsDir := filepath.Join(dir, "secrets")
	if err := os.Mkdir(secretsDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFile(t, filepath.Join(secretsDir, "my.key"), "sk-relative-789\n")

	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, `
[[host]]
domain = "example.com"
[[host.inject]]
source = "my.key"
header = "x-api-key"
`)

	hosts, err := load(cfg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if v := hosts[0].InjectionRules[0].Injections[0].Value; v != "sk-relative-789" {
		t.Errorf("value=%q", v)
	}
}

func TestLoadSourcePathFromJSON(t *testing.T) {
	dir := t.TempDir()
	jsonFile := filepath.Join(dir, "creds.json")
	writeFile(t, jsonFile, `{"token": {"access_token": "abc123"}}`)

	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, fmt.Sprintf(`
[[host]]
domain = "example.com"
[[host.inject]]
source = "%s"
source-path = "token.access_token"
header = "Authorization"
format = "Bearer {}"
`, jsonFile))

	hosts, err := load(cfg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if v := hosts[0].InjectionRules[0].Injections[0].Value; v != "Bearer abc123" {
		t.Errorf("value=%q", v)
	}
}

func TestLoadSourcePathArrayIndex(t *testing.T) {
	dir := t.TempDir()
	jsonFile := filepath.Join(dir, "creds.json")
	writeFile(t, jsonFile, `{"tokens": ["first", "second"]}`)

	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, fmt.Sprintf(`
[[host]]
domain = "example.com"
[[host.inject]]
source = "%s"
source-path = "tokens.0"
header = "Authorization"
`, jsonFile))

	hosts, err := load(cfg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if v := hosts[0].InjectionRules[0].Injections[0].Value; v != "first" {
		t.Errorf("value=%q", v)
	}
}

func TestLoadSourcePathUnknownExtensionFails(t *testing.T) {
	dir := t.TempDir()
	yamlFile := filepath.Join(dir, "creds.yaml")
	writeFile(t, yamlFile, "key: value")

	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, fmt.Sprintf(`
[[host]]
domain = "example.com"
[[host.inject]]
source = "%s"
source-path = "key"
header = "x-token"
`, yamlFile))

	_, err := load(cfg)
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("want unsupported-extension error, got %v", err)
	}
}

func TestLoadRulesInheritHostSourceTOML(t *testing.T) {
	dir := t.TempDir()
	tomlFile := filepath.Join(dir, "creds.toml")
	writeFile(t, tomlFile, `
[account]
id = "ak-test123"
secret = "as-test456"
`)

	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, fmt.Sprintf(`
[[host]]
domain = "api.example.com"
source = "%s"
[[host.inject]]
source-path = "account.id"
header = "x-id"
[[host.inject]]
source-path = "account.secret"
header = "x-secret"
`, tomlFile))

	hosts, err := load(cfg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	rules := hosts[0].InjectionRules
	if len(rules) != 2 {
		t.Fatalf("len=%d want 2", len(rules))
	}
	if v := rules[0].Injections[0].Value; v != "ak-test123" {
		t.Errorf("rule 0 value=%q", v)
	}
	if v := rules[1].Injections[0].Value; v != "as-test456" {
		t.Errorf("rule 1 value=%q", v)
	}
}

// ── source-sqlite (load-time validation) ──────────────────────────────

func TestLoadSourceSQLiteHeader(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cache.sqlite")
	// Validation only checks perms+size, not file contents.
	writeFileMode(t, dbPath, "stub-bytes", 0o600)

	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, fmt.Sprintf(`
[[host]]
domain = "example.com"
[[host.inject]]
source-sqlite = "%s"
source-sqlite-query = "SELECT value FROM cache WHERE key = 'tok'"
header = "cookie"
format = "session={}"
`, dbPath))

	hosts, err := load(cfg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	inj := hosts[0].InjectionRules[0].Injections[0]
	if inj.Kind != InjectSetHeaderSQLite {
		t.Fatalf("kind=%v want SetHeaderSQLite", inj.Kind)
	}
	if inj.Name != "cookie" || inj.DBPath != dbPath ||
		inj.Query != "SELECT value FROM cache WHERE key = 'tok'" ||
		inj.Format == nil || *inj.Format != "session={}" {
		t.Errorf("got %+v", inj)
	}
}

func TestLoadSourceSQLiteQueryParam(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cache.sqlite")
	writeFileMode(t, dbPath, "stub", 0o600)

	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, fmt.Sprintf(`
[[host]]
domain = "example.com"
[[host.inject]]
source-sqlite = "%s"
source-sqlite-query = "SELECT v FROM t LIMIT 1"
query-param = "key"
`, dbPath))

	hosts, err := load(cfg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	inj := hosts[0].InjectionRules[0].Injections[0]
	if inj.Kind != InjectSetQueryParamSQLite || inj.Name != "key" {
		t.Errorf("got %+v", inj)
	}
}

func TestLoadSourceSQLiteMissingQueryErrors(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, `
[[host]]
domain = "example.com"
[[host.inject]]
source-sqlite = "/tmp/test.sqlite"
header = "cookie"
`)
	_, err := load(cfg)
	if err == nil || !strings.Contains(err.Error(), "source-sqlite-query") {
		t.Errorf("want missing-query error, got %v", err)
	}
}

func TestLoadSourceSQLiteQueryWithoutSQLiteErrors(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, `
[[host]]
domain = "example.com"
[[host.inject]]
source-sqlite-query = "SELECT 1"
header = "cookie"
`)
	_, err := load(cfg)
	if err == nil || !strings.Contains(err.Error(), "source-sqlite") {
		t.Errorf("want source-sqlite error, got %v", err)
	}
}

func TestLoadSourceSQLiteConflictsWithSource(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.key")
	writeFile(t, secret, "val")

	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, fmt.Sprintf(`
[[host]]
domain = "example.com"
[[host.inject]]
source = "%s"
source-sqlite = "/tmp/test.sqlite"
source-sqlite-query = "SELECT 1"
header = "cookie"
`, secret))

	_, err := load(cfg)
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Errorf("want cannot-be-combined error, got %v", err)
	}
}

func TestLoadSourceSQLiteWithoutActionErrors(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, `
[[host]]
domain = "example.com"
[[host.inject]]
source-sqlite = "/tmp/test.sqlite"
source-sqlite-query = "SELECT 1"
`)
	_, err := load(cfg)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "header") && !strings.Contains(msg, "query-param") {
		t.Errorf("want missing-action error, got %v", err)
	}
}

func TestLoadSourceSQLiteNonexistentFileAccepted(t *testing.T) {
	// Spec: missing DB at startup is OK. The file may be created later.
	dir := t.TempDir()
	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, `
[[host]]
domain = "example.com"
[[host.inject]]
source-sqlite = "/tmp/nonexistent_crinj_test_go.sqlite"
source-sqlite-query = "SELECT 1"
header = "cookie"
`)
	hosts, err := load(cfg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(hosts) != 1 {
		t.Errorf("expected 1 host, got %d", len(hosts))
	}
}

func TestLoadHostLevelSourceInheritance(t *testing.T) {
	// Inject entry with no `source`; should fall back to host-level `source`.
	dir := t.TempDir()
	secret := filepath.Join(dir, "shared.key")
	writeFile(t, secret, "shared-token\n")

	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, fmt.Sprintf(`
[[host]]
domain = "api.example.com"
source = "%s"
[[host.inject]]
header = "x-api-key"
`, secret))

	hosts, err := load(cfg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if v := hosts[0].InjectionRules[0].Injections[0].Value; v != "shared-token" {
		t.Errorf("value=%q", v)
	}
}

func TestLoadNoCheckCertificate(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, `
[[host]]
domain = "10.0.0.1"
no-check-certificate = true
[[host.inject]]
header = "authorization"
value = "Bearer tok"
`)
	hosts, err := load(cfg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !hosts[0].NoCheckCertificate {
		t.Error("no-check-certificate not propagated")
	}
}
