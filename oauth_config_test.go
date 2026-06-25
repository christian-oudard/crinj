package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sp(s string) *string { return &s }

func chainsFor(t *testing.T, hosts ...tomlHostEntry) []OAuthChain {
	t.Helper()
	chains, err := parseOAuthChains(&tomlConfig{Host: hosts})
	if err != nil {
		t.Fatalf("parseOAuthChains: %v", err)
	}
	return chains
}

func TestOAuthConfigSingleHost(t *testing.T) {
	chains := chainsFor(t, tomlHostEntry{
		Domain: "api.anthropic.com",
		OAuth:  &tomlHostOAuth{TokenHost: sp("platform.claude.com"), TokenPath: sp("/v1/oauth/token")},
	})
	if len(chains) != 1 {
		t.Fatalf("got %d chains", len(chains))
	}
	c := chains[0]
	if c.TokenHost != "platform.claude.com" || c.TokenPath != "/v1/oauth/token" || c.Resource != "api.anthropic.com" {
		t.Fatalf("chain = %+v", c)
	}
}

func TestOAuthConfigTokenHostDefaultsToDomain(t *testing.T) {
	chains := chainsFor(t, tomlHostEntry{
		Domain: "idp.example.com",
		OAuth:  &tomlHostOAuth{TokenPath: sp("/token")},
	})
	if chains[0].TokenHost != "idp.example.com" {
		t.Errorf("token host = %q, want domain", chains[0].TokenHost)
	}
}

func TestOAuthConfigWildcardResource(t *testing.T) {
	chains := chainsFor(t, tomlHostEntry{
		Domain: "*.googleapis.com",
		OAuth:  &tomlHostOAuth{TokenHost: sp("oauth2.googleapis.com"), TokenPath: sp("/token")},
	})
	if chains[0].Resource != "*.googleapis.com" {
		t.Errorf("resource = %q, want wildcard", chains[0].Resource)
	}
	if !chains[0].matchesResource("sheets.googleapis.com") {
		t.Error("wildcard chain should cover family members")
	}
}

func TestOAuthConfigMissingTokenPath(t *testing.T) {
	_, err := parseOAuthChains(&tomlConfig{Host: []tomlHostEntry{
		{Domain: "a.example.com", OAuth: &tomlHostOAuth{TokenHost: sp("idp")}},
	}})
	if err == nil || !strings.Contains(err.Error(), "requires token-path") {
		t.Fatalf("expected missing token-path error, got %v", err)
	}
}

// load() must synthesize an intercept entry for the token host so it is MITM'd
// rather than tunneled, carrying real tokens.
func TestLoadSynthesizesTokenHostIntercept(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "rules.toml")
	cfg := `
[[host]]
domain = "api.anthropic.com"
access = "allow /v1/*"
[host.oauth]
token-host = "platform.claude.com"
token-path = "/v1/oauth/token"
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if r := resolveHosts("platform.claude.com:443", rules); !r.Intercept {
		t.Error("token host should be intercepted (synthesized)")
	}
	if r := resolveHosts("api.anthropic.com:443", rules); !r.Intercept {
		t.Error("resource host should be intercepted")
	}
}
