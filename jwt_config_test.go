package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeJWTConfig writes a rules.toml plus a 0600 key file in its secrets dir,
// returning the config path.
func writeJWTConfig(t *testing.T, cfg string) string {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "rules.toml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	_, pemBytes := testRSAKey(t)
	secrets := filepath.Join(dir, "secrets")
	if err := os.MkdirAll(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secrets, "sa-key.pem"), pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

const jwtConfigBody = `
[[host]]
domain = "*.googleapis.com"
[host.jwt]
token-host = "oauth2.googleapis.com"
token-path = "/token"
key = "sa-key.pem"
issuer = "svc@proj.iam.gserviceaccount.com"
scope = "https://www.googleapis.com/auth/logging.read"
`

func TestJWTConfigParsesChainWithSigner(t *testing.T) {
	cfgPath := writeJWTConfig(t, jwtConfigBody)
	chains, err := loadOAuth(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(chains) != 1 {
		t.Fatalf("got %d chains", len(chains))
	}
	c := chains[0]
	if c.Signer == nil {
		t.Fatal("chain has no signer")
	}
	if c.TokenHost != "oauth2.googleapis.com" || c.TokenPath != "/token" {
		t.Errorf("endpoint = %s %s", c.TokenHost, c.TokenPath)
	}
	// Audience defaults to the token URL when unset.
	if c.Signer.Audience != "https://oauth2.googleapis.com/token" {
		t.Errorf("audience = %q, want token URL default", c.Signer.Audience)
	}
	if c.Signer.Issuer != "svc@proj.iam.gserviceaccount.com" {
		t.Errorf("issuer = %q", c.Signer.Issuer)
	}
}

// The token host must be MITM'd so crinj can sign at it (like the OAuth case).
func TestLoadSynthesizesJWTTokenHostIntercept(t *testing.T) {
	cfgPath := writeJWTConfig(t, jwtConfigBody)
	rules, err := load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if r := resolveHosts("oauth2.googleapis.com:443", rules); !r.Intercept {
		t.Error("jwt token host should be intercepted")
	}
	if r := resolveHosts("logging.googleapis.com:443", rules); !r.Intercept {
		t.Error("resource host should be intercepted")
	}
}

func TestJWTConfigRejectsOAuthAndJWTTogether(t *testing.T) {
	cfg := `
[[host]]
domain = "api.example.com"
[host.oauth]
token-path = "/token"
[host.jwt]
token-path = "/token"
key = "sa-key.pem"
issuer = "x"
scope = "y"
`
	cfgPath := writeJWTConfig(t, cfg)
	if _, err := loadOAuth(cfgPath); err == nil || !strings.Contains(err.Error(), "both") {
		t.Fatalf("expected oauth/jwt conflict error, got %v", err)
	}
}

func TestJWTConfigRequiresFields(t *testing.T) {
	cases := map[string]string{
		"token-path": `key = "sa-key.pem"` + "\n" + `issuer = "x"` + "\n" + `scope = "y"`,
		"key":        `token-path = "/token"` + "\n" + `issuer = "x"` + "\n" + `scope = "y"`,
		"issuer":     `token-path = "/token"` + "\n" + `key = "sa-key.pem"` + "\n" + `scope = "y"`,
		"scope":      `token-path = "/token"` + "\n" + `key = "sa-key.pem"` + "\n" + `issuer = "x"`,
	}
	for missing, block := range cases {
		cfg := "[[host]]\ndomain = \"api.example.com\"\n[host.jwt]\n" + block + "\n"
		cfgPath := writeJWTConfig(t, cfg)
		_, err := loadOAuth(cfgPath)
		if err == nil || !strings.Contains(err.Error(), missing) {
			t.Errorf("missing %s: expected error naming it, got %v", missing, err)
		}
	}
}

func TestJWTConfigSkipsWhenKeyAbsent(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "rules.toml")
	// No secrets/sa-key.pem written: the key is not available yet.
	if err := os.WriteFile(cfgPath, []byte(jwtConfigBody), 0o600); err != nil {
		t.Fatal(err)
	}
	chains, err := loadOAuth(cfgPath)
	if err != nil {
		t.Fatalf("missing key should skip, not fail: %v", err)
	}
	if len(chains) != 0 {
		t.Errorf("expected the chain to be skipped, got %d", len(chains))
	}
}
