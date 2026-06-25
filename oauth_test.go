package main

import (
	"strings"
	"testing"
)

func testChain() OAuthChain {
	return OAuthChain{
		TokenHost: "platform.claude.com",
		TokenPath: "/v1/oauth/token",
		Resource:  "api.anthropic.com",
	}
}

func testEndpoint() string { return testChain().endpoint() }

func testEngine(t *testing.T, chains ...OAuthChain) *OAuthEngine {
	t.Helper()
	if len(chains) == 0 {
		chains = []OAuthChain{testChain()}
	}
	return NewOAuthEngine(chains, openTestStore(t))
}

func mustGet(t *testing.T, b *tokenBody, key string) string {
	t.Helper()
	v, ok := b.get(key)
	if !ok {
		t.Fatalf("expected key %q present", key)
	}
	return v
}

// ── Engine: full login lifecycle ─────────────────────────────────────────

func TestEngineCodeExchangeCapturesAndFakes(t *testing.T) {
	e := testEngine(t)
	endpoint := testEndpoint()

	// code-exchange request is not rewritten, but flags a new login.
	req := &tokenBody{json: map[string]any{"grant_type": "authorization_code", "code": "abc"}}
	ex, changed, err := e.beginTokenRequest(endpoint, req)
	if err != nil || changed || ex == nil || !ex.newLogin {
		t.Fatalf("beginTokenRequest: ex=%+v changed=%v err=%v", ex, changed, err)
	}

	resp := &tokenBody{json: map[string]any{
		"access_token":  "sk-ant-oat01-REALaccess",
		"refresh_token": "sk-ant-ort01-REALrefresh",
		"expires_in":    float64(3600),
	}}
	ok, err := e.completeResponse(ex, resp)
	if err != nil || !ok {
		t.Fatalf("completeResponse: ok=%v err=%v", ok, err)
	}
	issuedAccess := mustGet(t, resp, "access_token")
	issuedRefresh := mustGet(t, resp, "refresh_token")
	if !strings.HasPrefix(issuedAccess, "sk-ant-oat01-crinj-placeholder-") {
		t.Fatalf("issued access = %q", issuedAccess)
	}
	if strings.Contains(issuedAccess, "REALaccess") {
		t.Fatal("real token leaked into placeholder")
	}
	if resp.json["expires_in"] != float64(3600) {
		t.Error("expires_in mutated")
	}

	// the real access token is now injectable for that placeholder.
	bearer, ok, err := e.resourceBearer(endpoint, "Bearer "+issuedAccess)
	if err != nil || !ok || bearer != "Bearer sk-ant-oat01-REALaccess" {
		t.Fatalf("resourceBearer = %q ok=%v err=%v", bearer, ok, err)
	}

	// a refresh with the placeholder swaps in the real refresh token...
	req2 := &tokenBody{json: map[string]any{"grant_type": "refresh_token", "refresh_token": issuedRefresh}}
	ex2, changed, err := e.beginTokenRequest(endpoint, req2)
	if err != nil || !changed || ex2 == nil || ex2.refresh == nil {
		t.Fatalf("refresh begin: ex=%+v changed=%v err=%v", ex2, changed, err)
	}
	if got := mustGet(t, req2, "refresh_token"); got != "sk-ant-ort01-REALrefresh" {
		t.Fatalf("refresh request not swapped: %q", got)
	}

	// ...and the response rotates the real tokens but keeps the placeholders.
	resp2 := &tokenBody{json: map[string]any{"access_token": "REAL-at-2", "refresh_token": "REAL-rt-2"}}
	if _, err := e.completeResponse(ex2, resp2); err != nil {
		t.Fatal(err)
	}
	if got := mustGet(t, resp2, "access_token"); got != issuedAccess {
		t.Errorf("placeholder changed across refresh: %q vs %q", got, issuedAccess)
	}
	bearer, _, _ = e.resourceBearer(endpoint, "Bearer "+issuedAccess)
	if bearer != "Bearer REAL-at-2" {
		t.Errorf("rotated bearer = %q", bearer)
	}
}

func TestEngineMultipleTokensFromOneIssuer(t *testing.T) {
	e := testEngine(t)
	endpoint := testEndpoint()
	login := func(realAT string) string {
		ex := &tokenExchange{endpoint: endpoint, newLogin: true}
		resp := &tokenBody{json: map[string]any{"access_token": realAT}}
		e.completeResponse(ex, resp)
		return mustGet(t, resp, "access_token")
	}
	p1 := login("REAL-at-1")
	p2 := login("REAL-at-2")
	if p1 == p2 {
		t.Fatal("two logins from one issuer collided on the same placeholder")
	}
	b1, _, _ := e.resourceBearer(endpoint, "Bearer "+p1)
	b2, _, _ := e.resourceBearer(endpoint, "Bearer "+p2)
	if b1 != "Bearer REAL-at-1" || b2 != "Bearer REAL-at-2" {
		t.Fatalf("tokens not independent: %q %q", b1, b2)
	}
}

func TestEngineResourceBearerScopedToIssuer(t *testing.T) {
	e := testEngine(t)
	endpoint := testEndpoint()
	ex := &tokenExchange{endpoint: endpoint, newLogin: true}
	resp := &tokenBody{json: map[string]any{"access_token": "REAL-at"}}
	e.completeResponse(ex, resp)
	placeholder := mustGet(t, resp, "access_token")

	// presenting the placeholder under a different issuer must not inject.
	if _, ok, _ := e.resourceBearer("other.example.com /token", "Bearer "+placeholder); ok {
		t.Error("token injected for the wrong issuer")
	}
	// an unknown bearer is left alone.
	if _, ok, _ := e.resourceBearer(endpoint, "Bearer not-a-placeholder"); ok {
		t.Error("unknown bearer should not match")
	}
	// a non-bearer header is left alone.
	if _, ok, _ := e.resourceBearer(endpoint, "Basic abc"); ok {
		t.Error("non-bearer should not match")
	}
}

func TestEngineUnrecognizedRefreshPassesThrough(t *testing.T) {
	e := testEngine(t)
	req := &tokenBody{json: map[string]any{"grant_type": "refresh_token", "refresh_token": "stranger"}}
	ex, changed, err := e.beginTokenRequest(testEndpoint(), req)
	if err != nil || changed || ex != nil {
		t.Fatalf("unrecognized refresh: ex=%+v changed=%v err=%v", ex, changed, err)
	}
	if got := mustGet(t, req, "refresh_token"); got != "stranger" {
		t.Errorf("body mutated: %q", got)
	}
}

func TestEngineSurvivesRestart(t *testing.T) {
	store := openTestStore(t)
	endpoint := testEndpoint()

	first := NewOAuthEngine([]OAuthChain{testChain()}, store)
	resp := &tokenBody{json: map[string]any{"access_token": "REAL-at", "refresh_token": "REAL-rt"}}
	first.completeResponse(&tokenExchange{endpoint: endpoint, newLogin: true}, resp)
	placeholder := mustGet(t, resp, "access_token")

	// a fresh engine over the same store resolves the placeholder, as if
	// crinj had restarted.
	restored := NewOAuthEngine([]OAuthChain{testChain()}, store)
	bearer, ok, err := restored.resourceBearer(endpoint, "Bearer "+placeholder)
	if err != nil || !ok || bearer != "Bearer REAL-at" {
		t.Fatalf("did not survive restart: bearer=%q ok=%v err=%v", bearer, ok, err)
	}
}

// ── Form-encoded token flow ──────────────────────────────────────────────

func TestEngineFormRefreshRoundTrips(t *testing.T) {
	e := testEngine(t)
	endpoint := testEndpoint()
	// seed a login whose real refresh token contains chars needing re-encoding.
	ex := &tokenExchange{endpoint: endpoint, newLogin: true}
	resp := &tokenBody{json: map[string]any{"access_token": "REAL-at", "refresh_token": "1//0g-REAL/rt+x"}}
	e.completeResponse(ex, resp)
	issuedRefresh := mustGet(t, resp, "refresh_token")

	body, ok := parseTokenBody(formCT, []byte("grant_type=refresh_token&refresh_token="+issuedRefresh+"&client_id=x"))
	if !ok {
		t.Fatal("parse failed")
	}
	if _, changed, err := e.beginTokenRequest(endpoint, body); err != nil || !changed {
		t.Fatalf("form refresh: changed=%v err=%v", changed, err)
	}
	out := string(body.toBytes())
	if !strings.Contains(out, "refresh_token=1%2F%2F0g-REAL%2Frt%2Bx") {
		t.Fatalf("real refresh not re-encoded: %s", out)
	}
	if !strings.Contains(out, "client_id=x") {
		t.Fatalf("client_id lost: %s", out)
	}
}

// ── mintFake ─────────────────────────────────────────────────────────────

func TestMintFakePreservesPrefix(t *testing.T) {
	cases := []struct{ in, prefix string }{
		{"sk-ant-oat01-abcdef123456", "sk-ant-oat01-crinj-placeholder-"},
		{"ya29.aBcDeF", "ya29.crinj-placeholder-"},
		{"1//0gLongRefreshToken", "1//crinj-placeholder-"},
		{"gho_sometoken", "gho_crinj-placeholder-"},
	}
	for _, tc := range cases {
		if got := mintFake(tc.in); !strings.HasPrefix(got, tc.prefix) {
			t.Errorf("mintFake(%q) = %q, want prefix %q", tc.in, got, tc.prefix)
		}
	}
}

func TestMintFakeIsUnique(t *testing.T) {
	if mintFake("sk-ant-oat01-x") == mintFake("sk-ant-oat01-x") {
		t.Error("placeholders must be unique per login")
	}
}

// ── tokenBody parsing ────────────────────────────────────────────────────

const formCT = "application/x-www-form-urlencoded"

func TestFormDecodeHandlesPercentAndPlus(t *testing.T) {
	pairs := formParse([]byte("a=%2Fx%2B&b=hello+world"))
	want := []formPair{{"a", "/x+"}, {"b", "hello world"}}
	if len(pairs) != len(want) {
		t.Fatalf("got %v", pairs)
	}
	for i := range want {
		if pairs[i] != want[i] {
			t.Fatalf("pair %d = %v, want %v", i, pairs[i], want[i])
		}
	}
}

func TestParseFallsBackToJSON(t *testing.T) {
	body, ok := parseTokenBody("application/json", []byte(`{"access_token":"x"}`))
	if !ok || body.isForm {
		t.Fatalf("expected JSON parse, ok=%v isForm=%v", ok, body.isForm)
	}
	if got := mustGet(t, body, "access_token"); got != "x" {
		t.Fatalf("access_token = %q", got)
	}
}

func TestParseUnparseableBody(t *testing.T) {
	if _, ok := parseTokenBody("application/json", []byte("not json")); ok {
		t.Error("garbage should not parse")
	}
}

func TestIsTokenEndpointMatchesHostAndPath(t *testing.T) {
	c := testChain()
	cases := []struct {
		host, path string
		want       bool
	}{
		{"platform.claude.com", "/v1/oauth/token", true},
		{"platform.claude.com", "/v1/oauth/token?x=1", true},
		{"api.anthropic.com", "/v1/oauth/token", false},
		{"platform.claude.com", "/v1/other", false},
	}
	for _, tc := range cases {
		if got := c.isTokenEndpoint(tc.host, tc.path); got != tc.want {
			t.Errorf("isTokenEndpoint(%q,%q) = %v, want %v", tc.host, tc.path, got, tc.want)
		}
	}
}

func TestMatchesResourceWildcard(t *testing.T) {
	c := OAuthChain{Resource: "*.googleapis.com"}
	if !c.matchesResource("gmail.googleapis.com") {
		t.Error("wildcard should match family member")
	}
	if c.matchesResource("evil.com") {
		t.Error("unrelated host should not match")
	}
}
