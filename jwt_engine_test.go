package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

const jwtIssuer = "svc@proj.iam.gserviceaccount.com"

// jwtTestEngine builds an engine with one jwt-bearer chain over a temp vault,
// returning the engine, the endpoint identity, and the real public key so tests
// can verify crinj's outgoing signature.
func jwtTestEngine(t *testing.T) (*OAuthEngine, string, *rsa.PublicKey) {
	t.Helper()
	priv, pemBytes := testRSAKey(t)
	signer, err := NewJWTSigner(jwtIssuer,
		"https://oauth2.googleapis.com/token",
		"https://www.googleapis.com/auth/logging.read",
		"", "", "kid1", pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	chain := OAuthChain{
		TokenHost: "oauth2.googleapis.com",
		TokenPath: "/token",
		Resource:  []string{"*.googleapis.com"},
		Signer:    signer,
	}
	e := NewOAuthEngine([]OAuthChain{chain}, openTestStore(t))
	e.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	return e, chain.endpoint(), &priv.PublicKey
}

// clientAssertion is what the sandboxed client sends: a JWT whose issuer routes
// the request, signed with a throwaway key crinj ignores. Only the iss segment
// matters here.
func clientAssertion(iss string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + iss + `","aud":"x"}`))
	return header + "." + payload + ".throwaway-signature"
}

func verifyRS256(t *testing.T, assertion string, pub *rsa.PublicKey) {
	t.Helper()
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("assertion has %d segments", len(parts))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("crinj assertion does not verify against the real key: %v", err)
	}
}

func TestEngineJWTBearerSignsAndCaptures(t *testing.T) {
	e, endpoint, pub := jwtTestEngine(t)

	// The client's jwt-bearer request is rewritten: its throwaway assertion is
	// replaced by one crinj signs with the real key.
	req := &tokenBody{isForm: true, form: []formPair{
		{"grant_type", jwtBearerGrant},
		{"assertion", clientAssertion(jwtIssuer)},
	}}
	ex, changed, err := e.beginTokenRequest(endpoint, req)
	if err != nil || !changed || ex == nil || ex.jwtIdentity == "" {
		t.Fatalf("beginTokenRequest: ex=%+v changed=%v err=%v", ex, changed, err)
	}
	signed := mustGet(t, req, "assertion")
	if signed == clientAssertion(jwtIssuer) {
		t.Fatal("assertion was not replaced")
	}
	verifyRS256(t, signed, pub)
	if iss := unverifiedAssertionIssuer(signed); iss != jwtIssuer {
		t.Errorf("crinj assertion iss = %q", iss)
	}

	// The response carries an access token and no refresh token; crinj captures
	// it and hands back a placeholder that mimics the token's prefix but carries
	// none of its secret entropy.
	resp := &tokenBody{json: map[string]any{"access_token": "ya29.REALaccessTOKEN", "expires_in": float64(3600)}}
	ok, err := e.completeResponse(ex, resp)
	if err != nil || !ok {
		t.Fatalf("completeResponse: ok=%v err=%v", ok, err)
	}
	placeholder := mustGet(t, resp, "access_token")
	if !strings.HasPrefix(placeholder, "ya29.crinj-placeholder-") {
		t.Fatalf("placeholder = %q", placeholder)
	}
	if strings.Contains(placeholder, "REALaccess") {
		t.Fatalf("real token leaked into placeholder: %q", placeholder)
	}
	if _, present := resp.json["refresh_token"]; present {
		t.Error("jwt-bearer response should carry no refresh token")
	}

	// The placeholder resolves to the real access token on the resource host.
	bearer, ok, err := e.resourceBearer(endpoint, "Bearer "+placeholder)
	if err != nil || !ok || bearer != "Bearer ya29.REALaccessTOKEN" {
		t.Fatalf("resourceBearer = %q ok=%v err=%v", bearer, ok, err)
	}
}

func TestEngineJWTBearerIssuerMismatchPassesThrough(t *testing.T) {
	e, endpoint, _ := jwtTestEngine(t)
	original := clientAssertion("stranger@evil.com")
	req := &tokenBody{isForm: true, form: []formPair{
		{"grant_type", jwtBearerGrant},
		{"assertion", original},
	}}
	ex, changed, err := e.beginTokenRequest(endpoint, req)
	if err != nil || changed || ex != nil {
		t.Fatalf("unconfigured issuer should pass through: ex=%+v changed=%v err=%v", ex, changed, err)
	}
	if got := mustGet(t, req, "assertion"); got != original {
		t.Error("assertion mutated for an issuer we do not broker")
	}
}

func TestEngineJWTBearerRenewalReusesRow(t *testing.T) {
	e, endpoint, _ := jwtTestEngine(t)

	exchange := func(realAT string) string {
		req := &tokenBody{isForm: true, form: []formPair{
			{"grant_type", jwtBearerGrant},
			{"assertion", clientAssertion(jwtIssuer)},
		}}
		ex, _, err := e.beginTokenRequest(endpoint, req)
		if err != nil {
			t.Fatal(err)
		}
		resp := &tokenBody{json: map[string]any{"access_token": realAT}}
		if _, err := e.completeResponse(ex, resp); err != nil {
			t.Fatal(err)
		}
		return mustGet(t, resp, "access_token")
	}

	first := exchange("REAL-at-1")
	second := exchange("REAL-at-2")
	if first != second {
		t.Errorf("renewal changed the placeholder: %q vs %q", first, second)
	}

	// The same placeholder now resolves to the rotated real token.
	bearer, _, _ := e.resourceBearer(endpoint, "Bearer "+second)
	if bearer != "Bearer REAL-at-2" {
		t.Errorf("rotated bearer = %q", bearer)
	}

	// And there is exactly one row: renewals rotate, they do not accumulate.
	var count int
	if err := e.store.db.QueryRow("SELECT COUNT(*) FROM token").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("row count = %d, want 1 (identity-keyed reuse)", count)
	}
}
