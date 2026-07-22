package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
	if iss, _ := unverifiedClaims(signed); iss != jwtIssuer {
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

// decodeJWTSegment decodes one base64url JWT segment as JSON.
func decodeJWTSegment(t *testing.T, seg string) map[string]any {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestEngineResignsSelfSignedJWTBearer(t *testing.T) {
	e, endpoint, pub := jwtTestEngine(t)

	bearer, ok, err := e.resignResourceBearer(endpoint, "Bearer "+clientAssertion(jwtIssuer))
	if err != nil || !ok {
		t.Fatalf("resignResourceBearer: ok=%v err=%v", ok, err)
	}
	signed := strings.TrimPrefix(bearer, "Bearer ")
	verifyRS256(t, signed, pub)

	parts := strings.Split(signed, ".")
	header := decodeJWTSegment(t, parts[0])
	if header["kid"] != "kid1" {
		t.Errorf("kid = %v", header["kid"])
	}
	claims := decodeJWTSegment(t, parts[1])
	if claims["iss"] != jwtIssuer || claims["sub"] != jwtIssuer {
		t.Errorf("iss = %v, sub = %v", claims["iss"], claims["sub"])
	}
	// Authority claims are crinj-fixed: the configured scope wins and the
	// client's aud ("x" in clientAssertion) is dropped.
	if claims["scope"] != "https://www.googleapis.com/auth/logging.read" {
		t.Errorf("scope = %v", claims["scope"])
	}
	if _, present := claims["aud"]; present {
		t.Errorf("aud should be dropped when a scope is configured, got %v", claims["aud"])
	}
	if exp, iat := claims["exp"].(float64), claims["iat"].(float64); exp-iat != 3600 {
		t.Errorf("lifetime = %v seconds, want 3600", exp-iat)
	}
}

func TestEngineResignKeepsClientAudWithoutScope(t *testing.T) {
	priv, pemBytes := testRSAKey(t)
	signer, err := NewJWTSigner(jwtIssuer, "https://oauth2.googleapis.com/token",
		"", "", "", "", pemBytes)
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

	bearer, ok, err := e.resignResourceBearer(chain.endpoint(), "Bearer "+clientAssertion(jwtIssuer))
	if err != nil || !ok {
		t.Fatalf("resignResourceBearer: ok=%v err=%v", ok, err)
	}
	signed := strings.TrimPrefix(bearer, "Bearer ")
	verifyRS256(t, signed, &priv.PublicKey)
	claims := decodeJWTSegment(t, strings.Split(signed, ".")[1])
	if claims["aud"] != "x" {
		t.Errorf("aud = %v, want client's own aud kept", claims["aud"])
	}
	if _, present := claims["scope"]; present {
		t.Errorf("scope should be absent, got %v", claims["scope"])
	}
}

func TestEngineResignPassesThroughForeignBearers(t *testing.T) {
	e, endpoint, _ := jwtTestEngine(t)
	for _, auth := range []string{
		"Bearer ya29.crinj-placeholder-notajwt", // opaque token, not a JWT
		"Bearer " + clientAssertion("stranger@evil.com"),
		"Basic dXNlcjpwYXNz",
	} {
		if _, ok, err := e.resignResourceBearer(endpoint, auth); ok || err != nil {
			t.Errorf("resignResourceBearer(%q) = ok=%v err=%v, want pass-through", auth, ok, err)
		}
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
