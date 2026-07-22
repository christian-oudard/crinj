package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

// testRSAKey returns a fresh 2048-bit RSA key and its PKCS#8 PEM encoding (the
// form Google service-account JSON carries).
func testRSAKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// decodeSegment parses one base64url JWT segment as JSON.
func decodeSegment(t *testing.T, seg string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatalf("decoding segment: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshaling segment: %v", err)
	}
	return m
}

func TestJWTSignerRoundTrip(t *testing.T) {
	priv, pemBytes := testRSAKey(t)
	signer, err := NewJWTSigner(
		"svc@proj.iam.gserviceaccount.com",
		"https://oauth2.googleapis.com/token",
		"https://www.googleapis.com/auth/logging.read",
		"", "", "key-id-123", pemBytes)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1_700_000_000, 0)
	assertion, err := signer.buildAndSign(now)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("assertion has %d segments, want 3", len(parts))
	}

	// The signature must verify against the real key over the signing input.
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}

	header := decodeSegment(t, parts[0])
	if header["alg"] != "RS256" || header["typ"] != "JWT" || header["kid"] != "key-id-123" {
		t.Fatalf("header = %v", header)
	}

	claims := decodeSegment(t, parts[1])
	if claims["iss"] != "svc@proj.iam.gserviceaccount.com" {
		t.Errorf("iss = %v", claims["iss"])
	}
	if claims["aud"] != "https://oauth2.googleapis.com/token" {
		t.Errorf("aud = %v", claims["aud"])
	}
	if claims["scope"] != "https://www.googleapis.com/auth/logging.read" {
		t.Errorf("scope = %v", claims["scope"])
	}
	if claims["iat"].(float64) != 1_700_000_000 {
		t.Errorf("iat = %v", claims["iat"])
	}
	// Google caps assertion lifetime at one hour.
	if claims["exp"].(float64) != 1_700_003_600 {
		t.Errorf("exp = %v, want iat+3600", claims["exp"])
	}
	if _, present := claims["sub"]; present {
		t.Error("sub must be absent when not configured")
	}
}

func TestJWTSignerSubjectOptIn(t *testing.T) {
	_, pemBytes := testRSAKey(t)
	signer, err := NewJWTSigner("iss", "aud", "scope", "user@example.com", "", "", pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := signer.buildAndSign(time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	claims := decodeSegment(t, strings.Split(assertion, ".")[1])
	if claims["sub"] != "user@example.com" {
		t.Errorf("sub = %v, want the configured subject", claims["sub"])
	}
}

func TestJWTSignerAcceptsPKCS1(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if _, err := NewJWTSigner("iss", "aud", "scope", "", "", "", pemBytes); err != nil {
		t.Fatalf("PKCS#1 key should parse: %v", err)
	}
}

func TestJWTSignerRejectsBadAlg(t *testing.T) {
	_, pemBytes := testRSAKey(t)
	if _, err := NewJWTSigner("iss", "aud", "scope", "", "ES256", "", pemBytes); err == nil {
		t.Fatal("expected unsupported-alg error")
	}
}

func TestJWTSignerRejectsGarbageKey(t *testing.T) {
	if _, err := NewJWTSigner("iss", "aud", "scope", "", "", "", []byte("not a pem")); err == nil {
		t.Fatal("expected key parse error")
	}
}

func TestUnverifiedClaims(t *testing.T) {
	// A well-formed (but irrelevantly-signed) token yields its iss and aud.
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"who@example.com","aud":"x"}`))
	token := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + payload + ".sig"
	if iss, aud := unverifiedClaims(token); iss != "who@example.com" || aud != "x" {
		t.Errorf("iss = %q, aud = %q", iss, aud)
	}
	// Malformed inputs yield "".
	for _, bad := range []string{"", "onlyonesegment", "a.!!!notbase64!!!.c", "a." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".c"} {
		if iss, aud := unverifiedClaims(bad); iss != "" || aud != "" {
			t.Errorf("unverifiedClaims(%q) = %q, %q, want empty", bad, iss, aud)
		}
	}
}
