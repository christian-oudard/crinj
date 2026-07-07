package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256" // register SHA-256/384 for crypto.Hash.New
	_ "crypto/sha512" // register SHA-512
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// JWT-bearer assertion signing for service-account auth (RFC 7523). crinj holds
// the real private key and signs a fresh assertion per token exchange, so a
// sandboxed client authenticates as the service account without ever holding
// the key. Unlike a bearer secret, a private key cannot be injected by
// substitution: there is no static value in the request to swap, only a
// per-request signature. So this is crinj's one signing path; capture, vault,
// and resource-bearer injection are reused from the OAuth engine. See SPEC.md.

// jwtBearerGrant is the RFC 7523 grant type a service-account client sends to
// exchange a signed assertion for an access token.
const jwtBearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// JWTSigner signs a service-account assertion from crinj-fixed claims. It is
// built once at config load from a [host.jwt] block; the private key never
// leaves the process, and the claims (issuer, scope, subject) are fixed here,
// not taken from the client, so the client cannot widen its own authority.
type JWTSigner struct {
	Issuer   string
	Audience string
	Scope    string
	Subject  string // optional; setting it opts into domain-wide-delegation impersonation
	Kid      string
	alg      string
	hash     crypto.Hash
	key      *rsa.PrivateKey
}

// jwtHashes is the supported alg set. Google service-account keys are RSA, so
// the RSA family covers every real use; anything else is a config error rather
// than a silent fallback.
var jwtHashes = map[string]crypto.Hash{
	"RS256": crypto.SHA256,
	"RS384": crypto.SHA384,
	"RS512": crypto.SHA512,
}

// NewJWTSigner parses the PEM private key and validates the algorithm. alg
// defaults to RS256.
func NewJWTSigner(issuer, audience, scope, subject, alg, kid string, keyPEM []byte) (*JWTSigner, error) {
	if alg == "" {
		alg = "RS256"
	}
	h, ok := jwtHashes[alg]
	if !ok {
		return nil, fmt.Errorf("unsupported jwt alg %q (want RS256, RS384, or RS512)", alg)
	}
	key, err := parseRSAPrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	return &JWTSigner{
		Issuer: issuer, Audience: audience, Scope: scope, Subject: subject,
		Kid: kid, alg: alg, hash: h, key: key,
	}, nil
}

// identity is the vault reuse key. A jwt-bearer exchange returns no refresh
// token, so a re-exchange cannot be matched by a placeholder the way a refresh
// is; without a stable key each renewal would mint a new placeholder and row.
// Keying by authority (endpoint + the crinj-fixed claims) lets a renewal find
// and rotate the existing row, keeping one stable placeholder.
func (s *JWTSigner) identity(endpoint string) string {
	return strings.Join([]string{endpoint, s.Issuer, s.Subject, s.Scope}, "\x00")
}

// buildAndSign mints a fresh assertion from the crinj-fixed claims. iat/exp
// come from crinj's own clock (Google rejects an assertion whose lifetime
// exceeds one hour); the client's incoming assertion contributes nothing but
// its issuer, matched upstream in beginTokenRequest.
func (s *JWTSigner) buildAndSign(now time.Time) (string, error) {
	header := map[string]any{"alg": s.alg, "typ": "JWT"}
	if s.Kid != "" {
		header["kid"] = s.Kid
	}
	claims := map[string]any{
		"iss": s.Issuer,
		"aud": s.Audience,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
	if s.Scope != "" {
		claims["scope"] = s.Scope
	}
	if s.Subject != "" {
		claims["sub"] = s.Subject
	}
	signingInput, err := jwtSigningInput(header, claims)
	if err != nil {
		return "", err
	}
	h := s.hash.New()
	h.Write([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, s.hash, h.Sum(nil))
	if err != nil {
		return "", fmt.Errorf("signing jwt assertion: %w", err)
	}
	return signingInput + "." + b64url(sig), nil
}

// jwtSigningInput returns the base64url(header) + "." + base64url(claims) that
// a JWS signs over.
func jwtSigningInput(header, claims map[string]any) (string, error) {
	h, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshaling jwt header: %w", err)
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshaling jwt claims: %w", err)
	}
	return b64url(h) + "." + b64url(c), nil
}

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// parseRSAPrivateKey accepts a PEM RSA key in either PKCS#1 (`RSA PRIVATE KEY`)
// or PKCS#8 (`PRIVATE KEY`, what Google service-account JSON carries) form.
func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("jwt key is not valid PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing jwt private key (tried PKCS#1 and PKCS#8): %w", err)
	}
	key, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("jwt private key is %T, want RSA", keyAny)
	}
	return key, nil
}

// unverifiedAssertionIssuer extracts the `iss` claim from a JWT WITHOUT
// verifying its signature. crinj uses it only to route an incoming jwt-bearer
// request to the matching signer; the client's assertion is signed with a
// throwaway key and is otherwise discarded, so there is nothing to verify. A
// malformed assertion yields "".
func unverifiedAssertionIssuer(assertion string) string {
	parts := strings.Split(assertion, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Iss
}
