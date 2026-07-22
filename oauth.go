package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// OAuth passthrough: broker a provider's token flow so a sandboxed client never
// holds a usable refresh token (and, for opaque-token providers, never a real
// access token either). The real tokens are captured in transit at the token
// endpoint and kept in a server-side vault; the client only ever sees unique
// opaque placeholders.
//
// A single issuer endpoint can mint many distinct tokens at once (different
// accounts, OAuth clients, or scopes), so the vault is keyed per login by the
// placeholder crinj issued — not by the endpoint. This file is the pure
// rewrite/match logic; gateway.go wires it into the request/response path.

// OAuthChain is the routing for one [host.oauth] block: the token endpoint to
// intercept and the resource-host pattern whose Authorization bearer is
// brokered. A host family that shares one login is a single wildcard pattern
// (e.g. *.googleapis.com), so there is no vault name and no host list.
type OAuthChain struct {
	TokenHost string
	TokenPath string
	Resource  []string

	// Signer is non-nil for a [host.jwt] chain: instead of swapping a stored
	// refresh token, crinj signs a fresh service-account assertion at the token
	// endpoint. Everything downstream (capture, vault, resource-bearer
	// injection) is shared with the OAuth path.
	Signer *JWTSigner
}

// endpoint is the token-endpoint identity, used to scope which resource hosts a
// captured token may be injected on. token paths and hosts contain no spaces.
func (c OAuthChain) endpoint() string {
	return c.TokenHost + " " + c.TokenPath
}

// isTokenEndpoint reports whether a request hits this chain's token endpoint.
func (c OAuthChain) isTokenEndpoint(host, path string) bool {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	return host == c.TokenHost && globMatches(path, c.TokenPath)
}

// matchesResource reports whether host is this chain's resource host. The
// pattern may be a wildcard (*.googleapis.com), matched like a [[host]] domain.
func (c OAuthChain) matchesResource(host string) bool {
	for _, pattern := range c.Resource {
		if globMatches(host, pattern) {
			return true
		}
	}
	return false
}

// mintFake mints a placeholder that mimics the real token's prefix — so a
// client-side format check (e.g. Anthropic's sk-ant-oat01-, Google's ya29.)
// passes — but carries no real entropy. The random suffix makes it unique per
// login, so two tokens from one issuer never collide; it is stable within a
// login because it is minted once at capture and reused across refreshes. OAuth
// bearer and refresh tokens are ASCII, so byte-slicing the prefix is safe.
func mintFake(real string) string {
	headLen := len(real)
	if headLen > 20 {
		headLen = 20
	}
	prefixEnd := strings.LastIndexAny(real[:headLen], "-./_") + 1
	if prefixEnd == 0 {
		prefixEnd = headLen
		if prefixEnd > 4 {
			prefixEnd = 4
		}
	}
	return real[:prefixEnd] + "crinj-placeholder-" + randomSuffix()
}

func randomSuffix() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err)) // unrecoverable
	}
	return hex.EncodeToString(b[:])
}

// ── Token body ──────────────────────────────────────────────────────────

// tokenBody is a token-endpoint body in its wire format. OAuth token
// request/response bodies are flat key->value, so JSON and form-urlencoded
// reduce to the same get/set surface; we re-serialize in the original format so
// the swap is transparent to both client and provider. JSON is the OAuth
// outlier (Anthropic); form-urlencoded is the RFC 6749 default (Google,
// GitHub, ...).
type tokenBody struct {
	isForm bool
	json   map[string]any // when !isForm
	form   []formPair     // when isForm
}

type formPair struct{ key, val string }

// parseTokenBody parses a body by its Content-Type:
// application/x-www-form-urlencoded as a form, anything else as JSON. ok is
// false if neither parses (the caller then forwards the body untouched).
func parseTokenBody(contentType string, data []byte) (*tokenBody, bool) {
	if isFormContentType(contentType) {
		return &tokenBody{isForm: true, form: formParse(data)}, true
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, false
	}
	return &tokenBody{json: m}, true
}

// toBytes re-serializes in the original wire format.
func (b *tokenBody) toBytes() []byte {
	if b.isForm {
		return []byte(formSerialize(b.form))
	}
	out, _ := json.Marshal(b.json)
	return out
}

func (b *tokenBody) get(key string) (string, bool) {
	if b.isForm {
		for _, p := range b.form {
			if p.key == key {
				return p.val, true
			}
		}
		return "", false
	}
	v, ok := b.json[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func (b *tokenBody) set(key, val string) {
	if b.isForm {
		for i := range b.form {
			if b.form[i].key == key {
				b.form[i].val = val
				return
			}
		}
		b.form = append(b.form, formPair{key, val})
		return
	}
	b.json[key] = val
}

func isFormContentType(contentType string) bool {
	if contentType == "" {
		return false
	}
	head := contentType
	if i := strings.IndexByte(head, ';'); i >= 0 {
		head = head[:i]
	}
	return strings.EqualFold(strings.TrimSpace(head), "application/x-www-form-urlencoded")
}

// formParse parses application/x-www-form-urlencoded into ordered key/value
// pairs.
func formParse(data []byte) []formPair {
	var pairs []formPair
	for _, part := range strings.Split(string(data), "&") {
		if part == "" {
			continue
		}
		k, v := part, ""
		if i := strings.IndexByte(part, '='); i >= 0 {
			k, v = part[:i], part[i+1:]
		}
		pairs = append(pairs, formPair{formDecode(k), formDecode(v)})
	}
	return pairs
}

func formSerialize(pairs []formPair) string {
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = formEncode(p.key) + "=" + formEncode(p.val)
	}
	return strings.Join(parts, "&")
}

func formDecode(s string) string {
	b := []byte(s)
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); {
		switch {
		case b[i] == '+':
			out = append(out, ' ')
			i++
		case b[i] == '%' && i+2 < len(b):
			h, okh := hexVal(b[i+1])
			l, okl := hexVal(b[i+2])
			if okh && okl {
				out = append(out, h<<4|l)
				i += 3
			} else {
				out = append(out, '%')
				i++
			}
		default:
			out = append(out, b[i])
			i++
		}
	}
	return string(out)
}

// formEncode percent-encodes per application/x-www-form-urlencoded: unreserved
// characters pass through, space becomes +, everything else is %XX. A
// conservative encoding the provider decodes back to the same value regardless
// of how the client originally encoded it.
func formEncode(s string) string {
	var out strings.Builder
	for _, b := range []byte(s) {
		switch {
		case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9',
			b == '-', b == '_', b == '.', b == '~':
			out.WriteByte(b)
		case b == ' ':
			out.WriteByte('+')
		default:
			fmt.Fprintf(&out, "%%%02X", b)
		}
	}
	return out.String()
}

func hexVal(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	}
	return 0, false
}

// ── Engine ──────────────────────────────────────────────────────────────

// OAuthEngine brokers the token flow for the configured chains, backed by the
// persistent vault. It holds no per-login state itself: every login lives as a
// row in the store, keyed by placeholder, so concurrent logins from one issuer
// are independent and survive a restart.
type OAuthEngine struct {
	chains []OAuthChain
	store  *VaultStore
	// now supplies the clock for jwt-bearer assertion iat/exp. A field so tests
	// can pin it; defaults to time.Now.
	now func() time.Time
}

// NewOAuthEngine returns an engine over the chains and vault store.
func NewOAuthEngine(chains []OAuthChain, store *VaultStore) *OAuthEngine {
	return &OAuthEngine{chains: chains, store: store, now: time.Now}
}

// findSigner returns the signer for a jwt-bearer request, matched by both the
// token endpoint and the issuer claimed in the client's assertion. The issuer
// match is what keeps crinj from signing for an issuer it was not configured
// to broker, and disambiguates when several keys share one token endpoint.
func (e *OAuthEngine) findSigner(endpoint, issuer string) *JWTSigner {
	for i := range e.chains {
		c := &e.chains[i]
		if c.Signer != nil && c.endpoint() == endpoint && c.Signer.Issuer == issuer {
			return c.Signer
		}
	}
	return nil
}

// tokenEndpoint returns the endpoint identity if (host, path) is a token
// endpoint to broker.
func (e *OAuthEngine) tokenEndpoint(host, path string) (string, bool) {
	for i := range e.chains {
		if e.chains[i].isTokenEndpoint(host, path) {
			return e.chains[i].endpoint(), true
		}
	}
	return "", false
}

// resourceEndpoint returns the endpoint identity governing host if host is a
// resource host whose bearer should be brokered.
func (e *OAuthEngine) resourceEndpoint(host string) (string, bool) {
	for i := range e.chains {
		if e.chains[i].matchesResource(host) {
			return e.chains[i].endpoint(), true
		}
	}
	return "", false
}

// tokenExchange carries what a token-endpoint request decided, so the response
// handler can finish the capture. newLogin means an initial grant whose
// response mints a fresh row; refresh points at the existing row to rotate.
type tokenExchange struct {
	endpoint string
	newLogin bool
	refresh  *tokenRow
	// jwtIdentity is set for a jwt-bearer exchange; the response captures the
	// real access token into the row keyed by this identity (reusing it across
	// renewals), and no refresh token is expected.
	jwtIdentity string
}

// beginTokenRequest inspects an outbound token request and routes by grant
// type. A refresh carrying one of our placeholders has the real refresh token
// swapped in, returning the row to rotate. A jwt-bearer request whose issuer
// matches a configured signer has its (throwaway-signed) assertion replaced by
// one crinj signs with the real key and its own fixed claims. Any other grant
// (authorization_code, ...) is a new login to capture. An unrecognized refresh
// or an unconfigured jwt-bearer issuer is left untouched (nil exchange, no
// capture). The bool reports whether the body was modified.
func (e *OAuthEngine) beginTokenRequest(endpoint string, body *tokenBody) (*tokenExchange, bool, error) {
	gt, _ := body.get("grant_type")
	switch gt {
	case "refresh_token":
		rt, _ := body.get("refresh_token")
		row, ok, err := e.store.GetByRefresh(rt)
		if err != nil {
			return nil, false, err
		}
		if ok && row.Endpoint == endpoint {
			body.set("refresh_token", row.RealRefresh)
			return &tokenExchange{endpoint: endpoint, refresh: &row}, true, nil
		}
		return nil, false, nil
	case jwtBearerGrant:
		assertion, _ := body.get("assertion")
		iss, _ := unverifiedClaims(assertion)
		signer := e.findSigner(endpoint, iss)
		if signer == nil {
			return nil, false, nil // issuer we were not configured to broker
		}
		signed, err := signer.buildAndSign(e.now())
		if err != nil {
			return nil, false, err
		}
		body.set("assertion", signed)
		return &tokenExchange{endpoint: endpoint, jwtIdentity: signer.identity(endpoint)}, true, nil
	default:
		return &tokenExchange{endpoint: endpoint, newLogin: true}, false, nil
	}
}

// completeResponse captures the real tokens from a successful token response and
// rewrites the body to the client's placeholders, persisting the row. A new
// login mints fresh unique placeholders; a refresh keeps the existing ones and
// rotates the real tokens. The bool reports whether the body was modified.
func (e *OAuthEngine) completeResponse(ex *tokenExchange, body *tokenBody) (bool, error) {
	if ex == nil {
		return false, nil
	}
	at, hasAT := body.get("access_token")
	rt, hasRT := body.get("refresh_token")

	if ex.jwtIdentity != "" {
		// jwt-bearer returns an access token and no refresh token. Reuse the
		// row for this identity so renewals rotate the real token under one
		// stable placeholder instead of accumulating rows.
		if !hasAT {
			return false, nil
		}
		row, ok, err := e.store.GetByIdentity(ex.jwtIdentity)
		if err != nil {
			return false, err
		}
		if !ok {
			row = tokenRow{Endpoint: ex.endpoint, Identity: ex.jwtIdentity, IssuedAccess: mintFake(at)}
		}
		row.RealAccess = at
		body.set("access_token", row.IssuedAccess)
		if err := e.store.Upsert(row); err != nil {
			return false, err
		}
		return true, nil
	}

	if ex.newLogin {
		if !hasAT {
			return false, nil // not a token response we can capture
		}
		row := tokenRow{Endpoint: ex.endpoint, RealAccess: at, IssuedAccess: mintFake(at)}
		body.set("access_token", row.IssuedAccess)
		if hasRT {
			row.RealRefresh = rt
			row.IssuedRefresh = mintFake(rt)
			body.set("refresh_token", row.IssuedRefresh)
		}
		if err := e.store.Upsert(row); err != nil {
			return false, err
		}
		return true, nil
	}

	// Recognized refresh: rotate the real tokens, keep the stable placeholders.
	row := *ex.refresh
	changed := false
	if hasAT {
		row.RealAccess = at
		body.set("access_token", row.IssuedAccess)
		changed = true
	}
	if hasRT {
		row.RealRefresh = rt
		if row.IssuedRefresh == "" {
			row.IssuedRefresh = mintFake(rt)
		}
		body.set("refresh_token", row.IssuedRefresh)
		changed = true
	}
	if changed {
		if err := e.store.Upsert(row); err != nil {
			return false, err
		}
	}
	return changed, nil
}

// resourceBearer maps a client's placeholder bearer to the real access token to
// inject on a resource host. ok is false when the header is not one of crinj's
// placeholders, or belongs to a different issuer than the one governing this
// host (so a misdirected token is never injected at the wrong host).
func (e *OAuthEngine) resourceBearer(endpoint, authHeader string) (string, bool, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return "", false, nil
	}
	row, ok, err := e.store.GetByAccess(authHeader[len(prefix):])
	if err != nil {
		return "", false, err
	}
	if !ok || row.Endpoint != endpoint || row.RealAccess == "" {
		return "", false, nil
	}
	return "Bearer " + row.RealAccess, true, nil
}

// resignResourceBearer re-signs a self-signed JWT bearer on a resource host.
// Some clients skip the token endpoint entirely and send a JWT they sign
// themselves as the bearer (Google's GAPIC libraries do, by default); the
// sandboxed client's copy is signed with its throwaway key, so crinj replaces
// it with one signed by the real key, claims fixed by config as always. ok is
// false when the bearer is not a JWT from an issuer we are configured to sign
// for; the request is then forwarded untouched.
func (e *OAuthEngine) resignResourceBearer(endpoint, authHeader string) (string, bool, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return "", false, nil
	}
	iss, aud := unverifiedClaims(authHeader[len(prefix):])
	if iss == "" {
		return "", false, nil
	}
	signer := e.findSigner(endpoint, iss)
	if signer == nil {
		return "", false, nil
	}
	signed, err := signer.selfSignBearer(e.now(), aud)
	if err != nil {
		return "", false, err
	}
	return prefix + signed, true, nil
}
