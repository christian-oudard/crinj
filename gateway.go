package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	dialTimeout      = 30 * time.Second
	handshakeTimeout = 15 * time.Second
	idleTimeout      = 5 * time.Minute
	keepAlivePeriod  = 30 * time.Second
)

// HTTP gateway server: connection handling, MITM interception, and tunneling.
//
// This file currently holds the pure-utility pieces (header filtering, host
// parsing, proxy-address parsing). The async server, CONNECT handler, MITM,
// and tunnel paths land in subsequent iterations.

// stripPort returns the hostname portion of a "host:port" or bracketed-IPv6
// authority. It mirrors the Rust helper: it does not validate the port and
// simply splits on the first `:` for non-bracketed inputs.
func stripPort(host string) string {
	if rest, ok := strings.CutPrefix(host, "["); ok {
		if i := strings.Index(rest, "]"); i >= 0 {
			return rest[:i]
		}
		return rest
	}
	if i := strings.Index(host, ":"); i >= 0 {
		return host[:i]
	}
	return host
}

// hopByHopHeaders is the canonical RFC 7230 §6.1 list. Names are stored
// lowercase for case-insensitive comparison.
var hopByHopHeaders = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"proxy-connection":    true,
	"te":                  true,
	"trailers":            true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

// isHopByHop reports whether a header name must not be forwarded between the
// client and upstream. Comparison is case-insensitive.
func isHopByHop(name string) bool {
	return hopByHopHeaders[strings.ToLower(name)]
}

// filterHeaders returns a copy of in with all hop-by-hop headers stripped.
// Duplicate values for end-to-end headers (e.g. set-cookie) are preserved.
func filterHeaders(in http.Header) http.Header {
	out := http.Header{}
	for name, values := range in {
		if isHopByHop(name) {
			continue
		}
		for _, v := range values {
			out.Add(name, v)
		}
	}
	return out
}

// ── Upstream proxy chaining ─────────────────────────────────────────────

// UpstreamProxy is the parent-proxy configuration parsed from HTTPS_PROXY and
// NO_PROXY. When set, outbound CONNECTs flow through the parent rather than
// being dialled directly.
type UpstreamProxy struct {
	addr    string
	noProxy []string
}

// Addr returns the parent proxy's host:port.
func (p *UpstreamProxy) Addr() string { return p.addr }

// upstreamProxyFromEnv reads HTTPS_PROXY (or lowercase https_proxy) and
// NO_PROXY (or no_proxy) from the environment. Returns nil when no proxy is
// configured.
func upstreamProxyFromEnv() (*UpstreamProxy, error) {
	raw := os.Getenv("HTTPS_PROXY")
	if raw == "" {
		raw = os.Getenv("https_proxy")
	}
	if raw == "" {
		return nil, nil
	}
	addr, err := parseProxyAddr(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing HTTPS_PROXY=%q: %w", raw, err)
	}
	npRaw := os.Getenv("NO_PROXY")
	if npRaw == "" {
		npRaw = os.Getenv("no_proxy")
	}
	var noProxy []string
	if npRaw != "" {
		for _, p := range strings.Split(npRaw, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				noProxy = append(noProxy, p)
			}
		}
	}
	return &UpstreamProxy{addr: addr, noProxy: noProxy}, nil
}

// appliesTo reports whether traffic to hostname should be routed through the
// upstream proxy. Returns false if hostname matches any NO_PROXY entry.
//
// Entries may be exact hostnames, `.suffix` patterns (matching `suffix` or
// `*.suffix`), or a single `*` meaning "bypass everything".
func (p *UpstreamProxy) appliesTo(hostname string) bool {
	for _, entry := range p.noProxy {
		if entry == "*" {
			return false
		}
		if suffix, ok := strings.CutPrefix(entry, "."); ok {
			if hostname == suffix {
				return false
			}
			if len(hostname) > len(suffix) &&
				strings.HasSuffix(hostname, suffix) &&
				hostname[len(hostname)-len(suffix)-1] == '.' {
				return false
			}
		} else if entry == hostname {
			return false
		}
	}
	return true
}

// ── GatewayServer ──────────────────────────────────────────────────────

// GatewayServer is the listening proxy. Connections are accepted in Run (next
// iteration) and dispatched to handleConnection. SIGHUP triggers a config
// reload via handleSIGHUP.
type GatewayServer struct {
	ca                 *CertificateAuthority
	upstreamTLS        *tls.Config
	upstreamTLSNoCheck *tls.Config
	upstreamProxy      *UpstreamProxy

	rulesMu         sync.RWMutex
	rules           []ResolvedHost
	configPath      string
	allowEmptyRules bool

	// oauth brokers token flows, backed by the persistent vault. It is shared
	// across every connection and, unlike rules, is not rebuilt on SIGHUP. nil
	// when no [host.oauth] is configured.
	oauth *OAuthEngine

	bindAddr string
	port     uint16
}

// NewGatewayServer constructs a server with the given dependencies. The
// upstream TLS configs are built up-front: a strict one (or insecure when
// GATEWAY_DANGER_ACCEPT_INVALID_CERTS is set) and an always-insecure one for
// hosts marked no-check-certificate.
func NewGatewayServer(ca *CertificateAuthority, port uint16, bindAddr string,
	rules []ResolvedHost, oauth *OAuthEngine, configPath string, allowEmptyRules bool,
	upstreamProxy *UpstreamProxy) *GatewayServer {

	danger := os.Getenv("GATEWAY_DANGER_ACCEPT_INVALID_CERTS") != ""
	return &GatewayServer{
		ca:                 ca,
		upstreamTLS:        buildUpstreamTLSConfig(danger),
		upstreamTLSNoCheck: buildUpstreamTLSConfig(true),
		upstreamProxy:      upstreamProxy,
		rules:              rules,
		oauth:              oauth,
		configPath:         configPath,
		allowEmptyRules:    allowEmptyRules,
		bindAddr:           bindAddr,
		port:               port,
	}
}

// Run binds the listener, hooks up SIGHUP for config reload, and serves
// connections until ctx is cancelled.
func (s *GatewayServer) Run(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", s.bindAddr, s.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("binding %s: %w", addr, err)
	}
	slog.Info("listening", "addr", addr)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sigCh:
				s.handleSIGHUP()
			}
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(keepAlivePeriod)
		}
		go s.handleConnection(conn)
	}
}

// handleConnection reads the first HTTP/1 request off conn and dispatches it.
// CONNECT goes to handleConnect (which hijacks); /healthz returns 200; any
// other path returns 400. The connection is closed on return.
func (s *GatewayServer) handleConnection(conn net.Conn) {
	defer conn.Close()
	peer := ""
	if addr := conn.RemoteAddr(); addr != nil {
		peer = addr.String()
	}
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method == http.MethodConnect {
		s.handleConnect(conn, br, req, peer)
		return
	}
	if req.URL.Path == "/healthz" {
		body := fmt.Sprintf("{\"commit\":%q}\n", commit)
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"+
			"Content-Length: %d\r\n\r\n%s", len(body), body)
		return
	}
	writeSimpleResponse(conn, http.StatusBadRequest)
}

// handleConnect resolves the CONNECT authority against the loaded rules,
// writes the 200 Connection Established line, then either runs the MITM loop
// or a passthrough tunnel.
func (s *GatewayServer) handleConnect(clientConn net.Conn, br *bufio.Reader, req *http.Request, peer string) {
	host := req.Host
	if req.URL != nil && req.URL.Host != "" {
		host = req.URL.Host
	}

	s.rulesMu.RLock()
	rules := s.rules
	s.rulesMu.RUnlock()

	resolved := resolveHosts(host, rules)
	upstreamTLS := s.upstreamTLS
	if resolved.NoCheckCertificate {
		upstreamTLS = s.upstreamTLSNoCheck
	}

	mode := "tunnel"
	if resolved.Intercept {
		mode = "mitm"
	}
	upstreamMode := "direct"
	if s.upstreamProxy != nil && s.upstreamProxy.appliesTo(stripPort(host)) {
		upstreamMode = "proxy"
	}
	slog.Info("CONNECT",
		"peer", peer,
		"host", host,
		"mode", mode,
		"upstream", upstreamMode,
		"rule_count", len(resolved.InjectionRules))

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	// Any bytes the client pipelined past the CONNECT line are sitting in
	// br. Hand mitm/tunnel a wrapper that reads from br first.
	client := wrapBuffered(clientConn, br)

	// Routine connection errors (peer hangup, upstream TLS reset, etc.) are
	// noisy in normal operation and were intentionally demoted to debug in
	// the Rust original; match that.
	if resolved.Intercept {
		if err := mitm(client, host, s.ca, upstreamTLS, s.upstreamProxy,
			resolved.Access, resolved.InjectionRules, s.oauth); err != nil {
			slog.Debug("connection error", "host", host, "error", err)
		}
		return
	}
	if err := tunnel(client, host, s.upstreamProxy); err != nil {
		slog.Debug("connection error", "host", host, "error", err)
	}
}

// handleSIGHUP reloads rules from disk, keeping the old set on parse error or
// when the new set is empty without --allow-empty-rules.
func (s *GatewayServer) handleSIGHUP() {
	newRules, err := load(s.configPath)
	if err != nil {
		slog.Warn("SIGHUP: failed to reload config (keeping old)", "error", err)
		return
	}
	if len(newRules) == 0 && !s.allowEmptyRules {
		slog.Warn("SIGHUP: reloaded config has no host rules; rejecting reload (start with --allow-empty-rules to permit)",
			"config", s.configPath)
		return
	}
	s.rulesMu.Lock()
	s.rules = newRules
	s.rulesMu.Unlock()
	slog.Info("SIGHUP: reloaded config", "host_count", len(newRules))
	if len(newRules) == 0 {
		slog.Info("SIGHUP: reloaded config has no rules; running in passthrough mode",
			"config", s.configPath)
	}
}

// writeSimpleResponse writes a status-line + Content-Length: 0 reply suitable
// for /healthz and 400 responses on the raw client connection.
func writeSimpleResponse(w io.Writer, status int) {
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n",
		status, http.StatusText(status))
}

// wrapBuffered returns a net.Conn whose Read drains the buffered bytes in br
// before falling through to the underlying conn. Write/Close/etc go to the
// real connection unchanged.
func wrapBuffered(c net.Conn, br *bufio.Reader) net.Conn {
	if br.Buffered() == 0 {
		return c
	}
	return &bufferedConn{br: br, Conn: c}
}

type bufferedConn struct {
	br *bufio.Reader
	net.Conn
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.br.Read(p) }

// mitm terminates TLS with the client (using a CA-issued leaf cert), opens a
// TLS connection to the upstream, and forwards HTTP/1 requests through with
// access control + injections applied. Loops on the client connection until
// it closes or the upstream errors.
//
// upstreamTLS is the *tls.Config used for the upstream handshake; the caller
// has already chosen between the strict and no-check-cert variants.
func mitm(
	clientConn net.Conn,
	host string,
	ca *CertificateAuthority,
	upstreamTLS *tls.Config,
	upstreamProxy *UpstreamProxy,
	access []AccessEntry,
	rules []InjectionRule,
	oauth *OAuthEngine,
) error {
	hostname := stripPort(host)

	leafCfg, err := ca.ServerConfigForHost(hostname)
	if err != nil {
		return fmt.Errorf("issuing leaf cert for %s: %w", hostname, err)
	}
	_ = clientConn.SetDeadline(time.Now().Add(handshakeTimeout))
	tlsClient := tls.Server(clientConn, leafCfg)
	if err := tlsClient.Handshake(); err != nil {
		return fmt.Errorf("client TLS handshake: %w", err)
	}
	_ = tlsClient.SetDeadline(time.Time{})
	defer tlsClient.Close()

	if tlsClient.ConnectionState().NegotiatedProtocol == "h2" {
		return mitmH2(tlsClient, host, hostname, upstreamTLS, upstreamProxy, access, rules, oauth)
	}

	target := host
	if !strings.Contains(host, ":") {
		target = host + ":443"
	}
	upstreamRaw, err := dialUpstream(target, upstreamProxy)
	if err != nil {
		return err
	}
	upstreamCfg := upstreamTLS.Clone()
	upstreamCfg.ServerName = hostname
	upstreamCfg.NextProtos = []string{"http/1.1"}
	_ = upstreamRaw.SetDeadline(time.Now().Add(handshakeTimeout))
	tlsUpstream := tls.Client(upstreamRaw, upstreamCfg)
	if err := tlsUpstream.Handshake(); err != nil {
		upstreamRaw.Close()
		return fmt.Errorf("upstream TLS handshake with %s: %w", host, err)
	}
	_ = tlsUpstream.SetDeadline(time.Time{})
	defer tlsUpstream.Close()

	clientReader := bufio.NewReader(tlsClient)
	upstreamReader := bufio.NewReader(tlsUpstream)

	for {
		_ = tlsClient.SetReadDeadline(time.Now().Add(idleTimeout))
		req, err := http.ReadRequest(clientReader)
		_ = tlsClient.SetReadDeadline(time.Time{})
		if err != nil {
			if err == io.EOF || isIdleTimeout(err) {
				return nil
			}
			return fmt.Errorf("reading client request: %w", err)
		}

		blocked, injections, err := prepareUpstreamRequest(req, access, rules)
		if err != nil {
			slog.Warn("forward error", "host", host, "error", err)
			return err
		}

		if blocked {
			slog.Info("blocked",
				"method", req.Method,
				"url", "https://"+host+req.URL.RequestURI(),
				"status", 200)
			if err := writeSyntheticBlocked(tlsClient); err != nil {
				return err
			}
			continue
		}

		// OAuth: on the resource host swap the placeholder bearer for the real
		// access token; on the token endpoint rewrite the placeholder refresh
		// token and return an exchange so the response can be captured.
		exchange, err := applyOAuthRequest(req, hostname, oauth)
		if err != nil {
			slog.Warn("oauth request error", "host", host, "error", err)
			return err
		}

		if err := req.Write(tlsUpstream); err != nil {
			return fmt.Errorf("forwarding to %s: %w", host, err)
		}

		resp, err := http.ReadResponse(upstreamReader, req)
		if err != nil {
			return fmt.Errorf("reading upstream response from %s: %w", host, err)
		}

		resp.Header = filterHeaders(resp.Header)

		// OAuth token endpoint: capture the real tokens into the vault and
		// return placeholders to the client.
		if exchange != nil {
			if err := captureOAuthResponse(resp, exchange, oauth); err != nil {
				_ = resp.Body.Close()
				return err
			}
		}

		writeErr := resp.Write(tlsClient)
		_ = resp.Body.Close()
		if writeErr != nil {
			return fmt.Errorf("writing client response: %w", writeErr)
		}

		slog.Info("forwarded",
			"method", req.Method,
			"url", "https://"+host+req.URL.RequestURI(),
			"status", resp.StatusCode,
			"injections_applied", injections)

		if resp.Close || req.Close {
			return nil
		}
	}
}

// writeSyntheticBlocked writes the access-blocked synthetic response (200 OK
// `{}`) directly to a connection, used inside the MITM loop where we don't
// have an http.ResponseWriter.
func writeSyntheticBlocked(w io.Writer) error {
	body := "{}"
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	return resp.Write(w)
}

// prepareUpstreamRequest applies access control and injection rules to req,
// mutating it in place into the upstream request. Returns blocked=true when
// access control rejects the request (req is left untouched in that case),
// and the count of injection actions applied. Dynamic resolution errors
// (sqlite lookups) bubble up as errors so the caller refuses to forward the
// request rather than leaking the placeholder upstream.
func prepareUpstreamRequest(req *http.Request, access []AccessEntry, rules []InjectionRule) (bool, int, error) {
	pathAndQuery := req.URL.RequestURI()
	pathOnly := pathAndQuery
	if i := strings.Index(pathOnly, "?"); i >= 0 {
		pathOnly = pathOnly[:i]
	}

	if v, ok := evaluateAccess(pathOnly, access); ok && v == AccessBlock {
		return true, 0, nil
	}

	newPath, queryCount, err := applyQueryInjections(pathAndQuery, rules)
	if err != nil {
		return false, 0, err
	}

	filtered := filterHeaders(req.Header)
	headerCount, err := applyInjections(filtered, newPath, rules)
	if err != nil {
		return false, 0, err
	}

	req.Header = filtered
	// Path-only URI for the upstream wire form. url.Parse on a relative path
	// gives a URL with no scheme/host — exactly what proxy semantics want.
	u, err := url.Parse(newPath)
	if err != nil {
		return false, 0, fmt.Errorf("parsing path %q as URI: %w", newPath, err)
	}
	req.URL = u
	req.RequestURI = ""

	return false, headerCount + queryCount, nil
}

// applyOAuthRequest applies the request side of OAuth passthrough to a request
// already prepared for the upstream (headers filtered, URI path-only). On a
// resource host it swaps the client's placeholder bearer for the real access
// token. On the token endpoint it buffers the body and swaps the placeholder
// refresh token for the real one, returning an exchange so the response can be
// captured. Returns nil when there is nothing to capture on the response.
func applyOAuthRequest(req *http.Request, hostname string, oauth *OAuthEngine) (*tokenExchange, error) {
	if oauth == nil {
		return nil, nil
	}

	if endpoint, ok := oauth.resourceEndpoint(hostname); ok {
		if auth := req.Header.Get("Authorization"); auth != "" {
			bearer, ok, err := oauth.resourceBearer(endpoint, auth)
			if err != nil {
				return nil, err
			}
			if ok {
				req.Header.Set("Authorization", bearer)
			}
		}
	}

	endpoint, ok := oauth.tokenEndpoint(hostname, req.URL.Path)
	if !ok {
		return nil, nil
	}
	body, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("reading token request body: %w", err)
	}
	out := body
	var exchange *tokenExchange
	if tb, ok := parseTokenBody(req.Header.Get("Content-Type"), body); ok {
		ex, changed, err := oauth.beginTokenRequest(endpoint, tb)
		if err != nil {
			return nil, err
		}
		exchange = ex
		if changed {
			out = tb.toBytes()
		}
	}
	setRequestBody(req, out)
	return exchange, nil
}

// captureOAuthResponse handles the token-endpoint response: on a successful
// status it captures the real tokens into the vault and rewrites the body to
// the client's placeholders. Always buffers and replaces the body so the
// Content-Length is exact. Decompresses gzip-encoded bodies transparently
// (http.ReadResponse does not auto-decompress, unlike http.Client).
func captureOAuthResponse(resp *http.Response, exchange *tokenExchange, oauth *OAuthEngine) error {
	body, err := readMaybeGzip(resp)
	if err != nil {
		return fmt.Errorf("reading token response body: %w", err)
	}
	out := body
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if tb, ok := parseTokenBody(resp.Header.Get("Content-Type"), body); ok {
			changed, err := oauth.completeResponse(exchange, tb)
			if err != nil {
				return err
			}
			if changed {
				out = tb.toBytes()
			}
		} else {
			slog.Warn("oauth: token response body unparsable; passed through uncaptured",
				"content_type", resp.Header.Get("Content-Type"),
				"body_prefix", truncate(body, 100))
		}
	}
	setResponseBody(resp, out)
	return nil
}

// readMaybeGzip reads and fully buffers resp.Body. If the response carries
// Content-Encoding: gzip it decompresses on the fly and strips that header so
// the caller (and the downstream client) see plain bytes. http.ReadResponse
// does not auto-decompress, so without this gzip bodies arrive as opaque
// binary and cannot be parsed as JSON/form.
func readMaybeGzip(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	if !strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		return io.ReadAll(resp.Body)
	}
	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("opening gzip reader: %w", err)
	}
	defer gr.Close()
	body, err := io.ReadAll(gr)
	if err != nil {
		return nil, err
	}
	resp.Header.Del("Content-Encoding")
	return body, nil
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}

// setRequestBody replaces a request's body with a fixed byte slice, fixing up
// the length fields so http.Request.Write emits an exact Content-Length and no
// chunked transfer encoding.
func setRequestBody(req *http.Request, body []byte) {
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.TransferEncoding = nil
	req.Header.Del("Content-Length")
}

// setResponseBody is the response-side counterpart of setRequestBody.
func setResponseBody(resp *http.Response, body []byte) {
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.TransferEncoding = nil
	resp.Header.Del("Content-Length")
}

// buildUpstreamTLSConfig returns a *tls.Config used when crinj acts as a TLS
// client to the real upstream. When dangerAcceptInvalidCerts is true,
// upstream cert validation is skipped (used for hosts with
// no-check-certificate or when GATEWAY_DANGER_ACCEPT_INVALID_CERTS is set).
// Otherwise the system root store is used.
func buildUpstreamTLSConfig(dangerAcceptInvalidCerts bool) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: dangerAcceptInvalidCerts,
	}
}

// writeBlockedResponse writes the synthetic 200 OK with `{}` body that crinj
// returns when access control blocks a request. The upstream is never
// contacted.
func writeBlockedResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "{}")
}

// tunnel is the passthrough mode used when no host rule matches the CONNECT
// authority. It bidirectionally copies bytes between the hijacked client
// connection and the upstream, returning when both directions close.
func tunnel(client net.Conn, host string, proxy *UpstreamProxy) error {
	target := host
	if !strings.Contains(host, ":") {
		target = host + ":443"
	}
	upstream, err := dialUpstream(target, proxy)
	if err != nil {
		return err
	}

	var c2s, s2c int64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		c2s, _ = io.Copy(upstream, client)
		closeWrite(upstream)
	}()
	go func() {
		defer wg.Done()
		s2c, _ = io.Copy(client, upstream)
		closeWrite(client)
	}()
	wg.Wait()
	upstream.Close()

	slog.Info("tunnel closed", "host", host, "client_to_server", c2s, "server_to_client", s2c)
	return nil
}

// closeWrite shuts down the write half of c when supported, signalling EOF
// to the peer without blowing up the read half.
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// dialUpstream opens a TCP connection to target ("host:port"), routing
// through the upstream proxy if one is configured and the host is not in
// NO_PROXY.
// isIdleTimeout reports whether err is a network timeout on an idle connection
// (no request arrived within idleTimeout). These are normal and should be
// treated as a clean close, not an error worth logging.
func isIdleTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func dialUpstream(target string, proxy *UpstreamProxy) (net.Conn, error) {
	if proxy != nil && proxy.appliesTo(stripPort(target)) {
		return dialViaProxy(proxy.addr, target)
	}
	conn, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", target, err)
	}
	return conn, nil
}

// dialViaProxy connects to the parent proxy and issues an HTTP CONNECT for
// target. Returns the still-open TCP connection on a 200 response, ready for
// the caller to layer TLS or raw bytes on top.
func dialViaProxy(proxyAddr, target string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("connecting to upstream proxy %s: %w", proxyAddr, err)
	}
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("writing CONNECT to upstream proxy: %w", err)
	}
	resp, err := readProxyResponse(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("reading CONNECT response from %s: %w", proxyAddr, err)
	}
	statusLine := resp
	if i := strings.Index(resp, "\r\n"); i >= 0 {
		statusLine = resp[:i]
	}
	parts := strings.Fields(statusLine)
	var status string
	if len(parts) >= 2 {
		status = parts[1]
	}
	if status != "200" {
		conn.Close()
		return nil, fmt.Errorf("upstream proxy %s refused CONNECT to %s: %s",
			proxyAddr, target, statusLine)
	}
	return conn, nil
}

// readProxyResponse reads an HTTP response head from r byte-by-byte until
// the \r\n\r\n boundary, without over-reading into any tunneled body. Caps at
// 8 KiB.
func readProxyResponse(r io.Reader) (string, error) {
	buf := make([]byte, 0, 256)
	one := make([]byte, 1)
	for {
		n, err := r.Read(one)
		if err != nil {
			if err == io.EOF {
				return "", fmt.Errorf("upstream proxy closed connection during CONNECT")
			}
			return "", err
		}
		if n == 0 {
			return "", fmt.Errorf("upstream proxy closed connection during CONNECT")
		}
		buf = append(buf, one[0])
		if len(buf) >= 4 && string(buf[len(buf)-4:]) == "\r\n\r\n" {
			return string(buf), nil
		}
		if len(buf) > 8192 {
			return "", fmt.Errorf("CONNECT response head exceeds 8 KiB")
		}
	}
}

// parseProxyAddr coerces an HTTPS_PROXY value into a host:port string suitable
// for net.Dial. Accepts http:// and https:// schemes, bare host:port, and
// bracketed IPv6 (e.g. http://[::1]:8080). Rejects embedded credentials.
func parseProxyAddr(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("empty proxy URL")
	}
	if rest, ok := strings.CutPrefix(s, "http://"); ok {
		s = rest
	} else if rest, ok := strings.CutPrefix(s, "https://"); ok {
		s = rest
	}
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	if strings.Contains(s, "@") {
		return "", fmt.Errorf("proxy auth (user:pass@host) is not supported")
	}
	if rest, ok := strings.CutPrefix(s, "["); ok {
		closeIdx := strings.Index(rest, "]")
		if closeIdx < 0 {
			return "", fmt.Errorf("bracketed IPv6 proxy address missing ']'")
		}
		after := rest[closeIdx+1:]
		if !strings.HasPrefix(after, ":") || len(after) < 2 {
			return "", fmt.Errorf("IPv6 proxy URL must include explicit port, e.g. http://[::1]:8080")
		}
		return s, nil
	}
	if !strings.Contains(s, ":") {
		return "", fmt.Errorf("proxy URL must include an explicit port, e.g. http://host:8080")
	}
	if strings.Count(s, ":") > 1 {
		return "", fmt.Errorf("ambiguous proxy address %q: bare IPv6 must be bracketed, e.g. [::1]:8080", s)
	}
	return s, nil
}
