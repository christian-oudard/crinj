package main

import (
	"bufio"
	"context"
	"crypto/tls"
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

	bindAddr string
	port     uint16
}

// NewGatewayServer constructs a server with the given dependencies. The
// upstream TLS configs are built up-front: a strict one (or insecure when
// GATEWAY_DANGER_ACCEPT_INVALID_CERTS is set) and an always-insecure one for
// hosts marked no-check-certificate.
func NewGatewayServer(ca *CertificateAuthority, port uint16, bindAddr string,
	rules []ResolvedHost, configPath string, allowEmptyRules bool,
	upstreamProxy *UpstreamProxy) *GatewayServer {

	danger := os.Getenv("GATEWAY_DANGER_ACCEPT_INVALID_CERTS") != ""
	return &GatewayServer{
		ca:                 ca,
		upstreamTLS:        buildUpstreamTLSConfig(danger),
		upstreamTLSNoCheck: buildUpstreamTLSConfig(true),
		upstreamProxy:      upstreamProxy,
		rules:              rules,
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
		writeSimpleResponse(conn, http.StatusOK)
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
			resolved.Access, resolved.InjectionRules); err != nil {
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
) error {
	hostname := stripPort(host)

	leafCfg, err := ca.ServerConfigForHost(hostname)
	if err != nil {
		return fmt.Errorf("issuing leaf cert for %s: %w", hostname, err)
	}
	tlsClient := tls.Server(clientConn, leafCfg)
	if err := tlsClient.Handshake(); err != nil {
		return fmt.Errorf("client TLS handshake: %w", err)
	}
	defer tlsClient.Close()

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
	tlsUpstream := tls.Client(upstreamRaw, upstreamCfg)
	if err := tlsUpstream.Handshake(); err != nil {
		upstreamRaw.Close()
		return fmt.Errorf("upstream TLS handshake with %s: %w", host, err)
	}
	defer tlsUpstream.Close()

	clientReader := bufio.NewReader(tlsClient)
	upstreamReader := bufio.NewReader(tlsUpstream)

	for {
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			if err == io.EOF {
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

		if err := req.Write(tlsUpstream); err != nil {
			return fmt.Errorf("forwarding to %s: %w", host, err)
		}

		resp, err := http.ReadResponse(upstreamReader, req)
		if err != nil {
			return fmt.Errorf("reading upstream response from %s: %w", host, err)
		}

		resp.Header = filterHeaders(resp.Header)

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
		StatusCode: http.StatusOK,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
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
func dialUpstream(target string, proxy *UpstreamProxy) (net.Conn, error) {
	if proxy != nil && proxy.appliesTo(stripPort(target)) {
		return dialViaProxy(proxy.addr, target)
	}
	conn, err := net.Dial("tcp", target)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", target, err)
	}
	return conn, nil
}

// dialViaProxy connects to the parent proxy and issues an HTTP CONNECT for
// target. Returns the still-open TCP connection on a 200 response, ready for
// the caller to layer TLS or raw bytes on top.
func dialViaProxy(proxyAddr, target string) (net.Conn, error) {
	conn, err := net.Dial("tcp", proxyAddr)
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
