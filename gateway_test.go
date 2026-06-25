package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── stripPort ──────────────────────────────────────────────────────────

func TestStripPortRemovesPort(t *testing.T) {
	cases := []struct{ in, want string }{
		{"example.com:443", "example.com"},
		{"api.anthropic.com:8080", "api.anthropic.com"},
	}
	for _, c := range cases {
		if got := stripPort(c.in); got != c.want {
			t.Errorf("stripPort(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestStripPortHandlesBareHostname(t *testing.T) {
	for _, in := range []string{"example.com", "localhost"} {
		if got := stripPort(in); got != in {
			t.Errorf("stripPort(%q)=%q want unchanged", in, got)
		}
	}
}

func TestStripPortHandlesIPv6Bracketed(t *testing.T) {
	cases := []struct{ in, want string }{
		{"[::1]:443", "::1"},
		{"[::1]", "::1"},
		{"[2001:db8::1]:8080", "2001:db8::1"},
	}
	for _, c := range cases {
		if got := stripPort(c.in); got != c.want {
			t.Errorf("stripPort(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestStripPortHandlesEmpty(t *testing.T) {
	if got := stripPort(""); got != "" {
		t.Errorf("stripPort(\"\")=%q want \"\"", got)
	}
}

// ── hop-by-hop ─────────────────────────────────────────────────────────

func TestHopByHopHeadersAreStripped(t *testing.T) {
	for name := range hopByHopHeaders {
		if !isHopByHop(name) {
			t.Errorf("%s should be hop-by-hop", name)
		}
	}
}

func TestEndToEndHeadersNotHopByHop(t *testing.T) {
	for _, name := range []string{
		"content-type", "content-length", "host", "authorization",
		"accept", "user-agent", "x-api-key", "x-custom-header",
		"cache-control", "date",
	} {
		if isHopByHop(name) {
			t.Errorf("%s should NOT be hop-by-hop", name)
		}
	}
}

func TestFilterHeadersStripsHopByHop(t *testing.T) {
	h := http.Header{}
	h.Set("content-type", "text/html")
	h.Set("connection", "keep-alive")
	h.Set("transfer-encoding", "chunked")
	h.Set("x-request-id", "abc123")

	out := filterHeaders(h)
	if got := len(out); got != 2 {
		t.Errorf("filtered len=%d want 2", got)
	}
	if got := out.Get("content-type"); got != "text/html" {
		t.Errorf("content-type=%q", got)
	}
	if got := out.Get("x-request-id"); got != "abc123" {
		t.Errorf("x-request-id=%q", got)
	}
	if out.Get("connection") != "" {
		t.Error("connection should be stripped")
	}
	if out.Get("transfer-encoding") != "" {
		t.Error("transfer-encoding should be stripped")
	}
}

func TestFilterHeadersPreservesAllEndToEnd(t *testing.T) {
	h := http.Header{}
	h.Set("content-length", "42")
	h.Set("authorization", "Bearer tok")
	h.Set("x-repo-commit", "abc")
	h.Set("location", "https://cdn.example.com")

	out := filterHeaders(h)
	if got := len(out); got != 4 {
		t.Errorf("filtered len=%d want 4", got)
	}
}

func TestFilterHeadersPreservesDuplicateValues(t *testing.T) {
	h := http.Header{}
	h.Add("set-cookie", "a=1")
	h.Add("set-cookie", "b=2")

	out := filterHeaders(h)
	if got := len(out.Values("set-cookie")); got != 2 {
		t.Errorf("set-cookie count=%d want 2", got)
	}
}

func TestFilterHeadersEmptyInput(t *testing.T) {
	if got := len(filterHeaders(http.Header{})); got != 0 {
		t.Errorf("empty filter len=%d want 0", got)
	}
}

// ── parseProxyAddr ─────────────────────────────────────────────────────

func TestParseProxyAddrHTTPScheme(t *testing.T) {
	got, err := parseProxyAddr("http://127.0.0.1:8081")
	if err != nil || got != "127.0.0.1:8081" {
		t.Errorf("got (%q,%v)", got, err)
	}
}

func TestParseProxyAddrHTTPSScheme(t *testing.T) {
	got, err := parseProxyAddr("https://proxy.corp:3128")
	if err != nil || got != "proxy.corp:3128" {
		t.Errorf("got (%q,%v)", got, err)
	}
}

func TestParseProxyAddrBareHostPort(t *testing.T) {
	got, err := parseProxyAddr("127.0.0.1:8081")
	if err != nil || got != "127.0.0.1:8081" {
		t.Errorf("got (%q,%v)", got, err)
	}
}

func TestParseProxyAddrStripsTrailingPath(t *testing.T) {
	got, err := parseProxyAddr("http://proxy:3128/")
	if err != nil || got != "proxy:3128" {
		t.Errorf("got (%q,%v)", got, err)
	}
}

func TestParseProxyAddrRejectsMissingPort(t *testing.T) {
	_, err := parseProxyAddr("http://proxy.corp")
	if err == nil || !strings.Contains(err.Error(), "explicit port") {
		t.Errorf("want missing-port error, got %v", err)
	}
}

func TestParseProxyAddrRejectsAuth(t *testing.T) {
	_, err := parseProxyAddr("http://user:pass@proxy:3128")
	if err == nil || !strings.Contains(err.Error(), "auth") {
		t.Errorf("want auth-rejected error, got %v", err)
	}
}

func TestParseProxyAddrRejectsEmpty(t *testing.T) {
	if _, err := parseProxyAddr(""); err == nil {
		t.Error("empty should error")
	}
	if _, err := parseProxyAddr("   "); err == nil {
		t.Error("whitespace should error")
	}
}

func TestParseProxyAddrIPv6WithScheme(t *testing.T) {
	got, err := parseProxyAddr("http://[::1]:8081")
	if err != nil || got != "[::1]:8081" {
		t.Errorf("got (%q,%v)", got, err)
	}
}

func TestParseProxyAddrIPv6Bare(t *testing.T) {
	got, err := parseProxyAddr("[2001:db8::1]:3128")
	if err != nil || got != "[2001:db8::1]:3128" {
		t.Errorf("got (%q,%v)", got, err)
	}
}

func TestParseProxyAddrIPv6MissingPortFails(t *testing.T) {
	_, err := parseProxyAddr("http://[::1]")
	if err == nil || !strings.Contains(err.Error(), "port") {
		t.Errorf("want port-error, got %v", err)
	}
}

func TestParseProxyAddrIPv6MissingCloseBracketFails(t *testing.T) {
	_, err := parseProxyAddr("http://[::1:8081")
	if err == nil || !strings.Contains(err.Error(), "']'") {
		t.Errorf("want missing-bracket error, got %v", err)
	}
}

func TestParseProxyAddrUnbracketedIPv6Rejected(t *testing.T) {
	_, err := parseProxyAddr("::1:8081")
	if err == nil || !strings.Contains(err.Error(), "bracketed") {
		t.Errorf("want bracketed error, got %v", err)
	}
}

// ── UpstreamProxy.appliesTo / NO_PROXY ─────────────────────────────────

func proxyWithNoProxy(entries ...string) *UpstreamProxy {
	return &UpstreamProxy{addr: "127.0.0.1:8081", noProxy: entries}
}

func TestNoProxyEmptyMeansProxyEverything(t *testing.T) {
	p := proxyWithNoProxy()
	if !p.appliesTo("api.example.com") {
		t.Error("api.example.com")
	}
	if !p.appliesTo("localhost") {
		t.Error("localhost")
	}
}

func TestNoProxyExactHostname(t *testing.T) {
	p := proxyWithNoProxy("localhost", "127.0.0.1")
	if p.appliesTo("localhost") {
		t.Error("localhost should bypass")
	}
	if p.appliesTo("127.0.0.1") {
		t.Error("127.0.0.1 should bypass")
	}
	if !p.appliesTo("api.example.com") {
		t.Error("api.example.com should still proxy")
	}
}

func TestNoProxyDotSuffixMatchesSubdomains(t *testing.T) {
	p := proxyWithNoProxy(".internal.corp")
	for _, h := range []string{"internal.corp", "api.internal.corp", "a.b.internal.corp"} {
		if p.appliesTo(h) {
			t.Errorf("%s should bypass", h)
		}
	}
	for _, h := range []string{"internal.corpx", "notinternal.corp"} {
		if !p.appliesTo(h) {
			t.Errorf("%s should still proxy", h)
		}
	}
}

func TestNoProxyStarMeansBypassAll(t *testing.T) {
	p := proxyWithNoProxy("*")
	if p.appliesTo("anything.com") || p.appliesTo("localhost") {
		t.Error("* should bypass everything")
	}
}

func TestNoProxyDotSuffixNoPartialMatch(t *testing.T) {
	p := proxyWithNoProxy(".example.com")
	if p.appliesTo("foo.example.com") {
		t.Error("foo.example.com should bypass")
	}
	if !p.appliesTo("fooexample.com") {
		t.Error("fooexample.com should not match label boundary")
	}
}

// ── upstreamProxyFromEnv ───────────────────────────────────────────────

func TestUpstreamProxyFromEnvUnset(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("https_proxy", "")
	p, err := upstreamProxyFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if p != nil {
		t.Errorf("expected nil, got %+v", p)
	}
}

// ── End-to-end CONNECT → MITM round-trip ───────────────────────────────

// readCONNECTResponse drains bytes off conn up to the \r\n\r\n boundary so
// we can hand the conn off to a TLS client untouched.
func readCONNECTResponse(t *testing.T, c net.Conn) string {
	t.Helper()
	buf := make([]byte, 0, 256)
	one := make([]byte, 1)
	for {
		n, err := c.Read(one)
		if err != nil || n == 0 {
			t.Fatalf("read CONNECT response: %v", err)
		}
		buf = append(buf, one[0])
		if len(buf) >= 4 && string(buf[len(buf)-4:]) == "\r\n\r\n" {
			return string(buf)
		}
	}
}

func TestGatewayServerEndToEndCONNECTAndInject(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "x-api-key=%s|path=%s", r.Header.Get("x-api-key"), r.URL.RequestURI())
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, _ := url.Parse(upstream.URL)
	target := upstreamURL.Host
	hostname := stripPort(target)

	ca, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}

	// no-check-certificate so the upstream-side TLS accepts httptest's
	// self-signed cert.
	rules := []ResolvedHost{{
		HostPattern:        hostname,
		NoCheckCertificate: true,
		InjectionRules: []InjectionRule{
			makeRule("*", []Injection{setHeader("x-api-key", "INJECTED")}),
		},
	}}

	srv := &GatewayServer{
		ca:                 ca,
		upstreamTLS:        buildUpstreamTLSConfig(false),
		upstreamTLSNoCheck: buildUpstreamTLSConfig(true),
		rules:              rules,
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go srv.handleConnection(conn)
		}
	}()

	proxyConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer proxyConn.Close()

	if _, err := fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatal(err)
	}
	resp := readCONNECTResponse(t, proxyConn)
	if !strings.HasPrefix(resp, "HTTP/1.1 200") {
		t.Fatalf("CONNECT response: %q", resp)
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca.caCert)
	tlsClient := tls.Client(proxyConn, &tls.Config{
		ServerName: hostname,
		RootCAs:    pool,
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}

	req := &http.Request{
		Method:     "GET",
		URL:        &url.URL{Path: "/api"},
		Host:       target,
		Header:     http.Header{"X-Api-Key": []string{"PLACEHOLDER"}},
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	if err := req.Write(tlsClient); err != nil {
		t.Fatalf("write request: %v", err)
	}

	httpResp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(httpResp.Body)
	httpResp.Body.Close()

	if httpResp.StatusCode != 200 {
		t.Errorf("status=%d", httpResp.StatusCode)
	}
	if !strings.Contains(string(body), "x-api-key=INJECTED") {
		t.Errorf("upstream did not see injected header, body=%q", body)
	}
	if !strings.Contains(string(body), "path=/api") {
		t.Errorf("upstream did not see expected path, body=%q", body)
	}

	tlsClient.Close()
}

func TestGatewayServerEndToEndForwardsRequestBody(t *testing.T) {
	// POST a JSON body through the proxy and verify the upstream sees the
	// exact bytes. Catches issues in body streaming through the MITM loop.
	var receivedBody []byte
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		receivedBody = b
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "received len=%d ct=%s", len(b), r.Header.Get("Content-Type"))
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, _ := url.Parse(upstream.URL)
	target := upstreamURL.Host
	hostname := stripPort(target)

	ca, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}
	rules := []ResolvedHost{{
		HostPattern:        hostname,
		NoCheckCertificate: true,
		InjectionRules: []InjectionRule{
			makeRule("*", []Injection{setHeader("x-api-key", "INJECTED")}),
		},
	}}

	srv := &GatewayServer{
		ca:                 ca,
		upstreamTLS:        buildUpstreamTLSConfig(false),
		upstreamTLSNoCheck: buildUpstreamTLSConfig(true),
		rules:              rules,
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go srv.handleConnection(conn)
		}
	}()

	proxyConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer proxyConn.Close()

	if _, err := fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatal(err)
	}
	if resp := readCONNECTResponse(t, proxyConn); !strings.HasPrefix(resp, "HTTP/1.1 200") {
		t.Fatalf("CONNECT response: %q", resp)
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca.caCert)
	tlsClient := tls.Client(proxyConn, &tls.Config{ServerName: hostname, RootCAs: pool})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}

	bodyText := `{"hello":"world","n":42}`
	req, err := http.NewRequest("POST", "https://"+target+"/api",
		strings.NewReader(bodyText))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", "PLACEHOLDER")
	req.Host = target
	// Use absolute URL form for client-side; the proxy will rewrite to path-only.
	req.URL = &url.URL{Path: "/api"}
	if err := req.Write(tlsClient); err != nil {
		t.Fatalf("write request: %v", err)
	}

	httpResp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	io.Copy(io.Discard, httpResp.Body)
	httpResp.Body.Close()

	if httpResp.StatusCode != 200 {
		t.Errorf("status=%d", httpResp.StatusCode)
	}
	if string(receivedBody) != bodyText {
		t.Errorf("upstream received body=%q want %q", receivedBody, bodyText)
	}

	tlsClient.Close()
}

// TestGatewayServerEndToEndForwardsChunkedBody verifies a body sent with
// chunked transfer-encoding survives the MITM round-trip. Chunked is
// hop-by-hop on the wire but the body content must arrive at upstream
// regardless of which framing crinj chose.
func TestGatewayServerEndToEndForwardsChunkedBody(t *testing.T) {
	var receivedBody []byte
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		receivedBody = b
		w.WriteHeader(200)
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, _ := url.Parse(upstream.URL)
	target := upstreamURL.Host
	hostname := stripPort(target)

	ca, _ := generateCA()
	rules := []ResolvedHost{{
		HostPattern:        hostname,
		NoCheckCertificate: true,
		InjectionRules:     nil,
	}}
	srv := &GatewayServer{
		ca:                 ca,
		upstreamTLS:        buildUpstreamTLSConfig(false),
		upstreamTLSNoCheck: buildUpstreamTLSConfig(true),
		rules:              rules,
	}

	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go srv.handleConnection(c)
		}
	}()

	proxyConn, _ := net.Dial("tcp", listener.Addr().String())
	defer proxyConn.Close()
	fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	readCONNECTResponse(t, proxyConn)

	pool := x509.NewCertPool()
	pool.AddCert(ca.caCert)
	tlsClient := tls.Client(proxyConn, &tls.Config{ServerName: hostname, RootCAs: pool})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatal(err)
	}

	// Write a chunked-transfer request manually so the proxy must read a
	// chunked body and forward it.
	chunked := "POST /api HTTP/1.1\r\n" +
		"Host: " + target + "\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n" +
		"5\r\nhello\r\n" +
		"6\r\n world\r\n" +
		"0\r\n\r\n"
	if _, err := io.WriteString(tlsClient, chunked); err != nil {
		t.Fatal(err)
	}

	httpResp, err := http.ReadResponse(bufio.NewReader(tlsClient), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	io.Copy(io.Discard, httpResp.Body)
	httpResp.Body.Close()

	if httpResp.StatusCode != 200 {
		t.Errorf("status=%d", httpResp.StatusCode)
	}
	if string(receivedBody) != "hello world" {
		t.Errorf("upstream body=%q want 'hello world'", receivedBody)
	}
	tlsClient.Close()
}

func TestGatewayServerEndToEndTunnelPassthrough(t *testing.T) {
	// Upstream that's just a TCP echo — no TLS. The proxy should not MITM
	// because no rule matches the hostname; it should tunnel raw bytes.
	upstreamL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { upstreamL.Close() })
	go func() {
		for {
			c, err := upstreamL.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	target := upstreamL.Addr().String()

	ca, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}
	srv := &GatewayServer{
		ca:                 ca,
		upstreamTLS:        buildUpstreamTLSConfig(false),
		upstreamTLSNoCheck: buildUpstreamTLSConfig(true),
		rules:              nil, // no rules → tunnel
	}

	proxyL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { proxyL.Close() })
	go func() {
		for {
			c, err := proxyL.Accept()
			if err != nil {
				return
			}
			go srv.handleConnection(c)
		}
	}()

	conn, err := net.Dial("tcp", proxyL.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatal(err)
	}
	resp := readCONNECTResponse(t, conn)
	if !strings.HasPrefix(resp, "HTTP/1.1 200") {
		t.Fatalf("CONNECT response: %q", resp)
	}

	if _, err := conn.Write([]byte("hello-tunnel")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("hello-tunnel"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello-tunnel" {
		t.Errorf("tunnel echo=%q", got)
	}
}

// ── Connection: close propagation ──────────────────────────────────────

// TestMITMRespectsClientConnectionClose verifies that when the client sends
// Connection: close, the MITM loop processes one request then returns
// (rather than waiting on another ReadRequest).
func TestMITMRespectsClientConnectionClose(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, _ := url.Parse(upstream.URL)
	target := upstreamURL.Host
	hostname := stripPort(target)

	ca, _ := generateCA()
	rules := []ResolvedHost{{
		HostPattern:        hostname,
		NoCheckCertificate: true,
	}}
	srv := &GatewayServer{
		ca:                 ca,
		upstreamTLS:        buildUpstreamTLSConfig(false),
		upstreamTLSNoCheck: buildUpstreamTLSConfig(true),
		rules:              rules,
	}

	proxyL, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { proxyL.Close() })

	mitmDone := make(chan error, 1)
	go func() {
		c, err := proxyL.Accept()
		if err != nil {
			mitmDone <- err
			return
		}
		srv.handleConnection(c)
		mitmDone <- nil
	}()

	proxyConn, _ := net.Dial("tcp", proxyL.Addr().String())
	defer proxyConn.Close()
	fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	readCONNECTResponse(t, proxyConn)

	pool := x509.NewCertPool()
	pool.AddCert(ca.caCert)
	tlsClient := tls.Client(proxyConn, &tls.Config{ServerName: hostname, RootCAs: pool})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatal(err)
	}

	// Send request with Connection: close.
	if _, err := io.WriteString(tlsClient,
		"GET / HTTP/1.1\r\nHost: "+target+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// mitm should return on its own within reasonable time, not wait for
	// another request that's never coming.
	select {
	case <-mitmDone:
	case <-time.After(2 * time.Second):
		t.Fatal("mitm did not exit after client Connection: close")
	}
}

// TestMITMRespectsUpstreamConnectionClose verifies that an upstream response
// carrying Connection: close ends the MITM loop after the response is
// delivered.
func TestMITMRespectsUpstreamConnectionClose(t *testing.T) {
	// Upstream hand-rolled with Connection: close in the response.
	upstreamL, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { upstreamL.Close() })

	// Need TLS upstream because the proxy connects over TLS.
	ca, _ := generateCA()
	leafCfg, err := ca.ServerConfigForHost("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	upstreamReady := make(chan struct{})
	go func() {
		close(upstreamReady)
		c, err := upstreamL.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		tlsConn := tls.Server(c, leafCfg)
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		defer tlsConn.Close()
		br := bufio.NewReader(tlsConn)
		_, _ = http.ReadRequest(br)
		// Respond with Connection: close.
		fmt.Fprintf(tlsConn,
			"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	}()
	<-upstreamReady

	target := upstreamL.Addr().String()
	hostname := stripPort(target)

	// Trust our own CA for the upstream connection (since we issued the leaf).
	upstreamCfg := buildUpstreamTLSConfig(false)
	upstreamCfg.RootCAs = x509.NewCertPool()
	upstreamCfg.RootCAs.AddCert(ca.caCert)

	srv := &GatewayServer{
		ca:                 ca,
		upstreamTLS:        upstreamCfg,
		upstreamTLSNoCheck: buildUpstreamTLSConfig(true),
		rules: []ResolvedHost{{
			HostPattern: hostname,
		}},
	}

	proxyL, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { proxyL.Close() })

	mitmDone := make(chan error, 1)
	go func() {
		c, _ := proxyL.Accept()
		srv.handleConnection(c)
		mitmDone <- nil
	}()

	proxyConn, _ := net.Dial("tcp", proxyL.Addr().String())
	defer proxyConn.Close()
	fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	readCONNECTResponse(t, proxyConn)

	pool := x509.NewCertPool()
	pool.AddCert(ca.caCert)
	tlsClient := tls.Client(proxyConn, &tls.Config{ServerName: hostname, RootCAs: pool})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatal(err)
	}

	if _, err := io.WriteString(tlsClient, "GET / HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	select {
	case <-mitmDone:
	case <-time.After(2 * time.Second):
		t.Fatal("mitm did not exit after upstream Connection: close")
	}
}

// ── bufferedConn wrapper ───────────────────────────────────────────────

func TestWrapBufferedReturnsConnDirectlyWhenBufferEmpty(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	br := bufio.NewReader(c1)
	got := wrapBuffered(c1, br)
	if got != c1 {
		t.Error("expected the original conn when bufio buffer is empty")
	}
}

func TestWrapBufferedDrainsBufferedBytesFirst(t *testing.T) {
	// Set up a pair where one side has bytes already in a bufio reader.
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	// Write some bytes that we'll have the bufio "consume" but stay buffered.
	go func() {
		_, _ = c2.Write([]byte("BUFFERED-prefixDIRECT-suffix"))
	}()

	br := bufio.NewReader(c1)
	prefix, err := br.Peek(15) // "BUFFERED-prefix"
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if string(prefix) != "BUFFERED-prefix" {
		t.Fatalf("peek got %q", prefix)
	}
	// br has 15 bytes buffered. wrapBuffered should preserve them.
	wrapped := wrapBuffered(c1, br)
	if wrapped == c1 {
		t.Fatal("expected wrapper, not raw conn")
	}

	out := make([]byte, len("BUFFERED-prefixDIRECT-suffix"))
	n, err := io.ReadFull(wrapped, out)
	if err != nil {
		t.Fatalf("read: %v (got %d bytes)", err, n)
	}
	if string(out) != "BUFFERED-prefixDIRECT-suffix" {
		t.Errorf("got %q want BUFFERED-prefixDIRECT-suffix", out)
	}
}

func TestWrapBufferedPreservesWriteAndClose(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()

	go func() {
		// Send some bytes so wrapBuffered actually wraps.
		_, _ = c2.Write([]byte("x"))
	}()
	br := bufio.NewReader(c1)
	if _, err := br.Peek(1); err != nil {
		t.Fatal(err)
	}
	wrapped := wrapBuffered(c1, br)

	// Write to the wrapped conn must flow through to the underlying.
	go func() {
		_, _ = wrapped.Write([]byte("pong"))
	}()
	got := make([]byte, 4)
	if _, err := io.ReadFull(c2, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "pong" {
		t.Errorf("write didn't pass through: %q", got)
	}

	// Close also delegates.
	if err := wrapped.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

// ── handleConnection / handleSIGHUP ────────────────────────────────────

// runHandleConnection sets up a net.Pipe pair, runs handleConnection on the
// "server" side in a goroutine, and returns the "client" side for the test
// to drive plus a done channel that closes when the handler returns.
func runHandleConnection(t *testing.T, srv *GatewayServer) (net.Conn, chan struct{}) {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		srv.handleConnection(server)
		close(done)
	}()
	return client, done
}

func newTestServer(rules []ResolvedHost) *GatewayServer {
	return &GatewayServer{
		upstreamTLS:        buildUpstreamTLSConfig(false),
		upstreamTLSNoCheck: buildUpstreamTLSConfig(true),
		rules:              rules,
	}
}

func TestHandleConnectionHealthzReturns200(t *testing.T) {
	srv := newTestServer(nil)
	client, done := runHandleConnection(t, srv)
	defer client.Close()

	if _, err := io.WriteString(client, "GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status=%d want 200", resp.StatusCode)
	}
	resp.Body.Close()
	<-done
}

func TestHandleConnectionUnknownPathReturns400(t *testing.T) {
	srv := newTestServer(nil)
	client, done := runHandleConnection(t, srv)
	defer client.Close()

	if _, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != 400 {
		t.Errorf("status=%d want 400", resp.StatusCode)
	}
	resp.Body.Close()
	<-done
}

func TestHandleSIGHUPReloadsConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, `
[[host]]
domain = "first.example.com"
[[host.inject]]
header = "x-api-key"
value = "v1"
`)
	rules, err := load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &GatewayServer{rules: rules, configPath: cfg, allowEmptyRules: false}

	writeFile(t, cfg, `
[[host]]
domain = "second.example.com"
[[host.inject]]
header = "x-api-key"
value = "v2"
`)
	srv.handleSIGHUP()
	if got := srv.rules[0].HostPattern; got != "second.example.com" {
		t.Errorf("after SIGHUP, host=%q want second.example.com", got)
	}
}

func TestHandleSIGHUPRejectsEmptyConfigWithoutFlag(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, `
[[host]]
domain = "kept.example.com"
[[host.inject]]
header = "x-api-key"
value = "v1"
`)
	rules, _ := load(cfg)
	srv := &GatewayServer{rules: rules, configPath: cfg, allowEmptyRules: false}

	writeFile(t, cfg, "")
	srv.handleSIGHUP()
	if got := srv.rules[0].HostPattern; got != "kept.example.com" {
		t.Errorf("rules should be unchanged, got host=%q", got)
	}
}

func TestHandleSIGHUPAcceptsEmptyWithFlag(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, `
[[host]]
domain = "kept.example.com"
[[host.inject]]
header = "x-api-key"
value = "v1"
`)
	rules, _ := load(cfg)
	srv := &GatewayServer{rules: rules, configPath: cfg, allowEmptyRules: true}

	writeFile(t, cfg, "")
	srv.handleSIGHUP()
	if len(srv.rules) != 0 {
		t.Errorf("expected empty rules after reload, got %d", len(srv.rules))
	}
}

func TestHandleSIGHUPKeepsOldOnParseError(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "rules.toml")
	writeFile(t, cfg, `
[[host]]
domain = "kept.example.com"
[[host.inject]]
header = "x-api-key"
value = "v1"
`)
	rules, _ := load(cfg)
	srv := &GatewayServer{rules: rules, configPath: cfg, allowEmptyRules: true}

	writeFile(t, cfg, "this is not [valid toml")
	srv.handleSIGHUP()
	if got := srv.rules[0].HostPattern; got != "kept.example.com" {
		t.Errorf("rules should be unchanged on parse error, got host=%q", got)
	}
}

// ── writeSyntheticBlocked ──────────────────────────────────────────────

func TestWriteSyntheticBlockedParsesAs200(t *testing.T) {
	var buf bytes.Buffer
	if err := writeSyntheticBlocked(&buf); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(&buf), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status=%d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("content-type=%q", got)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "{}" {
		t.Errorf("body=%q", body)
	}
}

// ── mitm end-to-end ────────────────────────────────────────────────────

func TestMITMInjectsHeaderEndToEnd(t *testing.T) {
	// Upstream: echoes the x-api-key header back so the test can confirm
	// the injection landed.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "x-api-key=%s|path=%s", r.Header.Get("x-api-key"), r.URL.RequestURI())
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	target := upstreamURL.Host
	hostname := stripPort(target)

	ca, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}
	rules := []InjectionRule{makeRule("*", []Injection{setHeader("x-api-key", "INJECTED")})}

	proxyL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { proxyL.Close() })

	proxyDone := make(chan error, 1)
	go func() {
		c, err := proxyL.Accept()
		if err != nil {
			proxyDone <- err
			return
		}
		// Upstream is httptest's self-signed cert; use the insecure config.
		proxyDone <- mitm(c, target, ca, buildUpstreamTLSConfig(true), nil, nil, rules, nil)
	}()

	rawConn, err := net.Dial("tcp", proxyL.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer rawConn.Close()

	pool := x509.NewCertPool()
	pool.AddCert(ca.caCert)
	clientTLS := tls.Client(rawConn, &tls.Config{
		ServerName: hostname,
		RootCAs:    pool,
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}

	req := &http.Request{
		Method:     "GET",
		URL:        &url.URL{Path: "/api"},
		Host:       target,
		Header:     http.Header{"X-Api-Key": []string{"PLACEHOLDER"}},
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	if err := req.Write(clientTLS); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status=%d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "x-api-key=INJECTED") {
		t.Errorf("missing injected header in upstream echo, body=%q", body)
	}
	if !strings.Contains(string(body), "path=/api") {
		t.Errorf("missing path in upstream echo, body=%q", body)
	}

	clientTLS.Close()
	rawConn.Close()
	select {
	case err := <-proxyDone:
		if err != nil && !strings.Contains(err.Error(), "use of closed") &&
			!strings.Contains(err.Error(), "EOF") &&
			!strings.Contains(err.Error(), "connection reset") {
			t.Logf("mitm returned (expected EOF-ish): %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("mitm did not exit after client closed")
	}
}

func TestMITMBlockedResponseShortCircuits(t *testing.T) {
	// Upstream that should NEVER be touched (access-blocks the request).
	hits := make(chan struct{}, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits <- struct{}{}
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, _ := url.Parse(upstream.URL)
	target := upstreamURL.Host
	hostname := stripPort(target)

	ca, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}
	access, _ := parseAccess("block *")

	proxyL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { proxyL.Close() })

	go func() {
		c, err := proxyL.Accept()
		if err != nil {
			return
		}
		_ = mitm(c, target, ca, buildUpstreamTLSConfig(true), nil, access, nil, nil)
	}()

	rawConn, err := net.Dial("tcp", proxyL.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer rawConn.Close()

	pool := x509.NewCertPool()
	pool.AddCert(ca.caCert)
	clientTLS := tls.Client(rawConn, &tls.Config{ServerName: hostname, RootCAs: pool})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatal(err)
	}

	req := &http.Request{
		Method:     "GET",
		URL:        &url.URL{Path: "/admin"},
		Host:       target,
		Header:     http.Header{},
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	if err := req.Write(clientTLS); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status=%d", resp.StatusCode)
	}
	if string(body) != "{}" {
		t.Errorf("body=%q", body)
	}

	// Upstream must NOT have been hit.
	select {
	case <-hits:
		t.Error("upstream was hit despite access block")
	case <-time.After(100 * time.Millisecond):
	}
	clientTLS.Close()
}

// ── prepareUpstreamRequest ─────────────────────────────────────────────

func newTestRequest(method, target string, headers map[string]string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func TestPrepareUpstreamRequestBlockedReturnsEarly(t *testing.T) {
	req := newTestRequest("GET", "https://api.example.com/admin/x", nil)
	access, _ := parseAccess("block *")
	blocked, count, err := prepareUpstreamRequest(req, access, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !blocked {
		t.Error("expected blocked=true")
	}
	if count != 0 {
		t.Errorf("count=%d", count)
	}
}

func TestPrepareUpstreamRequestAccessAllowsThroughInjections(t *testing.T) {
	req := newTestRequest("GET", "https://api.example.com/v1/messages",
		map[string]string{"x-api-key": "PLACEHOLDER", "accept": "application/json"})
	access, _ := parseAccess("block *\nallow /v1/*")
	rules := []InjectionRule{makeRule("*", []Injection{setHeader("x-api-key", "sk-real")})}

	blocked, count, err := prepareUpstreamRequest(req, access, rules)
	if err != nil {
		t.Fatal(err)
	}
	if blocked {
		t.Error("should not be blocked")
	}
	if count != 1 {
		t.Errorf("count=%d want 1", count)
	}
	if got := req.Header.Get("x-api-key"); got != "sk-real" {
		t.Errorf("x-api-key=%q", got)
	}
}

func TestPrepareUpstreamRequestStripsHopByHop(t *testing.T) {
	req := newTestRequest("GET", "https://api.example.com/anything",
		map[string]string{
			"connection":        "keep-alive",
			"transfer-encoding": "chunked",
			"x-keep":            "yes",
		})
	_, _, err := prepareUpstreamRequest(req, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("connection"); got != "" {
		t.Errorf("connection should be stripped, got %q", got)
	}
	if got := req.Header.Get("x-keep"); got != "yes" {
		t.Errorf("x-keep=%q", got)
	}
}

func TestPrepareUpstreamRequestQueryInjection(t *testing.T) {
	req := newTestRequest("GET", "https://api.example.com/fred/series?api_key=PLACEHOLDER&series_id=GDP", nil)
	rules := []InjectionRule{makeRule("*", []Injection{setQueryParam("api_key", "real-key")})}

	blocked, count, err := prepareUpstreamRequest(req, nil, rules)
	if err != nil {
		t.Fatal(err)
	}
	if blocked {
		t.Error("should not be blocked")
	}
	if count != 1 {
		t.Errorf("count=%d want 1", count)
	}
	uri := req.URL.RequestURI()
	if !strings.Contains(uri, "api_key=real-key") {
		t.Errorf("URI=%q missing real-key", uri)
	}
	if strings.Contains(uri, "PLACEHOLDER") {
		t.Errorf("URI=%q still has placeholder", uri)
	}
	if !strings.Contains(uri, "series_id=GDP") {
		t.Errorf("URI=%q missing series_id", uri)
	}
}

func TestPrepareUpstreamRequestNoRulesIsNoOp(t *testing.T) {
	req := newTestRequest("GET", "https://api.example.com/v1/foo", map[string]string{"x-keep": "yes"})
	originalPath := req.URL.RequestURI()

	blocked, count, err := prepareUpstreamRequest(req, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if blocked || count != 0 {
		t.Errorf("blocked=%v count=%d", blocked, count)
	}
	if req.URL.RequestURI() != originalPath {
		t.Errorf("path mutated: %q", req.URL.RequestURI())
	}
	if req.Header.Get("x-keep") != "yes" {
		t.Error("x-keep lost")
	}
}

func TestPrepareUpstreamRequestPathOnlyURI(t *testing.T) {
	// Upstream sends path-only URI on the wire (proxy semantics: URL stripped
	// of scheme/host).
	req := newTestRequest("GET", "https://api.example.com/v1/messages?x=1", nil)
	if _, _, err := prepareUpstreamRequest(req, nil, nil); err != nil {
		t.Fatal(err)
	}
	if req.URL.Scheme != "" || req.URL.Host != "" {
		t.Errorf("URL still absolute: scheme=%q host=%q", req.URL.Scheme, req.URL.Host)
	}
	if req.URL.RequestURI() != "/v1/messages?x=1" {
		t.Errorf("RequestURI=%q", req.URL.RequestURI())
	}
	if req.RequestURI != "" {
		t.Errorf("RequestURI string field=%q (must be cleared)", req.RequestURI)
	}
}

// ── buildUpstreamTLSConfig ─────────────────────────────────────────────

func TestBuildUpstreamTLSConfigSafe(t *testing.T) {
	cfg := buildUpstreamTLSConfig(false)
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be false by default")
	}
}

func TestBuildUpstreamTLSConfigInsecure(t *testing.T) {
	cfg := buildUpstreamTLSConfig(true)
	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true when danger flag set")
	}
}

// ── writeBlockedResponse ───────────────────────────────────────────────

func TestWriteBlockedResponseBody(t *testing.T) {
	rec := httptest.NewRecorder()
	writeBlockedResponse(rec)
	resp := rec.Result()
	if resp.StatusCode != 200 {
		t.Errorf("status=%d want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("content-type=%q", got)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "{}" {
		t.Errorf("body=%q want {}", body)
	}
}

// ── tunnel ─────────────────────────────────────────────────────────────

// echoListener spawns a TCP listener that echoes every accepted connection.
func echoListener(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	return l.Addr().String()
}

func TestTunnelEchoesBothDirections(t *testing.T) {
	upstreamAddr := echoListener(t)

	// Client→proxy listener: the test connects on one side, the tunnel
	// runs on the other side.
	proxyL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { proxyL.Close() })

	serverCh := make(chan net.Conn, 1)
	go func() {
		c, err := proxyL.Accept()
		if err == nil {
			serverCh <- c
		}
	}()

	client, err := net.Dial("tcp", proxyL.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	server := <-serverCh

	doneCh := make(chan error, 1)
	go func() { doneCh <- tunnel(server, upstreamAddr, nil) }()

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "ping" {
		t.Errorf("got=%q want ping", got)
	}

	// Half-close client side; tunnel should see EOF, propagate, and exit.
	if cw, ok := client.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	} else {
		client.Close()
	}
	select {
	case err := <-doneCh:
		if err != nil {
			t.Errorf("tunnel returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tunnel did not exit")
	}
}

// ── Mock CONNECT proxy ─────────────────────────────────────────────────

// spawnMockProxy starts a one-shot listener that records the CONNECT head
// in reqCh, replies with statusLine, then echoes any subsequent bytes back.
// Returns the bound address; the listener auto-closes via t.Cleanup.
func spawnMockProxy(t *testing.T, statusLine string) (string, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	reqCh := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 0, 256)
		one := make([]byte, 1)
		for {
			n, err := conn.Read(one)
			if err != nil || n == 0 {
				return
			}
			buf = append(buf, one[0])
			if len(buf) >= 4 && string(buf[len(buf)-4:]) == "\r\n\r\n" {
				break
			}
		}
		reqCh <- string(buf)

		fmt.Fprintf(conn, "%s\r\n\r\n", statusLine)

		echo := make([]byte, 1024)
		for {
			n, err := conn.Read(echo)
			if err != nil || n == 0 {
				return
			}
			if _, err := conn.Write(echo[:n]); err != nil {
				return
			}
		}
	}()
	return listener.Addr().String(), reqCh
}

func TestDialViaProxyHandshakeAndEcho(t *testing.T) {
	addr, reqCh := spawnMockProxy(t, "HTTP/1.1 200 Connection Established")
	conn, err := dialViaProxy(addr, "api.example.com:443")
	if err != nil {
		t.Fatalf("dialViaProxy: %v", err)
	}
	defer conn.Close()

	req := <-reqCh
	first := strings.SplitN(req, "\r\n", 2)[0]
	if first != "CONNECT api.example.com:443 HTTP/1.1" {
		t.Errorf("CONNECT line=%q", first)
	}
	if !strings.Contains(req, "Host: api.example.com:443") {
		t.Errorf("missing Host header: %q", req)
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := conn.Read(got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "ping" {
		t.Errorf("echo=%q", got)
	}
}

func TestDialViaProxyPropagatesNon200(t *testing.T) {
	addr, _ := spawnMockProxy(t, "HTTP/1.1 502 Bad Gateway")
	_, err := dialViaProxy(addr, "api.example.com:443")
	if err == nil {
		t.Fatal("want error on non-200")
	}
	msg := err.Error()
	if !strings.Contains(msg, "502") {
		t.Errorf("missing 502 in error: %s", msg)
	}
	if !strings.Contains(msg, "api.example.com:443") {
		t.Errorf("missing target in error: %s", msg)
	}
}

func TestDialUpstreamRoutesThroughProxyWhenConfigured(t *testing.T) {
	addr, reqCh := spawnMockProxy(t, "HTTP/1.1 200 OK")
	proxy := &UpstreamProxy{addr: addr}
	conn, err := dialUpstream("origin.example.com:443", proxy)
	if err != nil {
		t.Fatalf("dialUpstream: %v", err)
	}
	defer conn.Close()

	req := <-reqCh
	if !strings.HasPrefix(req, "CONNECT origin.example.com:443 HTTP/1.1\r\n") {
		t.Errorf("CONNECT line wrong: %q", req)
	}
}

func TestDialUpstreamBypassesProxyWhenNoProxyMatches(t *testing.T) {
	// Real origin listener so the direct dial succeeds.
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	t.Cleanup(func() { origin.Close() })
	go func() {
		c, err := origin.Accept()
		if err == nil {
			c.Close()
		}
	}()

	proxyAddr, reqCh := spawnMockProxy(t, "HTTP/1.1 200 OK")
	proxy := &UpstreamProxy{addr: proxyAddr, noProxy: []string{"127.0.0.1"}}

	conn, err := dialUpstream(origin.Addr().String(), proxy)
	if err != nil {
		t.Fatalf("dialUpstream: %v", err)
	}
	conn.Close()

	select {
	case <-reqCh:
		t.Error("proxy unexpectedly received CONNECT")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestUpstreamProxyFromEnvParsesNoProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy:3128")
	t.Setenv("NO_PROXY", "localhost, .internal.corp ,*")
	p, err := upstreamProxyFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		t.Fatal("expected non-nil proxy")
	}
	if p.Addr() != "proxy:3128" {
		t.Errorf("addr=%q", p.Addr())
	}
	want := []string{"localhost", ".internal.corp", "*"}
	if len(p.noProxy) != len(want) {
		t.Fatalf("noProxy=%+v want %v", p.noProxy, want)
	}
	for i, w := range want {
		if p.noProxy[i] != w {
			t.Errorf("noProxy[%d]=%q want %q", i, p.noProxy[i], w)
		}
	}
}
