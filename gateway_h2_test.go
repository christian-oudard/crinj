package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// h2Upstream starts an HTTP/2 TLS server and returns it. httptest with
// EnableHTTP2 negotiates h2 over ALPN.
func h2Upstream(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(h)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

// dialH2ThroughProxy drives a CONNECT, negotiates h2 with the MITM leaf, and
// returns an *http2.ClientConn ready for RoundTrip.
func dialH2ThroughProxy(t *testing.T, proxyAddr, target, hostname string, ca *CertificateAuthority) *http2.ClientConn {
	t.Helper()
	proxyConn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { proxyConn.Close() })
	fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if resp := readCONNECTResponse(t, proxyConn); !strings.HasPrefix(resp, "HTTP/1.1 200") {
		t.Fatalf("CONNECT response: %q", resp)
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca.caCert)
	tlsClient := tls.Client(proxyConn, &tls.Config{
		ServerName: hostname,
		RootCAs:    pool,
		NextProtos: []string{"h2"},
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	if proto := tlsClient.ConnectionState().NegotiatedProtocol; proto != "h2" {
		t.Fatalf("client negotiated %q, want h2", proto)
	}
	tr := &http2.Transport{}
	cc, err := tr.NewClientConn(tlsClient)
	if err != nil {
		t.Fatalf("h2 client conn: %v", err)
	}
	return cc
}

// startProxy runs the gateway on a listener and returns its address.
func startProxy(t *testing.T, srv *GatewayServer) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go srv.handleConnection(conn)
		}
	}()
	return l.Addr().String()
}

func TestMITMH2EndToEndAppliesInjection(t *testing.T) {
	upstream := h2Upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo the (possibly injected) header and the negotiated protocol so the
		// test can prove both that h2 reached upstream and injection applied.
		fmt.Fprintf(w, "x-api-key=%s|proto=%d|path=%s",
			r.Header.Get("x-api-key"), r.ProtoMajor, r.URL.RequestURI())
	}))
	target := strings.TrimPrefix(upstream.URL, "https://")
	hostname := stripPort(target)

	ca, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}
	srv := &GatewayServer{
		ca:                 ca,
		upstreamTLS:        buildUpstreamTLSConfig(false),
		upstreamTLSNoCheck: buildUpstreamTLSConfig(true),
		rules: []ResolvedHost{{
			HostPattern:        hostname,
			NoCheckCertificate: true,
			InjectionRules:     []InjectionRule{makeRule("*", []Injection{setHeader("x-api-key", "INJECTED")})},
		}},
	}
	addr := startProxy(t, srv)
	cc := dialH2ThroughProxy(t, addr, target, hostname, ca)

	req, _ := http.NewRequest("GET", "https://"+hostname+"/api", nil)
	req.Header.Set("x-api-key", "PLACEHOLDER")
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.ProtoMajor != 2 {
		t.Errorf("client saw proto %d, want 2", resp.ProtoMajor)
	}
	if !strings.Contains(string(body), "x-api-key=INJECTED") {
		t.Errorf("injection not applied over h2, body=%q", body)
	}
	if !strings.Contains(string(body), "proto=2") {
		t.Errorf("upstream leg was not h2, body=%q", body)
	}
	if !strings.Contains(string(body), "path=/api") {
		t.Errorf("path not forwarded, body=%q", body)
	}
}

func TestMITMH2ForwardsRequestBody(t *testing.T) {
	upstream := h2Upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "len=%d body=%s", len(b), b)
	}))
	target := strings.TrimPrefix(upstream.URL, "https://")
	hostname := stripPort(target)

	ca, _ := generateCA()
	srv := &GatewayServer{
		ca:                 ca,
		upstreamTLS:        buildUpstreamTLSConfig(false),
		upstreamTLSNoCheck: buildUpstreamTLSConfig(true),
		rules:              []ResolvedHost{{HostPattern: hostname, NoCheckCertificate: true}},
	}
	addr := startProxy(t, srv)
	cc := dialH2ThroughProxy(t, addr, target, hostname, ca)

	req, _ := http.NewRequest("POST", "https://"+hostname+"/echo", strings.NewReader("hello-h2-body"))
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "body=hello-h2-body") {
		t.Errorf("request body not forwarded, got %q", body)
	}
}

// TestMITMH2ForwardsTrailers proves gRPC works through the MITM: gRPC carries
// its status in HTTP/2 trailers, so the trailer must survive the proxy hop.
func TestMITMH2ForwardsTrailers(t *testing.T) {
	upstream := h2Upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("payload"))
		w.Header().Set("Grpc-Status", "0")
	}))
	target := strings.TrimPrefix(upstream.URL, "https://")
	hostname := stripPort(target)

	ca, _ := generateCA()
	srv := &GatewayServer{
		ca:                 ca,
		upstreamTLS:        buildUpstreamTLSConfig(false),
		upstreamTLSNoCheck: buildUpstreamTLSConfig(true),
		rules:              []ResolvedHost{{HostPattern: hostname, NoCheckCertificate: true}},
	}
	addr := startProxy(t, srv)
	cc := dialH2ThroughProxy(t, addr, target, hostname, ca)

	req, _ := http.NewRequest("GET", "https://"+hostname+"/grpc", nil)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Errorf("trailer Grpc-Status=%q want 0 (gRPC would break)", got)
	}
}

func TestMITMH2AccessBlockReturnsSynthetic(t *testing.T) {
	upstream := h2Upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("blocked request should never reach upstream")
	}))
	target := strings.TrimPrefix(upstream.URL, "https://")
	hostname := stripPort(target)

	ca, _ := generateCA()
	srv := &GatewayServer{
		ca:                 ca,
		upstreamTLS:        buildUpstreamTLSConfig(false),
		upstreamTLSNoCheck: buildUpstreamTLSConfig(true),
		rules: []ResolvedHost{{
			HostPattern:        hostname,
			NoCheckCertificate: true,
			Access:             []AccessEntry{{Verb: AccessBlock, PathPattern: "*"}},
		}},
	}
	addr := startProxy(t, srv)
	cc := dialH2ThroughProxy(t, addr, target, hostname, ca)

	req, _ := http.NewRequest("GET", "https://"+hostname+"/secret", nil)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("blocked status=%d want 200", resp.StatusCode)
	}
	if strings.TrimSpace(string(body)) != "{}" {
		t.Errorf("blocked body=%q want {}", body)
	}
}

// TestMITMHTTP1StillWorksAfterH2ALPN guards the fallback: a client that only
// offers http/1.1 must still be served by the HTTP/1.1 loop now that the leaf
// advertises both protocols.
func TestMITMHTTP1StillWorksAfterH2ALPN(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "proto=%d", r.ProtoMajor)
	}))
	t.Cleanup(upstream.Close)
	target := strings.TrimPrefix(upstream.URL, "https://")
	hostname := stripPort(target)

	ca, _ := generateCA()
	srv := &GatewayServer{
		ca:                 ca,
		upstreamTLS:        buildUpstreamTLSConfig(false),
		upstreamTLSNoCheck: buildUpstreamTLSConfig(true),
		rules:              []ResolvedHost{{HostPattern: hostname, NoCheckCertificate: true}},
	}
	addr := startProxy(t, srv)

	proxyConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer proxyConn.Close()
	fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	readCONNECTResponse(t, proxyConn)

	pool := x509.NewCertPool()
	pool.AddCert(ca.caCert)
	// Only offer http/1.1.
	tlsClient := tls.Client(proxyConn, &tls.Config{
		ServerName: hostname,
		RootCAs:    pool,
		NextProtos: []string{"http/1.1"},
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	_ = tlsClient.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(tlsClient, "GET /x HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "proto=1") {
		t.Errorf("http/1.1 fallback broke, body=%q", body)
	}
}
