package main

// HTTP/2 MITM path. When the client negotiates `h2` over ALPN (gRPC and modern
// HTTP clients do), the HTTP/1.1 request/response loop in gateway.go cannot
// carry the connection. mitmH2 serves the client leg with an http2.Server and
// bridges to the upstream through a standard http.Transport that negotiates
// h2-or-h1 itself, wrapped in httputil.ReverseProxy so streaming bodies and
// gRPC trailers flow through untouched. Access control, header/query injection,
// and OAuth token brokering reuse the same helpers as the HTTP/1.1 path.

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

// h2RequestState carries per-request bookkeeping from the handler (where
// injection and OAuth request rewriting happen) to ReverseProxy.ModifyResponse
// (where the token exchange is captured and the forward is logged).
type h2RequestState struct {
	exchange   *tokenExchange
	injections int
}

type h2ContextKey struct{}

func mitmH2(
	tlsClient net.Conn,
	host, hostname string,
	upstreamTLS *tls.Config,
	upstreamProxy *UpstreamProxy,
	access []AccessEntry,
	rules []InjectionRule,
	oauth *OAuthEngine,
) error {
	target := host
	if !strings.Contains(host, ":") {
		target = host + ":443"
	}

	// Upstream leg: dial through any parent proxy, complete TLS ourselves with
	// ALPN advertising h2+http/1.1, and let the Transport speak whichever the
	// upstream negotiated. ForceAttemptHTTP2 keeps h2 in play despite the custom
	// DialTLSContext (a custom dialer otherwise disables h2).
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			raw, err := dialUpstream(target, upstreamProxy)
			if err != nil {
				return nil, err
			}
			cfg := upstreamTLS.Clone()
			cfg.ServerName = hostname
			cfg.NextProtos = []string{"h2", "http/1.1"}
			uconn := tls.Client(raw, cfg)
			_ = uconn.SetDeadline(time.Now().Add(handshakeTimeout))
			if err := uconn.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, fmt.Errorf("upstream TLS handshake with %s: %w", host, err)
			}
			_ = uconn.SetDeadline(time.Time{})
			return uconn, nil
		},
	}
	defer transport.CloseIdleConnections()

	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Director: func(outreq *http.Request) {
			outreq.URL.Scheme = "https"
			outreq.URL.Host = host
			// Stay transparent: don't append a proxy hop header.
			outreq.Header["X-Forwarded-For"] = nil
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header = filterHeaders(resp.Header)
			st, _ := resp.Request.Context().Value(h2ContextKey{}).(*h2RequestState)
			if st != nil && st.exchange != nil {
				if err := captureOAuthResponse(resp, st.exchange, oauth); err != nil {
					return err
				}
			}
			injections := 0
			if st != nil {
				injections = st.injections
			}
			slog.Info("forwarded",
				"method", resp.Request.Method,
				"url", "https://"+host+resp.Request.URL.RequestURI(),
				"status", resp.StatusCode,
				"injections_applied", injections)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			slog.Warn("h2 upstream error", "host", host, "error", err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		blocked, injections, err := prepareUpstreamRequest(r, access, rules)
		if err != nil {
			slog.Warn("forward error", "host", host, "error", err)
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		if blocked {
			slog.Info("blocked",
				"method", r.Method,
				"url", "https://"+host+r.URL.RequestURI(),
				"status", 200)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{}"))
			return
		}
		exchange, err := applyOAuthRequest(r, hostname, oauth)
		if err != nil {
			slog.Warn("oauth request error", "host", host, "error", err)
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		st := &h2RequestState{exchange: exchange, injections: injections}
		proxy.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), h2ContextKey{}, st)))
	})

	(&http2.Server{IdleTimeout: idleTimeout}).ServeConn(
		tlsClient, &http2.ServeConnOpts{Handler: handler})
	return nil
}
