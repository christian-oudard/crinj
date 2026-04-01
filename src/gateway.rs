//! HTTP gateway server: connection handling, MITM interception, and tunneling.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use http_body_util::Empty;
use hyper::body::{Bytes, Incoming};
use hyper::header::HeaderName;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{info, warn};

use crate::ca::CertificateAuthority;
use crate::inject::{self, InjectionRule};
use crate::local::ResolvedHost;

// ── GatewayServer ───────────────────────────────────────────────────────

pub struct GatewayServer {
    ca: Arc<CertificateAuthority>,
    upstream_tls: Arc<TlsConnector>,
    port: u16,
    bind_addr: String,
    rules: Arc<std::sync::RwLock<Vec<ResolvedHost>>>,
    config_path: PathBuf,
}

impl GatewayServer {
    pub fn new(
        ca: CertificateAuthority,
        port: u16,
        bind_addr: String,
        rules: Vec<ResolvedHost>,
        config_path: PathBuf,
    ) -> Self {
        let client_config = build_upstream_tls_config(
            std::env::var("GATEWAY_DANGER_ACCEPT_INVALID_CERTS").is_ok(),
        );
        Self {
            ca: Arc::new(ca),
            upstream_tls: Arc::new(TlsConnector::from(Arc::new(client_config))),
            port,
            bind_addr,
            rules: Arc::new(std::sync::RwLock::new(rules)),
            config_path,
        }
    }

    pub async fn run(&self) -> Result<()> {
        let addr: SocketAddr = format!("{}:{}", self.bind_addr, self.port)
            .parse()
            .context("parsing bind address")?;
        let listener = TcpListener::bind(addr)
            .await
            .context("binding TCP listener")?;

        info!(addr = %addr, "listening for connections");

        #[cfg(unix)]
        let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            .context("registering SIGHUP handler")?;

        loop {
            #[cfg(unix)]
            tokio::select! {
                result = listener.accept() => {
                    let (stream, peer_addr) = result?;
                    self.spawn_connection(stream, peer_addr);
                }
                _ = sighup.recv() => {
                    self.handle_sighup();
                }
            }

            #[cfg(not(unix))]
            {
                let (stream, peer_addr) = listener.accept().await?;
                self.spawn_connection(stream, peer_addr);
            }
        }
    }

    fn spawn_connection(&self, stream: TcpStream, peer_addr: SocketAddr) {
        let ca = Arc::clone(&self.ca);
        let upstream_tls = Arc::clone(&self.upstream_tls);
        let rules = Arc::clone(&self.rules);

        tokio::spawn(async move {
            if let Err(e) =
                handle_connection(stream, peer_addr, ca, upstream_tls, rules).await
            {
                warn!(peer = %peer_addr, error = %e, "connection error");
            }
        });
    }

    fn handle_sighup(&self) {
        match crate::local::load(&self.config_path) {
            Ok(new_rules) => {
                let count = new_rules.len();
                *self.rules.write().unwrap() = new_rules;
                info!(host_count = count, "SIGHUP: reloaded config");
            }
            Err(e) => {
                warn!(error = %e, "SIGHUP: failed to reload config, keeping old one");
            }
        }
    }
}

// ── Upstream TLS ────────────────────────────────────────────────────────

fn build_upstream_tls_config(danger_accept_invalid_certs: bool) -> rustls::ClientConfig {
    if danger_accept_invalid_certs {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    }
}

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ── Connection handling ─────────────────────────────────────────────────

async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    ca: Arc<CertificateAuthority>,
    upstream_tls: Arc<TlsConnector>,
    rules: Arc<std::sync::RwLock<Vec<ResolvedHost>>>,
) -> Result<()> {
    let io = TokioIo::new(stream);

    http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(
            io,
            service_fn(move |req: Request<Incoming>| {
                let ca = Arc::clone(&ca);
                let upstream_tls = Arc::clone(&upstream_tls);
                let rules = Arc::clone(&rules);
                async move {
                    if req.method() == Method::CONNECT {
                        handle_connect(req, peer_addr, ca, upstream_tls, rules).await
                    } else if req.uri().path() == "/healthz" {
                        Ok(Response::new(Empty::new()))
                    } else {
                        let mut resp = Response::new(Empty::new());
                        *resp.status_mut() = StatusCode::BAD_REQUEST;
                        Ok(resp)
                    }
                }
            }),
        )
        .with_upgrades()
        .await
        .context("serving HTTP connection")
}

// ── CONNECT handling ────────────────────────────────────────────────────

async fn handle_connect(
    req: Request<Incoming>,
    peer_addr: SocketAddr,
    ca: Arc<CertificateAuthority>,
    upstream_tls: Arc<TlsConnector>,
    rules: Arc<std::sync::RwLock<Vec<ResolvedHost>>>,
) -> Result<Response<Empty<Bytes>>, anyhow::Error> {
    let host = req
        .uri()
        .authority()
        .context("CONNECT request missing host:port")?
        .to_string();

    let hostname = strip_port(&host).to_string();

    let (intercept, injection_rules) = {
        let rules = rules.read().unwrap();
        crate::local::resolve(&hostname, &rules)
    };

    info!(
        peer = %peer_addr,
        host = %host,
        mode = if intercept { "mitm" } else { "tunnel" },
        rule_count = injection_rules.len(),
        "CONNECT"
    );

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let result = if intercept {
                    mitm(upgraded, &host, &ca, upstream_tls, injection_rules).await
                } else {
                    tunnel(upgraded, &host).await
                };
                if let Err(e) = result {
                    warn!(host = %host, error = %e, "connection error");
                }
            }
            Err(e) => {
                warn!(host = %host, error = %e, "upgrade failed");
            }
        }
    });

    Ok(Response::new(Empty::new()))
}

// ── MITM & tunnel ───────────────────────────────────────────────────────

async fn mitm(
    upgraded: hyper::upgrade::Upgraded,
    host: &str,
    ca: &CertificateAuthority,
    upstream_tls: Arc<TlsConnector>,
    injection_rules: Vec<InjectionRule>,
) -> Result<()> {
    let hostname = strip_port(host);

    // Client side: accept TLS from the CONNECT client.
    let server_config = ca.server_config_for_host(hostname)?;
    let acceptor = TlsAcceptor::from(server_config);
    let client_io = TokioIo::new(upgraded);
    let tls_stream = acceptor
        .accept(client_io)
        .await
        .context("TLS handshake with client")?;

    // Upstream side: single TLS connection reused for all requests.
    let connect_addr = if host.contains(':') {
        host.to_string()
    } else {
        format!("{host}:443")
    };
    let tcp = TcpStream::connect(&connect_addr)
        .await
        .with_context(|| format!("connecting to {connect_addr}"))?;
    let server_name = rustls::pki_types::ServerName::try_from(hostname.to_string())
        .map_err(|e| anyhow::anyhow!("invalid server name: {e}"))?;
    let upstream_stream: tokio_rustls::client::TlsStream<TcpStream> = upstream_tls
        .connect(server_name, tcp)
        .await
        .with_context(|| format!("TLS handshake with {host}"))?;

    let (sender, conn): (hyper::client::conn::http1::SendRequest<Incoming>, _) =
        hyper::client::conn::http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .handshake(TokioIo::new(upstream_stream))
            .await
            .context("HTTP/1.1 handshake with upstream")?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            warn!(error = %e, "upstream connection error");
        }
    });

    let host_owned = host.to_string();
    let injection_rules = Arc::new(injection_rules);
    let sender = Arc::new(tokio::sync::Mutex::new(sender));
    let io = TokioIo::new(tls_stream);

    http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(
            io,
            service_fn(move |req| {
                let host = host_owned.clone();
                let sender = Arc::clone(&sender);
                let inj_rules = Arc::clone(&injection_rules);
                async move { forward_request(req, &host, &sender, &inj_rules).await }
            }),
        )
        .await
        .context("serving MITM connection")
}

async fn forward_request(
    req: Request<Incoming>,
    host: &str,
    sender: &tokio::sync::Mutex<hyper::client::conn::http1::SendRequest<Incoming>>,
    injection_rules: &[InjectionRule],
) -> anyhow::Result<Response<Incoming>> {
    let method = req.method().clone();
    let raw_path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    let (path, query_injection_count) =
        inject::apply_query_injections(&raw_path, injection_rules);

    let (mut parts, body) = req.into_parts();

    // Filter hop-by-hop headers, apply injections.
    let mut headers = filter_headers(&parts.headers);
    let injection_count = inject::apply_injections(&mut headers, &path, injection_rules);

    // Reconstruct request with path-only URI (not full URL).
    parts.headers = headers;
    parts.uri = path.parse().context("parsing path as URI")?;
    let upstream_req = Request::from_parts(parts, body);

    let mut sender = sender.lock().await;
    let resp = sender
        .send_request(upstream_req)
        .await
        .with_context(|| format!("forwarding to {host}{path}"))?;

    let status = resp.status();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-");

    info!(
        method = %method,
        url = format!("https://{host}{path}"),
        status = %status.as_u16(),
        content_type = %content_type,
        injections_applied = injection_count + query_injection_count,
        "forwarded"
    );

    // Strip hop-by-hop headers from response.
    let (resp_parts, body) = resp.into_parts();
    let mut response = Response::new(body);
    *response.status_mut() = resp_parts.status;
    *response.headers_mut() = filter_headers(&resp_parts.headers);

    Ok(response)
}

async fn tunnel(upgraded: hyper::upgrade::Upgraded, host: &str) -> Result<()> {
    let mut server = TcpStream::connect(host)
        .await
        .with_context(|| format!("connecting to upstream {host}"))?;

    let mut client = TokioIo::new(upgraded);

    let (client_to_server, server_to_client) =
        tokio::io::copy_bidirectional(&mut client, &mut server)
            .await
            .context("bidirectional copy")?;

    info!(
        host = %host,
        client_to_server,
        server_to_client,
        "tunnel closed"
    );

    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Hop-by-hop headers that must not be forwarded between client and upstream.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

fn is_hop_by_hop(name: &HeaderName) -> bool {
    HOP_BY_HOP.contains(&name.as_str())
}

fn filter_headers(headers: &hyper::HeaderMap) -> hyper::HeaderMap {
    let mut out = hyper::HeaderMap::new();
    for (name, value) in headers.iter() {
        if !is_hop_by_hop(name) {
            out.append(name.clone(), value.clone());
        }
    }
    out
}

fn strip_port(host: &str) -> &str {
    // Handle bracketed IPv6, e.g. "[::1]:443" → "::1"
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    host.split(':').next().unwrap_or(host)
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    #[test]
    fn strip_port_removes_port() {
        assert_eq!(strip_port("example.com:443"), "example.com");
        assert_eq!(strip_port("api.anthropic.com:8080"), "api.anthropic.com");
    }

    #[test]
    fn strip_port_handles_bare_hostname() {
        assert_eq!(strip_port("example.com"), "example.com");
        assert_eq!(strip_port("localhost"), "localhost");
    }

    #[test]
    fn strip_port_handles_ipv6_bracketed() {
        assert_eq!(strip_port("[::1]:443"), "::1");
        assert_eq!(strip_port("[::1]"), "::1");
        assert_eq!(strip_port("[2001:db8::1]:8080"), "2001:db8::1");
    }

    #[test]
    fn strip_port_handles_empty() {
        assert_eq!(strip_port(""), "");
    }

    #[test]
    fn hop_by_hop_headers_are_stripped() {
        for name in HOP_BY_HOP {
            let header = HeaderName::from_static(name);
            assert!(is_hop_by_hop(&header), "{name} should be hop-by-hop");
        }
    }

    #[test]
    fn end_to_end_headers_not_hop_by_hop() {
        let forwarded = [
            "content-type",
            "content-length",
            "host",
            "authorization",
            "accept",
            "user-agent",
            "x-api-key",
            "x-custom-header",
            "cache-control",
            "date",
        ];
        for name in forwarded {
            let header = HeaderName::from_static(name);
            assert!(!is_hop_by_hop(&header), "{name} should not be hop-by-hop");
        }
    }

    #[test]
    fn filter_headers_strips_hop_by_hop() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("text/html"));
        headers.insert("connection", HeaderValue::from_static("keep-alive"));
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        headers.insert("x-request-id", HeaderValue::from_static("abc123"));

        let filtered = filter_headers(&headers);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered.get("content-type").unwrap(), "text/html");
        assert_eq!(filtered.get("x-request-id").unwrap(), "abc123");
        assert!(filtered.get("connection").is_none());
        assert!(filtered.get("transfer-encoding").is_none());
    }

    #[test]
    fn filter_headers_preserves_all_end_to_end() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("content-length", HeaderValue::from_static("42"));
        headers.insert("authorization", HeaderValue::from_static("Bearer tok"));
        headers.insert("x-repo-commit", HeaderValue::from_static("abc"));
        headers.insert("location", HeaderValue::from_static("https://cdn.example.com"));

        let filtered = filter_headers(&headers);
        assert_eq!(filtered.len(), 4);
    }

    #[test]
    fn filter_headers_preserves_duplicate_values() {
        let mut headers = hyper::HeaderMap::new();
        headers.append("set-cookie", HeaderValue::from_static("a=1"));
        headers.append("set-cookie", HeaderValue::from_static("b=2"));

        let filtered = filter_headers(&headers);
        let cookies: Vec<_> = filtered.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 2);
    }

    #[test]
    fn filter_headers_empty_input() {
        let headers = hyper::HeaderMap::new();
        let filtered = filter_headers(&headers);
        assert!(filtered.is_empty());
    }
}
