//! HTTP gateway server: connection handling, MITM interception, and tunneling.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use http_body_util::Empty;
use hyper::body::{Bytes, Incoming};
use hyper::header::HeaderName;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    upstream_proxy: Arc<Option<UpstreamProxy>>,
    port: u16,
    bind_addr: String,
    rules: Arc<std::sync::RwLock<Vec<ResolvedHost>>>,
    config_path: PathBuf,
    allow_empty_rules: bool,
}

impl GatewayServer {
    pub fn new(
        ca: CertificateAuthority,
        port: u16,
        bind_addr: String,
        rules: Vec<ResolvedHost>,
        config_path: PathBuf,
        allow_empty_rules: bool,
        upstream_proxy: Option<UpstreamProxy>,
    ) -> Self {
        let client_config = build_upstream_tls_config(
            std::env::var("GATEWAY_DANGER_ACCEPT_INVALID_CERTS").is_ok(),
        );
        Self {
            ca: Arc::new(ca),
            upstream_tls: Arc::new(TlsConnector::from(Arc::new(client_config))),
            upstream_proxy: Arc::new(upstream_proxy),
            port,
            bind_addr,
            rules: Arc::new(std::sync::RwLock::new(rules)),
            config_path,
            allow_empty_rules,
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
        let upstream_proxy = Arc::clone(&self.upstream_proxy);
        let rules = Arc::clone(&self.rules);

        tokio::spawn(async move {
            if let Err(e) =
                handle_connection(stream, peer_addr, ca, upstream_tls, upstream_proxy, rules).await
            {
                warn!(peer = %peer_addr, error = %e, "connection error");
            }
        });
    }

    fn handle_sighup(&self) {
        match crate::local::load(&self.config_path) {
            Ok(new_rules) => {
                if new_rules.is_empty() && !self.allow_empty_rules {
                    warn!(
                        config = %self.config_path.display(),
                        "SIGHUP: reloaded config has no host rules; rejecting reload \
                         and keeping old rules (start with --allow-empty-rules to permit)"
                    );
                    return;
                }
                let count = new_rules.len();
                *self.rules.write().unwrap() = new_rules;
                info!(host_count = count, "SIGHUP: reloaded config");
                if count == 0 {
                    info!(
                        config = %self.config_path.display(),
                        "SIGHUP: reloaded config has no rules; running in passthrough mode (--allow-empty-rules)"
                    );
                }
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
    upstream_proxy: Arc<Option<UpstreamProxy>>,
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
                let upstream_proxy = Arc::clone(&upstream_proxy);
                let rules = Arc::clone(&rules);
                async move {
                    if req.method() == Method::CONNECT {
                        handle_connect(req, peer_addr, ca, upstream_tls, upstream_proxy, rules)
                            .await
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
    upstream_proxy: Arc<Option<UpstreamProxy>>,
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

    let via_proxy = upstream_proxy
        .as_ref()
        .as_ref()
        .map(|p| p.applies_to(&hostname))
        .unwrap_or(false);

    info!(
        peer = %peer_addr,
        host = %host,
        mode = if intercept { "mitm" } else { "tunnel" },
        upstream = if via_proxy { "proxy" } else { "direct" },
        rule_count = injection_rules.len(),
        "CONNECT"
    );

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let result = if intercept {
                    mitm(
                        upgraded,
                        &host,
                        &ca,
                        upstream_tls,
                        upstream_proxy.as_ref().as_ref(),
                        injection_rules,
                    )
                    .await
                } else {
                    tunnel(upgraded, &host, upstream_proxy.as_ref().as_ref()).await
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
    upstream_proxy: Option<&UpstreamProxy>,
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
    let tcp = dial_upstream(&connect_addr, upstream_proxy).await?;
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

async fn tunnel(
    upgraded: hyper::upgrade::Upgraded,
    host: &str,
    upstream_proxy: Option<&UpstreamProxy>,
) -> Result<()> {
    let connect_addr = if host.contains(':') {
        host.to_string()
    } else {
        format!("{host}:443")
    };
    let mut server = dial_upstream(&connect_addr, upstream_proxy).await?;

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

// ── Upstream proxy chaining ─────────────────────────────────────────────

/// Upstream proxy configuration parsed from `HTTPS_PROXY` and `NO_PROXY`
/// environment variables. When set, outbound TCP for both `mitm()` and
/// `tunnel()` is routed through the parent proxy via HTTP `CONNECT`.
#[derive(Debug, Clone)]
pub struct UpstreamProxy {
    /// Parent proxy address as `host:port`.
    addr: String,
    /// `NO_PROXY` exception list. Entries may be exact hostnames, `.suffix`
    /// patterns (matching `suffix` and `*.suffix`), or a single `*` meaning
    /// "bypass for everything" (which effectively disables the proxy).
    no_proxy: Vec<String>,
}

impl UpstreamProxy {
    /// Read `HTTPS_PROXY` (or lowercase `https_proxy`) and `NO_PROXY` from the
    /// environment. Returns `None` if no proxy is configured.
    pub fn from_env() -> Result<Option<Self>> {
        let raw = std::env::var("HTTPS_PROXY")
            .or_else(|_| std::env::var("https_proxy"))
            .ok();
        let Some(raw) = raw else {
            return Ok(None);
        };
        let addr = parse_proxy_addr(&raw)
            .with_context(|| format!("parsing HTTPS_PROXY={raw:?}"))?;
        let no_proxy = std::env::var("NO_PROXY")
            .or_else(|_| std::env::var("no_proxy"))
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        Ok(Some(Self { addr, no_proxy }))
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// Returns true if traffic to `hostname` should be sent through the
    /// upstream proxy (i.e. it does not match any `NO_PROXY` entry).
    fn applies_to(&self, hostname: &str) -> bool {
        for entry in &self.no_proxy {
            if entry == "*" {
                return false;
            }
            if let Some(suffix) = entry.strip_prefix('.') {
                if hostname == suffix
                    || (hostname.len() > suffix.len()
                        && hostname.ends_with(suffix)
                        && hostname.as_bytes()[hostname.len() - suffix.len() - 1] == b'.')
                {
                    return false;
                }
            } else if entry == hostname {
                return false;
            }
        }
        true
    }
}

/// Parse `HTTPS_PROXY` value into a `host:port` string suitable for
/// `TcpStream::connect`. Accepts forms like `http://host:port`,
/// `https://host:port`, bare `host:port`, and bracketed IPv6 such as
/// `http://[::1]:8080`. Rejects embedded credentials (`user:pass@host`)
/// since proxy auth isn't supported.
fn parse_proxy_addr(raw: &str) -> Result<String> {
    let s = raw.trim();
    if s.is_empty() {
        bail!("empty proxy URL");
    }
    let s = s
        .strip_prefix("http://")
        .or_else(|| s.strip_prefix("https://"))
        .unwrap_or(s);
    // Strip any trailing path/query.
    let s = s.split('/').next().unwrap_or(s);
    if s.contains('@') {
        bail!("proxy auth (user:pass@host) is not supported");
    }
    // Bracketed IPv6: [::1]:port
    if let Some(rest) = s.strip_prefix('[') {
        let close = rest
            .find(']')
            .context("bracketed IPv6 proxy address missing ']'")?;
        let after = &rest[close + 1..];
        if !after.starts_with(':') || after.len() < 2 {
            bail!("IPv6 proxy URL must include explicit port, e.g. http://[::1]:8080");
        }
        return Ok(s.to_string());
    }
    // IPv4 or hostname: must have host:port (and only one colon).
    if !s.contains(':') {
        bail!("proxy URL must include an explicit port, e.g. http://host:8080");
    }
    if s.matches(':').count() > 1 {
        bail!("ambiguous proxy address {s:?}: bare IPv6 must be bracketed, e.g. [::1]:8080");
    }
    Ok(s.to_string())
}

/// Open a TCP connection to `target` (`host:port`), routing through the
/// upstream proxy if one is configured and the host doesn't match `NO_PROXY`.
async fn dial_upstream(target: &str, proxy: Option<&UpstreamProxy>) -> Result<TcpStream> {
    let hostname = strip_port(target);
    if let Some(p) = proxy {
        if p.applies_to(hostname) {
            return dial_via_proxy(&p.addr, target).await;
        }
    }
    TcpStream::connect(target)
        .await
        .with_context(|| format!("connecting to {target}"))
}

/// Dial the parent proxy and issue an HTTP `CONNECT` for `target`.
/// Returns the TCP stream after a successful `200` response, ready for the
/// caller to start its own TLS handshake or raw byte forwarding on top.
async fn dial_via_proxy(proxy_addr: &str, target: &str) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .with_context(|| format!("connecting to upstream proxy {proxy_addr}"))?;
    let req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .context("writing CONNECT to upstream proxy")?;
    let response = read_proxy_response(&mut stream)
        .await
        .with_context(|| format!("reading CONNECT response from {proxy_addr}"))?;
    let status_line = response.lines().next().unwrap_or("");
    let mut parts = status_line.split_whitespace();
    let _version = parts.next();
    let status = parts.next().unwrap_or("");
    if status != "200" {
        bail!(
            "upstream proxy {proxy_addr} refused CONNECT to {target}: {status_line}"
        );
    }
    Ok(stream)
}

/// Read an HTTP response head from `stream` byte-by-byte until `\r\n\r\n`,
/// without over-reading into the tunneled body. Caps at 8 KiB.
async fn read_proxy_response(stream: &mut TcpStream) -> Result<String> {
    let mut buf = Vec::with_capacity(256);
    loop {
        let mut byte = [0u8; 1];
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            bail!("upstream proxy closed connection during CONNECT");
        }
        buf.push(byte[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if buf.len() > 8192 {
            bail!("CONNECT response head exceeds 8 KiB");
        }
    }
    String::from_utf8(buf).context("CONNECT response is not valid UTF-8")
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

    // ── parse_proxy_addr ────────────────────────────────────────────────

    #[test]
    fn parse_proxy_addr_http_scheme() {
        assert_eq!(parse_proxy_addr("http://127.0.0.1:8081").unwrap(), "127.0.0.1:8081");
    }

    #[test]
    fn parse_proxy_addr_https_scheme() {
        assert_eq!(parse_proxy_addr("https://proxy.corp:3128").unwrap(), "proxy.corp:3128");
    }

    #[test]
    fn parse_proxy_addr_bare_host_port() {
        assert_eq!(parse_proxy_addr("127.0.0.1:8081").unwrap(), "127.0.0.1:8081");
    }

    #[test]
    fn parse_proxy_addr_strips_trailing_path() {
        assert_eq!(parse_proxy_addr("http://proxy:3128/").unwrap(), "proxy:3128");
    }

    #[test]
    fn parse_proxy_addr_rejects_missing_port() {
        let err = parse_proxy_addr("http://proxy.corp").unwrap_err();
        assert!(format!("{err:?}").contains("explicit port"));
    }

    #[test]
    fn parse_proxy_addr_rejects_auth() {
        let err = parse_proxy_addr("http://user:pass@proxy:3128").unwrap_err();
        assert!(format!("{err:?}").contains("auth"));
    }

    #[test]
    fn parse_proxy_addr_rejects_empty() {
        assert!(parse_proxy_addr("").is_err());
        assert!(parse_proxy_addr("   ").is_err());
    }

    // ── UpstreamProxy::applies_to / NO_PROXY ────────────────────────────

    fn proxy_with_no_proxy(entries: &[&str]) -> UpstreamProxy {
        UpstreamProxy {
            addr: "127.0.0.1:8081".to_string(),
            no_proxy: entries.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn no_proxy_empty_means_proxy_everything() {
        let p = proxy_with_no_proxy(&[]);
        assert!(p.applies_to("api.example.com"));
        assert!(p.applies_to("localhost"));
    }

    #[test]
    fn no_proxy_exact_hostname() {
        let p = proxy_with_no_proxy(&["localhost", "127.0.0.1"]);
        assert!(!p.applies_to("localhost"));
        assert!(!p.applies_to("127.0.0.1"));
        assert!(p.applies_to("api.example.com"));
    }

    #[test]
    fn no_proxy_dot_suffix_matches_subdomains() {
        let p = proxy_with_no_proxy(&[".internal.corp"]);
        assert!(!p.applies_to("internal.corp"));
        assert!(!p.applies_to("api.internal.corp"));
        assert!(!p.applies_to("a.b.internal.corp"));
        assert!(p.applies_to("internal.corpx"));
        assert!(p.applies_to("notinternal.corp"));
    }

    #[test]
    fn no_proxy_star_means_bypass_all() {
        let p = proxy_with_no_proxy(&["*"]);
        assert!(!p.applies_to("anything.com"));
        assert!(!p.applies_to("localhost"));
    }

    #[test]
    fn no_proxy_dot_suffix_no_partial_match() {
        let p = proxy_with_no_proxy(&[".example.com"]);
        // hostname must end at a label boundary
        assert!(!p.applies_to("foo.example.com"));
        assert!(p.applies_to("fooexample.com"));
    }

    // ── parse_proxy_addr: IPv6 ──────────────────────────────────────────

    #[test]
    fn parse_proxy_addr_ipv6_with_scheme() {
        assert_eq!(parse_proxy_addr("http://[::1]:8081").unwrap(), "[::1]:8081");
    }

    #[test]
    fn parse_proxy_addr_ipv6_bare() {
        assert_eq!(
            parse_proxy_addr("[2001:db8::1]:3128").unwrap(),
            "[2001:db8::1]:3128"
        );
    }

    #[test]
    fn parse_proxy_addr_ipv6_missing_port_fails() {
        let err = parse_proxy_addr("http://[::1]").unwrap_err();
        assert!(format!("{err:?}").contains("port"));
    }

    #[test]
    fn parse_proxy_addr_ipv6_missing_close_bracket_fails() {
        let err = parse_proxy_addr("http://[::1:8081").unwrap_err();
        assert!(format!("{err:?}").contains("']'"));
    }

    #[test]
    fn parse_proxy_addr_unbracketed_ipv6_rejected() {
        // bare IPv6 (no brackets) is ambiguous with host:port; reject it.
        let err = parse_proxy_addr("::1:8081").unwrap_err();
        assert!(format!("{err:?}").contains("bracketed"));
    }

    // ── End-to-end CONNECT handshake against a mock parent proxy ────────

    /// Spawn a one-shot mock CONNECT proxy on a random localhost port.
    /// Captures the CONNECT request head into `req_tx`, replies with the
    /// given status line, then echoes any subsequent bytes back. Returns
    /// the bound address so the test can dial it.
    async fn spawn_mock_proxy(
        status_line: &'static str,
        req_tx: tokio::sync::oneshot::Sender<String>,
    ) -> std::net::SocketAddr {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            // Read CONNECT head byte-by-byte until \r\n\r\n.
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                let n = socket.read(&mut byte).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.push(byte[0]);
                if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
                    break;
                }
            }
            let _ = req_tx.send(String::from_utf8(buf).unwrap());
            let resp = format!("{status_line}\r\n\r\n");
            socket.write_all(resp.as_bytes()).await.unwrap();
            // Echo any further bytes back until the client closes.
            let mut echo = [0u8; 1024];
            while let Ok(n) = socket.read(&mut echo).await {
                if n == 0 {
                    break;
                }
                if socket.write_all(&echo[..n]).await.is_err() {
                    break;
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn dial_via_proxy_e2e_handshake_and_echo() {
        let (req_tx, req_rx) = tokio::sync::oneshot::channel();
        let proxy_addr = spawn_mock_proxy("HTTP/1.1 200 Connection Established", req_tx).await;

        let mut stream = dial_via_proxy(&proxy_addr.to_string(), "api.example.com:443")
            .await
            .expect("dial_via_proxy succeeded");

        // The mock proxy received exactly the CONNECT we expected.
        let req = req_rx.await.unwrap();
        let first_line = req.lines().next().unwrap();
        assert_eq!(first_line, "CONNECT api.example.com:443 HTTP/1.1");
        assert!(
            req.contains("Host: api.example.com:443"),
            "missing Host header in CONNECT: {req:?}"
        );

        // The returned socket is live: bytes flow end-to-end through the tunnel.
        stream.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
    }

    #[tokio::test]
    async fn dial_via_proxy_e2e_propagates_non_200() {
        let (req_tx, _req_rx) = tokio::sync::oneshot::channel();
        let proxy_addr = spawn_mock_proxy("HTTP/1.1 502 Bad Gateway", req_tx).await;

        let err = dial_via_proxy(&proxy_addr.to_string(), "api.example.com:443")
            .await
            .expect_err("dial_via_proxy should fail on non-200");
        let msg = format!("{err:?}");
        assert!(msg.contains("502"), "expected 502 in error: {msg}");
        assert!(msg.contains("api.example.com:443"));
    }

    #[tokio::test]
    async fn dial_upstream_routes_through_proxy_when_configured() {
        let (req_tx, req_rx) = tokio::sync::oneshot::channel();
        let proxy_addr = spawn_mock_proxy("HTTP/1.1 200 OK", req_tx).await;

        let proxy = UpstreamProxy {
            addr: proxy_addr.to_string(),
            no_proxy: vec![],
        };
        let _stream = dial_upstream("origin.example.com:443", Some(&proxy))
            .await
            .expect("dial_upstream via proxy succeeded");

        let req = req_rx.await.unwrap();
        assert!(
            req.starts_with("CONNECT origin.example.com:443 HTTP/1.1\r\n"),
            "got: {req:?}"
        );
    }

    #[tokio::test]
    async fn dial_upstream_bypasses_proxy_when_no_proxy_matches() {
        // Bind a real "origin" listener on localhost so a direct dial succeeds,
        // and a separate mock proxy that we expect NOT to be touched.
        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = origin.accept().await;
        });

        let (req_tx, mut req_rx) = tokio::sync::oneshot::channel();
        let proxy_addr = spawn_mock_proxy("HTTP/1.1 200 OK", req_tx).await;

        let proxy = UpstreamProxy {
            addr: proxy_addr.to_string(),
            no_proxy: vec!["127.0.0.1".to_string()],
        };
        let _stream = dial_upstream(&origin_addr.to_string(), Some(&proxy))
            .await
            .expect("direct dial to origin succeeded");

        // The proxy should never have received a CONNECT.
        // Give it a brief moment, then assert the channel is still empty.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            req_rx.try_recv().is_err(),
            "proxy unexpectedly received a CONNECT"
        );
    }
}
