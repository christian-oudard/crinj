//! Load host config from a TOML file.
//!
//! Parses the file at startup, resolves `source` references into in-memory
//! strings, validates access-control natural order, and produces `ResolvedHost`
//! values used by the runtime.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use tracing::warn;

use crate::glob;
use crate::inject::{self, AccessEntry, Injection, InjectionRule};

/// Marker error attached to failures that come from a host's secret being
/// unreadable (missing file, wrong permissions, etc.) as opposed to a schema
/// mistake in rules.toml. Present in the error chain when this distinction
/// matters at the load level.
#[derive(Debug)]
struct SecretUnavailable;

impl std::fmt::Display for SecretUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("secret unavailable")
    }
}

impl std::error::Error for SecretUnavailable {}

fn is_secret_unavailable(err: &anyhow::Error) -> bool {
    err.chain().any(|c| c.is::<SecretUnavailable>())
}

// ── TOML schema ─────────────────────────────────────────────────────────

/// Top-level config file.
#[derive(Deserialize)]
struct Config {
    #[serde(default)]
    host: Vec<HostEntry>,
}

/// A single `[[host]]` entry.
///
/// Canonical field order:
/// 1. `domain` — match pattern
/// 2. `no-check-certificate` — TLS (bool, default false)
/// 3. `access` — multiline access-control list (optional)
/// 4. `source` — host-level default source, inherited by inject entries (optional)
/// 5. `inject` — list of `[[host.inject]]`
#[derive(Deserialize)]
struct HostEntry {
    domain: String,
    #[serde(default, rename = "no-check-certificate")]
    no_check_certificate: bool,
    #[serde(default)]
    access: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    inject: Vec<InjectEntry>,
}

fn default_path() -> String {
    "*".to_string()
}

/// A single `[[host.inject]]` entry.
///
/// Canonical field order:
/// 1. `url-path` — path match (default `*`)
/// 2. `ports` — port filter (default all)
/// 3. `source` — credential source file
/// 4. `source-path` — structured lookup inside source
/// 5. `value` — inline literal (alternative to source)
/// 6. `header` / `query-param` / `remove-header` — action (exactly one)
/// 7. `format` — format string (`{}` substitution)
#[derive(Deserialize, Default)]
struct InjectEntry {
    #[serde(default = "default_path", rename = "url-path")]
    url_path: String,
    #[serde(default)]
    ports: Vec<u16>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default, rename = "source-path")]
    source_path: Option<String>,
    #[serde(default, rename = "source-sqlite")]
    source_sqlite: Option<String>,
    #[serde(default, rename = "source-sqlite-query")]
    source_sqlite_query: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    header: Option<String>,
    #[serde(default, rename = "query-param")]
    query_param: Option<String>,
    #[serde(default, rename = "remove-header")]
    remove_header: Option<String>,
    #[serde(default)]
    format: Option<String>,
}

// ── Resolved types ──────────────────────────────────────────────────────

/// A fully resolved host entry ready for runtime matching.
#[derive(Debug)]
pub(crate) struct ResolvedHost {
    pub host_pattern: String,
    pub no_check_certificate: bool,
    pub access: Vec<AccessEntry>,
    pub injection_rules: Vec<InjectionRule>,
}

// ── Loading ─────────────────────────────────────────────────────────────

/// Parse the config TOML file and resolve all source file references.
pub(crate) fn load(path: &Path) -> Result<Vec<ResolvedHost>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading config file {}", path.display()))?;
    let config: Config =
        toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;

    let mut resolved = Vec::with_capacity(config.host.len());
    let mut fatal: Vec<anyhow::Error> = Vec::new();
    for entry in config.host {
        match resolve_host(&entry, path) {
            Ok(host) => resolved.push(host),
            Err(e) if is_secret_unavailable(&e) => warn!(
                domain = %entry.domain,
                error = format!("{e:#}"),
                "skipping host: secret not available"
            ),
            Err(e) => fatal.push(e),
        }
    }
    if !fatal.is_empty() {
        let combined = fatal
            .iter()
            .map(|e| format!("  - {e:#}"))
            .collect::<Vec<_>>()
            .join("\n");
        bail!(
            "{} host config error(s) in {}:\n{}",
            fatal.len(),
            path.display(),
            combined
        );
    }
    validate_host_specificity(&resolved)?;
    Ok(resolved)
}

/// Build a fully resolved host. Any failure here causes the host to be skipped
/// at the call site with a warning.
fn resolve_host(entry: &HostEntry, path: &Path) -> Result<ResolvedHost> {
    let access = match &entry.access {
        Some(s) => inject::parse_access(s)
            .with_context(|| format!("host {:?} in {}", entry.domain, path.display()))?,
        None => Vec::new(),
    };
    let injection_rules = resolve_host_injects(entry, path)?;
    Ok(ResolvedHost {
        host_pattern: entry.domain.clone(),
        no_check_certificate: entry.no_check_certificate,
        access,
        injection_rules,
    })
}

/// Error out if two host entries have equal specificity (duplicate domains).
fn validate_host_specificity(hosts: &[ResolvedHost]) -> Result<()> {
    for i in 0..hosts.len() {
        for j in (i + 1)..hosts.len() {
            if hosts[i].host_pattern == hosts[j].host_pattern {
                bail!(
                    "duplicate host domain {:?} (entries {} and {})",
                    hosts[i].host_pattern,
                    i + 1,
                    j + 1
                );
            }
        }
    }
    Ok(())
}

/// Build injection rules from a host entry's `[[host.inject]]` list.
fn resolve_host_injects(entry: &HostEntry, config_path: &Path) -> Result<Vec<InjectionRule>> {
    let fallback_source = entry.source.as_deref();
    let domain = &entry.domain;

    entry
        .inject
        .iter()
        .map(|ie| {
            let injection = resolve_injection(ie, fallback_source, domain, config_path)?;
            Ok(InjectionRule {
                path_pattern: ie.url_path.clone(),
                ports: ie.ports.clone(),
                injections: vec![injection],
            })
        })
        .collect()
}

/// Resolve a single inject entry into an `Injection` value.
/// `fallback_source` is the host-level `source`, used when the entry doesn't have one.
fn resolve_injection(
    entry: &InjectEntry,
    fallback_source: Option<&str>,
    domain: &str,
    config_path: &Path,
) -> Result<Injection> {
    if let Some(ref name) = entry.remove_header {
        return Ok(Injection::RemoveHeader {
            name: name.clone(),
        });
    }

    // SQLite source: deferred resolution at request time.
    if entry.source_sqlite.is_some() || entry.source_sqlite_query.is_some() {
        return resolve_sqlite_injection(entry, domain, config_path);
    }

    if let Some(ref name) = entry.header {
        let raw = resolve_value(entry, fallback_source, domain, config_path)?;
        let value = format_value(&raw, &entry.format);
        return Ok(Injection::SetHeader {
            name: name.clone(),
            value,
        });
    }
    if let Some(ref name) = entry.query_param {
        let raw = resolve_value(entry, fallback_source, domain, config_path)?;
        let value = format_value(&raw, &entry.format);
        return Ok(Injection::SetQueryParam {
            name: name.clone(),
            value,
        });
    }
    bail!(
        "inject entry for domain {:?} in {} must have `header`, `query-param`, or `remove-header`",
        domain,
        config_path.display()
    );
}

/// Resolve a SQLite-backed inject entry. The actual query runs at request time,
/// but we validate the config and resolve the path here.
fn resolve_sqlite_injection(
    entry: &InjectEntry,
    domain: &str,
    config_path: &Path,
) -> Result<Injection> {
    let sqlite_path = entry.source_sqlite.as_ref().with_context(|| {
        format!(
            "inject entry for domain {:?} in {}: \
             `source-sqlite-query` requires `source-sqlite`",
            domain,
            config_path.display()
        )
    })?;
    let query = entry.source_sqlite_query.as_ref().with_context(|| {
        format!(
            "inject entry for domain {:?} in {}: \
             `source-sqlite` requires `source-sqlite-query`",
            domain,
            config_path.display()
        )
    })?;
    if entry.source.is_some() || entry.value.is_some() || entry.source_path.is_some() {
        bail!(
            "inject entry for domain {:?} in {}: \
             `source-sqlite` cannot be combined with `source`, `source-path`, or `value`",
            domain,
            config_path.display()
        );
    }
    let db_path = resolve_source_path(sqlite_path, config_path);
    // Validate permissions if the file is present and populated; missing/empty
    // SQLite files are handled at request time (the query simply fails to
    // find rows). Bad permissions on a populated db is an emergency.
    validate_secret_file(&db_path)?;
    if let Some(ref name) = entry.header {
        return Ok(Injection::SetHeaderSqlite {
            name: name.clone(),
            db_path,
            query: query.clone(),
            format: entry.format.clone(),
        });
    }
    if let Some(ref name) = entry.query_param {
        return Ok(Injection::SetQueryParamSqlite {
            name: name.clone(),
            db_path,
            query: query.clone(),
            format: entry.format.clone(),
        });
    }
    bail!(
        "inject entry for domain {:?} in {}: \
         `source-sqlite` inject entry must have `header` or `query-param`",
        domain,
        config_path.display()
    );
}

/// Apply format string to the resolved raw value. `{}` is replaced with the value.
fn format_value(raw: &str, format: &Option<String>) -> String {
    match format {
        Some(fmt) => fmt.replace("{}", raw),
        None => raw.to_string(),
    }
}

/// Resolve the value for an inject entry: inline `value` or `source` file.
/// Falls back to the host-level `source` if the entry doesn't specify one.
fn resolve_value(
    entry: &InjectEntry,
    fallback_source: Option<&str>,
    domain: &str,
    config_path: &Path,
) -> Result<String> {
    if let Some(ref v) = entry.value {
        return Ok(v.clone());
    }

    let source = entry.source.as_deref().or(fallback_source);
    if let Some(source) = source {
        let expanded = resolve_source_path(source, config_path);
        match validate_secret_file(&expanded)? {
            SecretState::Missing => {
                return Err(anyhow!(SecretUnavailable)).with_context(|| {
                    format!(
                        "secret file {} does not exist (for domain {:?})",
                        expanded.display(),
                        domain
                    )
                });
            }
            SecretState::Empty => {
                return Err(anyhow!(SecretUnavailable)).with_context(|| {
                    format!(
                        "secret file {} is empty (for domain {:?})",
                        expanded.display(),
                        domain
                    )
                });
            }
            SecretState::Populated => {}
        }
        let content = std::fs::read_to_string(&expanded).with_context(|| {
            format!(
                "reading source {} (for domain {:?}) referenced from {}",
                expanded.display(),
                domain,
                config_path.display()
            )
        })?;

        if let Some(ref sp) = entry.source_path {
            return extract_path(&content, sp, &expanded).with_context(|| {
                format!(
                    "extracting source-path {:?} from {} (for domain {:?})",
                    sp,
                    expanded.display(),
                    domain
                )
            });
        }

        return Ok(content.trim().to_string());
    }
    bail!(
        "inject entry for domain {:?} in {} has neither `value` nor `source`",
        domain,
        config_path.display()
    );
}

enum SecretState {
    /// File does not exist. Treat as "key not provided yet" (warn, skip host).
    Missing,
    /// File exists but is zero bytes. Same treatment as Missing.
    Empty,
    /// File exists with non-zero contents and acceptable permissions.
    Populated,
}

/// Inspect a secret file. Empty/missing files yield non-fatal states. A
/// populated file with group/world-readable permissions is an emergency:
/// the secret has already been exposed. We refuse to load and exit so the
/// user fixes it before the proxy runs another second.
fn validate_secret_file(path: &Path) -> Result<SecretState> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(SecretState::Missing),
        Err(e) => {
            return Err(anyhow::Error::from(e))
                .with_context(|| format!("stat'ing secret file {}", path.display()));
        }
    };

    let empty = meta.len() == 0;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = meta.mode() & 0o777;
        if mode & 0o077 != 0 && !empty {
            bail!(
                "secret file {} has mode {:o} — must not be group/world-accessible (chmod 600)",
                path.display(),
                mode,
            );
        }
    }

    if empty {
        Ok(SecretState::Empty)
    } else {
        Ok(SecretState::Populated)
    }
}

/// Auto-detect format from file extension and extract a dot-separated path.
fn extract_path(content: &str, path: &str, file: &Path) -> Result<String> {
    match file.extension().and_then(|e| e.to_str()) {
        Some("json") => extract_json_path(content, path),
        Some("toml") => extract_toml_path(content, path),
        Some(ext) => bail!(
            "unsupported source file extension {:?}, expected .json or .toml",
            ext
        ),
        None => bail!("source file has no extension, cannot determine format for source-path"),
    }
}

/// Walk a dot-separated path through a JSON value, returning the leaf as a string.
/// Segments that parse as integers index into arrays.
fn extract_json_path(content: &str, path: &str) -> Result<String> {
    let root: serde_json::Value =
        serde_json::from_str(content).context("source file is not valid JSON")?;
    let mut current = &root;
    for segment in path.split('.') {
        current = if let Ok(idx) = segment.parse::<usize>() {
            current.get(idx)
        } else {
            current.get(segment)
        }
        .with_context(|| format!("{:?} not found (full path: {:?})", segment, path))?;
    }
    match current {
        serde_json::Value::String(s) => Ok(s.clone()),
        other => Ok(other.to_string()),
    }
}

/// Walk a dot-separated path through a TOML value, returning the leaf as a string.
/// Segments that parse as integers index into arrays.
fn extract_toml_path(content: &str, path: &str) -> Result<String> {
    let root: toml::Value = content.parse().context("source file is not valid TOML")?;
    let mut current = &root;
    for segment in path.split('.') {
        current = if let Ok(idx) = segment.parse::<usize>() {
            current.get(idx)
        } else {
            current.get(segment)
        }
        .with_context(|| format!("{:?} not found (full path: {:?})", segment, path))?;
    }
    match current {
        toml::Value::String(s) => Ok(s.clone()),
        other => Ok(other.to_string()),
    }
}

// ── Runtime resolution ──────────────────────────────────────────────────

/// Result of resolving a host against the config.
pub(crate) struct ResolveResult {
    pub intercept: bool,
    pub no_check_certificate: bool,
    pub access: Vec<AccessEntry>,
    pub injection_rules: Vec<InjectionRule>,
}

/// Find the most-specific host entry matching the CONNECT authority, and
/// return its access list plus port-filtered injection rules.
///
/// `host` is the raw CONNECT authority, e.g. `example.com:443`.
pub(crate) fn resolve(host: &str, hosts: &[ResolvedHost]) -> ResolveResult {
    let (hostname, port) = split_host_port(host);

    // Find all matching hosts and pick the most specific.
    let best = hosts
        .iter()
        .filter(|h| glob::matches(hostname, &h.host_pattern))
        .max_by_key(|h| glob::specificity(&h.host_pattern));

    match best {
        Some(h) => {
            let injection_rules: Vec<InjectionRule> = h
                .injection_rules
                .iter()
                .filter(|r| r.port_matches(port))
                .cloned()
                .collect();
            ResolveResult {
                intercept: true,
                no_check_certificate: h.no_check_certificate,
                access: h.access.clone(),
                injection_rules,
            }
        }
        None => ResolveResult {
            intercept: false,
            no_check_certificate: false,
            access: Vec::new(),
            injection_rules: Vec::new(),
        },
    }
}

/// Split a `host:port` string into (hostname, optional port number).
fn split_host_port(s: &str) -> (&str, Option<u16>) {
    // Bracketed IPv6: [::1]:443
    if s.starts_with('[') {
        if let Some(bracket_end) = s.find(']') {
            if let Some(port_str) = s[bracket_end + 1..].strip_prefix(':') {
                if let Ok(port) = port_str.parse() {
                    return (&s[1..bracket_end], Some(port));
                }
            }
            return (&s[1..bracket_end], None);
        }
        return (s, None);
    }
    if let Some(colon_pos) = s.rfind(':') {
        let port_str = &s[colon_pos + 1..];
        if let Ok(port) = port_str.parse() {
            return (&s[..colon_pos], Some(port));
        }
    }
    (s, None)
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn expand_tilde(path: &str) -> PathBuf {
    if path.starts_with("~/") || path == "~" {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(path.strip_prefix("~/").unwrap_or(""));
        }
    }
    PathBuf::from(path)
}

/// Resolve a source path from the config file.
/// Absolute (`/...`) and home-relative (`~/...`) paths are used as-is.
/// Bare names are resolved relative to a `secrets/` directory next to the config file.
fn resolve_source_path(source: &str, config_path: &Path) -> PathBuf {
    if source.starts_with('/') || source.starts_with("~/") {
        return expand_tilde(source);
    }
    let secrets_dir = config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("secrets");
    secrets_dir.join(source)
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inject::AccessVerb;

    /// Write a secret file with 0o600 permissions.
    fn write_secret(path: &Path, content: &str) {
        std::fs::write(path, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn host(pattern: &str) -> ResolvedHost {
        ResolvedHost {
            host_pattern: pattern.to_string(),
            no_check_certificate: false,
            access: vec![],
            injection_rules: vec![InjectionRule {
                path_pattern: "*".to_string(),
                ports: vec![],
                injections: vec![Injection::SetHeader {
                    name: "x-api-key".to_string(),
                    value: "sk-123".to_string(),
                }],
            }],
        }
    }

    // ── resolve: domain matching ────────────────────────────────────────

    #[test]
    fn resolve_exact_domain() {
        let hosts = vec![host("api.example.com")];
        assert!(resolve("api.example.com:443", &hosts).intercept);
        assert!(!resolve("other.com:443", &hosts).intercept);
    }

    #[test]
    fn resolve_wildcard_domain() {
        let hosts = vec![host("*.example.com")];
        assert!(resolve("api.example.com:443", &hosts).intercept);
        assert!(resolve("a.b.example.com:443", &hosts).intercept);
        assert!(!resolve("example.com:443", &hosts).intercept);
    }

    #[test]
    fn resolve_middle_wildcard_domain() {
        let hosts = vec![host("http-intake.logs*.datadoghq.com")];
        assert!(resolve("http-intake.logs.datadoghq.com:443", &hosts).intercept);
        assert!(resolve("http-intake.logs.us5.datadoghq.com:443", &hosts).intercept);
        assert!(!resolve("api.datadoghq.com:443", &hosts).intercept);
    }

    #[test]
    fn resolve_most_specific_wins() {
        // Specific entry has different rule than wildcard; verify specific matches first.
        let mut specific = host("api.datadoghq.com");
        specific.injection_rules[0].injections[0] = Injection::SetHeader {
            name: "x-api-key".to_string(),
            value: "specific".to_string(),
        };
        let mut wildcard = host("*.datadoghq.com");
        wildcard.access = inject::parse_access("block *").unwrap();
        wildcard.injection_rules.clear();

        let hosts = vec![wildcard, specific];
        let r = resolve("api.datadoghq.com:443", &hosts);
        assert!(r.intercept);
        assert!(r.access.is_empty(), "specific host has no access block");
        assert_eq!(r.injection_rules.len(), 1);
    }

    #[test]
    fn resolve_wildcard_wins_when_specific_doesnt_match() {
        let mut specific = host("api.datadoghq.com");
        specific.injection_rules[0].injections[0] = Injection::SetHeader {
            name: "x-api-key".to_string(),
            value: "specific".to_string(),
        };
        let mut wildcard = host("*.datadoghq.com");
        wildcard.access = inject::parse_access("block *").unwrap();
        wildcard.injection_rules.clear();

        let hosts = vec![wildcard, specific];
        let r = resolve("http-intake.logs.datadoghq.com:443", &hosts);
        assert!(r.intercept);
        assert_eq!(r.access.len(), 1);
        assert_eq!(r.access[0].verb, AccessVerb::Block);
    }

    // ── resolve: port filtering (per rule) ─────────────────────────────

    #[test]
    fn resolve_rule_port_filter() {
        let mut h = host("35.194.69.156");
        h.injection_rules[0].ports = vec![8443];
        let hosts = vec![h];
        assert_eq!(resolve("35.194.69.156:8443", &hosts).injection_rules.len(), 1);
        assert_eq!(resolve("35.194.69.156:443", &hosts).injection_rules.len(), 0);
    }

    #[test]
    fn resolve_rule_no_port_matches_any() {
        let h = host("api.example.com"); // default: ports = []
        let hosts = vec![h];
        assert_eq!(resolve("api.example.com:443", &hosts).injection_rules.len(), 1);
        assert_eq!(resolve("api.example.com:8443", &hosts).injection_rules.len(), 1);
    }

    // ── resolve: access propagation ────────────────────────────────────

    #[test]
    fn resolve_propagates_access() {
        let mut h = host("api.example.com");
        h.access = inject::parse_access("block *\nallow /v1/*").unwrap();
        let hosts = vec![h];
        let r = resolve("api.example.com:443", &hosts);
        assert_eq!(r.access.len(), 2);
    }

    #[test]
    fn resolve_propagates_no_check_certificate() {
        let mut h = host("10.0.0.1");
        h.no_check_certificate = true;
        let hosts = vec![h];
        assert!(resolve("10.0.0.1:8443", &hosts).no_check_certificate);
    }

    // ── load: basic ────────────────────────────────────────────────────

    #[test]
    fn load_empty_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rules.toml");
        std::fs::write(&config_path, "").unwrap();

        let hosts = load(&config_path).unwrap();
        assert!(hosts.is_empty());
    }

    #[test]
    fn load_single_rule_header() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            r#"
[[host]]
domain = "api.anthropic.com"
[[host.inject]]
header = "x-api-key"
value = "sk-inline-123"
"#,
        )
        .unwrap();

        let hosts = load(&config_path).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].host_pattern, "api.anthropic.com");
        match &hosts[0].injection_rules[0].injections[0] {
            Injection::SetHeader { name, value } => {
                assert_eq!(name, "x-api-key");
                assert_eq!(value, "sk-inline-123");
            }
            other => panic!("expected SetHeader, got {:?}", other),
        }
    }

    #[test]
    fn load_source_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let secret_path = dir.path().join("secret.key");
        write_secret(&secret_path, "sk-from-file-456\n");

        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"
[[host]]
domain = "api.anthropic.com"
[[host.inject]]
source = "{}"
header = "x-api-key"
"#,
                secret_path.display()
            ),
        )
        .unwrap();

        let hosts = load(&config_path).unwrap();
        match &hosts[0].injection_rules[0].injections[0] {
            Injection::SetHeader { value, .. } => assert_eq!(value, "sk-from-file-456"),
            other => panic!("expected SetHeader, got {:?}", other),
        }
    }

    #[test]
    fn load_with_format() {
        let dir = tempfile::tempdir().unwrap();
        let secret_path = dir.path().join("token.key");
        write_secret(&secret_path, "hf_abc123\n");

        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"
[[host]]
domain = "huggingface.co"
[[host.inject]]
source = "{}"
header = "authorization"
format = "Bearer {{}}"
"#,
                secret_path.display()
            ),
        )
        .unwrap();

        let hosts = load(&config_path).unwrap();
        match &hosts[0].injection_rules[0].injections[0] {
            Injection::SetHeader { value, .. } => assert_eq!(value, "Bearer hf_abc123"),
            other => panic!("expected SetHeader, got {:?}", other),
        }
    }

    #[test]
    fn load_query_param() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("fred.key");
        write_secret(&secret, "MY_API_KEY\n");

        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"
[[host]]
domain = "api.stlouisfed.org"
[[host.inject]]
source = "{}"
query-param = "api_key"
"#,
                secret.display()
            ),
        )
        .unwrap();

        let hosts = load(&config_path).unwrap();
        match &hosts[0].injection_rules[0].injections[0] {
            Injection::SetQueryParam { name, value } => {
                assert_eq!(name, "api_key");
                assert_eq!(value, "MY_API_KEY");
            }
            other => panic!("expected SetQueryParam, got {:?}", other),
        }
    }

    #[test]
    fn load_remove_header() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            r#"
[[host]]
domain = "example.com"
[[host.inject]]
remove-header = "authorization"
"#,
        )
        .unwrap();

        let hosts = load(&config_path).unwrap();
        match &hosts[0].injection_rules[0].injections[0] {
            Injection::RemoveHeader { name } => assert_eq!(name, "authorization"),
            other => panic!("expected RemoveHeader, got {:?}", other),
        }
    }

    // ── load: host-level source inheritance ────────────────────────────

    #[test]
    fn load_rules_inherit_host_source() {
        let dir = tempfile::tempdir().unwrap();
        let toml_file = dir.path().join("creds.toml");
        write_secret(
            &toml_file,
            r#"
[account]
id = "ak-test123"
secret = "as-test456"
"#,
        );

        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"
[[host]]
domain = "api.example.com"
source = "{0}"
[[host.inject]]
source-path = "account.id"
header = "x-id"
[[host.inject]]
source-path = "account.secret"
header = "x-secret"
"#,
                toml_file.display()
            ),
        )
        .unwrap();

        let hosts = load(&config_path).unwrap();
        let rules = &hosts[0].injection_rules;
        assert_eq!(rules.len(), 2);
        match &rules[0].injections[0] {
            Injection::SetHeader { name, value } => {
                assert_eq!(name, "x-id");
                assert_eq!(value, "ak-test123");
            }
            other => panic!("expected SetHeader, got {:?}", other),
        }
    }

    // ── load: structured source-path ───────────────────────────────────

    #[test]
    fn load_source_path_from_json() {
        let dir = tempfile::tempdir().unwrap();
        let json_file = dir.path().join("creds.json");
        write_secret(&json_file, r#"{"token": {"access_token": "abc123"}}"#);

        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"
[[host]]
domain = "example.com"
[[host.inject]]
source = "{}"
source-path = "token.access_token"
header = "Authorization"
format = "Bearer {{}}"
"#,
                json_file.display()
            ),
        )
        .unwrap();

        let hosts = load(&config_path).unwrap();
        match &hosts[0].injection_rules[0].injections[0] {
            Injection::SetHeader { value, .. } => assert_eq!(value, "Bearer abc123"),
            other => panic!("expected SetHeader, got {:?}", other),
        }
    }

    #[test]
    fn load_source_path_array_index() {
        let dir = tempfile::tempdir().unwrap();
        let json_file = dir.path().join("creds.json");
        write_secret(&json_file, r#"{"tokens": ["first", "second"]}"#);

        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"
[[host]]
domain = "example.com"
[[host.inject]]
source = "{}"
source-path = "tokens.0"
header = "Authorization"
"#,
                json_file.display()
            ),
        )
        .unwrap();

        let hosts = load(&config_path).unwrap();
        match &hosts[0].injection_rules[0].injections[0] {
            Injection::SetHeader { value, .. } => assert_eq!(value, "first"),
            other => panic!("expected SetHeader, got {:?}", other),
        }
    }

    #[test]
    fn load_source_path_unknown_extension_fails() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("creds.yaml");
        write_secret(&file, "key: value");

        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"
[[host]]
domain = "example.com"
[[host.inject]]
source = "{}"
source-path = "key"
header = "x-token"
"#,
                file.display()
            ),
        )
        .unwrap();

        let err = load(&config_path).unwrap_err();
        assert!(format!("{err:?}").contains("unsupported"));
    }

    // ── load: per-rule ports ────────────────────────────────────────────

    #[test]
    fn load_rule_ports() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            r#"
[[host]]
domain = "35.194.69.156"
[[host.inject]]
ports = [8443]
header = "authorization"
value = "Bearer tok"
"#,
        )
        .unwrap();

        let hosts = load(&config_path).unwrap();
        assert_eq!(hosts[0].injection_rules[0].ports, vec![8443]);
    }

    // ── load: no-check-certificate ────────────────────────────────────

    #[test]
    fn load_no_check_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            r#"
[[host]]
domain = "10.0.0.1"
no-check-certificate = true
[[host.inject]]
header = "authorization"
value = "Bearer tok"
"#,
        )
        .unwrap();

        let hosts = load(&config_path).unwrap();
        assert!(hosts[0].no_check_certificate);
    }

    // ── load: access ──────────────────────────────────────────────────

    #[test]
    fn load_access_multiline() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            r#"
[[host]]
domain = "api.anthropic.com"
access = """
block *
allow /v1/*
"""
[[host.inject]]
header = "x-api-key"
value = "sk-ant"
"#,
        )
        .unwrap();

        let hosts = load(&config_path).unwrap();
        assert_eq!(hosts[0].access.len(), 2);
        assert_eq!(hosts[0].access[0].verb, AccessVerb::Block);
        assert_eq!(hosts[0].access[1].verb, AccessVerb::Allow);
    }

    #[test]
    fn load_access_single_line() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            r#"
[[host]]
domain = "telemetry.example.com"
access = "block *"
"#,
        )
        .unwrap();

        let hosts = load(&config_path).unwrap();
        assert_eq!(hosts[0].access.len(), 1);
        assert_eq!(hosts[0].access[0].verb, AccessVerb::Block);
        assert!(hosts[0].injection_rules.is_empty());
    }

    #[test]
    fn load_access_unnatural_order_errors() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            r#"
[[host]]
domain = "api.example.com"
access = """
allow /v1/*
block *
"""
[[host.inject]]
header = "x-api-key"
value = "sk"
"#,
        )
        .unwrap();

        let err = load(&config_path).unwrap_err();
        assert!(format!("{err:?}").contains("broader than earlier"));
    }

    // ── load: duplicate domains ───────────────────────────────────────

    #[test]
    fn load_duplicate_domain_errors() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            r#"
[[host]]
domain = "api.example.com"
[[host.inject]]
header = "x-api-key"
value = "first"

[[host]]
domain = "api.example.com"
[[host.inject]]
header = "x-api-key"
value = "second"
"#,
        )
        .unwrap();

        let err = load(&config_path).unwrap_err();
        assert!(format!("{err:?}").contains("duplicate host"));
    }

    // ── load: misc ────────────────────────────────────────────────────

    #[test]
    fn load_multiple_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            r#"
[[host]]
domain = "api.anthropic.com"
[[host.inject]]
header = "x-api-key"
value = "sk-ant"

[[host]]
domain = "huggingface.co"
[[host.inject]]
header = "authorization"
value = "Bearer hf-tok"
"#,
        )
        .unwrap();

        let hosts = load(&config_path).unwrap();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].host_pattern, "api.anthropic.com");
        assert_eq!(hosts[1].host_pattern, "huggingface.co");
    }

    #[test]
    fn load_rule_without_action_fails() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            r#"
[[host]]
domain = "example.com"
[[host.inject]]
value = "whatever"
"#,
        )
        .unwrap();

        let err = load(&config_path).unwrap_err();
        assert!(format!("{err:?}").contains("header"));
    }

    #[test]
    fn load_collects_multiple_schema_errors() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            r#"
[[host]]
domain = "a.example.com"
[[host.inject]]
value = "x"

[[host]]
domain = "b.example.com"
[[host.inject]]
value = "y"
"#,
        )
        .unwrap();

        let err = load(&config_path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("a.example.com"), "missing a.example.com: {msg}");
        assert!(msg.contains("b.example.com"), "missing b.example.com: {msg}");
    }

    #[test]
    fn load_missing_secret_file_skips_host() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"
[[host]]
domain = "broken.example.com"
[[host.inject]]
header = "x-api-key"
source = "{}/does-not-exist"

[[host]]
domain = "ok.example.com"
[[host.inject]]
header = "x-api-key"
value = "sk-good"
"#,
                dir.path().display()
            ),
        )
        .unwrap();

        let hosts = load(&config_path).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].host_pattern, "ok.example.com");
    }

    #[cfg(unix)]
    #[test]
    fn load_empty_secret_with_bad_perms_skips_host() {
        // touch'd file with default 644: nothing to leak yet, treat as
        // "key not provided" and warn-and-skip.
        let dir = tempfile::tempdir().unwrap();
        let secret_path = dir.path().join("secret.key");
        std::fs::write(&secret_path, "").unwrap();

        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"
[[host]]
domain = "example.com"
[[host.inject]]
source = "{}"
header = "x-api-key"
"#,
                secret_path.display()
            ),
        )
        .unwrap();

        let hosts = load(&config_path).unwrap();
        assert!(hosts.is_empty());
    }

    // ── load: permissions ──────────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn load_populated_world_readable_secret_fails() {
        // A populated key with 644 perms is an emergency: the secret has
        // already leaked. Refuse to start.
        let dir = tempfile::tempdir().unwrap();
        let secret_path = dir.path().join("secret.key");
        std::fs::write(&secret_path, "sk-test\n").unwrap();

        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"
[[host]]
domain = "example.com"
[[host.inject]]
source = "{}"
header = "x-api-key"
"#,
                secret_path.display()
            ),
        )
        .unwrap();

        let err = load(&config_path).unwrap_err();
        assert!(format!("{err:?}").contains("must not be group/world-accessible"));
    }

    // ── load: relative source paths ───────────────────────────────────

    // ── load: source-sqlite ──────────────────────────────────────────

    #[test]
    fn load_source_sqlite_header() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("cache.sqlite");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE cache (key TEXT, value TEXT);
             INSERT INTO cache VALUES ('tok', 'secret123');",
        )
        .unwrap();
        drop(conn);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"
[[host]]
domain = "example.com"
[[host.inject]]
source-sqlite = "{}"
source-sqlite-query = "SELECT value FROM cache WHERE key = 'tok'"
header = "cookie"
format = "session={{}}"
"#,
                db_path.display()
            ),
        )
        .unwrap();

        let hosts = load(&config_path).unwrap();
        assert_eq!(hosts.len(), 1);
        match &hosts[0].injection_rules[0].injections[0] {
            Injection::SetHeaderSqlite {
                name,
                db_path: p,
                query,
                format,
            } => {
                assert_eq!(name, "cookie");
                assert_eq!(p, &db_path);
                assert_eq!(query, "SELECT value FROM cache WHERE key = 'tok'");
                assert_eq!(format.as_deref(), Some("session={}"));
            }
            other => panic!("expected SetHeaderSqlite, got {:?}", other),
        }
    }

    #[test]
    fn load_source_sqlite_query_param() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("cache.sqlite");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch("CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('val');")
            .unwrap();
        drop(conn);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"
[[host]]
domain = "example.com"
[[host.inject]]
source-sqlite = "{}"
source-sqlite-query = "SELECT v FROM t LIMIT 1"
query-param = "key"
"#,
                db_path.display()
            ),
        )
        .unwrap();

        let hosts = load(&config_path).unwrap();
        match &hosts[0].injection_rules[0].injections[0] {
            Injection::SetQueryParamSqlite { name, .. } => {
                assert_eq!(name, "key");
            }
            other => panic!("expected SetQueryParamSqlite, got {:?}", other),
        }
    }

    #[test]
    fn load_source_sqlite_missing_query_errors() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            r#"
[[host]]
domain = "example.com"
[[host.inject]]
source-sqlite = "/tmp/test.sqlite"
header = "cookie"
"#,
        )
        .unwrap();

        let err = load(&config_path).unwrap_err();
        assert!(
            format!("{err:?}").contains("source-sqlite-query"),
            "got: {err:?}"
        );
    }

    #[test]
    fn load_source_sqlite_query_without_sqlite_errors() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            r#"
[[host]]
domain = "example.com"
[[host.inject]]
source-sqlite-query = "SELECT 1"
header = "cookie"
"#,
        )
        .unwrap();

        let err = load(&config_path).unwrap_err();
        assert!(
            format!("{err:?}").contains("source-sqlite"),
            "got: {err:?}"
        );
    }

    #[test]
    fn load_source_sqlite_conflicts_with_source() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret.key");
        write_secret(&secret, "val");

        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"
[[host]]
domain = "example.com"
[[host.inject]]
source = "{}"
source-sqlite = "/tmp/test.sqlite"
source-sqlite-query = "SELECT 1"
header = "cookie"
"#,
                secret.display()
            ),
        )
        .unwrap();

        let err = load(&config_path).unwrap_err();
        assert!(
            format!("{err:?}").contains("cannot be combined"),
            "got: {err:?}"
        );
    }

    #[test]
    fn load_source_sqlite_without_action_errors() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            r#"
[[host]]
domain = "example.com"
[[host.inject]]
source-sqlite = "/tmp/test.sqlite"
source-sqlite-query = "SELECT 1"
"#,
        )
        .unwrap();

        let err = load(&config_path).unwrap_err();
        assert!(
            format!("{err:?}").contains("header") || format!("{err:?}").contains("query-param"),
            "got: {err:?}"
        );
    }

    #[test]
    fn load_source_sqlite_nonexistent_file_accepted() {
        // File doesn't exist yet, but config should still load (it may be created later).
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            r#"
[[host]]
domain = "example.com"
[[host.inject]]
source-sqlite = "/tmp/nonexistent_crinj_test.sqlite"
source-sqlite-query = "SELECT 1"
header = "cookie"
"#,
        )
        .unwrap();

        let hosts = load(&config_path).unwrap();
        assert_eq!(hosts.len(), 1);
    }

    // ── load: relative source paths ───────────────────────────────────

    #[test]
    fn load_relative_source_resolves_to_secrets_dir() {
        let dir = tempfile::tempdir().unwrap();
        let secrets_dir = dir.path().join("secrets");
        std::fs::create_dir(&secrets_dir).unwrap();
        let secret_path = secrets_dir.join("my.key");
        write_secret(&secret_path, "sk-relative-789\n");

        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            r#"
[[host]]
domain = "example.com"
[[host.inject]]
source = "my.key"
header = "x-api-key"
"#,
        )
        .unwrap();

        let hosts = load(&config_path).unwrap();
        match &hosts[0].injection_rules[0].injections[0] {
            Injection::SetHeader { value, .. } => assert_eq!(value, "sk-relative-789"),
            other => panic!("expected SetHeader, got {:?}", other),
        }
    }

    // ── split_host_port ────────────────────────────────────────────────

    #[test]
    fn split_host_port_basic() {
        assert_eq!(split_host_port("example.com:443"), ("example.com", Some(443)));
        assert_eq!(split_host_port("example.com:8443"), ("example.com", Some(8443)));
    }

    #[test]
    fn split_host_port_no_port() {
        assert_eq!(split_host_port("example.com"), ("example.com", None));
    }

    #[test]
    fn split_host_port_ipv6() {
        assert_eq!(split_host_port("[::1]:443"), ("::1", Some(443)));
        assert_eq!(split_host_port("[2001:db8::1]:8080"), ("2001:db8::1", Some(8080)));
    }

    #[test]
    fn split_host_port_ipv6_no_port() {
        assert_eq!(split_host_port("[::1]"), ("::1", None));
    }
}
