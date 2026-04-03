//! Standalone mode: load host config from a TOML file instead of the database.
//!
//! In standalone mode the gateway reads host entries at startup, resolves `source`
//! file references into in-memory strings, and matches incoming CONNECT hostnames against
//! those entries. No database, auth tokens, or web API involved.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::inject::{Injection, InjectionRule};

// ── TOML schema ─────────────────────────────────────────────────────────

/// Top-level config file.
#[derive(Deserialize)]
struct Config {
    #[serde(default)]
    host: Vec<HostEntry>,
}

/// A single host entry in the TOML file.
///
/// Two forms, mutually exclusive:
///
/// 1. Inline (single rule, most common):
/// ```toml
/// [[host]]
/// domain = "api.example.com"
/// source = "~/.secrets/key"
/// header = "Authorization"
/// format = "Bearer {}"
/// ```
///
/// 2. Rule sub-tables (multiple rules, each with optional url-path):
/// ```toml
/// [[host]]
/// domain = "api.example.com"
/// source = "~/.config/creds.toml"
/// [[host.rule]]
/// source-path = "account.token_id"
/// header = "x-token-id"
/// [[host.rule]]
/// source-path = "account.token_secret"
/// header = "x-token-secret"
/// ```
#[derive(Deserialize)]
struct HostEntry {
    domain: String,
    /// Default source file (inherited by rule entries).
    #[serde(default)]
    source: Option<String>,
    /// Multi-rule sub-tables.
    #[serde(default)]
    rule: Vec<RuleEntry>,
    /// Inline rule fields (flattened into the host entry).
    #[serde(flatten)]
    inline: RuleEntry,
}

fn default_path() -> String {
    "*".to_string()
}

/// Rule fields shared by both inline and sub-table forms.
/// Exactly one of `header`, `query_param`, or `remove_header` must be set.
#[derive(Deserialize, Default)]
struct RuleEntry {
    /// Path to a file containing the value (read at startup).
    #[serde(default)]
    source: Option<String>,
    /// Inline literal value.
    #[serde(default)]
    value: Option<String>,
    /// Dot-notation path into a structured `source` file.
    /// Segments are keys or array indices. Format auto-detected from extension.
    #[serde(default, rename = "source-path")]
    source_path: Option<String>,
    /// Header name (implies set_header action).
    #[serde(default)]
    header: Option<String>,
    /// Query parameter name (implies set_query_param action).
    #[serde(default, rename = "query-param")]
    query_param: Option<String>,
    /// Header name to remove (implies remove_header action).
    #[serde(default, rename = "remove-header")]
    remove_header: Option<String>,
    /// Optional format string. `{}` is replaced with the resolved value.
    #[serde(default)]
    format: Option<String>,
    /// URL path pattern. Default `*`. Supports `/v1/*` prefix wildcards.
    #[serde(default = "default_path", rename = "url-path")]
    url_path: String,
}

impl RuleEntry {
    /// True if this entry specifies an action (header, query-param, or remove-header).
    fn has_action(&self) -> bool {
        self.header.is_some() || self.query_param.is_some() || self.remove_header.is_some()
    }

    /// The target name (header or query param name) for error messages.
    fn target_name(&self) -> &str {
        self.header
            .as_deref()
            .or(self.query_param.as_deref())
            .or(self.remove_header.as_deref())
            .unwrap_or("?")
    }
}

// ── Resolved types ──────────────────────────────────────────────────────

/// A fully resolved host entry ready for runtime matching.
#[derive(Debug)]
pub(crate) struct ResolvedHost {
    pub host_pattern: String,
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
    for entry in config.host {
        let injection_rules = resolve_host_rules(&entry, path)?;
        resolved.push(ResolvedHost {
            host_pattern: entry.domain,
            injection_rules,
        });
    }
    Ok(resolved)
}

/// Resolve rules for a host entry, handling inline and sub-table forms.
fn resolve_host_rules(entry: &HostEntry, config_path: &Path) -> Result<Vec<InjectionRule>> {
    let has_inline = entry.inline.has_action();
    let has_rules = !entry.rule.is_empty();

    if has_inline && has_rules {
        bail!(
            "host {:?} in {}: use either inline fields or [[host.rule]], not both",
            entry.domain,
            config_path.display()
        );
    }

    // Host-level source, used as fallback for inline/rules.
    // For inline, serde(flatten) means source is consumed by the host-level field,
    // so the inline RuleEntry always has source = None.
    let fallback_source = entry.source.as_deref();

    if has_inline {
        let injection = resolve_injection(&entry.inline, fallback_source, config_path)?;
        return Ok(vec![InjectionRule {
            path_pattern: entry.inline.url_path.clone(),
            injections: vec![injection],
        }]);
    }

    entry
        .rule
        .iter()
        .map(|rule| {
            let injection = resolve_injection(rule, fallback_source, config_path)?;
            Ok(InjectionRule {
                path_pattern: rule.url_path.clone(),
                injections: vec![injection],
            })
        })
        .collect()
}

/// Resolve a single rule entry into an `Injection` value.
/// `fallback_source` is the host-level `source`, used when the rule doesn't have one.
fn resolve_injection(
    rule: &RuleEntry,
    fallback_source: Option<&str>,
    config_path: &Path,
) -> Result<Injection> {
    if let Some(ref name) = rule.remove_header {
        return Ok(Injection::RemoveHeader {
            name: name.clone(),
        });
    }
    if let Some(ref name) = rule.header {
        let raw = resolve_value(rule, fallback_source, config_path)?;
        let value = format_value(&raw, &rule.format);
        return Ok(Injection::SetHeader {
            name: name.clone(),
            value,
        });
    }
    if let Some(ref name) = rule.query_param {
        let raw = resolve_value(rule, fallback_source, config_path)?;
        let value = format_value(&raw, &rule.format);
        return Ok(Injection::SetQueryParam {
            name: name.clone(),
            value,
        });
    }
    bail!(
        "rule in {} must have `header`, `query-param`, or `remove-header`",
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

/// Resolve the value for a rule: inline `value` or `source` file.
/// Falls back to the host-level `source` if the rule doesn't specify one.
fn resolve_value(
    rule: &RuleEntry,
    fallback_source: Option<&str>,
    config_path: &Path,
) -> Result<String> {
    let target = rule.target_name();

    if let Some(ref v) = rule.value {
        return Ok(v.clone());
    }

    let source = rule.source.as_deref().or(fallback_source);
    if let Some(source) = source {
        let expanded = expand_tilde(source);
        check_file_permissions(&expanded);
        let content = std::fs::read_to_string(&expanded).with_context(|| {
            format!(
                "reading source {} (for {:?}) referenced from {}",
                expanded.display(),
                target,
                config_path.display()
            )
        })?;

        if let Some(ref sp) = rule.source_path {
            return extract_path(&content, sp, &expanded).with_context(|| {
                format!(
                    "extracting source-path {:?} from {} (for {:?})",
                    sp,
                    expanded.display(),
                    target
                )
            });
        }

        return Ok(content.trim().to_string());
    }
    bail!(
        "rule for {:?} in {} has neither `value` nor `source`",
        target,
        config_path.display()
    );
}

/// Warn if a secret file has group/world-readable permissions.
fn check_file_permissions(_path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = std::fs::metadata(_path) {
            if meta.mode() & 0o077 != 0 {
                tracing::warn!(
                    path = %_path.display(),
                    mode = format!("{:o}", meta.mode() & 0o777),
                    "secret file has group/world permissions, consider chmod 600"
                );
            }
        }
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

/// Find all host entries matching a hostname. Returns `(intercept, rules)`.
pub(crate) fn resolve(hostname: &str, hosts: &[ResolvedHost]) -> (bool, Vec<InjectionRule>) {
    let mut matched = Vec::new();
    for host in hosts {
        if domain_matches(hostname, &host.host_pattern) {
            matched.extend(host.injection_rules.iter().cloned());
        }
    }
    if matched.is_empty() {
        (false, vec![])
    } else {
        (true, matched)
    }
}

/// Check if a hostname matches a domain pattern (`*.suffix` wildcard or exact).
fn domain_matches(hostname: &str, pattern: &str) -> bool {
    if pattern == hostname {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return hostname.ends_with(suffix)
            && hostname.len() > suffix.len()
            && hostname.as_bytes()[hostname.len() - suffix.len() - 1] == b'.';
    }
    false
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

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── domain_matches ──────────────────────────────────────────────────

    #[test]
    fn domain_exact_match() {
        assert!(domain_matches("api.anthropic.com", "api.anthropic.com"));
        assert!(!domain_matches("api.anthropic.com", "other.com"));
    }

    #[test]
    fn domain_wildcard_match() {
        assert!(domain_matches("api.example.com", "*.example.com"));
        assert!(domain_matches("sub.api.example.com", "*.example.com"));
    }

    #[test]
    fn domain_wildcard_no_match_bare() {
        assert!(!domain_matches("example.com", "*.example.com"));
    }

    #[test]
    fn domain_wildcard_no_match_different() {
        assert!(!domain_matches("api.other.com", "*.example.com"));
    }

    #[test]
    fn domain_wildcard_no_partial_match() {
        assert!(!domain_matches("notexample.com", "*.example.com"));
    }

    // ── resolve ─────────────────────────────────────────────────────────

    #[test]
    fn resolve_no_match_returns_tunnel() {
        let hosts = vec![ResolvedHost {
            host_pattern: "api.anthropic.com".to_string(),
            injection_rules: vec![InjectionRule {
                path_pattern: "*".to_string(),
                injections: vec![Injection::SetHeader {
                    name: "x-api-key".to_string(),
                    value: "sk-123".to_string(),
                }],
            }],
        }];
        let (intercept, matched) = resolve("other.com", &hosts);
        assert!(!intercept);
        assert!(matched.is_empty());
    }

    #[test]
    fn resolve_match_returns_rules() {
        let hosts = vec![ResolvedHost {
            host_pattern: "api.anthropic.com".to_string(),
            injection_rules: vec![InjectionRule {
                path_pattern: "*".to_string(),
                injections: vec![Injection::SetHeader {
                    name: "x-api-key".to_string(),
                    value: "sk-123".to_string(),
                }],
            }],
        }];
        let (intercept, matched) = resolve("api.anthropic.com", &hosts);
        assert!(intercept);
        assert_eq!(matched.len(), 1);
    }

    // ── load: inline form ──────────────────────────────────────────────

    #[test]
    fn load_inline_header() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            r#"
[[host]]
domain = "api.anthropic.com"
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
    fn load_inline_header_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let secret_path = dir.path().join("secret.key");
        std::fs::write(&secret_path, "sk-from-file-456\n").unwrap();

        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"
[[host]]
domain = "api.anthropic.com"
header = "x-api-key"
source = "{}"
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
    fn load_inline_with_format() {
        let dir = tempfile::tempdir().unwrap();
        let secret_path = dir.path().join("token.key");
        std::fs::write(&secret_path, "hf_abc123\n").unwrap();

        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"
[[host]]
domain = "huggingface.co"
header = "authorization"
source = "{}"
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
    fn load_inline_query_param() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("fred.key");
        std::fs::write(&secret, "MY_API_KEY\n").unwrap();

        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"
[[host]]
domain = "api.stlouisfed.org"
query-param = "api_key"
source = "{}"
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
    fn load_inline_remove_header() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            r#"
[[host]]
domain = "example.com"
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

    // ── load: rule sub-tables ─────────────────────────────────────────

    #[test]
    fn load_rule_subtable() {
        let dir = tempfile::tempdir().unwrap();
        let toml_file = dir.path().join("modal.toml");
        std::fs::write(
            &toml_file,
            r#"
[christian-oudard]
token_id = "ak-oDO-test123"
token_secret = "as-PsX-test456"
"#,
        )
        .unwrap();

        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"
[[host]]
domain = "api.modal.com"
[[host.rule]]
header = "x-modal-token-id"
source = "{0}"
source-path = "christian-oudard.token_id"
[[host.rule]]
header = "x-modal-token-secret"
source = "{0}"
source-path = "christian-oudard.token_secret"
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
                assert_eq!(name, "x-modal-token-id");
                assert_eq!(value, "ak-oDO-test123");
            }
            other => panic!("expected SetHeader, got {:?}", other),
        }
        match &rules[1].injections[0] {
            Injection::SetHeader { name, value } => {
                assert_eq!(name, "x-modal-token-secret");
                assert_eq!(value, "as-PsX-test456");
            }
            other => panic!("expected SetHeader, got {:?}", other),
        }
    }

    #[test]
    fn load_source_path_from_json() {
        let dir = tempfile::tempdir().unwrap();
        let json_file = dir.path().join("creds.json");
        std::fs::write(&json_file, r#"{"token": {"access_token": "abc123"}}"#).unwrap();

        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"
[[host]]
domain = "example.com"
header = "Authorization"
source = "{}"
source-path = "token.access_token"
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
    fn load_source_path_unknown_extension_fails() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("creds.yaml");
        std::fs::write(&file, "key: value").unwrap();

        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"
[[host]]
domain = "example.com"
header = "x-token"
source = "{}"
source-path = "key"
"#,
                file.display()
            ),
        )
        .unwrap();

        let err = load(&config_path).unwrap_err();
        assert!(format!("{err:?}").contains("unsupported"));
    }

    #[test]
    fn load_source_path_array_index() {
        let dir = tempfile::tempdir().unwrap();
        let json_file = dir.path().join("creds.json");
        std::fs::write(&json_file, r#"{"tokens": ["first", "second"]}"#).unwrap();

        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"
[[host]]
domain = "example.com"
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

    // ── load: misc ─────────────────────────────────────────────────────

    #[test]
    fn load_empty_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rules.toml");
        std::fs::write(&config_path, "").unwrap();

        let hosts = load(&config_path).unwrap();
        assert!(hosts.is_empty());
    }

    #[test]
    fn load_multiple_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            r#"
[[host]]
domain = "api.anthropic.com"
header = "x-api-key"
value = "sk-ant"

[[host]]
domain = "huggingface.co"
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
    fn load_mix_inline_and_subtable_fails() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            r#"
[[host]]
domain = "example.com"
header = "x-inline"
value = "inline-val"
[[host.rule]]
header = "x-extra"
value = "extra-val"
"#,
        )
        .unwrap();

        let err = load(&config_path).unwrap_err();
        assert!(format!("{err:?}").contains("inline fields or [[host.rule]]"));
    }

    // ── load: host-level source inheritance ────────────────────────────

    #[test]
    fn load_rules_inherit_host_source() {
        let dir = tempfile::tempdir().unwrap();
        let toml_file = dir.path().join("creds.toml");
        std::fs::write(
            &toml_file,
            r#"
[account]
id = "ak-test123"
secret = "as-test456"
"#,
        )
        .unwrap();

        let config_path = dir.path().join("rules.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"
[[host]]
domain = "api.example.com"
source = "{0}"
[[host.rule]]
header = "x-id"
source-path = "account.id"
[[host.rule]]
header = "x-secret"
source-path = "account.secret"
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
}
