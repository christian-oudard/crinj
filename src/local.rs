//! Standalone mode: load injection rules from a TOML file instead of the database.
//!
//! In standalone mode the gateway reads rules at startup, resolves `value-file`
//! references into in-memory strings, and matches incoming CONNECT hostnames against
//! those rules. No database, auth tokens, or web API involved.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::inject::{Injection, InjectionRule};

// ── TOML schema ─────────────────────────────────────────────────────────

/// Top-level rules file.
#[derive(Deserialize)]
struct RulesFile {
    #[serde(default)]
    rules: Vec<TomlRule>,
}

/// A single rule entry in the TOML file.
#[derive(Deserialize)]
struct TomlRule {
    host: String,
    #[serde(default = "default_path")]
    path: String,
    #[serde(default)]
    inject: Vec<TomlInjection>,
}

fn default_path() -> String {
    "*".to_string()
}

/// A single injection action in the TOML file.
#[derive(Deserialize)]
struct TomlInjection {
    action: String,
    name: String,
    /// Inline literal value.
    #[serde(default)]
    value: Option<String>,
    /// Path to a file containing the value (read at startup).
    #[serde(default, rename = "value-file")]
    value_file: Option<String>,
    /// Dot-notation path to extract a value from a structured `value-file`.
    /// Format auto-detected from file extension (.json or .toml).
    #[serde(default, rename = "value-path")]
    value_path: Option<String>,
    /// Legacy alias for `value-path` (JSON files only).
    #[serde(default, rename = "json-path")]
    json_path: Option<String>,
    /// Optional format string. `{value}` is replaced with the resolved value.
    #[serde(default, rename = "value-format")]
    value_format: Option<String>,
    /// Simple prefix prepended to the resolved value (convenience for `Bearer ` etc.).
    #[serde(default, rename = "value-prefix")]
    value_prefix: Option<String>,
    /// When true, the request is blocked if the header cannot be set.
    #[serde(default)]
    require: Option<bool>,
}

// ── Resolved types ──────────────────────────────────────────────────────

/// A fully resolved rule ready for runtime matching.
#[derive(Debug)]
pub(crate) struct ResolvedLocalRule {
    pub host_pattern: String,
    pub injection_rules: Vec<InjectionRule>,
}

// ── Loading ─────────────────────────────────────────────────────────────

/// Parse the rules TOML file and resolve all value-file references.
pub(crate) fn load(path: &Path) -> Result<Vec<ResolvedLocalRule>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading rules file {}", path.display()))?;
    let file: RulesFile =
        toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;

    let mut resolved = Vec::with_capacity(file.rules.len());
    for rule in file.rules {
        let injections = resolve_injections(&rule.inject, path)?;
        let injection_rule = InjectionRule {
            path_pattern: rule.path,
            injections,
        };
        resolved.push(ResolvedLocalRule {
            host_pattern: rule.host,
            injection_rules: vec![injection_rule],
        });
    }
    Ok(resolved)
}

/// Resolve a list of TOML injection entries into `Injection` values.
fn resolve_injections(entries: &[TomlInjection], rules_path: &Path) -> Result<Vec<Injection>> {
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        match entry.action.as_str() {
            "set_header" => {
                let raw_value = resolve_value(entry, rules_path)?;
                let value = format_value(&raw_value, &entry.value_format, &entry.value_prefix);
                out.push(Injection::SetHeader {
                    name: entry.name.clone(),
                    value,
                    require: entry.require.unwrap_or(false),
                });
            }
            "replace_header" => {
                let raw_value = resolve_value(entry, rules_path)?;
                let value = format_value(&raw_value, &entry.value_format, &entry.value_prefix);
                out.push(Injection::ReplaceHeader {
                    name: entry.name.clone(),
                    value,
                });
            }
            "remove_header" => {
                out.push(Injection::RemoveHeader {
                    name: entry.name.clone(),
                });
            }
            "set_query_param" => {
                let raw_value = resolve_value(entry, rules_path)?;
                let value = format_value(&raw_value, &entry.value_format, &entry.value_prefix);
                out.push(Injection::SetQueryParam {
                    name: entry.name.clone(),
                    value,
                    require: entry.require.unwrap_or(false),
                });
            }
            other => bail!(
                "unknown injection action {:?} in {}",
                other,
                rules_path.display()
            ),
        }
    }
    Ok(out)
}

/// Apply `value-format` and/or `value-prefix` to the resolved raw value.
fn format_value(
    raw: &str,
    value_format: &Option<String>,
    value_prefix: &Option<String>,
) -> String {
    let formatted = match value_format {
        Some(fmt) => fmt.replace("{value}", raw),
        None => raw.to_string(),
    };
    match value_prefix {
        Some(prefix) => format!("{prefix}{formatted}"),
        None => formatted,
    }
}

/// Resolve the value for a set_header injection: inline `value` or `value-file`.
fn resolve_value(entry: &TomlInjection, rules_path: &Path) -> Result<String> {
    if let Some(ref v) = entry.value {
        return Ok(v.clone());
    }
    if let Some(ref file_path) = entry.value_file {
        let expanded = expand_tilde(file_path);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let Ok(meta) = std::fs::metadata(&expanded) {
                if meta.mode() & 0o077 != 0 {
                    tracing::warn!(
                        path = %expanded.display(),
                        mode = format!("{:o}", meta.mode() & 0o777),
                        "secret file has group/world permissions, consider chmod 600"
                    );
                }
            }
        }
        let content = std::fs::read_to_string(&expanded).with_context(|| {
            format!(
                "reading value-file {} (for header {:?}) referenced from {}",
                expanded.display(),
                entry.name,
                rules_path.display()
            )
        })?;

        // json-path is a legacy alias for value-path (JSON only)
        if let Some(ref json_path) = entry.json_path {
            return extract_json_path(&content, json_path).with_context(|| {
                format!(
                    "extracting json-path {:?} from {} (for header {:?})",
                    json_path,
                    expanded.display(),
                    entry.name
                )
            });
        }

        if let Some(ref vpath) = entry.value_path {
            return extract_value_path(&content, vpath, &expanded).with_context(|| {
                format!(
                    "extracting value-path {:?} from {} (for header {:?})",
                    vpath,
                    expanded.display(),
                    entry.name
                )
            });
        }

        return Ok(content.trim().to_string());
    }
    bail!(
        "injection for header {:?} in {} has neither `value` nor `value-file`",
        entry.name,
        rules_path.display()
    );
}

/// Walk a dot-separated path through a JSON value, returning the leaf as a string.
fn extract_json_path(content: &str, path: &str) -> Result<String> {
    let root: serde_json::Value =
        serde_json::from_str(content).context("value-file is not valid JSON")?;
    let mut current = &root;
    for key in path.split('.') {
        current = current
            .get(key)
            .with_context(|| format!("key {:?} not found (full path: {:?})", key, path))?;
    }
    match current {
        serde_json::Value::String(s) => Ok(s.clone()),
        other => Ok(other.to_string()),
    }
}

/// Auto-detect format from file extension and extract a dot-separated path.
fn extract_value_path(content: &str, path: &str, file: &Path) -> Result<String> {
    match file.extension().and_then(|e| e.to_str()) {
        Some("json") => extract_json_path(content, path),
        Some("toml") => extract_toml_path(content, path),
        Some(ext) => bail!(
            "unsupported value-file extension {:?}, expected .json or .toml",
            ext
        ),
        None => bail!("value-file has no extension, cannot determine format for value-path"),
    }
}

/// Walk a dot-separated path through a TOML value, returning the leaf as a string.
fn extract_toml_path(content: &str, path: &str) -> Result<String> {
    let root: toml::Value = content.parse().context("value-file is not valid TOML")?;
    let mut current = &root;
    for key in path.split('.') {
        current = current
            .get(key)
            .with_context(|| format!("key {:?} not found (full path: {:?})", key, path))?;
    }
    match current {
        toml::Value::String(s) => Ok(s.clone()),
        other => Ok(other.to_string()),
    }
}

// ── Runtime resolution ──────────────────────────────────────────────────

/// Find all rules matching a hostname. Returns `(intercept, rules)`.
pub(crate) fn resolve(hostname: &str, rules: &[ResolvedLocalRule]) -> (bool, Vec<InjectionRule>) {
    let mut matched = Vec::new();
    for rule in rules {
        if host_matches(hostname, &rule.host_pattern) {
            matched.extend(rule.injection_rules.iter().cloned());
        }
    }
    if matched.is_empty() {
        (false, vec![])
    } else {
        (true, matched)
    }
}

/// Check if a hostname matches a pattern (`*.suffix` wildcard or exact).
fn host_matches(hostname: &str, pattern: &str) -> bool {
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

    // ── host_matches ────────────────────────────────────────────────────

    #[test]
    fn host_exact_match() {
        assert!(host_matches("api.anthropic.com", "api.anthropic.com"));
        assert!(!host_matches("api.anthropic.com", "other.com"));
    }

    #[test]
    fn host_wildcard_match() {
        assert!(host_matches("api.example.com", "*.example.com"));
        assert!(host_matches("sub.api.example.com", "*.example.com"));
    }

    #[test]
    fn host_wildcard_no_match_bare_domain() {
        assert!(!host_matches("example.com", "*.example.com"));
    }

    #[test]
    fn host_wildcard_no_match_different_domain() {
        assert!(!host_matches("api.other.com", "*.example.com"));
    }

    #[test]
    fn host_wildcard_no_partial_match() {
        assert!(!host_matches("notexample.com", "*.example.com"));
    }

    // ── resolve ─────────────────────────────────────────────────────────

    #[test]
    fn resolve_no_match_returns_tunnel() {
        let rules = vec![ResolvedLocalRule {
            host_pattern: "api.anthropic.com".to_string(),
            injection_rules: vec![InjectionRule {
                path_pattern: "*".to_string(),
                injections: vec![Injection::SetHeader {
                    name: "x-api-key".to_string(),
                    value: "sk-123".to_string(),
                    require: false,
                }],
            }],
        }];
        let (intercept, matched) = resolve("other.com", &rules);
        assert!(!intercept);
        assert!(matched.is_empty());
    }

    #[test]
    fn resolve_match_returns_rules() {
        let rules = vec![ResolvedLocalRule {
            host_pattern: "api.anthropic.com".to_string(),
            injection_rules: vec![InjectionRule {
                path_pattern: "*".to_string(),
                injections: vec![Injection::SetHeader {
                    name: "x-api-key".to_string(),
                    value: "sk-123".to_string(),
                    require: false,
                }],
            }],
        }];
        let (intercept, matched) = resolve("api.anthropic.com", &rules);
        assert!(intercept);
        assert_eq!(matched.len(), 1);
    }

    // ── load ────────────────────────────────────────────────────────────

    #[test]
    fn load_inline_value() {
        let dir = tempfile::tempdir().unwrap();
        let rules_path = dir.path().join("rules.toml");
        std::fs::write(
            &rules_path,
            r#"
[[rules]]
host = "api.anthropic.com"
[[rules.inject]]
action = "set_header"
name = "x-api-key"
value = "sk-inline-123"
"#,
        )
        .unwrap();

        let rules = load(&rules_path).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].host_pattern, "api.anthropic.com");
        match &rules[0].injection_rules[0].injections[0] {
            Injection::SetHeader { name, value, .. } => {
                assert_eq!(name, "x-api-key");
                assert_eq!(value, "sk-inline-123");
            }
            other => panic!("expected SetHeader, got {:?}", other),
        }
    }

    #[test]
    fn load_value_file() {
        let dir = tempfile::tempdir().unwrap();
        let secret_path = dir.path().join("secret.key");
        std::fs::write(&secret_path, "sk-from-file-456\n").unwrap();

        let rules_path = dir.path().join("rules.toml");
        std::fs::write(
            &rules_path,
            format!(
                r#"
[[rules]]
host = "api.anthropic.com"
[[rules.inject]]
action = "set_header"
name = "x-api-key"
value-file = "{}"
"#,
                secret_path.display()
            ),
        )
        .unwrap();

        let rules = load(&rules_path).unwrap();
        match &rules[0].injection_rules[0].injections[0] {
            Injection::SetHeader { value, .. } => assert_eq!(value, "sk-from-file-456"),
            other => panic!("expected SetHeader, got {:?}", other),
        }
    }

    #[test]
    fn load_value_format() {
        let dir = tempfile::tempdir().unwrap();
        let secret_path = dir.path().join("token.key");
        std::fs::write(&secret_path, "hf_abc123\n").unwrap();

        let rules_path = dir.path().join("rules.toml");
        std::fs::write(
            &rules_path,
            format!(
                r#"
[[rules]]
host = "huggingface.co"
[[rules.inject]]
action = "set_header"
name = "authorization"
value-file = "{}"
value-format = "Bearer {{value}}"
"#,
                secret_path.display()
            ),
        )
        .unwrap();

        let rules = load(&rules_path).unwrap();
        match &rules[0].injection_rules[0].injections[0] {
            Injection::SetHeader { value, .. } => assert_eq!(value, "Bearer hf_abc123"),
            other => panic!("expected SetHeader, got {:?}", other),
        }
    }

    #[test]
    fn load_value_path_toml() {
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

        let rules_path = dir.path().join("rules.toml");
        std::fs::write(
            &rules_path,
            format!(
                r#"
[[rules]]
host = "api.modal.com"
[[rules.inject]]
action = "set_header"
name = "x-modal-token-id"
value-file = "{0}"
value-path = "christian-oudard.token_id"
[[rules.inject]]
action = "set_header"
name = "x-modal-token-secret"
value-file = "{0}"
value-path = "christian-oudard.token_secret"
"#,
                toml_file.display()
            ),
        )
        .unwrap();

        let rules = load(&rules_path).unwrap();
        let injections = &rules[0].injection_rules[0].injections;
        assert_eq!(injections.len(), 2);
        match &injections[0] {
            Injection::SetHeader { name, value, .. } => {
                assert_eq!(name, "x-modal-token-id");
                assert_eq!(value, "ak-oDO-test123");
            }
            other => panic!("expected SetHeader, got {:?}", other),
        }
    }

    #[test]
    fn load_value_path_json() {
        let dir = tempfile::tempdir().unwrap();
        let json_file = dir.path().join("creds.json");
        std::fs::write(&json_file, r#"{"token": {"access_token": "abc123"}}"#).unwrap();

        let rules_path = dir.path().join("rules.toml");
        std::fs::write(
            &rules_path,
            format!(
                r#"
[[rules]]
host = "example.com"
[[rules.inject]]
action = "set_header"
name = "Authorization"
value-file = "{}"
value-path = "token.access_token"
value-prefix = "Bearer "
"#,
                json_file.display()
            ),
        )
        .unwrap();

        let rules = load(&rules_path).unwrap();
        match &rules[0].injection_rules[0].injections[0] {
            Injection::SetHeader { value, .. } => assert_eq!(value, "Bearer abc123"),
            other => panic!("expected SetHeader, got {:?}", other),
        }
    }

    #[test]
    fn load_value_path_unknown_extension_fails() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("creds.yaml");
        std::fs::write(&file, "key: value").unwrap();

        let rules_path = dir.path().join("rules.toml");
        std::fs::write(
            &rules_path,
            format!(
                r#"
[[rules]]
host = "example.com"
[[rules.inject]]
action = "set_header"
name = "x-token"
value-file = "{}"
value-path = "key"
"#,
                file.display()
            ),
        )
        .unwrap();

        let err = load(&rules_path).unwrap_err();
        assert!(format!("{err:?}").contains("unsupported"));
    }

    #[test]
    fn load_empty_rules() {
        let dir = tempfile::tempdir().unwrap();
        let rules_path = dir.path().join("rules.toml");
        std::fs::write(&rules_path, "").unwrap();

        let rules = load(&rules_path).unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn load_multiple_rules() {
        let dir = tempfile::tempdir().unwrap();
        let rules_path = dir.path().join("rules.toml");
        std::fs::write(
            &rules_path,
            r#"
[[rules]]
host = "api.anthropic.com"
[[rules.inject]]
action = "set_header"
name = "x-api-key"
value = "sk-ant"

[[rules]]
host = "huggingface.co"
[[rules.inject]]
action = "set_header"
name = "authorization"
value = "Bearer hf-tok"
"#,
        )
        .unwrap();

        let rules = load(&rules_path).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].host_pattern, "api.anthropic.com");
        assert_eq!(rules[1].host_pattern, "huggingface.co");
    }

    #[test]
    fn load_set_query_param() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("fred.key");
        std::fs::write(&secret, "MY_API_KEY\n").unwrap();

        let rules_path = dir.path().join("rules.toml");
        std::fs::write(
            &rules_path,
            format!(
                r#"
[[rules]]
host = "api.stlouisfed.org"
[[rules.inject]]
action = "set_query_param"
name = "api_key"
value-file = "{}"
require = true
"#,
                secret.display()
            ),
        )
        .unwrap();

        let rules = load(&rules_path).unwrap();
        assert_eq!(rules.len(), 1);
        match &rules[0].injection_rules[0].injections[0] {
            Injection::SetQueryParam {
                name,
                value,
                require,
            } => {
                assert_eq!(name, "api_key");
                assert_eq!(value, "MY_API_KEY");
                assert!(*require);
            }
            other => panic!("expected SetQueryParam, got {:?}", other),
        }
    }
}
