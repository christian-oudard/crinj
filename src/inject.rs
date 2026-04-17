//! Request injection engine and access control.
//!
//! Applies injection rules to forwarded requests, with path pattern matching.
//! All injections require a placeholder: the header or query parameter must
//! already exist in the request for injection to occur.

use std::path::PathBuf;

use anyhow::{bail, Result};
use hyper::header::{HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::glob;

// ── Data types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "action", rename_all = "snake_case")]
pub(crate) enum Injection {
    SetHeader {
        name: String,
        value: String,
    },
    SetHeaderSqlite {
        name: String,
        db_path: PathBuf,
        query: String,
        format: Option<String>,
    },
    RemoveHeader {
        name: String,
    },
    SetQueryParam {
        name: String,
        value: String,
    },
    SetQueryParamSqlite {
        name: String,
        db_path: PathBuf,
        query: String,
        format: Option<String>,
    },
}

/// One `[[host.inject]]` resolved into runtime form.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct InjectionRule {
    pub path_pattern: String,
    /// Empty = any port.
    #[serde(default)]
    pub ports: Vec<u16>,
    pub injections: Vec<Injection>,
}

impl InjectionRule {
    pub fn port_matches(&self, port: Option<u16>) -> bool {
        self.ports.is_empty() || port.map_or(false, |p| self.ports.contains(&p))
    }
}

/// Access control verbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AccessVerb {
    Block,
    Allow,
}

/// One line of an `access` list.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct AccessEntry {
    pub verb: AccessVerb,
    pub path_pattern: String,
}

// ── Access control ──────────────────────────────────────────────────────

/// Parse an `access` string into an ordered list of entries.
///
/// Each non-empty, non-comment line is `<verb> <path>`. Comments start with `#`.
/// Validates natural order: broader entries must precede narrower ones.
pub(crate) fn parse_access(s: &str) -> Result<Vec<AccessEntry>> {
    let mut entries = Vec::new();
    for (lineno, raw) in s.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (verb_str, path) = line
            .split_once(char::is_whitespace)
            .map(|(v, p)| (v, p.trim()))
            .unwrap_or((line, ""));
        let verb = match verb_str {
            "block" => AccessVerb::Block,
            "allow" => AccessVerb::Allow,
            other => bail!(
                "access line {}: unknown verb {:?} (expected `block` or `allow`)",
                lineno + 1,
                other
            ),
        };
        if path.is_empty() {
            bail!("access line {}: missing path after {}", lineno + 1, verb_str);
        }
        entries.push(AccessEntry {
            verb,
            path_pattern: path.to_string(),
        });
    }
    validate_natural_order(&entries)?;
    Ok(entries)
}

/// Error out if any entry is a superset of an earlier entry (broader-after-narrower).
fn validate_natural_order(entries: &[AccessEntry]) -> Result<()> {
    for j in 0..entries.len() {
        for i in 0..j {
            let a = &entries[i];
            let b = &entries[j];
            if a.path_pattern == b.path_pattern {
                continue; // equal is OK, last wins
            }
            if glob::is_superset_of(&b.path_pattern, &a.path_pattern) {
                bail!(
                    "access: entry {} ({} {}) is broader than earlier entry {} ({} {}); \
                     put broader patterns first",
                    j + 1,
                    verb_str(b.verb),
                    b.path_pattern,
                    i + 1,
                    verb_str(a.verb),
                    a.path_pattern,
                );
            }
        }
    }
    Ok(())
}

fn verb_str(v: AccessVerb) -> &'static str {
    match v {
        AccessVerb::Block => "block",
        AccessVerb::Allow => "allow",
    }
}

/// Evaluate access rules against a request path.
/// Returns the verb of the last matching entry, or `None` if nothing matches
/// (default allow).
pub(crate) fn evaluate_access(path: &str, entries: &[AccessEntry]) -> Option<AccessVerb> {
    let mut result = None;
    for entry in entries {
        if glob::matches(path, &entry.path_pattern) {
            result = Some(entry.verb);
        }
    }
    result
}

// ── SQLite resolution ───────────────────────────────────────────────────

/// Query a SQLite database for a single text value.
fn resolve_sqlite(
    db_path: &std::path::Path,
    query: &str,
    format: &Option<String>,
) -> Option<String> {
    match resolve_sqlite_inner(db_path, query) {
        Ok(raw) => {
            let value = match format {
                Some(fmt) => fmt.replace("{}", &raw),
                None => raw,
            };
            Some(value)
        }
        Err(e) => {
            warn!(
                db = %db_path.display(),
                error = %e,
                "sqlite injection failed"
            );
            None
        }
    }
}

fn resolve_sqlite_inner(db_path: &std::path::Path, query: &str) -> Result<String> {
    let conn = rusqlite::Connection::open_with_flags(
        db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(std::time::Duration::from_secs(1))?;
    let value: String = conn.query_row(query, [], |row| row.get(0))?;
    Ok(value)
}

// ── Injection application ───────────────────────────────────────────────

/// Apply injection rules to the request headers.
/// Returns the number of injection actions applied.
pub(crate) fn apply_injections(
    headers: &mut hyper::HeaderMap,
    request_path: &str,
    rules: &[InjectionRule],
) -> usize {
    let mut count = 0;

    for rule in rules {
        if !glob::matches(request_path, &rule.path_pattern) {
            continue;
        }

        for injection in &rule.injections {
            match injection {
                Injection::SetHeader { name, value } => {
                    if let (Ok(header_name), Ok(header_value)) = (
                        HeaderName::from_bytes(name.as_bytes()),
                        HeaderValue::from_str(value),
                    ) {
                        if !headers.contains_key(&header_name) {
                            continue;
                        }
                        headers.insert(header_name.clone(), header_value);
                        debug!(header = %header_name, "injected header");
                        count += 1;
                    } else {
                        warn!(
                            header = %name,
                            "injection skipped: invalid header name or value"
                        );
                    }
                }
                Injection::SetHeaderSqlite {
                    name,
                    db_path,
                    query,
                    format,
                } => {
                    let Ok(header_name) = HeaderName::from_bytes(name.as_bytes()) else {
                        continue;
                    };
                    if !headers.contains_key(&header_name) {
                        continue;
                    }
                    if let Some(value) = resolve_sqlite(db_path, query, format) {
                        if let Ok(header_value) = HeaderValue::from_str(&value) {
                            headers.insert(header_name.clone(), header_value);
                            debug!(header = %header_name, "injected header (sqlite)");
                            count += 1;
                        }
                    }
                }
                Injection::RemoveHeader { name } => {
                    if let Ok(header_name) = HeaderName::from_bytes(name.as_bytes()) {
                        if headers.remove(&header_name).is_some() {
                            debug!(header = %header_name, "removed header");
                            count += 1;
                        }
                    }
                }
                Injection::SetQueryParam { .. } | Injection::SetQueryParamSqlite { .. } => {}
            }
        }
    }

    count
}

/// Apply query parameter injections to a URL path+query string.
/// Returns the modified path+query and the number of injections applied.
pub(crate) fn apply_query_injections(
    path_and_query: &str,
    rules: &[InjectionRule],
) -> (String, usize) {
    let (path, existing_query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path_and_query, None),
    };

    let existing_params: std::collections::HashSet<&str> = existing_query
        .map(|q| {
            q.split('&')
                .filter_map(|pair| pair.split('=').next())
                .collect()
        })
        .unwrap_or_default();

    let mut params_to_set: Vec<(String, String)> = Vec::new();
    for rule in rules {
        if !glob::matches(path, &rule.path_pattern) {
            continue;
        }
        for injection in &rule.injections {
            match injection {
                Injection::SetQueryParam { name, value } => {
                    if existing_params.contains(name.as_str()) {
                        params_to_set.push((name.clone(), value.clone()));
                    }
                }
                Injection::SetQueryParamSqlite {
                    name,
                    db_path,
                    query,
                    format,
                } => {
                    if existing_params.contains(name.as_str()) {
                        if let Some(value) = resolve_sqlite(db_path, query, format) {
                            params_to_set.push((name.clone(), value));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    if params_to_set.is_empty() {
        return (path_and_query.to_string(), 0);
    }

    let count = params_to_set.len();
    for (name, _) in &params_to_set {
        debug!(param = %name, "injected query param");
    }

    let inject_names: std::collections::HashSet<&str> =
        params_to_set.iter().map(|(n, _)| n.as_str()).collect();
    let mut parts: Vec<String> = Vec::new();
    if let Some(q) = existing_query {
        for pair in q.split('&') {
            let name = pair.split('=').next().unwrap_or(pair);
            if !inject_names.contains(name) {
                parts.push(pair.to_string());
            }
        }
    }

    for (name, value) in &params_to_set {
        parts.push(format!(
            "{}={}",
            percent_encode(name),
            percent_encode(value)
        ));
    }

    (format!("{}?{}", path, parts.join("&")), count)
}

/// Percent-encode a query parameter name or value (RFC 3986 unreserved chars).
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(char::from(b"0123456789ABCDEF"[(b >> 4) as usize]));
                out.push(char::from(b"0123456789ABCDEF"[(b & 0xf) as usize]));
            }
        }
    }
    out
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rule(path_pattern: &str, injections: Vec<Injection>) -> InjectionRule {
        InjectionRule {
            path_pattern: path_pattern.to_string(),
            ports: vec![],
            injections,
        }
    }

    fn set_header(name: &str, value: &str) -> Injection {
        Injection::SetHeader {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    fn remove_header(name: &str) -> Injection {
        Injection::RemoveHeader {
            name: name.to_string(),
        }
    }

    fn set_query_param(name: &str, value: &str) -> Injection {
        Injection::SetQueryParam {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    // ── apply_injections ────────────────────────────────────────────────

    #[test]
    fn inject_set_header_replaces_placeholder() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("accept", HeaderValue::from_static("application/json"));
        headers.insert("x-api-key", HeaderValue::from_static("PLACEHOLDER"));

        let rules = vec![make_rule("*", vec![set_header("x-api-key", "sk-ant-123")])];

        let count = apply_injections(&mut headers, "/v1/messages", &rules);
        assert_eq!(count, 1);
        assert_eq!(headers.get("x-api-key").unwrap(), "sk-ant-123");
        assert_eq!(headers.get("accept").unwrap(), "application/json");
    }

    #[test]
    fn inject_set_header_skips_when_no_placeholder() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("accept", HeaderValue::from_static("application/json"));

        let rules = vec![make_rule("*", vec![set_header("x-api-key", "sk-ant-123")])];

        let count = apply_injections(&mut headers, "/v1/messages", &rules);
        assert_eq!(count, 0);
        assert!(headers.get("x-api-key").is_none());
    }

    #[test]
    fn inject_remove_header() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer token"));

        let rules = vec![make_rule("*", vec![remove_header("authorization")])];

        let count = apply_injections(&mut headers, "/", &rules);
        assert_eq!(count, 1);
        assert!(headers.get("authorization").is_none());
    }

    #[test]
    fn inject_path_mismatch_skips_rule() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-api-key", HeaderValue::from_static("PLACEHOLDER"));

        let rules = vec![make_rule(
            "/v1/*",
            vec![set_header("x-api-key", "sk-ant-123")],
        )];

        let count = apply_injections(&mut headers, "/v2/messages", &rules);
        assert_eq!(count, 0);
        assert_eq!(headers.get("x-api-key").unwrap(), "PLACEHOLDER");
    }

    #[test]
    fn inject_multiple_rules_different_paths() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-api-key", HeaderValue::from_static("PLACEHOLDER"));

        let rules = vec![
            make_rule("/v1/*", vec![set_header("x-api-key", "key-v1")]),
            make_rule("/v2/*", vec![set_header("x-api-key", "key-v2")]),
        ];

        let count = apply_injections(&mut headers, "/v1/messages", &rules);
        assert_eq!(count, 1);
        assert_eq!(headers.get("x-api-key").unwrap(), "key-v1");
    }

    // ── apply_query_injections ──────────────────────────────────────────

    #[test]
    fn query_inject_skips_when_no_placeholder() {
        let rules = vec![make_rule("*", vec![set_query_param("api_key", "abc123")])];
        let (result, count) = apply_query_injections("/fred/series", &rules);
        assert_eq!(count, 0);
        assert_eq!(result, "/fred/series");
    }

    #[test]
    fn query_inject_replaces_placeholder() {
        let rules = vec![make_rule("*", vec![set_query_param("api_key", "abc123")])];
        let (result, count) =
            apply_query_injections("/fred/series?api_key=PLACEHOLDER&series_id=GDP", &rules);
        assert_eq!(count, 1);
        assert!(result.contains("series_id=GDP"));
        assert!(result.contains("api_key=abc123"));
        assert!(!result.contains("PLACEHOLDER"));
    }

    #[test]
    fn query_inject_encodes_special_chars() {
        let rules = vec![make_rule(
            "*",
            vec![set_query_param("q", "hello world&more")],
        )];
        let (result, _) = apply_query_injections("/search?q=PLACEHOLDER", &rules);
        assert!(result.contains("q=hello%20world%26more"));
    }

    // ── access: parse ──────────────────────────────────────────────────

    #[test]
    fn parse_access_basic() {
        let entries = parse_access("block *\nallow /v1/*\nblock /v1/admin/*").unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].verb, AccessVerb::Block);
        assert_eq!(entries[0].path_pattern, "*");
        assert_eq!(entries[2].verb, AccessVerb::Block);
        assert_eq!(entries[2].path_pattern, "/v1/admin/*");
    }

    #[test]
    fn parse_access_single_line() {
        let entries = parse_access("block *").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].verb, AccessVerb::Block);
    }

    #[test]
    fn parse_access_ignores_blanks_and_comments() {
        let entries = parse_access(
            "
# top-level block
block *

# allow API
allow /v1/*
",
        )
        .unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn parse_access_unknown_verb_errors() {
        let err = parse_access("deny /v1/*").unwrap_err();
        assert!(format!("{err:?}").contains("unknown verb"));
    }

    #[test]
    fn parse_access_missing_path_errors() {
        let err = parse_access("block").unwrap_err();
        assert!(format!("{err:?}").contains("missing path"));
    }

    #[test]
    fn parse_access_unnatural_order_errors() {
        let err = parse_access("allow /v1/*\nblock *").unwrap_err();
        assert!(format!("{err:?}").contains("broader than earlier"));
    }

    #[test]
    fn parse_access_nested_unnatural_errors() {
        let err = parse_access("block /v1/admin/*\nallow /v1/*").unwrap_err();
        assert!(format!("{err:?}").contains("broader than earlier"));
    }

    #[test]
    fn parse_access_disjoint_any_order() {
        // /v1 and /v2 are disjoint, any order works.
        parse_access("block /v1/*\nallow /v2/*").unwrap();
        parse_access("allow /v2/*\nblock /v1/*").unwrap();
    }

    // ── access: evaluate ───────────────────────────────────────────────

    #[test]
    fn eval_empty_list_returns_none() {
        assert_eq!(evaluate_access("/v1/foo", &[]), None);
    }

    #[test]
    fn eval_block_all() {
        let entries = parse_access("block *").unwrap();
        assert_eq!(evaluate_access("/anything", &entries), Some(AccessVerb::Block));
    }

    #[test]
    fn eval_last_match_wins() {
        let entries = parse_access("block *\nallow /v1/*").unwrap();
        assert_eq!(evaluate_access("/v1/foo", &entries), Some(AccessVerb::Allow));
        assert_eq!(evaluate_access("/v2/foo", &entries), Some(AccessVerb::Block));
    }

    #[test]
    fn eval_nested_block_after_allow() {
        let entries = parse_access("block *\nallow /v1/*\nblock /v1/admin/*").unwrap();
        assert_eq!(evaluate_access("/v1/admin/x", &entries), Some(AccessVerb::Block));
        assert_eq!(evaluate_access("/v1/users", &entries), Some(AccessVerb::Allow));
        assert_eq!(evaluate_access("/anything", &entries), Some(AccessVerb::Block));
    }

    // ── SQLite injection ──────────────────────────────────────────────────

    fn create_test_db(dir: &std::path::Path) -> PathBuf {
        let db_path = dir.join("test.sqlite");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE cache (key TEXT PRIMARY KEY, value TEXT);
             INSERT INTO cache VALUES ('cookie', 'session_abc123');",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        db_path
    }

    #[test]
    fn sqlite_header_injection_replaces_placeholder() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = create_test_db(dir.path());

        let mut headers = hyper::HeaderMap::new();
        headers.insert("cookie", HeaderValue::from_static("PLACEHOLDER"));

        let rules = vec![make_rule(
            "*",
            vec![Injection::SetHeaderSqlite {
                name: "cookie".to_string(),
                db_path,
                query: "SELECT value FROM cache WHERE key = 'cookie'".to_string(),
                format: Some("_yhlsoft_user={}".to_string()),
            }],
        )];

        let count = apply_injections(&mut headers, "/api/data", &rules);
        assert_eq!(count, 1);
        assert_eq!(
            headers.get("cookie").unwrap(),
            "_yhlsoft_user=session_abc123"
        );
    }

    #[test]
    fn sqlite_header_injection_skips_when_no_placeholder() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = create_test_db(dir.path());

        let mut headers = hyper::HeaderMap::new();
        // No cookie header present.

        let rules = vec![make_rule(
            "*",
            vec![Injection::SetHeaderSqlite {
                name: "cookie".to_string(),
                db_path,
                query: "SELECT value FROM cache WHERE key = 'cookie'".to_string(),
                format: None,
            }],
        )];

        let count = apply_injections(&mut headers, "/api/data", &rules);
        assert_eq!(count, 0);
    }

    #[test]
    fn sqlite_header_injection_skips_on_missing_db() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("cookie", HeaderValue::from_static("PLACEHOLDER"));

        let rules = vec![make_rule(
            "*",
            vec![Injection::SetHeaderSqlite {
                name: "cookie".to_string(),
                db_path: PathBuf::from("/nonexistent/test.sqlite"),
                query: "SELECT value FROM cache WHERE key = 'cookie'".to_string(),
                format: None,
            }],
        )];

        let count = apply_injections(&mut headers, "/api/data", &rules);
        assert_eq!(count, 0);
        // Placeholder is not replaced.
        assert_eq!(headers.get("cookie").unwrap(), "PLACEHOLDER");
    }

    #[test]
    fn sqlite_query_param_injection() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = create_test_db(dir.path());

        let rules = vec![make_rule(
            "*",
            vec![Injection::SetQueryParamSqlite {
                name: "token".to_string(),
                db_path,
                query: "SELECT value FROM cache WHERE key = 'cookie'".to_string(),
                format: None,
            }],
        )];

        let (result, count) =
            apply_query_injections("/api/data?token=PLACEHOLDER&foo=bar", &rules);
        assert_eq!(count, 1);
        assert!(result.contains("token=session_abc123"));
        assert!(result.contains("foo=bar"));
    }

    #[test]
    fn sqlite_reads_updated_value() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = create_test_db(dir.path());

        // Update the value after initial creation.
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "UPDATE cache SET value = 'new_session_xyz' WHERE key = 'cookie'",
            [],
        )
        .unwrap();
        drop(conn);

        let mut headers = hyper::HeaderMap::new();
        headers.insert("cookie", HeaderValue::from_static("PLACEHOLDER"));

        let rules = vec![make_rule(
            "*",
            vec![Injection::SetHeaderSqlite {
                name: "cookie".to_string(),
                db_path,
                query: "SELECT value FROM cache WHERE key = 'cookie'".to_string(),
                format: None,
            }],
        )];

        let count = apply_injections(&mut headers, "/", &rules);
        assert_eq!(count, 1);
        assert_eq!(headers.get("cookie").unwrap(), "new_session_xyz");
    }
}
