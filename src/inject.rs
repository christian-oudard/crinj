//! Request injection engine.
//!
//! Applies injection rules to forwarded requests, with path pattern matching.
//! All injections require a placeholder: the header or query parameter must
//! already exist in the request for injection to occur.

use hyper::header::{HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

// ── Data types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "action", rename_all = "snake_case")]
pub(crate) enum Injection {
    SetHeader {
        name: String,
        value: String,
    },
    RemoveHeader {
        name: String,
    },
    SetQueryParam {
        name: String,
        value: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct InjectionRule {
    pub path_pattern: String,
    pub injections: Vec<Injection>,
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
        if !path_matches(request_path, &rule.path_pattern) {
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
                Injection::RemoveHeader { name } => {
                    if let Ok(header_name) = HeaderName::from_bytes(name.as_bytes()) {
                        if headers.remove(&header_name).is_some() {
                            debug!(header = %header_name, "removed header");
                            count += 1;
                        }
                    }
                }
                Injection::SetQueryParam { .. } => {} // handled by apply_query_injections
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

    let mut params_to_set: Vec<(&str, &str)> = Vec::new();
    for rule in rules {
        if !path_matches(path, &rule.path_pattern) {
            continue;
        }
        for injection in &rule.injections {
            if let Injection::SetQueryParam { name, value } = injection {
                if !existing_params.contains(name.as_str()) {
                    continue;
                }
                params_to_set.push((name, value));
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
        params_to_set.iter().map(|(n, _)| *n).collect();
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

/// Check if a request path matches a rule's path pattern.
/// Supports: `"*"` (matches everything), `"/prefix/*"` (prefix match), exact match.
pub(crate) fn path_matches(request_path: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return request_path == prefix
            || (request_path.starts_with(prefix)
                && request_path.as_bytes().get(prefix.len()) == Some(&b'/'));
    }
    request_path == pattern
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── path_matches ────────────────────────────────────────────────────

    #[test]
    fn path_wildcard_matches_everything() {
        assert!(path_matches("/v1/messages", "*"));
        assert!(path_matches("/", "*"));
        assert!(path_matches("/any/path/here", "*"));
    }

    #[test]
    fn path_prefix_wildcard() {
        assert!(path_matches("/v1/messages", "/v1/*"));
        assert!(path_matches("/v1/", "/v1/*"));
        assert!(path_matches("/v1/completions/stream", "/v1/*"));
        assert!(path_matches("/v1", "/v1/*"));
    }

    #[test]
    fn path_prefix_wildcard_rejects_non_matching() {
        assert!(!path_matches("/v2/messages", "/v1/*"));
        assert!(!path_matches("/", "/v1/*"));
        assert!(!path_matches("/v1beta/foo", "/v1/*"));
    }

    #[test]
    fn path_exact() {
        assert!(path_matches("/v1/messages", "/v1/messages"));
        assert!(!path_matches("/v1/messages/", "/v1/messages"));
        assert!(!path_matches("/v1/other", "/v1/messages"));
    }

    // ── apply_injections ────────────────────────────────────────────────

    fn make_rule(path_pattern: &str, injections: Vec<Injection>) -> InjectionRule {
        InjectionRule {
            path_pattern: path_pattern.to_string(),
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
    fn inject_set_header_overwrites_existing() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer old-token"),
        );

        let rules = vec![make_rule(
            "*",
            vec![set_header("authorization", "Bearer new-token")],
        )];

        let count = apply_injections(&mut headers, "/", &rules);
        assert_eq!(count, 1);
        assert_eq!(headers.get("authorization").unwrap(), "Bearer new-token");
    }

    #[test]
    fn inject_remove_header() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer token"));
        headers.insert("accept", HeaderValue::from_static("application/json"));

        let rules = vec![make_rule("*", vec![remove_header("authorization")])];

        let count = apply_injections(&mut headers, "/", &rules);
        assert_eq!(count, 1);
        assert!(headers.get("authorization").is_none());
        assert_eq!(headers.get("accept").unwrap(), "application/json");
    }

    #[test]
    fn inject_remove_nonexistent_counts_zero() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("accept", HeaderValue::from_static("application/json"));

        let rules = vec![make_rule("*", vec![remove_header("x-not-present")])];

        let count = apply_injections(&mut headers, "/", &rules);
        assert_eq!(count, 0);
    }

    #[test]
    fn inject_combined_set_and_remove() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-api-key", HeaderValue::from_static("PLACEHOLDER"));
        headers.insert("authorization", HeaderValue::from_static("Bearer old"));

        let rules = vec![make_rule(
            "*",
            vec![
                set_header("x-api-key", "sk-ant-123"),
                remove_header("authorization"),
            ],
        )];

        let count = apply_injections(&mut headers, "/v1/messages", &rules);
        assert_eq!(count, 2);
        assert_eq!(headers.get("x-api-key").unwrap(), "sk-ant-123");
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

    #[test]
    fn inject_no_rules_returns_zero() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("accept", HeaderValue::from_static("*/*"));

        let count = apply_injections(&mut headers, "/anything", &[]);
        assert_eq!(count, 0);
    }

    // ── apply_query_injections ──────────────────────────────────────────

    fn set_query_param(name: &str, value: &str) -> Injection {
        Injection::SetQueryParam {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

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
    fn query_inject_replaces_existing_param() {
        let rules = vec![make_rule("*", vec![set_query_param("api_key", "new")])];
        let (result, count) = apply_query_injections("/path?api_key=old&other=1", &rules);
        assert_eq!(count, 1);
        assert!(result.contains("api_key=new"));
        assert!(!result.contains("api_key=old"));
        assert!(result.contains("other=1"));
    }

    #[test]
    fn query_inject_no_match_returns_unchanged() {
        let rules = vec![make_rule("/v1/*", vec![set_query_param("key", "val")])];
        let (result, count) = apply_query_injections("/v2/foo?key=PLACEHOLDER", &rules);
        assert_eq!(count, 0);
        assert_eq!(result, "/v2/foo?key=PLACEHOLDER");
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

    #[test]
    fn query_inject_multiple_params() {
        let rules = vec![make_rule(
            "*",
            vec![
                set_query_param("api_key", "abc"),
                set_query_param("file_type", "json"),
            ],
        )];
        let (result, count) =
            apply_query_injections("/fred/series?api_key=PH&file_type=PH", &rules);
        assert_eq!(count, 2);
        assert!(result.contains("api_key=abc"));
        assert!(result.contains("file_type=json"));
    }

    #[test]
    fn query_inject_skips_header_injections() {
        let rules = vec![make_rule(
            "*",
            vec![
                set_header("x-api-key", "secret"),
                set_query_param("api_key", "abc"),
            ],
        )];
        let (result, count) = apply_query_injections("/path?api_key=PH", &rules);
        assert_eq!(count, 1);
        assert!(result.contains("api_key=abc"));
        assert!(!result.contains("x-api-key"));
    }

    // ── placeholder requirement ────────────────────────────────────────

    #[test]
    fn header_skips_when_no_placeholder() {
        let mut headers = hyper::HeaderMap::new();
        let rules = vec![make_rule(
            "*",
            vec![set_header("x-api-key", "secret")],
        )];
        let count = apply_injections(&mut headers, "/", &rules);
        assert_eq!(count, 0);
        assert!(headers.get("x-api-key").is_none());
    }

    #[test]
    fn header_injects_when_placeholder_present() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-api-key", HeaderValue::from_static("PLACEHOLDER"));
        let rules = vec![make_rule(
            "*",
            vec![set_header("x-api-key", "real-secret")],
        )];
        let count = apply_injections(&mut headers, "/", &rules);
        assert_eq!(count, 1);
        assert_eq!(headers.get("x-api-key").unwrap(), "real-secret");
    }

    #[test]
    fn query_skips_when_no_placeholder() {
        let rules = vec![make_rule(
            "*",
            vec![set_query_param("api_key", "secret")],
        )];
        let (result, count) = apply_query_injections("/path", &rules);
        assert_eq!(count, 0);
        assert_eq!(result, "/path");
    }

    #[test]
    fn query_injects_when_placeholder_present() {
        let rules = vec![make_rule(
            "*",
            vec![set_query_param("api_key", "real-secret")],
        )];
        let (result, count) = apply_query_injections("/path?api_key=PLACEHOLDER", &rules);
        assert_eq!(count, 1);
        assert!(result.contains("api_key=real-secret"));
        assert!(!result.contains("PLACEHOLDER"));
    }
}
