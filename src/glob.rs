//! Shared glob matcher. `*` is the only metacharacter, matches any sequence of
//! characters (including dots). Everything else is literal.
//!
//! Used for both domain patterns and URL path patterns.

/// Return true if `text` matches `pattern`. `*` matches any sequence (possibly empty).
pub(crate) fn matches(text: &str, pattern: &str) -> bool {
    // Split pattern by `*` and greedily find each literal chunk in order.
    let mut chunks = pattern.split('*');
    let first = chunks.next().unwrap_or("");
    if !text.starts_with(first) {
        return false;
    }
    let mut cursor = first.len();

    let remaining: Vec<&str> = chunks.collect();
    if remaining.is_empty() {
        // No `*` in pattern — must match exactly.
        return cursor == text.len();
    }

    let last = remaining.len() - 1;
    for (i, chunk) in remaining.iter().enumerate() {
        if chunk.is_empty() {
            if i == last {
                return true; // trailing `*` absorbs the rest
            }
            continue;
        }
        if i == last {
            // Last chunk must match at the end of text, at or after cursor.
            return text.len() >= cursor + chunk.len() && text.ends_with(chunk);
        }
        match text[cursor..].find(chunk) {
            Some(rel) => cursor += rel + chunk.len(),
            None => return false,
        }
    }
    true
}

/// Specificity score for host-match disambiguation.
///
/// Returns `(num_literal_chars, -num_stars)`. Higher tuple = more specific:
/// - More literal characters is more specific.
/// - Fewer wildcards is more specific at the same literal count.
pub(crate) fn specificity(pattern: &str) -> (usize, isize) {
    let stars = pattern.chars().filter(|c| *c == '*').count();
    let literals = pattern.len() - stars;
    (literals, -(stars as isize))
}

/// Return true if `broader`'s matched set is a (non-strict) superset of `narrower`'s.
/// Used for natural-order validation of access entries.
///
/// Handles `*`, trailing-star prefix (`/v1/*`, `/v1*`), and exact patterns.
/// Patterns with internal `*`s are treated conservatively (returns false unless
/// exactly equal).
pub(crate) fn is_superset_of(broader: &str, narrower: &str) -> bool {
    if broader == narrower {
        return true;
    }
    if broader == "*" {
        return true;
    }

    // broader must end with a single trailing `*` and have no other `*`s to compare structurally.
    let Some(b_prefix) = broader.strip_suffix('*') else {
        return false;
    };
    if b_prefix.contains('*') {
        return false;
    }

    // broader = b_prefix + `*`. narrower ⊆ broader iff every string matching narrower starts with b_prefix.
    if narrower == "*" {
        return false;
    }
    if let Some(n_prefix) = narrower.strip_suffix('*') {
        if n_prefix.contains('*') {
            return false;
        }
        return n_prefix.starts_with(b_prefix);
    }
    narrower.starts_with(b_prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── matches ─────────────────────────────────────────────────────────

    #[test]
    fn exact_match() {
        assert!(matches("foo", "foo"));
        assert!(!matches("foo", "bar"));
        assert!(!matches("foo", "fo"));
        assert!(!matches("foo", "foobar"));
    }

    #[test]
    fn star_matches_everything() {
        assert!(matches("", "*"));
        assert!(matches("anything", "*"));
        assert!(matches("a.b.c", "*"));
    }

    #[test]
    fn leading_star() {
        assert!(matches("api.example.com", "*.example.com"));
        assert!(matches("a.b.example.com", "*.example.com"));
        assert!(!matches("example.com", "*.example.com"));
        assert!(!matches("other.com", "*.example.com"));
    }

    #[test]
    fn trailing_star() {
        assert!(matches("/v1/users", "/v1/*"));
        assert!(matches("/v1/", "/v1/*"));
        assert!(matches("/v1/", "/v1*"));
        assert!(!matches("/v2/users", "/v1/*"));
    }

    #[test]
    fn middle_star() {
        assert!(matches("http-intake.logs.us5.datadoghq.com", "http-intake.logs*.datadoghq.com"));
        assert!(matches("http-intake.logs.datadoghq.com", "http-intake.logs*.datadoghq.com"));
        assert!(matches("http-intake.logs.eu.datadoghq.com", "http-intake.logs*.datadoghq.com"));
        assert!(!matches("api.datadoghq.com", "http-intake.logs*.datadoghq.com"));
    }

    // ── specificity ─────────────────────────────────────────────────────

    #[test]
    fn specificity_exact_beats_wildcard() {
        assert!(specificity("api.example.com") > specificity("*.example.com"));
    }

    #[test]
    fn specificity_fewer_stars_wins() {
        assert!(specificity("http-intake.logs*.datadoghq.com") > specificity("*.datadoghq.com"));
    }

    #[test]
    fn specificity_longer_literal_wins() {
        assert!(specificity("*.api.example.com") > specificity("*.example.com"));
    }

    // ── is_superset_of ──────────────────────────────────────────────────

    #[test]
    fn star_is_superset_of_anything() {
        assert!(is_superset_of("*", "/v1/*"));
        assert!(is_superset_of("*", "/exact"));
        assert!(is_superset_of("*", "*"));
    }

    #[test]
    fn prefix_superset() {
        assert!(is_superset_of("/v1/*", "/v1/admin/*"));
        assert!(is_superset_of("/v1/*", "/v1/users"));
        assert!(!is_superset_of("/v1/admin/*", "/v1/*"));
    }

    #[test]
    fn disjoint_not_superset() {
        assert!(!is_superset_of("/v1/*", "/v2/*"));
        assert!(!is_superset_of("/v1", "/v2"));
    }

    #[test]
    fn equal_is_superset() {
        assert!(is_superset_of("/v1/*", "/v1/*"));
        assert!(is_superset_of("*", "*"));
    }

    #[test]
    fn path_boundary_prefix() {
        assert!(is_superset_of("/v1*", "/v1/admin"));
        assert!(is_superset_of("/v1*", "/v1"));
        // /v1* matches /v1abc too — is /v1abc a superset? Only by structural prefix.
        assert!(is_superset_of("/v1*", "/v1abc"));
    }
}
