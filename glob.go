package main

import "strings"

// Shared glob matcher. `*` is the only metacharacter, matches any sequence of
// characters (including dots). Everything else is literal.
//
// Used for both domain patterns and URL path patterns.

// globMatches reports whether text matches pattern. `*` matches any sequence
// (possibly empty).
func globMatches(text, pattern string) bool {
	chunks := strings.Split(pattern, "*")
	first := chunks[0]
	if !strings.HasPrefix(text, first) {
		return false
	}
	cursor := len(first)
	remaining := chunks[1:]
	if len(remaining) == 0 {
		return cursor == len(text)
	}
	last := len(remaining) - 1
	for i, chunk := range remaining {
		if chunk == "" {
			if i == last {
				return true
			}
			continue
		}
		if i == last {
			return len(text) >= cursor+len(chunk) && strings.HasSuffix(text, chunk)
		}
		rel := strings.Index(text[cursor:], chunk)
		if rel < 0 {
			return false
		}
		cursor += rel + len(chunk)
	}
	return true
}

// specificity is the host-match disambiguation score. More literal characters
// or fewer wildcards both increase specificity.
type specificity struct {
	literals int
	stars    int
}

func patternSpecificity(pattern string) specificity {
	stars := strings.Count(pattern, "*")
	return specificity{literals: len(pattern) - stars, stars: stars}
}

// moreSpecificThan reports whether a is strictly more specific than b.
func (a specificity) moreSpecificThan(b specificity) bool {
	if a.literals != b.literals {
		return a.literals > b.literals
	}
	return a.stars < b.stars
}

func (a specificity) equals(b specificity) bool {
	return a.literals == b.literals && a.stars == b.stars
}

// isSupersetOf reports whether broader's matched set is a (non-strict) superset
// of narrower's. Used for natural-order validation of access entries.
//
// Handles `*`, trailing-star prefix (`/v1/*`, `/v1*`), and exact patterns.
// Patterns with internal `*`s are treated conservatively (returns false unless
// exactly equal).
func isSupersetOf(broader, narrower string) bool {
	if broader == narrower {
		return true
	}
	if broader == "*" {
		return true
	}
	if !strings.HasSuffix(broader, "*") {
		return false
	}
	bPrefix := strings.TrimSuffix(broader, "*")
	if strings.Contains(bPrefix, "*") {
		return false
	}
	if narrower == "*" {
		return false
	}
	if strings.HasSuffix(narrower, "*") {
		nPrefix := strings.TrimSuffix(narrower, "*")
		if strings.Contains(nPrefix, "*") {
			return false
		}
		return strings.HasPrefix(nPrefix, bPrefix)
	}
	return strings.HasPrefix(narrower, bPrefix)
}
