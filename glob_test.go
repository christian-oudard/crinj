package main

import "testing"

func TestGlobExactMatch(t *testing.T) {
	cases := []struct {
		text, pattern string
		want          bool
	}{
		{"foo", "foo", true},
		{"foo", "bar", false},
		{"foo", "fo", false},
		{"foo", "foobar", false},
	}
	for _, c := range cases {
		if got := globMatches(c.text, c.pattern); got != c.want {
			t.Errorf("globMatches(%q,%q)=%v want %v", c.text, c.pattern, got, c.want)
		}
	}
}

func TestGlobStarMatchesEverything(t *testing.T) {
	for _, s := range []string{"", "anything", "a.b.c"} {
		if !globMatches(s, "*") {
			t.Errorf("globMatches(%q, *) = false", s)
		}
	}
}

func TestGlobLeadingStar(t *testing.T) {
	cases := []struct {
		text string
		want bool
	}{
		{"api.example.com", true},
		{"a.b.example.com", true},
		{"example.com", false},
		{"other.com", false},
	}
	for _, c := range cases {
		if got := globMatches(c.text, "*.example.com"); got != c.want {
			t.Errorf("globMatches(%q, *.example.com)=%v want %v", c.text, got, c.want)
		}
	}
}

func TestGlobTrailingStar(t *testing.T) {
	if !globMatches("/v1/users", "/v1/*") {
		t.Error("expected /v1/users to match /v1/*")
	}
	if !globMatches("/v1/", "/v1/*") {
		t.Error("expected /v1/ to match /v1/*")
	}
	if !globMatches("/v1/", "/v1*") {
		t.Error("expected /v1/ to match /v1*")
	}
	if globMatches("/v2/users", "/v1/*") {
		t.Error("expected /v2/users not to match /v1/*")
	}
}

func TestGlobMiddleStar(t *testing.T) {
	pat := "http-intake.logs*.datadoghq.com"
	cases := []struct {
		text string
		want bool
	}{
		{"http-intake.logs.us5.datadoghq.com", true},
		{"http-intake.logs.datadoghq.com", true},
		{"http-intake.logs.eu.datadoghq.com", true},
		{"api.datadoghq.com", false},
	}
	for _, c := range cases {
		if got := globMatches(c.text, pat); got != c.want {
			t.Errorf("globMatches(%q, %q)=%v want %v", c.text, pat, got, c.want)
		}
	}
}

func TestSpecificityExactBeatsWildcard(t *testing.T) {
	if !patternSpecificity("api.example.com").moreSpecificThan(patternSpecificity("*.example.com")) {
		t.Error("exact should beat wildcard")
	}
}

func TestSpecificityFewerStarsWins(t *testing.T) {
	if !patternSpecificity("http-intake.logs*.datadoghq.com").moreSpecificThan(patternSpecificity("*.datadoghq.com")) {
		t.Error("fewer stars should win")
	}
}

func TestSpecificityLongerLiteralWins(t *testing.T) {
	if !patternSpecificity("*.api.example.com").moreSpecificThan(patternSpecificity("*.example.com")) {
		t.Error("longer literal should win")
	}
}

func TestSupersetStarOfAnything(t *testing.T) {
	for _, s := range []string{"/v1/*", "/exact", "*"} {
		if !isSupersetOf("*", s) {
			t.Errorf("* should be superset of %q", s)
		}
	}
}

func TestSupersetPrefix(t *testing.T) {
	if !isSupersetOf("/v1/*", "/v1/admin/*") {
		t.Error("/v1/* should be superset of /v1/admin/*")
	}
	if !isSupersetOf("/v1/*", "/v1/users") {
		t.Error("/v1/* should be superset of /v1/users")
	}
	if isSupersetOf("/v1/admin/*", "/v1/*") {
		t.Error("/v1/admin/* should NOT be superset of /v1/*")
	}
}

func TestSupersetDisjoint(t *testing.T) {
	if isSupersetOf("/v1/*", "/v2/*") {
		t.Error("/v1/* and /v2/* are disjoint")
	}
	if isSupersetOf("/v1", "/v2") {
		t.Error("/v1 and /v2 are disjoint")
	}
}

func TestSupersetEqual(t *testing.T) {
	if !isSupersetOf("/v1/*", "/v1/*") {
		t.Error("equal should be superset")
	}
	if !isSupersetOf("*", "*") {
		t.Error("* should be superset of *")
	}
}

func TestSupersetPathBoundaryPrefix(t *testing.T) {
	cases := []string{"/v1/admin", "/v1", "/v1abc"}
	for _, s := range cases {
		if !isSupersetOf("/v1*", s) {
			t.Errorf("/v1* should be superset of %q", s)
		}
	}
}
