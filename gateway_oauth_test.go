package main

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// seedLogin captures one login directly into the engine's store and returns the
// placeholders the client would hold.
func seedLogin(t *testing.T, e *OAuthEngine, realAccess, realRefresh string) (issuedAccess, issuedRefresh string) {
	t.Helper()
	resp := &tokenBody{json: map[string]any{"access_token": realAccess}}
	if realRefresh != "" {
		resp.json["refresh_token"] = realRefresh
	}
	if _, err := e.completeResponse(&tokenExchange{endpoint: testEndpoint(), newLogin: true}, resp); err != nil {
		t.Fatal(err)
	}
	issuedAccess = mustGet(t, resp, "access_token")
	if realRefresh != "" {
		issuedRefresh = mustGet(t, resp, "refresh_token")
	}
	return
}

func TestApplyOAuthRequestSwapsResourceBearer(t *testing.T) {
	e := testEngine(t)
	issuedAccess, _ := seedLogin(t, e, "REAL-at", "")
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/v1/messages"},
		Host:   "api.anthropic.com",
		Header: http.Header{"Authorization": []string{"Bearer " + issuedAccess}},
		Body:   http.NoBody,
	}
	ex, err := applyOAuthRequest(req, "api.anthropic.com", e)
	if err != nil {
		t.Fatal(err)
	}
	if ex != nil {
		t.Error("resource host is not the token endpoint")
	}
	if got := req.Header.Get("Authorization"); got != "Bearer REAL-at" {
		t.Errorf("Authorization = %q", got)
	}
}

func TestApplyOAuthRequestLeavesUnknownBearer(t *testing.T) {
	e := testEngine(t)
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/v1/messages"},
		Host:   "api.anthropic.com",
		Header: http.Header{"Authorization": []string{"Bearer sk-ant-oat01-stranger"}},
		Body:   http.NoBody,
	}
	if _, err := applyOAuthRequest(req, "api.anthropic.com", e); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer sk-ant-oat01-stranger" {
		t.Errorf("unknown bearer should be untouched, got %q", got)
	}
}

func TestApplyOAuthRequestBuffersTokenBodyAndFixesLength(t *testing.T) {
	e := testEngine(t)
	_, issuedRefresh := seedLogin(t, e, "REAL-at", "REAL-rt")
	body := "grant_type=refresh_token&refresh_token=" + issuedRefresh + "&client_id=x"
	req := &http.Request{
		Method: "POST",
		URL:    &url.URL{Path: "/v1/oauth/token"},
		Host:   "platform.claude.com",
		Header: http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}},
		Body:   io.NopCloser(strings.NewReader(body)),
	}
	ex, err := applyOAuthRequest(req, "platform.claude.com", e)
	if err != nil {
		t.Fatal(err)
	}
	if ex == nil || ex.refresh == nil {
		t.Fatalf("expected refresh exchange, got %+v", ex)
	}
	out, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(out), "refresh_token=REAL-rt") {
		t.Errorf("body not rewritten: %s", out)
	}
	if req.ContentLength != int64(len(out)) {
		t.Errorf("ContentLength = %d, body len = %d", req.ContentLength, len(out))
	}
}

func TestCaptureOAuthResponseFakesBodyAndFixesLength(t *testing.T) {
	e := testEngine(t)
	ex := &tokenExchange{endpoint: testEndpoint(), newLogin: true}
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"access_token":"REAL-at","refresh_token":"REAL-rt"}`)),
	}
	if err := captureOAuthResponse(resp, ex, e); err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(out), "REAL-at") {
		t.Errorf("real token leaked to client: %s", out)
	}
	if !strings.Contains(string(out), "crinj-placeholder") {
		t.Errorf("response not faked: %s", out)
	}
	if resp.ContentLength != int64(len(out)) {
		t.Errorf("ContentLength = %d, body len = %d", resp.ContentLength, len(out))
	}
}

func TestCaptureOAuthResponseErrorStatusNotCaptured(t *testing.T) {
	e := testEngine(t)
	ex := &tokenExchange{endpoint: testEndpoint(), newLogin: true}
	resp := &http.Response{
		StatusCode: 400,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"error":"invalid_grant"}`)),
	}
	if err := captureOAuthResponse(resp, ex, e); err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	if string(out) != `{"error":"invalid_grant"}` {
		t.Errorf("error body should pass through: %s", out)
	}
}

func TestApplyOAuthRequestNilEngine(t *testing.T) {
	req := &http.Request{URL: &url.URL{Path: "/x"}, Host: "h", Header: http.Header{}, Body: http.NoBody}
	ex, err := applyOAuthRequest(req, "h", nil)
	if err != nil || ex != nil {
		t.Fatalf("nil engine should no-op: ex=%v err=%v", ex, err)
	}
}
