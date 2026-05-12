package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── XDG path resolution ────────────────────────────────────────────────

func TestResolveDataDirExplicit(t *testing.T) {
	got := resolveDataDir("/tmp/explicit-data")
	if got != "/tmp/explicit-data" {
		t.Errorf("got %q", got)
	}
}

func TestResolveDataDirExplicitTilde(t *testing.T) {
	t.Setenv("HOME", "/home/test")
	if got := resolveDataDir("~/data"); got != "/home/test/data" {
		t.Errorf("got %q", got)
	}
}

func TestResolveDataDirXDGFallback(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp) // ~/.crinj does not exist → fall through to XDG
	t.Setenv("XDG_DATA_HOME", "/xdg/data")
	if got := resolveDataDir(""); got != "/xdg/data/crinj" {
		t.Errorf("got %q", got)
	}
}

func TestResolveDataDirLegacyPreferredWhenPresent(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	if err := os.Mkdir(filepath.Join(tmp, ".crinj"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := resolveDataDir(""); got != filepath.Join(tmp, ".crinj") {
		t.Errorf("got %q", got)
	}
}

func TestResolveConfigFileExplicit(t *testing.T) {
	got := resolveConfigFile("/etc/crinj.toml")
	if got != "/etc/crinj.toml" {
		t.Errorf("got %q", got)
	}
}

func TestResolveConfigFileXDGFallback(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CONFIG_HOME", "/xdg/config")
	if got := resolveConfigFile(""); got != "/xdg/config/crinj/rules.toml" {
		t.Errorf("got %q", got)
	}
}

func TestResolveConfigFileLegacyPreferred(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	if err := os.Mkdir(filepath.Join(tmp, ".crinj"), 0o700); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(tmp, ".crinj", "rules.toml")
	if err := os.WriteFile(legacy, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := resolveConfigFile(""); got != legacy {
		t.Errorf("got %q", got)
	}
}

func TestXDGDataHomeFallbackUsesHomeShare(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("HOME", "/home/u")
	if got := xdgDataHome(); got != "/home/u/.local/share" {
		t.Errorf("got %q", got)
	}
}

func TestXDGConfigHomeFallbackUsesDotConfig(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "/home/u")
	if got := xdgConfigHome(); got != "/home/u/.config" {
		t.Errorf("got %q", got)
	}
}

// ── setupLogging ───────────────────────────────────────────────────────

func TestSetupLoggingRejectsBadFormat(t *testing.T) {
	if err := setupLogging("", "yaml"); err == nil {
		t.Error("expected error for bad format")
	}
}

func TestSetupLoggingAcceptsValidFormats(t *testing.T) {
	if err := setupLogging("", "text"); err != nil {
		t.Errorf("text: %v", err)
	}
	if err := setupLogging("", "json"); err != nil {
		t.Errorf("json: %v", err)
	}
}

func TestSetupLoggingOpensFile(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "crinj.log")
	if err := setupLogging(logPath, "text"); err != nil {
		t.Fatal(err)
	}
	// Reset so subsequent tests' log output goes to stderr.
	t.Cleanup(func() { _ = setupLogging("", "text") })
	if _, err := os.Stat(logPath); err != nil {
		t.Errorf("log file not created: %v", err)
	}
}

// ── Run() cancellation ─────────────────────────────────────────────────

func TestGatewayServerRunHonorsContextCancel(t *testing.T) {
	srv := newTestServer(nil)
	srv.bindAddr = "127.0.0.1"
	srv.port = 0 // OS-assigned port

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()

	// Give Run a beat to bind.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after ctx cancel")
	}
}

func TestGatewayServerRunReturnsBindError(t *testing.T) {
	// Hold a port, then try to bind to it from Run — should fail.
	holder, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()

	addr := holder.Addr().(*net.TCPAddr)
	srv := newTestServer(nil)
	srv.bindAddr = "127.0.0.1"
	srv.port = uint16(addr.Port)

	err = srv.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "binding") {
		t.Errorf("want bind error, got %v", err)
	}
}
