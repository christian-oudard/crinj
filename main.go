package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// CLI entry point: parses flags, resolves XDG paths, sets up logging, loads
// the CA + config, and runs the gateway server until SIGINT/SIGTERM.

func main() {
	ignoreSIGPIPE()
	port := flag.Uint("port", 10255, "Port to listen on")
	bind := flag.String("bind", "127.0.0.1", "Address to bind to")
	dataDir := flag.String("data-dir", "", "Data directory for CA certificates")
	configPath := flag.String("config", "", "Path to the config TOML file")
	allowEmptyRules := flag.Bool("allow-empty-rules", false,
		"Permit starting with zero host rules")
	logFile := flag.String("log-file", "",
		"Write log output to a file instead of stderr")
	logFormat := flag.String("log-format", "text", "Log output format: text or json")
	flag.Parse()

	if err := setupLogging(*logFile, *logFormat); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	resolvedDataDir := resolveDataDir(*dataDir)
	resolvedConfigPath := resolveConfigFile(*configPath)

	slog.Info("starting crinj", "data_dir", resolvedDataDir)

	ca, err := LoadOrGenerateCA(resolvedDataDir)
	if err != nil {
		slog.Error("loading CA", "error", err)
		os.Exit(1)
	}

	upstreamProxy, err := upstreamProxyFromEnv()
	if err != nil {
		slog.Error("parsing upstream proxy", "error", err)
		os.Exit(1)
	}
	if upstreamProxy != nil {
		slog.Info("upstream proxy: routing outbound CONNECT through parent",
			"addr", upstreamProxy.Addr())
	}

	rules, err := load(resolvedConfigPath)
	if err != nil {
		slog.Error("loading config", "error", err)
		os.Exit(1)
	}
	if len(rules) == 0 && !*allowEmptyRules {
		slog.Error("config has no host rules; refusing to start (pass --allow-empty-rules to permit)",
			"config", resolvedConfigPath)
		os.Exit(1)
	}
	slog.Info("loaded config (send SIGHUP to reload)",
		"config", resolvedConfigPath, "host_count", len(rules))
	if len(rules) == 0 {
		slog.Info("starting in passthrough mode: --allow-empty-rules set and config has no rules",
			"config", resolvedConfigPath)
	}

	oauthChains, err := loadOAuth(resolvedConfigPath)
	if err != nil {
		slog.Error("loading oauth config", "error", err)
		os.Exit(1)
	}
	var oauthEngine *OAuthEngine
	if len(oauthChains) > 0 {
		vaultStore, err := OpenVaultStore(filepath.Join(resolvedDataDir, "oauth.db"))
		if err != nil {
			slog.Error("opening oauth vault store", "error", err)
			os.Exit(1)
		}
		defer vaultStore.Close()
		oauthEngine = NewOAuthEngine(oauthChains, vaultStore)
		slog.Info("loaded oauth chains", "count", len(oauthChains))
	}

	slog.Info("ready", "port", *port, "bind", *bind)

	server := NewGatewayServer(ca, uint16(*port), *bind, rules, oauthEngine,
		resolvedConfigPath, *allowEmptyRules, upstreamProxy)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		sig := <-sigCh
		slog.Info("received signal, shutting down", "signal", sig.String())
		cancel()
	}()

	if err := server.Run(ctx); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
	slog.Info("crinj stopped")
}

// ignoreSIGPIPE keeps crinj alive when its log consumer disappears. crinj
// logs to stderr, typically a pipe held by the process that spawned it, and
// crinj outlives that process by design. Go's runtime escalates EPIPE on
// stderr to a fatal SIGPIPE, so without this the first log line written
// after the spawner exits kills the proxy.
func ignoreSIGPIPE() {
	signal.Ignore(syscall.SIGPIPE)
}

// setupLogging configures slog for the requested format and routes the
// global log package through the same handler. `--log-format=json` produces
// one JSON object per line on stderr (or the configured file), suitable for
// a parent process to parse.
func setupLogging(logFile, logFormat string) error {
	var dest io.Writer = os.Stderr
	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("opening log file %s: %w", logFile, err)
		}
		dest = f
	}

	var handler slog.Handler
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	switch logFormat {
	case "text":
		handler = slog.NewTextHandler(dest, opts)
	case "json":
		handler = slog.NewJSONHandler(dest, opts)
	default:
		return fmt.Errorf("invalid --log-format %q (expected text or json)", logFormat)
	}
	slog.SetDefault(slog.New(handler))

	// Route legacy log.Printf calls through the same handler so JSON mode
	// stays consistent across every log site. Each Printf line becomes the
	// `msg` of a slog.Info record. Structured-field call sites can be
	// converted to slog.Info directly over time.
	log.SetOutput(&slogWriter{handler: handler})
	log.SetFlags(0)
	return nil
}

// slogWriter adapts an io.Writer interface to slog: each Write becomes one
// slog.Info record with the trimmed line as the message.
type slogWriter struct {
	handler slog.Handler
}

func (w *slogWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\n")
	rec := slog.NewRecord(time.Now(), slog.LevelInfo, msg, 0)
	_ = w.handler.Handle(context.Background(), rec)
	return len(p), nil
}

// resolveDataDir returns the directory used for CA storage. Prefers an
// explicit --data-dir, then a legacy ~/.crinj directory, and finally
// $XDG_DATA_HOME/crinj.
func resolveDataDir(explicit string) string {
	if explicit != "" {
		return expandTilde(explicit)
	}
	legacy := expandTilde("~/.crinj")
	if info, err := os.Stat(legacy); err == nil && info.IsDir() {
		return legacy
	}
	return filepath.Join(xdgDataHome(), "crinj")
}

// resolveConfigFile returns the path to rules.toml. Prefers explicit --config,
// then a legacy ~/.crinj/rules.toml, and finally $XDG_CONFIG_HOME/crinj/rules.toml.
func resolveConfigFile(explicit string) string {
	if explicit != "" {
		return expandTilde(explicit)
	}
	legacy := expandTilde("~/.crinj/rules.toml")
	if info, err := os.Stat(legacy); err == nil && !info.IsDir() {
		return legacy
	}
	return filepath.Join(xdgConfigHome(), "crinj", "rules.toml")
}

func xdgDataHome() string {
	if v := os.Getenv("XDG_DATA_HOME"); v != "" {
		return v
	}
	return expandTilde("~/.local/share")
}

func xdgConfigHome() string {
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		return v
	}
	return expandTilde("~/.config")
}
