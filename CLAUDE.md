# crinj

Local MITM proxy that injects credentials into outbound HTTP requests based on TOML config. Designed for sandboxing AI agents that need API access without direct credential access.

## Commands

```bash
CGO_ENABLED=0 go build              # Build (pure-Go SQLite, no gcc needed)
CGO_ENABLED=0 go test ./...         # Run tests
CGO_ENABLED=0 go run . --config rules.toml  # Run with config
nix build                           # Nix build via buildGoModule
nix develop                         # Dev shell (go, gopls, gotools)
```

## Structure

Flat Go package at the repo root:

```
main.go        # CLI, XDG path resolution, startup
gateway.go     # MITM proxy server, connection handling, SIGHUP reload
ca.go          # Certificate authority (generate/persist CA, issue leaf certs)
inject.go      # Injection engine (headers, query params, path matching)
local.go       # TOML config loading and value resolution
glob.go        # Shared glob matcher / specificity / superset checks
flake.nix      # Nix build (buildGoModule) + NixOS module
go.mod / go.sum
```

modernc.org/sqlite is the SQLite driver (pure-Go, transpiled from C). Keep
`CGO_ENABLED=0` so builds stay fast: with cgo on, `net` and similar stdlib
packages compile a C path that slows every build, and any cgo-based SQLite
alternative would recompile bundled C source on each invocation — giving
back the compile-speed win that motivated leaving Rust. The Nix build sets
the env var via `env.CGO_ENABLED = "0"` in `flake.nix`. If you run `go test`
or `go build` without it set, you'll hit `cgo: C compiler "gcc" not found`
— enter a shell with gcc (`nix shell nixpkgs#gcc`) or, preferably, just
export `CGO_ENABLED=0`.

When dependencies change, re-derive the Nix `vendorHash` in `flake.nix`: set
it to `sha256-A...A=` (forty-three A's), run `nix build`, copy the suggested
hash from the error message into the flake.

## Config format

See SPEC.md for the full language. Quick reference:

```toml
# Single-inject host
[[host]]
domain = "api.example.com"
[[host.inject]]
source = "api-key"
header = "Authorization"
format = "Bearer {}"

# Multi-inject host with shared source + access control
[[host]]
domain = "api.anthropic.com"
access = """
block *
allow /v1/*
"""
source = "~/.config/example/creds.toml"
[[host.inject]]
source-path = "account.token_id"
header = "x-token-id"
[[host.inject]]
source-path = "account.token_secret"
header = "x-token-secret"

# Block all subdomains matching a glob
[[host]]
domain = "http-intake.logs*.datadoghq.com"
access = "block *"
```

All header and query-param injections require placeholders: the field must already exist in the request.

Canonical field order — host: `domain`, `no-check-certificate`, `access`, `source`, `inject`.
Canonical field order — inject: `url-path`, `ports`, `source`, `source-path`, `source-sqlite`, `source-sqlite-query`, `value`, `header`/`query-param`/`remove-header`, `format`.

Host selection is most-specific-wins (fewer `*` then longer literal portion). Tie = config error.
Access control is last-match-wins with natural-order enforcement (broader before narrower).
Inject entries are cumulative across all matching entries.

Glob patterns: `*` matches any sequence of characters (including dots), literal elsewhere.

Source path resolution: bare names → `<config_dir>/secrets/<name>`, `~/...` → home-relative, `/...` → absolute.
Secret files must be chmod 600. A populated secret file with wider permissions is treated as an emergency (the secret has already leaked) and crinj refuses to start. A missing or zero-byte secret file is treated as "key not provided yet": that host is skipped with a warning and crinj keeps starting. Schema errors in rules.toml are collected across all hosts and reported together at startup.
