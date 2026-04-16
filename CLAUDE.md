# crinj

Local MITM proxy that injects credentials into outbound HTTP requests based on TOML config. Designed for sandboxing AI agents that need API access without direct credential access.

## Commands

```bash
cargo build                    # Build
cargo test                     # Run tests
cargo run -- --config rules.toml  # Run with config
nix build                     # Nix build
nix develop                   # Dev shell
```

## Structure

```
src/
  main.rs      # CLI, XDG path resolution, startup
  gateway.rs   # MITM proxy server, connection handling, SIGHUP reload
  ca.rs        # Certificate authority (generate/persist CA, issue leaf certs)
  inject.rs    # Injection engine (headers, query params, path matching)
  local.rs     # TOML config loading and value resolution
flake.nix      # Nix build + NixOS module
```

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
Canonical field order — inject: `url-path`, `ports`, `source`, `source-path`, `value`, `header`/`query-param`/`remove-header`, `format`.

Host selection is most-specific-wins (fewer `*` then longer literal portion). Tie = config error.
Access control is last-match-wins with natural-order enforcement (broader before narrower).
Inject entries are cumulative across all matching entries.

Glob patterns: `*` matches any sequence of characters (including dots), literal elsewhere.

Source path resolution: bare names → `<config_dir>/secrets/<name>`, `~/...` → home-relative, `/...` → absolute.
Secret files must be chmod 600 (no group/world access) or crinj refuses to start.
