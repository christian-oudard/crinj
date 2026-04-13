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

```toml
# Inline single rule (most common) — bare source name resolves to secrets/ dir
[[host]]
domain = "api.example.com"
source = "api-key"
header = "authorization"
format = "Bearer {}"

# Multiple rules from one source file (absolute/~ paths also work)
[[host]]
domain = "api.example.com"
source = "~/.config/example/creds.toml"
[[host.rule]]
source-path = "account.token_id"
header = "x-token-id"
[[host.rule]]
source-path = "account.token_secret"
header = "x-token-secret"
```

All injections require placeholders: the header or query param must already exist in the request.

Canonical field order:
- Matching: `domain`, `url-path` (default `*`), `ports` (array of u16, default all)
- TLS: `no-check-certificate` (bool, default false) skips upstream cert verification per host
- Source: `source` (from file), `source-path` (extract from JSON/TOML file), `value` (inline literal)
- Action: `header`, `query-param`, `remove-header`
- Modifiers: `format` (`{}` substitution)

Source path resolution: bare names → `<config_dir>/secrets/<name>`, `~/...` → home-relative, `/...` → absolute
Secret files must be chmod 600 (no group/world access) or crinj refuses to start.
