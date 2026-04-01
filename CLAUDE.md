# crinj

Local MITM proxy that injects credentials into outbound HTTP requests based on TOML config. Designed for sandboxing AI agents that need API access without direct credential access.

## Commands

```bash
cargo build                    # Build
cargo test                     # Run tests
cargo run -- --config config.toml  # Run with config
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
# Inline single rule (most common)
[[host]]
domain = "api.example.com"
source = "~/.secrets/api-key"
header = "authorization"
format = "Bearer {}"

# Multiple rules from one source file
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

Value sources: `source` (from file), `value` (inline literal), `source-path` (extract from JSON/TOML file)
Actions: `header`, `query-param`, `remove-header`
Formatting: `format` (`{}` substitution)
Filtering: `url-path` (default `*`)
