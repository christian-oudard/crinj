# crinj

Local MITM proxy that injects credentials into outbound HTTP requests based on TOML rules. Designed for sandboxing AI agents that need API access without direct credential access.

## Commands

```bash
cargo build                    # Build
cargo test                     # Run tests
cargo run -- --rules-file rules.toml  # Run with rules
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
  local.rs     # TOML rule loading and value resolution
flake.nix      # Nix build + NixOS module
```

## Rules format

```toml
[[rules]]
host = "api.example.com"
path = "*"
[[rules.inject]]
action = "set_header"
name = "authorization"
value-file = "~/.secrets/api-key"
value-prefix = "Bearer "
require = true
```

Actions: `set_header`, `replace_header`, `remove_header`, `set_query_param`
Value sources: `value` (inline), `value-file` (from file), `value-path` (extract from JSON/TOML file)
Value formatting: `value-format` (`{value}` substitution), `value-prefix`
