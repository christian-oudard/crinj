# Crinj

**CR**edential **INJ**ector. A local MITM proxy that injects API credentials into outbound HTTP requests based on declarative TOML rules.

Designed for sandboxing AI agents and CLI tools that need API access without direct credential access. The agent talks through Crinj, which transparently adds the right headers or query parameters before forwarding to the real API.

## How it works

1. Configure your agent to use `http://127.0.0.1:10255` as its HTTP proxy
2. Crinj intercepts HTTPS requests, generates a TLS certificate for each target host, and forwards the request upstream
3. For hosts matching your rules, Crinj injects credentials (headers or query params) before forwarding
4. For unmatched hosts, traffic is tunneled through without interception

## Install

```bash
# From source
cargo build --release

# With Nix
nix build
nix run .#crinj
```

## Usage

```bash
crinj --rules-file ~/.config/crinj/rules.toml
```

On first run, Crinj generates a CA certificate at `~/.local/share/crinj/gateway/ca.pem`. Trust this CA in your agent's environment to avoid TLS errors.

Send `SIGHUP` to reload rules without restarting.

## Rules

Rules are defined in TOML. Each rule matches a hostname and injects credentials into matching requests.

```toml
# Inject an API key as a query parameter
[[rules]]
host = "api.stlouisfed.org"
[[rules.inject]]
action = "set_query_param"
name = "api_key"
value-file = "~/.config/crinj/secrets/fred.key"

# Inject a header from a file
[[rules]]
host = "huggingface.co"
[[rules.inject]]
action = "set_header"
name = "Authorization"
value-file = "~/.config/crinj/secrets/huggingface.key"
value-prefix = "Bearer "

# Extract a value from a JSON file
[[rules]]
host = "api.schwabapi.com"
[[rules.inject]]
action = "set_header"
name = "Authorization"
value-file = "~/.cache/rhs/schwab_token.json"
json-path = "token.access_token"
value-prefix = "Bearer "

# Extract from a TOML config file
[[rules]]
host = "api.modal.com"
[[rules.inject]]
action = "set_header"
name = "x-modal-token-id"
value-file = "~/.config/modal/modal.toml"
value-path = "default.token_id"
[[rules.inject]]
action = "set_header"
name = "x-modal-token-secret"
value-file = "~/.config/modal/modal.toml"
value-path = "default.token_secret"
```

### Actions

All actions require a placeholder: the header or query parameter must already exist in the request for injection to occur. The agent sends a dummy value, and Crinj replaces it with the real credential.

| Action | Description |
|---|---|
| `set_header` | Replace a header's placeholder value with the real credential |
| `remove_header` | Remove a header |
| `set_query_param` | Replace a query parameter's placeholder value with the real credential |

### Value sources

| Field | Description |
|---|---|
| `value` | Inline literal value |
| `value-file` | Read value from a file (trimmed) |
| `value-path` | Dot-notation path into a structured file (format auto-detected from extension) |
| `json-path` | Alias for `value-path` on JSON files |

### Value formatting

| Field | Description |
|---|---|
| `value-format` | Format string with `{value}` placeholder |
| `value-prefix` | Prepend a string (convenience for `Bearer ` etc.) |

### Options

| Field | Description |
|---|---|
| `host` | Hostname to match. Supports wildcards: `*.example.com` |
| `path` | Path pattern. Default `*`. Supports prefix wildcards: `/v1/*` |

## NixOS

```nix
{
  inputs.crinj.url = "github:christian-oudard/crinj";

  # ...

  services.crinj = {
    enable = true;
    rulesFile = ./rules.toml;
  };
}
```

## License

Apache 2.0. Forked from [OneCLI](https://github.com/onecli/onecli).
