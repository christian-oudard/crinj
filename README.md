# Crinj

**CR**edential **INJ**ector. A local MITM proxy that injects API credentials into outbound HTTP requests based on declarative TOML config.

Designed for sandboxing AI agents and CLI tools that need API access without direct credential access. The agent talks through Crinj, which transparently adds the right headers or query parameters before forwarding to the real API.

## How it works

1. Configure your agent to use `http://127.0.0.1:10255` as its HTTP proxy
2. Crinj intercepts HTTPS requests, generates a TLS certificate for each target host, and forwards the request upstream
3. For hosts matching your config, Crinj injects credentials (headers or query params) before forwarding
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
crinj --config ~/.config/crinj/config.toml
```

On first run, Crinj generates a CA certificate at `~/.local/share/crinj/gateway/ca.pem`. Trust this CA in your agent's environment to avoid TLS errors.

Send `SIGHUP` to reload config without restarting.

## Config

Host entries are defined in TOML. Each entry matches a domain and injects credentials into matching requests. All injections require a placeholder: the header or query parameter must already exist in the request. The agent sends a dummy value, and Crinj replaces it with the real credential.

Most entries need a single rule, written inline:

```toml
[[host]]
domain = "huggingface.co"
source = "~/.config/crinj/secrets/huggingface.key"
header = "Authorization"
format = "Bearer {}"

[[host]]
domain = "api.stlouisfed.org"
source = "~/.config/crinj/secrets/fred.key"
query-param = "api_key"

[[host]]
domain = "api.schwabapi.com"
source = "~/.cache/rhs/schwab_token.json"
source-path = "token.access_token"
header = "Authorization"
format = "Bearer {}"
```

For multiple rules per host, use `[[host.rule]]` sub-tables (which inherit the host-level `source`):

```toml
[[host]]
domain = "api.modal.com"
source = "~/.config/modal/modal.toml"
[[host.rule]]
source-path = "christian-oudard.token_id"
header = "x-modal-token-id"
[[host.rule]]
source-path = "christian-oudard.token_secret"
header = "x-modal-token-secret"
```

For other multi-rule cases:

```toml
[[host]]
domain = "api.example.com"
[[host.rule]]
source = "~/.config/creds.toml"
source-path = "account.token"
header = "x-token"
format = "Bearer {}"
[[host.rule]]
remove-header = "x-debug"
```

### Host fields

| Field | Description |
|---|---|
| `domain` | Domain to match. Supports wildcards: `*.example.com` |
| `source` | Default source file, inherited by rules |

### Rule fields

| Field | Description |
|---|---|
| `source` | Read value from a file (trimmed). Overrides host-level source |
| `value` | Inline literal value (alternative to source) |
| `source-path` | Dot-notation path into a structured source file (auto-detects JSON/TOML). Numeric segments index arrays |
| `header` | Header to set |
| `query-param` | Query parameter to set |
| `remove-header` | Header to remove (no value needed) |
| `format` | Format string, `{}` is replaced with the resolved value (e.g. `"Bearer {}"`) |
| `url-path` | URL path pattern. Default `*`. Supports prefix wildcards: `/v1/*` |

## NixOS

```nix
{
  inputs.crinj.url = "github:christian-oudard/crinj";

  # ...

  services.crinj = {
    enable = true;
    configFile = ./config.toml;
  };
}
```

## License

Apache 2.0. Forked from [OneCLI](https://github.com/onecli/onecli).
