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
crinj --config ~/.config/crinj/rules.toml
```

On first run, Crinj generates a CA certificate at `~/.local/share/crinj/gateway/ca.pem`. Trust this CA in your agent's environment to avoid TLS errors.

Send `SIGHUP` to reload config without restarting.

## Config

Host entries are defined in TOML. Each entry matches a domain and injects credentials into matching requests. All injections require a placeholder: the header or query parameter must already exist in the request. The agent sends a dummy value, and Crinj replaces it with the real credential.

Every inject entry lives in its own `[[host.inject]]` sub-table:

```toml
[[host]]
domain = "huggingface.co"
[[host.inject]]
source = "~/.config/crinj/secrets/huggingface.key"
header = "Authorization"
format = "Bearer {}"

[[host]]
domain = "api.stlouisfed.org"
[[host.inject]]
source = "~/.config/crinj/secrets/fred.key"
query-param = "api_key"

[[host]]
domain = "api.schwabapi.com"
[[host.inject]]
source = "~/.cache/rhs/schwab_token.json"
source-path = "token.access_token"
header = "Authorization"
format = "Bearer {}"
```

When multiple inject entries share a source file, lift `source` to the host level — entries inherit it:

```toml
[[host]]
domain = "api.modal.com"
source = "~/.config/modal/modal.toml"
[[host.inject]]
source-path = "christian-oudard.token_id"
header = "x-modal-token-id"
[[host.inject]]
source-path = "christian-oudard.token_secret"
header = "x-modal-token-secret"
```

### Host fields

| Field | Description |
|---|---|
| `domain` | Domain to match. Supports wildcards: `*.example.com` |
| `no-check-certificate` | Skip upstream TLS verification (bool, default false) |
| `access` | Access control list (multiline string, `block`/`allow` lines) |
| `source` | Default source file, inherited by inject entries |

### Inject entry fields

| Field | Description |
|---|---|
| `url-path` | URL path pattern. Default `*`. Supports wildcards: `/v1/*` |
| `ports` | Port list (array of u16, default all) |
| `source` | Read value from a file (trimmed). Overrides host-level source |
| `source-path` | Dot-notation path into a structured source file (auto-detects JSON/TOML). Numeric segments index arrays |
| `value` | Inline literal value (alternative to source) |
| `header` | Header to set |
| `query-param` | Query parameter to set |
| `remove-header` | Header to remove (no value needed) |
| `format` | Format string, `{}` is replaced with the resolved value (e.g. `"Bearer {}"`) |

## OAuth & JWT token brokering

Beyond static injection, crinj can broker a full OAuth 2.0 or JWT-bearer flow so a sandboxed client never holds a usable refresh token or private key. crinj captures the real tokens at the provider's token endpoint into a server-side vault and hands the client opaque **placeholders**; on each request to the resource host it swaps the placeholder back for the real token. The token host is auto-intercepted and needs no `[[host]]` of its own. See `SPEC.md` for the mechanism.

### OAuth (opaque-token providers)

```toml
[[host]]
domain = "api.anthropic.com"        # the resource host
[host.oauth]
token-host = "platform.claude.com"
token-path = "/v1/oauth/token"
```

### JWT-bearer (Google service accounts / gcloud)

For a service account the client signs a short-lived assertion with a private key rather than sending a bearer secret. crinj holds the real key and re-signs the assertion; the sandboxed client holds only a throwaway key.

```toml
[[host]]
domain = "*.googleapis.com"         # resource hosts: logging, storage, ...
[host.jwt]
token-host = "oauth2.googleapis.com"
token-path = "/token"
key = "gcp-service-account.json"    # the real key, crinj-side only
key-path = "private_key"
iss = "readonly@my-project.iam.gserviceaccount.com"
scope = "https://www.googleapis.com/auth/cloud-platform"
kid = "<private_key_id>"            # so Google selects the signing cert
```

The sandboxed copy of the key file keeps a **valid-PEM but throwaway** `private_key`; only crinj's copy has the real key. The client assembles a well-formed but unusable assertion, and crinj replaces it.

Both service-account flavors are brokered: the RFC 7523 token exchange (assertion re-signed at the token endpoint, access token vaulted and placeheld) and **self-signed JWT bearers** (Google AIP-4111, the GAPIC client libraries' default), which crinj re-signs directly at the resource host. Stock Google client libraries work unmodified, over both gRPC and REST.

### Client setup for Google Cloud

- **Trust the CA.** Point the client at crinj's CA. Most tools read `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE`, but **gRPC's C-core ignores those** — it reads `GRPC_DEFAULT_SSL_ROOTS_FILE_PATH`. Set it to a bundle containing crinj's CA.
- **HTTP/2 and gRPC** are supported: the leaf advertises `h2` over ALPN and crinj bridges h2 (including gRPC trailers) end-to-end.
- **Don't diagnose with raw curl.** `curl -H "Authorization: Bearer <placeholder>"` straight at a resource endpoint always 401s — there is no token exchange for crinj to intercept, and a hand-built header is not a JWT crinj re-signs. Drive a real client (google-auth, gcloud, a GAPIC library).

## NixOS

```nix
{
  inputs.crinj.url = "github:christian-oudard/crinj";

  # ...

  services.crinj = {
    enable = true;
    configFile = ./rules.toml;
  };
}
```

## License

Apache 2.0. Forked from [OneCLI](https://github.com/onecli/onecli).
