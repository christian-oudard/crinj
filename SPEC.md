# crinj

A local MITM proxy for sandboxing tools (typically AI agents) that need API access without direct credential access. The tool sends placeholder headers or query parameters; crinj transparently replaces them with real secrets before forwarding.

## How it works

1. The agent is pointed at crinj as its HTTPS proxy.
2. For each outbound `CONNECT`, crinj selects one matching host entry from its config.
   - If no host entry matches, traffic is tunneled through unchanged.
   - If one matches, crinj terminates TLS, generates a leaf cert on the fly, and forwards.
3. For each request on a matched host, crinj evaluates access control then applies inject entries.

## Config

TOML. A config is a list of host entries. Unknown fields (a typo or an unsupported block) fail config load naming the offending field, rather than being silently ignored.

```toml
[[host]]
domain = "api.example.com"
access = """
block *
allow /v1/*
"""
[[host.inject]]
source = "api-key"
header = "Authorization"
format = "Bearer {}"
```

### Host entry

Canonical field order:

1. `domain` — match pattern, or list of patterns (required). A scalar string or a TOML array. Multiple patterns in one block share all other fields (access, inject, oauth). Use this when disjoint domains share one OAuth login and cannot be covered by a single wildcard.
2. `no-check-certificate` — skip upstream TLS verification (bool, default false)
3. `access` — access control list (multiline string, optional)
4. `source` — host-level default source, inherited by inject entries (optional; omit when only one inject entry uses it)
5. `inject` — `[[host.inject]]` sub-tables (list)

### Inject entry

Canonical field order:

1. `url-path` — path match pattern (default `*`)
2. `ports` — port list (array of u16, default all)
3. `source` — credential source file
4. `source-path` — dot-notation path into a structured source (JSON/TOML)
5. `source-sqlite` — SQLite database path (alternative to source, for dynamic values)
6. `source-sqlite-query` — SQL query returning one text value (required with source-sqlite)
7. `value` — inline literal (alternative to source/source-path)
8. `header` / `query-param` / `remove-header` — action (exactly one)
9. `format` — format string, `{}` substituted with resolved value

Each inject entry must have exactly one action. Credential source resolution:
- `source` alone: read the whole file (trimmed)
- `source` + `source-path`: parse as JSON/TOML (by extension) and extract the dotted path
- `source-sqlite` + `source-sqlite-query`: query a SQLite database at request time (see below)
- `value`: use the inline literal instead
- If no entry-level `source`, inherit the host-level `source`.

### SQLite sources

For credentials that change over time (e.g. session cookies cached in a database), use `source-sqlite` and `source-sqlite-query` instead of `source`:

```toml
[[host]]
domain = "main.yhlsoft.com"
[[host.inject]]
source-sqlite = "~/.cache/rhs/account_data.sqlite"
source-sqlite-query = "SELECT json_extract(value, '$._yhlsoft_user') FROM cache WHERE key = 'cookie'"
header = "Cookie"
format = "_yhlsoft_user={}"
```

- `source-sqlite`: path to a SQLite database file (resolved like `source`: bare names relative to `secrets/`, `~/` for home, `/` for absolute)
- `source-sqlite-query`: SQL query that returns a single text value (first column of first row)

The query runs on every matching request, so the injected value always reflects the current database content. The database is opened read-only with a 1-second busy timeout.

`source-sqlite` cannot be combined with `source`, `source-path`, or `value`. Both `source-sqlite` and `source-sqlite-query` must be present together.

If the database does not exist at startup, crinj accepts the config (the file may be created later). If the query fails at request time (missing file, no rows, locked database), the injection is skipped with a warning log.

Permission check: if the file exists at config load time, it must be mode 0o600 (same as other secret files).

### OAuth passthrough

For an OAuth provider, crinj brokers the token flow so a sandboxed client never holds a usable refresh token, and (for opaque-token providers) never a real access token either. The real tokens are captured in transit at the provider's token endpoint and held in a server-side vault; the client only ever sees opaque placeholders.

OAuth is configured with a single `[host.oauth]` table under the `[[host]]` it protects — that host is the resource host:

```toml
[[host]]
domain = "api.anthropic.com"
access = "allow /v1/*"
[host.oauth]
token-host = "platform.claude.com"   # the IdP token endpoint
token-path = "/v1/oauth/token"
```

`[host.oauth]` carries exactly two keys: `token-host` (defaulting to the resource domain) and `token-path`. There is no vault name and no configured fakes — a host injects one bearer, brokered through one token endpoint.

The token host is **auto-intercepted** — crinj synthesizes an interception entry for it, so it needs no `[[host]]` of its own (the resource host already has one).

A host family that shares one login (one token authorizes a whole API family, e.g. Google's `*.googleapis.com`) can be a single wildcard resource host, or a `domain` list when the domains are disjoint and cannot be covered by a wildcard. Either way the endpoint is stated once with no repetition:

```toml
[[host]]
domain = "*.googleapis.com"
[host.oauth]
token-host = "oauth2.googleapis.com"
token-path = "/token"
```

Placeholders are **auto-minted**: crinj issues a placeholder that mimics the captured token's prefix (so a client-side format check like Anthropic's `sk-ant-oat01-` passes) with a unique random suffix. The suffix makes each login distinct, so one issuer can broker many tokens at once (multiple accounts, OAuth clients, or scopes); it is stable within a login, so the client's stored credentials do not change across refreshes.

The flow is selective body rewrite at the token endpoint plus header injection on the resource host:

- **Initial grant response** (e.g. `authorization_code`): mint a unique placeholder pair, store a new vault row (real tokens + placeholders + token endpoint), and return the placeholders in the response body. The refresh-token field is replaced, not omitted, so a client that requested `offline_access` does not error on a missing token.
- **Refresh request** (`grant_type=refresh_token`): match the vault row by the client's placeholder refresh token, swap in the real one, and forward upstream. A refresh whose token crinj does not recognize is passed through untouched.
- **Refresh response:** rotate the real tokens in the matched row and return the same stable placeholders.
- **Resource host:** match the vault row by the client's placeholder bearer and inject that row's real access token. The token is injected only when the placeholder belongs to the issuer governing this host, so a misdirected token is never sent to the wrong host.

Token request and response bodies are parsed by `Content-Type`: `application/x-www-form-urlencoded` (the OAuth 2.0 default, used by most providers) or JSON. The body is re-serialized in its original format, so the swap is transparent to client and provider. A body that parses as neither is forwarded untouched.

Refresh is reactive: the client's own refresh request drives the real upstream refresh, so there is no background refresher. There is no id_token / OIDC handling — any id_token in a response is passed through untouched. DPoP / sender-constrained tokens (RFC 9449) are out of scope; confirm a provider issues plain bearer tokens before configuring it.

The vault is shared across connections, so a login captured on one connection authorizes API calls on another. It is persisted to a SQLite database at `<data-dir>/oauth.db` (mode 0600, one row per login keyed by the placeholder access token), written on every capture and restored at startup, so captured tokens survive a crinj restart: the client keeps using its placeholders and crinj still maps them to the real tokens, with no re-login. A real access token that expired while crinj was down is refreshed reactively on the client's next refresh request.

### JWT-bearer signing

For a service account (RFC 7523 jwt-bearer, e.g. a Google service-account key), the client authenticates by signing a short-lived assertion with a private key, not by sending a bearer secret. There is no static value in the request to swap, only a per-request signature, so brokering by substitution cannot work. Instead crinj holds the real key and **signs** the assertion. The sandboxed client holds only a throwaway key: it can assemble a well-formed request, but its assertion grants nothing until crinj replaces it.

JWT is configured with a `[host.jwt]` table under the resource `[[host]]`, parallel to `[host.oauth]`. The token host is auto-intercepted the same way. A host may not declare both `[host.oauth]` and `[host.jwt]`.

```toml
[[host]]
domain = "*.googleapis.com"
[host.jwt]
token-host = "oauth2.googleapis.com"   # defaults to the resource domain
token-path = "/token"
key = "sa-key.pem"                      # source path to the real private key (PKCS#1 or PKCS#8 PEM)
issuer = "svc@proj.iam.gserviceaccount.com"
scope = "https://www.googleapis.com/auth/logging.read"
# audience defaults to https://<token-host><token-path>
# alg defaults to RS256 (RS256/RS384/RS512 supported)
# kid optional (JWS header; set to the key's private_key_id so Google selects the cert)
# sub optional; setting it opts into domain-wide-delegation impersonation
```

The claims crinj puts in the assertion (`iss`, `scope`, optional `sub`, `aud`, `iat`, `exp`) are fixed by config, not copied from the client's assertion, so a sandboxed client cannot widen its own scope or impersonate a subject. `iat`/`exp` come from crinj's clock with a one-hour lifetime (Google's cap). The key is read at startup from a source file (mode 0600, like any secret); an absent key skips the block with a warning rather than failing the load.

The flow reuses the OAuth machinery. At the token endpoint:

- **jwt-bearer request** (`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`): crinj reads the (unverified) `iss` from the client's assertion to route to the matching signer, then replaces the assertion with one it signs from the fixed claims. A jwt-bearer request whose issuer matches no configured signer is passed through untouched.
- **response:** captures the real access token and returns a placeholder, exactly as an OAuth initial grant does. jwt-bearer returns no refresh token; renewal is the client re-signing and re-exchanging, which crinj re-signs again.
- **resource host:** the placeholder bearer is swapped for the real access token, identical to OAuth.

Because there is no refresh token to key renewals by, a jwt-bearer login is keyed in the vault by its authority (token endpoint plus the fixed claims), so a renewal rotates the existing row under one stable placeholder instead of accumulating rows. The vault is the same `oauth.db`; a service-account access token is an OAuth token regardless of how it was obtained.

### Glob patterns

`*` is the only metacharacter, matches any sequence of characters. Used in both domain and URL-path patterns.

- `*` — match everything
- `api.example.com` — exact
- `*.example.com` — any prefix ending with `.example.com`
- `http-intake.logs*.datadoghq.com` — any middle insertion
- `/v1/*` — any path starting with `/v1/`

### Host selection (most-specific-wins)

When multiple host entries could match a request's hostname, crinj picks the most specific:

1. Fewer `*` characters wins.
2. If tied, the one with the longer literal (non-`*`) portion wins.
3. If still tied, it's a config error (duplicate host).

If no host matches, the request is tunneled unchanged.

### Access control

`access` is a multiline string. Each non-empty, non-comment line is `<verb> <path>`, where `<verb>` is `block` or `allow` and `<path>` is a glob pattern.

Evaluation: last matching entry wins. If no entry matches (or the list is empty/omitted), the request is allowed.

When blocked, crinj returns a synthetic `200 OK` with body `{}` and Content-Type `application/json`. The upstream is not contacted.

#### Natural order

The config loader requires access entries to be in *natural order*: for any two entries where one's matched URL set is a superset of the other's, the broader must appear before the narrower. Disjoint entries may be in any order. Equal patterns are allowed (later wins).

Valid:
```
block *
allow /v1/*
block /v1/admin/*
```

Invalid (broader after narrower):
```
allow /v1/*
block *
```

This makes last-match-wins unambiguous — the same effect could be computed by longest-prefix-match, but the linear ordered form reads top-to-bottom.

### Inject entries

Inject entries are *cumulative*: every entry whose `url-path` and `ports` match applies. Multiple headers or query params from different entries are set independently.

All injections require a placeholder: the header or query parameter must already exist in the request. The tool sends a dummy value, and crinj replaces it with the real credential. This prevents accidental credential leakage if an entry matches a request the tool didn't expect to authenticate.

## Source path resolution

- Bare names (`api-key`) → `<config_dir>/secrets/<name>`
- `~/...` → home-relative
- `/...` → absolute

Secret files must have mode 0o600 (no group/world access) or crinj refuses to start.

## Runtime behavior

- Listens on a configurable local address and port.
- Generates and persists a CA cert at first startup. The tool must trust this CA to avoid TLS errors.
- `SIGHUP` reloads config without restart. If the new config has no host entries, the reload is rejected unless crinj was started with `--allow-empty-rules`.
- `--log-file` writes structured logs to a file.
- Losing the log consumer never kills the proxy: if stderr is a pipe whose reader has exited, log writes are dropped and crinj keeps serving.

## Non-goals

- Not a general-purpose reverse proxy.
- Not a secret store. Credentials live on disk as plain files; crinj only reads them.
- No outbound proxy auth (user:pass@host not supported in `HTTPS_PROXY`).
- No HTTP/2 upstream. HTTP/1.1 only.
