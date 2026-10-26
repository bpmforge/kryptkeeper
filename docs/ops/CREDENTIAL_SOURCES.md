# Credential sources: fetch target credentials from a secret manager (W38-07, D-324)

By default an SSH key or WinRM password is stored in the hub, encrypted, and used
for every scan and install. Many security teams will not hand a standing
credential to a new tool. With a **credential source** the hub stores only a
reference (a path and a version) and fetches the secret from your secret manager
**each time it uses the credential**: discovery, preflight, renewal installs,
rollouts, device API logins and upstream CA credentials all go through the same
`Resolve`, so they all work with an external credential.

| Source | How | Proven |
|---|---|---|
| HashiCorp Vault KV v2 | native | live, against Vault 1.20 |
| OpenBao KV v2 (same API) | native | live, against OpenBao 2 |
| CyberArk Central Credential Provider | plugin `kryptkeeper.cyberark-ccp` | conformance suite and in-hub test against a mock only |
| Delinea Secret Server | plugin `kryptkeeper.delinea-secret-server` | conformance suite and in-hub test against a mock only |

The proof record is `docs/release/LIVE_RESULTS_CREDENTIAL_SOURCES_v1.1.md`;
real CyberArk and Delinea instances are a ROADMAP "Needs partner hardware" row.

## What the hub does and does not keep

- An external credential row holds `source_id`, a `reference` and optional
  `static` fields. **No secret, no envelope.** `GET /api/v1/credentials` shows
  those three fields and nothing else.
- Every use fetches again. The fetched payload is handed to the caller, which
  wipes it as it does for a local credential; the HTTP body the hub read is wiped.
  A Go string cannot be zeroized, so the decoded field values live until the
  garbage collector frees them: that is why the default keeps nothing.
- Optional cache: `config.cache_ttl_seconds` (1 to 300) holds the payload in
  memory that long (and never past a plugin's `lease_seconds`), wiped on expiry.
  The default is 0.
- The login to the manager is the one secret that stays in the hub: a **local**
  `api_token` credential. A source whose login is itself external is refused
  (it would loop).
- Failures are clear errors to the caller and audit rows: `credential.resolve`
  with `source=<kind>:<id>`, `credential_type`, `outcome=ok|error` and for errors
  `class=` one of `not_found`, `denied`, `login_failed`, `rate_limited`,
  `source_unavailable`, `invalid_payload`, `config`. The row never carries a value.
- Connections to Vault, OpenBao and plugin hosts go through the egress guard:
  https is required, redirects off the host and proxies are refused, loopback and
  link-local (cloud metadata) are never reachable, and a private server CA is
  pinned with `config.ca_cert_pem`.
- A source belongs to one tenant, like a credential. A credential can only use a
  source of its own tenant; a cross-tenant resolve is refused even if a row were
  forced across.

## 1. Vault or OpenBao

Prepare the manager (KV v2 mount, a read-only policy for the paths the hub needs,
and a token or an AppRole bound to it):

```bash
vault secrets enable -path=secret -version=2 kv
printf 'path "secret/data/ssh/*" { capabilities = ["read"] }\n' | vault policy write kryptkeeper-read -
vault token create -policy=kryptkeeper-read           # or an AppRole with token_policies=kryptkeeper-read
vault kv put -mount=secret ssh/web1 private_key_pem=@id_ed25519 user=kkscan \
  host_public_key="ssh-ed25519 AAAA..." port=22
```

Give the hub the login as a local credential:

```bash
curl -X POST "$HUB/api/v1/credentials" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"name":"vault login","credential_type":"api_token","payload":{"token":"hvs...."}}'
# AppRole instead: "payload":{"role_id":"...","secret_id":"..."}  (a login is never reused across uses)
```

Create the source, test a reference, then the credential:

```bash
curl -X POST "$HUB/api/v1/credential-sources" ... -d '{"name":"prod vault","kind":"vault_kv2","credential_ref":"<login id>",
  "config":{"base_url":"https://vault.example.com:8200","mount":"secret","namespace":"team-a","ca_cert_pem":"-----BEGIN CERTIFICATE-----..."}}'
curl -X POST "$HUB/api/v1/credential-sources/<source id>/test" ... \
  -d '{"credential_type":"ssh_key","reference":{"path":"ssh/web1"}}'      # -> {"ok":true,"fields":[...]}  names only
curl -X POST "$HUB/api/v1/credentials" ... \
  -d '{"name":"web1 ssh","credential_type":"ssh_key","source":"external","source_id":"<source id>",
       "reference":{"path":"ssh/web1","version":"3"}}'                    # version is optional; omit for latest
```

`namespace` is sent as `X-Vault-Namespace`; `mount` defaults to `secret`;
`approle_mount` to `approle`. The read is `GET /v1/<mount>/data/<path>[?version=N]`
([KV v2 API](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#read-secret-version));
live 200, 403 and 404 answers are recorded in the results file. A missing path, a
deleted version and a destroyed version all answer 404 and read as "not found".

## 2. How secret fields become the credential

Names match the payload the credential type reads. The hub validates the result
and refuses a secret that does not fit, naming fields and never values.

| credential_type | The secret must hold | Notes |
|---|---|---|
| `ssh_key` | `private_key_pem`, `user`, `host_public_key`; optional `port`, `keystore_password`, `keystore_format`, `sudo_mode`, `sudo_password`, `helper_sha256` | sudo fields are validated as for a stored credential; other fields are dropped |
| `windows_password` | `base_url`, `username`, `password` | every other field passes through: the IIS and SQL Server installers read `ipport`, `app_id`, `store_name`, `sql_instance`, `sql_port` from the same payload |
| `api_token` | any fields: they become the JSON object plugins, upstream CAs and inventory sources read; a secret holding only `value` is a raw token string | |
| `cloud_iam` | any fields (JSON object) | |

`static` supplies non-secret fields the manager does not hold (for example
`host_public_key` or `base_url`). Names that look like secrets (password, token,
private, api key, key_pem, credential...) are refused: the hub never stores a
secret for an external credential.

## 3. CyberArk and Delinea (plugins)

Install and enable the plugin like any other
([DELIVERY_PLUGINS.md](DELIVERY_PLUGINS.md)). A credentials plugin declares the
**Critical** capability `provide_credentials` ("This plugin returns credentials
the hub uses to log in to your systems.") plus network access, so enabling it
waits in Approvals for a second pki-admin.

| Plugin id | Source login (local `api_token` JSON) | Reference keys |
|---|---|---|
| `kryptkeeper.cyberark-ccp` | `base_url` (the CCP host), `app_id` | `safe`, `object` (required), `folder`, `username`, `address`, `map` |
| `kryptkeeper.delinea-secret-server` | `base_url`, `username`, `password`, optional `domain` | `secret_id` (required, numeric), `map` |

`map` renames the manager's fields onto the payload's, as `SourceField:payload_field`
pairs. CyberArk defaults to `Content:password,UserName:username,Address:address`,
so an SSH key stored as a CyberArk object needs
`map=Content:private_key_pem,UserName:user`. Delinea defaults to
`username:username,password:password`, with fields named by item slug, e.g.
`map=private-key:private_key_pem,username:user`.

```bash
curl -X POST "$HUB/api/v1/credential-sources" ... \
  -d '{"name":"ccp","kind":"plugin","credential_ref":"<login id>","config":{"plugin_id":"kryptkeeper.cyberark-ccp"}}'
```

- **CyberArk CCP:** `GET {base_url}/AIMWebService/api/Accounts?AppID=&Safe=&Object=`.
  CCP authenticates the caller by the AppID's **allowed machines** list (the hub's
  address) or by a client certificate; this release supports AppID plus allowed
  machines. Client-certificate (mTLS) authentication is a ROADMAP row. Values may
  not contain `+`, `&` or `%` (CyberArk documents them as unsupported). The
  CyberArk documentation pages were not reachable when this was built. The
  response keys (`Content`, `Username`/`UserName`, `Address`, ...) come from the
  RETURN block of CyberArk's own Ansible module, and a mapped field is matched
  ignoring case; the error `ErrorCode` is read as a short code and not verified.
  A run against a real CCP is the partner-hardware row.
- **Delinea Secret Server:** `POST {base_url}/oauth2/token` (form `grant_type=password`,
  `username`, `password`) then `GET {base_url}/api/v1/secrets/{id}` with the bearer
  token ([Delinea authentication guide](https://docs.delinea.com/online-help/secret-server-11-6-x/api-scripting/authenticating/index.htm)).
  Delinea Platform's client-credentials flow is not covered. Secret Server reports
  no lease, so none is passed on.

A plugin cannot keep what it fetches: each call is a fresh instance, and the hub
redacts every returned value from the plugin's own log and HTTP events before
they are recorded.

## 4. API

Admin role. All writes are audited (`credential_source.create`, `.delete`, `.test`,
`credential.create`, and `credential.resolve` for every fetch).

| Route | Use |
|---|---|
| `GET /api/v1/credential-sources` | sources of the caller's tenant |
| `POST /api/v1/credential-sources` | `{name, kind: vault_kv2 \| plugin, credential_ref, config}` |
| `DELETE /api/v1/credential-sources/{id}` | refused (409) while a credential uses it |
| `POST /api/v1/credential-sources/{id}/test` | `{credential_type, reference, static}` -> `{ok, fields \| error}` |
| `POST /api/v1/credentials` | add `source: "external"`, `source_id`, `reference`, `static`; no `payload` |

In the UI, Target Setup's credential step asks "Where does the secret live?":
store it here, or fetch it from a secret manager (pick a source, give the
reference, test it). Sources themselves are created through the API in this
release.

## 5. Limits worth knowing

- A failed fetch fails that scan or renewal with the manager's reason; there is
  no stale fallback. A manager outage stops installs that need the credential.
- Every use is a manager read. The audit trail therefore has one
  `credential.resolve` row per use; a busy fleet makes many rows.
- The Vault token or AppRole `secret_id` that logs in is stored in the hub like
  any local credential. Prefer a read-only policy scoped to the paths the hub
  needs and a short token TTL or AppRole.
