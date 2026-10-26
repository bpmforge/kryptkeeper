# Renewing at the original CA: the ACME upstream connector

An ACME connector renews certificates **at the CA that issued them**
(Let's Encrypt, ZeroSSL, Google Trust Services, or any RFC 8555 CA,
including private ones), then runs Kryptkeeper's own install, verify and
rollback. The customer keeps the CA relationship; Kryptkeeper keeps the
renewal loop. This is the "renew upstream" path of the estate takeover
(W11-04, W20-29).

## 1. Choose a challenge

| Challenge | Use when | Needs |
|---|---|---|
| `http-01` (default) | The CA can reach the hub on port 80 at the certificate's name | `http01_listen`, e.g. `":80"` |
| `dns-01` | The hub is internal (the usual case), or the name is a wildcard | A DNS provider API credential |

`dns-01` providers: **Cloudflare**, Route 53, Azure DNS, Google Cloud DNS,
RFC 2136, CNAME delegation (`delegated`), and **`plugin`**: a signed DNS plugin
(DigitalOcean, GoDaddy, NS1 and Akamai Edge DNS ship with Kryptkeeper; see
[`dns_provider: plugin`](#dns_provider-plugin-a-signed-dns-plugin)).

## 2. Credential (dns-01 via Cloudflare)

Create a Cloudflare API token from the **Edit zone DNS** template, limited
to the one zone the certificates live in. Store it as an outbound
credential; it is encrypted at rest and never returned by the API or
written to logs or audit:

```json
POST /api/v1/credentials
{
  "name": "cloudflare-dns",
  "credential_type": "api_token",
  "payload": {"cloudflare_api_token": "<token>"}
}
```

The same payload may also carry `account_key_pem` (keep one ACME account
across restarts; recommended for public CAs) and `eab_kid` / `eab_hmac_b64`
(CAs that require External Account Binding).

## 3. Connector

```json
POST /api/v1/connectors
{
  "name": "Let's Encrypt (dns-01)",
  "type": "acme",
  "credential_ref": "<credential id>",
  "config_json": "{\"directory_url\":\"https://acme-v02.api.letsencrypt.org/directory\",\"email\":\"pki@example.com\",\"challenge\":\"dns-01\",\"dns_provider\":\"cloudflare\"}"
}
```

Use `https://acme-staging-v02.api.letsencrypt.org/directory` while
trying it out: staging certificates are untrusted but have generous rate
limits.

## 4. Put certificates on it

From the estate view (or `POST /api/v1/estate/takeover`) pick
**Renewal path: connector** and this connector. Renewals for that
certificate, scheduled or `POST /api/v1/renewal/execute`, then order at the
CA.

## What happens during a dns-01 order

1. The hub finds the Cloudflare zone holding `_acme-challenge.<name>`
   (wildcards are validated at their base name).
2. It creates a TXT record (TTL 60) and waits until the record is visible
   by the configured propagation method (see below; by default every
   authoritative nameserver serves it, up to 3 minutes), so the CA's
   validator does not see a stale answer.
3. The CA validates; the hub finalizes and downloads the chain.
4. The TXT record is deleted, also when the order fails.
5. Install, verify (the served certificate's fingerprint) and rollback run
   as for any renewal.

A failed order reports the CA's own problem detail, or names the
nameserver that never served the record.

### `dns_provider: delegated` (acme-dns): the TXT is not removed

Step 4 above does not hold for the CNAME-delegation provider. acme-dns has no
delete call: it keeps the last two TXT values per account, and each value is
a one-time digest of that order's key authorization, so a leftover value
cannot validate anything. Nothing is removed after validation, and the
connector's cleanup is a no-op.

Set `dns_propagation` to `resolver`, `doh` or `none` for this provider. The
`authoritative` check asks the zone's own nameservers, which do not follow the
out-of-zone `_acme-challenge` CNAME to the acme-dns name.

### `dns_provider: plugin`: a signed DNS plugin

DNS providers without a built-in adapter run as signed WebAssembly plugins of
kind `dns01` (see [`docs/plugins/README.md`](../plugins/README.md#the-dns01-kind)).
The plugin only writes and deletes the TXT record. The hub still checks that
the record is visible (`dns_propagation`, below) and the CA still validates,
so a plugin cannot make a challenge pass.

1. Install the plugin (`POST /api/v1/delivery-plugins`, or the Plugins page)
   and have a second person enable it: it reaches the provider's API host, so
   it is a High capability. The first-party ones are built by
   `bash scripts/build-plugins.sh` into `dist/plugins/`.
2. Create an outbound credential of type `api_token` whose secret is a JSON
   object of the plugin's credential fields:

   | Plugin | Secret JSON |
   |---|---|
   | `kryptkeeper.digitalocean-dns` | `{"api_token":"..."}` (scopes: domain read, create, delete) |
   | `kryptkeeper.godaddy-dns` | `{"api_key":"...","api_secret":"..."}` (a production key) |
   | `kryptkeeper.ns1-dns` | `{"api_key":"..."}` |
   | `kryptkeeper.akamai-edgedns` | `{"host":"https://akab-xxxx.luna.akamaiapis.net","client_token":"...","client_secret":"...","access_token":"..."}` (the `.edgerc` values; `host` as an `https://` URL; read-write access to Edge DNS) |

3. Point the connector at both, with `dns_provider` `plugin`:

   ```json
   {"directory_url":"https://acme-v02.api.letsencrypt.org/directory","email":"pki@example.com",
    "challenge":"dns-01","dns_provider":"plugin",
    "dns_plugin_id":"kryptkeeper.digitalocean-dns","dns_plugin_credential":"cred-do-dns"}
   ```

   `dns_plugin_id` and `dns_plugin_credential` are names, not secrets. The
   credential must belong to the connector's tenant. The connector's own
   `credential_ref` still holds only the ACME account key and EAB.

The plugin finds the zone itself, longest parent first, so a delegated
subdomain managed as its own zone wins. GoDaddy's minimum TTL is 600 seconds,
so with that plugin the record stays cached up to ten minutes: leave
`dns_propagation` on `auto` rather than `none`.

Each present and cleanup writes an audit row (`delivery_plugin.dns01_present`,
`delivery_plugin.dns01_cleanup`) with the plugin version and module hash. A
cleanup that fails is logged and does not fail an order that already issued; a
leftover challenge record is untidy, not unsafe. When plugins are turned off
(`KRYPTKEEPER_DELIVERY_PLUGINS=off`), or the plugin is disabled or is not a
`dns01` plugin, an order fails at the first challenge, before any plugin call
(the order is already open at the CA by then).

GoDaddy: the plugin uses the v1 API with the classic `sso-key` developer key.
GoDaddy lists that credential as deprecated for Domains through 2026; a v3
plugin with personal access tokens is on the roadmap.

## How propagation is checked (`dns_propagation`)

The check only decides when the hub tells the CA to validate; the CA's
own validator remains the authority. Optional `config_json` fields:

| Field | Default | Meaning |
|---|---|---|
| `dns_propagation` | `auto` | `auto`, `authoritative`, `resolver`, `doh` or `none` |
| `dns_resolver` | system resolver | `host[:port]` of a recursive resolver (mode `resolver`; port defaults to 53) |
| `dns_doh_url` | `https://cloudflare-dns.com/dns-query` | DNS-over-HTTPS JSON endpoint (mode `doh`/`auto`); `https://dns.google/resolve` also works |
| `dns_propagation_timeout` | `3m` | Wait per name; maximum `10m` |
| `dns_propagation_delay` | `30s` | Mode `none`: fixed wait before the CA validates; maximum `10m` |

- `authoritative`: ask each of the zone's nameservers directly on port 53
  and require all of them to serve the record. Most precise.
- `resolver`: ask a recursive resolver (`dns_resolver`, else the system
  one). A caching resolver can hold a stale "no such record" answer for
  the zone's negative-cache TTL, so propagation may look slower.
- `doh`: ask a DNS-over-HTTPS JSON API (`application/dns-json` GET, the
  Cloudflare and Google form) over port 443.
- `none`: do not check; wait `dns_propagation_delay`, then validate.
- `auto` (default): start with `authoritative`. If **no** nameserver
  answers at all (every query times out or is refused), fall back to
  `doh`, then `resolver`. A nameserver that answers "no such record" is
  just propagation lag and does not trigger a fallback. The method used
  is logged once per renewal (`dns-01 propagation checked via ...`).

### Outbound port 53 blocked

Many enterprise networks block outbound port 53 except to a local
resolver. The authoritative check then never sees the record and the
renewal fails with `not visible at <ns> before the deadline`. `auto`
copes by itself when HTTPS egress works (the hub reaches the CA over
443 anyway): it falls back to DoH. To be explicit, or to use the local
resolver instead:

```json
{"challenge":"dns-01","dns_provider":"cloudflare","dns_propagation":"resolver","dns_resolver":"10.0.0.2"}
```

The DoH request carries only the record name and type: no credentials,
and never the DNS-provider token. It goes through the same egress guard
as `directory_url` (https only; loopback and link-local refused; private
space refused when `KRYPTKEEPER_EGRESS_DENY_PRIVATE=true`) and, like it,
does not use proxy environment variables. An internal DoH server on
private space therefore works by default.

`POST /api/v1/renewal/execute` allows an execution up to 15 minutes (the
10 minute propagation maximum plus order and install time) and always
answers with JSON, including when the renewal fails after the global
15 second server write timeout.

## Proof

`tests/live/acme-upstream/run.sh` runs the whole loop against Let's Encrypt
staging and a real Cloudflare zone: import an unmanaged certificate, take
it over onto a dns-01 connector, renew, install into nginx over SSH, verify
the served certificate, and check that no TXT record or token was left
behind. It needs the token in `~/.config/kryptkeeper-lab/cloudflare-token`.

## Network rules for `directory_url`

The hub reaches the CA through a guarded client (FG-8, OWASP-A10-002):

- `directory_url` must be `https`. Plain http is refused.
- The dialled address may not be loopback, link-local (including cloud
  metadata, 169.254.169.254), unspecified or multicast. Private space
  (RFC1918/ULA) is allowed so an internal CA works; set
  `KRYPTKEEPER_EGRESS_DENY_PRIVATE=true` to refuse it too.
- Redirects to a different host are refused; proxy environment variables
  are ignored.

`GET /api/v1/connectors` reports health as one of `healthy`, `unreachable`,
`blocked destination` or `directory returned an error status`. The underlying
error is written to the server log (`acme connector <id>: health probe
failed`), not returned to API callers.

## Retry-After survives restarts and is shared by replicas

When a CA answers 429, the hub stores the deadline for that connector
(`connector_retry_gate`, migration 000360) and reads it before every order.
A hub restarted inside the window places no order before `retry_at` (renewals
are deferred as `reason=backoff`, without using an attempt), and replicas
sharing the database hold each other: a 429 seen by one stops the others. When
two replicas save at once the later deadline wins.

If the database cannot be read, the hub **fails open**: it keeps using the hold
it holds in memory and logs `connectors: retry gate store unavailable` (at most
every 30 s). It does not stop issuing. Failing closed would stop every expiring
certificate from renewing on a database blip, while the worst fail-open result is
one order the CA refuses with another 429, which the in-memory hold then
catches. A restart during a database outage therefore loses the hold; avoid
restarting the hub inside a known 429 window while the database is down.

## Rolling issuance budget

To stay under a CA's published limit (for example 300 new orders per 3 hours),
set a window and a budget on the connector, in its `config_json`:
`"rate_window":"3h","rate_budget":300`. The operator can instead set
`KRYPTKEEPER_CONNECTOR_LIMITS` (`{"<connector id>":{"window":"3h","window_budget":300}}`),
which wins over the connector's own keys. The hub refuses order N+1 inside any
window with `reason=window_budget` and retries once the oldest order has left
it. Orders are logged in `connector_issue_log` (migration 000361), so a restart
does not reset the count. Revocations are not counted. The renewal SLO
report's `connector_budgets` show `window_used`, `window_limit` and
`window_seconds`. The existing daily budget is unchanged and applies as well.
Only the replica holding the renewal scheduler lease issues, so the count is
per hub; if you run several issuing replicas against one CA, split the budget.

