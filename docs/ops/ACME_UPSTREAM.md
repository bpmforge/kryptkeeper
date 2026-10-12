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

`dns-01` providers: **Cloudflare**. Others can be added behind the same
interface.

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
2. It creates a TXT record (TTL 60) and waits until **every** authoritative
   nameserver for the zone serves it (up to 3 minutes), so the CA's
   validator does not see a stale answer.
3. The CA validates; the hub finalizes and downloads the chain.
4. The TXT record is deleted, also when the order fails.
5. Install, verify (the served certificate's fingerprint) and rollback run
   as for any renewal.

A failed order reports the CA's own problem detail, or names the
nameserver that never served the record.

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
