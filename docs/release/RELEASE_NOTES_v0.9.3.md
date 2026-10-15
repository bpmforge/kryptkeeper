# Kryptkeeper v0.9.3

Network discovery now does what the product promises: it finds every TLS
endpoint on the networks you scan, puts the certificates it finds into the
inventory, and tells you whose certificate each one is and what is wrong with
it. This release also includes the fixes prepared as v0.9.2, which was not
published separately.

Validated on a 17-host lab with targeted, full-range (/24) and scheduled
scans, on the default configuration, before release.

## Discovery

- **Found certificates reach the inventory.** Certificates discovered on the
  network appear in the certificate list without a restart, marked unmanaged
  (or managed, if this hub issued them). Before, they were counted on the
  dashboard but never listed.
- **Whose certificate is it.** Every certificate a server presents is checked
  against this hub's CAs and the system root store and labelled `managed`,
  `public`, `private_other` (another private CA), `self_signed` or `unknown`.
  The dashboard shows a "Seen on the network by issuer" breakdown, and the
  Certificates and Discovery pages filter by issuer.
- **Chain problems.** `UNTRUSTED_ROOT` when a chain ends in a root no one
  trusts; `INCOMPLETE_CHAIN` only when a server provably leaves out an
  intermediate (for example, a hub certificate served without its hub
  intermediate). Leaving out the root is normal and is not flagged. A missing
  intermediate from someone else's private CA cannot be proven without
  fetching it, so it is reported as unknown rather than guessed.
- **Per-endpoint results.** Hostname mismatch and chain completeness are
  stored for each certificate on each endpoint, so a certificate served under
  two names keeps the right result for each, whatever order the scans run in.
- **Self-signed certificates** made the usual way (`openssl req -x509`, which
  marks them as CAs) are now flagged when a server presents them.
- **Range scans no longer flag every certificate as a hostname mismatch**
  because the target was an IP address.
- **Servers that answer but are not usable TLS are recorded** instead of
  disappearing: `NOT_TLS`, `TLS_HANDSHAKE_FAILED` with the reason, and
  `POSTGRES_TLS_DISABLED` for a PostgreSQL port that declines TLS. A scan
  where some hosts failed ends `completed_with_errors` and says which.
- **Old protocols are detected.** Servers that only offer TLS 1.0, TLS 1.1 or
  SSLv3 get `DEPRECATED_TLS_VERSION`; their certificate is captured where
  possible.
- **One rule for "risky".** An endpoint is risky when its certificate scores
  70 or more, or is expired, self-signed, weak (key or signature) or chains to
  an untrusted root, or when the endpoint has a hostname mismatch, is not
  TLS, fails the TLS handshake, has PostgreSQL TLS disabled, or only offers
  deprecated TLS. The dashboard, the "Risky only" filter and the endpoint list
  all use it, and the Findings panel counts real findings.
- **The Discovery list shows posture inline:** issuer badge, the top findings
  and a risky marker, and the protocol that was actually observed.

## Other fixes (from v0.9.2)

- **The audit log shows what each record is about.** `GET /api/v1/audit` adds
  `resource_name` (certificate common name, CA, template, approval, rule or
  scan target), resolved only for resources the caller may read. Stored
  records are unchanged. The CSV export gains a trailing `resource_name`
  column.
- **One rule for counting certificates.** A certificate is active unless it
  is revoked or superseded by a renewal. Every page that shows a certificate
  total uses this rule; revoked certificates have their own dashboard figure.
- **Issue and renew responses include `key_algorithm_display`** (for example
  `ML-DSA-65`).
- **UI:** the certificate table scrolls instead of clipping; the PQC
  readiness card shows the parts that make up its percentage; expired
  certificates are no longer described as "expiring".

## Behaviour changes to check before upgrading

- **Discovery defaults to the `db` provider** (persisted, full-featured) when
  `APP_DISCOVERY_PROVIDER` is unset, and in the shipped `env.example`,
  `docker-compose.yml` and Helm values. `scanner` remains available as a
  minimal in-memory mode. Docker Compose users who kept the old default now
  get persisted discovery.
- **More endpoints are reported as risky:** hostname mismatches, failed TLS
  handshakes and TLS-disabled PostgreSQL ports now count. Plain SMTP/IMAP
  ports that offer no STARTTLS are reported too.
- **Certificate totals** exclude revoked and superseded certificates, so
  numbers may drop. The dashboard summary adds `revoked`. Per-CA counts now
  include certificates marked `expired` or `reissue_required`.
- **`chain_complete` / `chain_trusted` are omitted** on discovered
  certificates in the certificate API: chain status is a per-endpoint fact
  and is reported on the endpoint's mapped certificates.
- **Scan jobs** can end `completed_with_errors`; `failed` now means nothing
  was reachable. `GET /api/v1/discovery/scan-jobs` returns `error`.
- **The audit CSV export** has one extra trailing column.

Database migrations 000077–000079 are added (trust class, scan status,
per-endpoint facts). They run automatically on start; take a backup first as
usual.

## Install and upgrade

Replace the binary or image with `0.9.3` and restart. Docker Compose: set the
image tag to `0.9.3` (or pull `0.9`), then `docker compose up -d`.

## Verify the release

`checksums.txt` and the image manifests are signed keyless with cosign
through the release workflow's GitHub OIDC identity.

```bash
V=0.9.3
curl -fsSLO https://github.com/bpmforge/kryptkeeper/releases/download/v$V/checksums.txt
curl -fsSLO https://github.com/bpmforge/kryptkeeper/releases/download/v$V/checksums.txt.sig
curl -fsSLO https://github.com/bpmforge/kryptkeeper/releases/download/v$V/checksums.txt.pem

cosign verify-blob \
  --certificate-identity "https://github.com/bpmforge/kryptkeeper/.github/workflows/release.yml@refs/tags/v$V" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --signature checksums.txt.sig --certificate checksums.txt.pem checksums.txt

sha256sum --ignore-missing -c checksums.txt   # after downloading an archive

cosign verify \
  --certificate-identity "https://github.com/bpmforge/kryptkeeper/.github/workflows/release.yml@refs/tags/v$V" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/bpmforge/kryptkeeper:$V
```

Full list of changes: [CHANGELOG](https://github.com/bpmforge/kryptkeeper/blob/v0.9.3/CHANGELOG.md).
