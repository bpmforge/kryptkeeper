# Kryptkeeper v0.9.1

A fix release for v0.9.0. Upgrade if you issue post-quantum (ML-DSA)
certificates or use the PQC reports: in v0.9.0, ML-DSA certificates were
signed but could not be stored on SQLite or PostgreSQL.

## Fixed

- **ML-DSA certificates are stored.** v0.9.0 signed the certificate and then
  answered `503 certificate was signed but could not be recorded`, because
  Go reports an ML-DSA key as `unknown`, which the database rejects. Issue,
  renew, import, ACME and discovery now record `ML-DSA`.
- **Standard OpenSSL ML-DSA requests work.** OpenSSL 3.5+ writes ML-DSA CSRs
  under the usual `CERTIFICATE REQUEST` label. The hub now picks the parser
  from the key's algorithm OID, so a plain `openssl req` CSR issues; the
  request's self-signature is still verified. See the README section
  "Issuing post-quantum (ML-DSA) certificates".
- **ML-DSA CAs can be created** through the API and the New CA form
  (`ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`; software key backend only).
- **PQC numbers agree across pages.** Crypto Posture, the PQC countdown and
  the PQC migration roadmap now share one definition.
- **Clearer errors on issue and renew.** An invalid or unsupported CSR returns
  `400`, and an inactive or keyless issuing CA returns `409`, instead of `503`.
- **Templates show how many certificates they issued,** and
  `GET /api/v1/certificates?template_id=` filters again.
- **`KRYPTKEEPER_ORG_NAME`** sets the organization of a newly bootstrapped
  root CA.
- **A missing `./var` directory** is created at startup instead of causing
  `503` on file-backed templates, CAs and certificates.
- **UI:** Approvals, Revocation Activity, certificate detail and SPIFFE show
  CA and template names instead of IDs; certificate detail shows the ML-DSA
  parameter set (for example `ML-DSA-65`); internal ticket references are
  gone from on-screen text. The Audit page has a "Hide read-only events"
  toggle (off by default). Denied or failed reads are never hidden, and the
  CSV export always contains every event.

## Behaviour changes to check before upgrading

- `quantum_safe_percent` (Crypto Posture, `GET /api/v1/reports/crypto-posture`) now
  counts only certificates whose whole chain is post-quantum. An ML-DSA leaf
  under a classical CA is reported separately as `quantum_safe_leaf_only`.
  Dashboards that read `quantum_safe_percent` may show a lower number. The
  PQC migration roadmap response adds `quantum_safe_leaf_only`,
  `not_applicable`, `pqc_score_percent` and `quantum_safe_percent`.
- Deleting a template that has issued certificates now returns `409`. This
  guard was always intended but never fired.
- Clients that retried on `503` from `POST /certificates` or `.../renew`
  should treat `400` and `409` as final.

No database migration is added; v0.9.0 schema 76 is unchanged.

## Install and upgrade

Replace the binary or image with `0.9.1` and restart. Docker Compose:
set the image tag to `0.9.1` (or pull `0.9`), then `docker compose up -d`.

## Verify the release

`checksums.txt` and the image manifests are signed keyless with cosign
through the release workflow's GitHub OIDC identity.

```bash
V=0.9.1
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

Full list of changes: [CHANGELOG](https://github.com/bpmforge/kryptkeeper/blob/v0.9.1/CHANGELOG.md).
