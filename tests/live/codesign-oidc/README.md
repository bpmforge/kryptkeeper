# Code-signing live test (W29-14)

`run.sh` proves the CI OIDC exchange and the RFC 3161 TSA end to end against a
real hub in podman, with real `openssl` and `cosign`:

1. a trust rule is proposed by alice and approved by bob (dual control),
2. a token from `fakeidp` plus a P-256 CSR yields a 45 s code-signing
   certificate bound to `acme/app@refs/heads/main`,
3. a blob is signed (openssl, cosign) and the signature is timestamped by
   `POST /api/v1/tsa`,
4. after the certificate has expired the timestamp (`openssl ts -verify`), the
   chain as of the timestamp (`openssl verify -attime`) and `cosign verify-blob
   --use-signed-timestamps` still pass, and the same checks without the
   timestamp fail,
5. refused tokens (replay, other repo, other ref) are 401 with a generic body,
   and the reasons are in the audit trail,
6. the revoked-certificate semantics below are asserted.

## Prerequisites

podman (machine running), openssl 3.x, cosign 3.x, curl, python3, Go. The hub
and the fake issuer run as linux containers so the hub can trust the issuer's CA
through `SSL_CERT_FILE` (Go on macOS ignores it). Run: `bash tests/live/codesign-oidc/run.sh`
(about 2.5 minutes, most of it waiting for the certificate to expire). Keys are
generated per run under `~/kk-uat-codesign-run` and deleted on exit.

Not covered here: `jarsigner -tsa` (no JDK on the dev host; the script says so)
and `signtool /tr` (Windows lane only; the command is
`signtool timestamp /tr https://HUB/api/v1/tsa /td sha256 file.exe`, with the
hub reached anonymously, see `KRYPTKEEPER_TSA_ALLOW_ANONYMOUS`).

## cosign findings (v3.1.3)

- `cosign` accepts only its own key format in `--key`: import the PKCS#8 key
  with `cosign import-key-pair` first.
- With `--certificate-chain`, `sign-blob` writes a legacy `x509CertificateChain`
  bundle that cosign's own verifier rejects (`Invalid IEEE_P1363 encoded
  bytes`). Sign with `--certificate` only and give the chain to the verifier in a
  `--trusted-root` file.
- The certificate has no Fulcio OIDC-issuer extension (Fulcio-style mode is
  v1.x), so an exact `--certificate-oidc-issuer` is refused (`got ""`); use
  `--certificate-oidc-issuer-regexp '.*'` and pin trust with the identity URI
  and the trusted root. `--insecure-ignore-sct` and `--insecure-ignore-tlog` are
  required (no CT log, no Rekor).
- `sign-blob` cannot send the hub's Bearer token to the TSA. Request the reply
  yourself over the bytes of cosign's signature and put the whole
  `TimeStampResp` in the bundle (`timestampVerificationData.rfc3161Timestamps[].signedTimestamp`).

## Revoked-certificate semantics

A timestamp proves only that a signature existed at `genTime`; it never
overrides revocation.

- Revoked with reason `keyCompromise`: treat every signature from that
  certificate as untrusted, timestamped or not. CRL/OCSP verifiers do. The
  script shows the hub CRL listing the serial with `Key Compromise`, while the
  timestamp token itself still verifies.
- Any other reason: signatures timestamped before the revocation time stay
  valid. The cut-off is the hub's `revoked_at` on the certificate
  (`GET /api/v1/certificates/{fingerprint}`) compared with the token's
  `genTime`; the script asserts `genTime <= revoked_at` for the revoked cert.
