# Live results W27-10: upstream renewal against independent servers - v0.15

Date: 2026-10-16. Hub commit: `80f4cf4c` plus the harness and the EST request-body fix in this branch (`kk/w27-c`).
Host: macOS 27.0.1, arm64 (Apple M4 Max), podman 6.1.3. Harness: `tests/live/upstream-renew/run.sh`.

## Verdict: PARTIAL - SCEP and EST VALIDATED; WSTEP and DigiCert NOT RUN

| Leg | Server | Version | Connector level | Hub level (`/connectors` + `renewal/execute`) | Verdict |
|---|---|---|---|---|---|
| SCEP | micromdm/scep `scepserver` (Go, RFC 8894) | v2.3.0, `go install` of the tag on `golang@sha256:2e926920...` (alpine runtime `alpine@sha256:45e09956...`) | PASS | PASS | PASS |
| EST | Cisco libest `estserver` (C, RFC 7030) | r3.2.0, commit `4ca02c6d7540f2b1bcea278a4fbe373daac7103b`, `ubuntu@sha256:722ea796...` | PASS | PASS | PASS (after the client fix below) |
| WSTEP | Windows Server AD CS (CES) | - | NOT RUN: no AD CS lab (`KK_UP_WSTEP_*` unset) | NOT RUN | NOT RUN |
| DigiCert | CertCentral test account | - | NOT RUN: no sandbox (`KK_UP_DIGICERT_*` unset) | NOT RUN | NOT RUN |
| DigiCert 429 | local stub (no account needed) | - | PASS | not exercised | PASS (connector + registry level) |

Overall: `PARTIAL - WSTEP and DigiCert issuance not run (no lab / sandbox)`. Image IDs are rebuilt per run; the
Containerfiles pin the base-image index digests and the upstream tags.

## Independence of the servers

Checked with curl/openssl before the clients ran: SCEP `GetCACaps` = `Renewal SHA-1 SHA-256 AES DES3 SCEPStandard POSTPKIOperation`,
`GetCACert` returns `CN=UAT SCEP Independent CA`; EST `/cacerts` returns a PKCS#7 bundle, and `simpleenroll` with a
valid CSR but no credentials answers 401. Neither server shares code with `internal/scep|est|wstep`.

## Connector level (go test, real output)

| Leg | CSR CN | `new_fingerprint` == served fingerprint | Issuer | Elapsed |
|---|---|---|---|---|
| SCEP (RSA-2048 key, Signer+Decrypter) | `scep-live.uat.example` | `cbfcee79b8d2db17a467de7df7a42a902bed0a15f55002342aba890a6f73e1c0` == served, yes | UAT SCEP Independent CA (chain verified) | 7 ms |
| EST (ECDSA P-256, Basic auth over TLS) | `est-live.uat.example` | `d29f929a956b1c3d7abc71312a3dcca13a85991aee09a9c92b8f74e385c20c7d` == served, yes | estExampleCA (chain verified) | 45 ms |

"Served" = a local TLS server presenting the issued leaf, dialled by a client that reads the peer certificate.

## Hub level (API: `POST /api/v1/connectors` -> import -> `estate/takeover` -> `renewal/execute` into nginx over SSH)

| Leg | Connector | Health probe | Outcome | nginx served == `new_fingerprint` | Served issuer | Elapsed |
|---|---|---|---|---|---|---|
| SCEP | type `scep`, `endpoint_url` http (no credential) | healthy | `installed_verified verified=True` | `98524d499ba7c10254d6922a6918221e61f47241a844068122bc97916802139d`, yes | UAT SCEP Independent CA (not the hub CA) | 1 s |
| EST | type `est`, https `base_url`, `credential_ref` to `{"password"}` | healthy | `installed_verified verified=True` | `f095ee6f49ffcbdd9351297ad3bb1f69f928cbc4a061ca090c6524b817c889e5`, yes | CN=estExampleCA (not the hub CA) | 1 s |

Credentials (acceptance 3): the EST password appears 0 times in the hub log and 0 times in the audit trail
(17 entries read through the API; `connector.create` is audited); 0 private-key markers in either.
The hub trusts the EST server through `SSL_CERT_FILE` (the server CA, mounted read-only).

## 429 (acceptance 2, account-free part)

A TLS stub answers every order with 429 and `Retry-After: 120`. The DigiCert connector returns a typed
`*RateLimitError{Reason: upstream_429, RetryAfter: 120s}` whose text reads `rate limited (HTTP 429)`, not the generic
`HTTP 4xx:` form. Through the `Registry` the hub uses, the next call is refused locally with `Reason: backoff` and the
upstream is hit exactly once. A real CertCentral 429 cannot be forced on demand; none was observed.

## Findings

1. **EST client bug, fixed in this branch.** libest's `estserver` answered the hub's first `simpleenroll` with
   `400 Invalid or corrupted pkcs10 request`. Verified by varying only the body of a valid CSR: single-line base64 without a
   trailing newline -> 400; the same with a trailing newline -> 200; wrapped at 64 columns with or without one -> 200.
   `ESTClient.Issue` now appends one newline (not 64-column wrapping, because our own `internal/est` server decodes with
   `TrimSpace` + `StdEncoding`, which rejects interior newlines). Regression test:
   `TestESTClientRequestBodyEndsWithNewline`; `internal/est` still passes. This is a product change outside W27-10's write_scope,
   committed separately so it can be dropped or re-homed.
2. **429 at the API.** The scheduler defers a rate-limited renewal with backoff (`deferredOutcome`), but
   `POST /api/v1/renewal/execute` has no `RateLimitError` branch: it answers a generic `503 renewal execution failed`
   (the detail is only in the hub log). Not changed here; raised for the lead.
3. libest's `estserver` stores `getopt`'s result in a plain `char`, so it prints usage and exits on arm64 unless built `-fsigned-char` (done in `est.Containerfile`).
