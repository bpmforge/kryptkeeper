# Day-one CA hierarchy (UC-A01)

Fresh `compose up` to a verified root + issuing CA + leaf, for every supported CA
algorithm, with the wall-clock published. Harness: `tests/live/ca-hierarchy/run.sh`.

## Prerequisites
- podman with `podman compose` (or an existing hub for attach mode), `curl`, `python3`.
- OpenSSL >= 3.5 to verify ML-DSA chains (`brew install openssl`; macOS system LibreSSL cannot).
  Older OpenSSL marks ML-DSA rows `SKIP-openssl<3.5`; `REQUIRE_ALL=1` turns that into a failure.

## Run
```
# compose mode: builds the image (untimed), then times compose up -> last verified leaf
bash tests/live/ca-hierarchy/run.sh

# attach mode against a running hub
KK_BASE_URL=https://localhost:8080 KK_TOKEN=<token> KK_CACERT=ca.pem bash tests/live/ca-hierarchy/run.sh
```
The algorithm list is not hardcoded: it is read from `supported_algorithms` in the 400
response to `POST /api/v1/cas` with `algorithm=DSA`, and the run asserts there are 9.

## Result (algorithm x tier)
| Algorithm | Root | Issuing | Leaf (ECDSA P-256) | openssl verify |
|---|---|---|---|---|
| ECDSA-P256 | created | created | created | OK |
| ECDSA-P384 | created | created | created | OK |
| RSA-2048 | created | created | created | OK |
| RSA-3072 | created | created | created | OK |
| RSA-4096 | created | created | created | OK |
| Ed25519 | created | created | created | OK |
| ML-DSA-44 | created | created | created | OK |
| ML-DSA-65 | created | created | created | OK |
| ML-DSA-87 | created | created | created | OK |

## Measured
Copied from `tests/live/ca-hierarchy/last-run.json` of a real run.

| Field | Value |
|---|---|
| Date (UTC) | 2026-10-16T01:27:27Z |
| Commit | 63d2cd14 (plus the harness script itself, uncommitted at run time) |
| Mode | compose (project `kkw23ca`, `kryptkeeper` service only) |
| Machine | Darwin arm64, Apple M4 Max, 64 GiB RAM, podman 6.1.3 |
| OpenSSL | OpenSSL 3.6.5 29 Sep 2026 |
| Elapsed, compose up to verified leaf | **13 s** (budget 900 s) |

## Caveats
- **Ed25519**: Windows/ADCS clients do not validate Ed25519 chains; use it only for fleets you control.
- Some key backends refuse Ed25519 or ML-DSA; see [CLOUD_KMS.md](CLOUD_KMS.md).
- Image pull and build are excluded from the clock (first pull is 5-15 min per PILOT_RUNBOOK.md).
- A fresh hub can start with zero CAs (first-run mode, for the UI onboarding wizard); compose mode sets `KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true`;
  the nine test hierarchies are created on top of that bootstrap root.
- Finding fixed by this harness: ML-DSA CA certificates carried keyEncipherment instead of
  keyCertSign (KeyUsage bit order), so OpenSSL rejected them; fixed in `internal/ca/mldsa_cert.go`.
