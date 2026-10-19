# W31-04: OpenSSL >= 3.5 interop for ML-DSA and hybrid leaves

Live drill (not part of `go test`, not wired into CI). A hub built from this checkout runs in
podman next to a throwaway Postgres; host OpenSSL does the verifying.

## What it proves

1. ML-DSA-44/65/87 leaves (CSR made by `openssl req`) issue under a classical ECDSA-P256
   intermediate C and under an ML-DSA-65 intermediate M; `openssl verify` returns OK for each
   under its chain (R,C and R,M).
2. Both hybrid leaves (`Hybrid-ECDSA-P256-ML-DSA-65`, `Hybrid-ECDSA-P384-ML-DSA-87`) issue under
   C; `openssl verify` is OK on the classical path and `openssl x509 -text` shows OID 2.5.29.72.
   Hybrid is Kryptkeeper's own encoding (D-104, `docs/PQC_HYBRID_ENCODING.md`); no LAMPS
   composite interop is claimed.
3. An ML-DSA CSR against an ECDSA-only template is refused (4xx, 422 expected); a CSR with a
   corrupted signature (ML-DSA and hybrid) is rejected with 400.
4. OCSP and the CRL of the ML-DSA CA M verify with openssl (W31-05): leaf `good`, then revoked
   via the API, then `revoked` in OCSP and listed in a CRL whose ML-DSA signature openssl checks.

## Prerequisites

podman (running machine on macOS), Go, python3, curl, and OpenSSL >= 3.5 on the host
(`OPENSSL=/opt/homebrew/bin/openssl` to pick one). With OpenSSL < 3.5 the script prints
`SKIPPED`, records it in `RESULTS.md` and exits 0 without running any step.

## Run

    bash tests/live/pqc/run.sh            # HUB_PORT (default 18441), KK_KEEP_GOING=1 to run past a FAIL

Containers are prefixed `kkw31-04-`; everything is removed on exit. Writes `RESULTS.md` here
(no tokens). Reuses `../ca-revoke/fixture.sh`; `hybridcsr/` builds the hybrid CSRs.
