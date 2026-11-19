# Kryptkeeper 1.2.1

A patch release. It moves the build to Go 1.27.4 for a standard-library security fix, and it
fixes two cloud inventory gaps that AWS's own emulator found. Upgrade if you run 1.2.0. Nothing
in the database changes.

## Security

- **Go 1.27.4** (GO-2026-6859, `net/http`). The hub's code can reach the affected `net/http`
  path, so `govulncheck` flagged 1.2.0. The FIPS build keeps the `GOFIPS140=v1.0.0` module
  (CMVP #5247).

## Fixed

- **ACM inventory listed only RSA-1024 and RSA-2048 certificates.** AWS's `ListCertificates`
  returns only those key types unless the request names the others, so ECDSA and RSA-3072/4096
  certificates in ACM never reached the inventory. The hub now asks for every key type. moto
  ignores the filter, which is why the earlier tests missed it.
- **ML-DSA keys in AWS and GCP KMS were scored `pqc_readiness: unknown`.** AWS reports
  `ML_DSA_65` and GCP `PQ_SIGN_ML_DSA_65`. The scorer now matches those spellings for ML-DSA,
  ML-KEM and SLH-DSA and scores them `quantum_safe`.

## Tests

- The live KMS, BYOK import, Private CA, ACM and key-inventory harnesses can run against AWS's
  own emulator (`KK_AWS_EMULATOR=aws`) as well as moto. The run record is in
  `docs/release/LIVE_RESULTS_AWS_EMULATOR_v1.2.md`.

## Upgrade notes

- No migrations, no new settings.
- After the upgrade, the next cloud inventory scan adds any ECDSA and RSA-3072/4096 ACM
  certificates that were missing before.
