# W19-12 (AWS leg) — KMS against moto and AWS's own emulator

```
CONTAINER_ENGINE=docker bash tests/live/kms-aws/run.sh   # moto in a container; podman is the default
KK_AWS_EMULATOR=aws bash tests/live/kms-aws/run.sh       # AWS's emulator (aws-emulator package)
```

Runs the real `CloudKMSStore` AWS path (aws-sdk-go-v2 honours `AWS_ENDPOINT_URL`)
against an emulator: CreateKey, GetPublicKey, Sign for ECDSA P-256/P-384,
RSA-2048 and RSA-3072, signatures verified against the returned public key,
tamper check, and Delete. Free, no AWS account.

`KK_AWS_EMULATOR=aws` starts `aws-emulator` through `tests/live/lib/aws-emulator.sh`
(telemetry off, SigV4 on with its per-run keys, its CA trusted through
`AWS_CA_BUNDLE`, 2 GiB cap). If the package is not installed the run prints a
named SKIP and exits 0. Record: `docs/release/LIVE_RESULTS_AWS_EMULATOR_v1.2.md`.

## Proven against AWS's emulator (not real AWS)
- `MessageType=DIGEST` semantics: with `KK_KMS_EMULATOR_MOTO` unset, every
  signature verifies over the digest itself, and a tampered digest fails.
- `CloudKMSStore.Delete` calls ScheduleKeyDeletion with the key ARN and the
  signer is gone afterwards.
- `TestAWSKMSDeletionPendingAndCancel`: PendingDeletion with the 7-day window,
  then the product cancel returns the key to Enabled.

## What this does NOT prove (do not close W19-12 on this alone)
- IAM, key policies, quotas and real HSM behaviour (neither emulator has them).
- moto: it ignores `MessageType=DIGEST` and hashes the digest again, so the moto
  leg verifies over h(digest) (`KK_KMS_EMULATOR_MOTO=1`), and it answers
  ScheduleKeyDeletion with a 500 when given an ARN; the store test then only
  asserts the W9-07 contract (a refused destroy keeps the reference). Use the
  AWS emulator leg for DIGEST and delete-by-ARN.
- ML-DSA keys: AWS's emulator creates `ML_DSA_65` but answers GetPublicKey and
  Sign with 501 NotImplemented (see `tests/live/key-inventory`).
- GCP and Azure legs are not covered here.
