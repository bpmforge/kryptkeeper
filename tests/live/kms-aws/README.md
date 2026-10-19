# W19-12 (AWS leg) — KMS against the moto emulator

```
CONTAINER_ENGINE=docker bash tests/live/kms-aws/run.sh   # podman is the default
```

Runs the real `CloudKMSStore` AWS path (aws-sdk-go-v2 honours `AWS_ENDPOINT_URL`)
against `motoserver/moto` in a container: CreateKey, GetPublicKey, Sign for
ECDSA P-256/P-384 and RSA-2048, signatures verified against the returned public
key, tamper check, and Delete. Free, no AWS account.

## What this does NOT prove (do not close W19-12 on this alone)
- moto ignores `MessageType=DIGEST` and hashes the digest again, so the test
  verifies over h(digest) when `KK_KMS_EMULATOR_MOTO=1`. Wiring and wire formats
  are covered; DIGEST semantics need real AWS.
- moto returns 500 for `ScheduleKeyDeletion` given an ARN; the store test then
  only asserts the W9-07 contract (refused destroy keeps the reference).
  `TestAWSKMSDeletionPendingAndCancel` (W23-24) sidesteps this with a bare key
  id: it schedules with the SDK and asserts PendingDeletion with the 7-day
  window, then calls the product cancel (`keystore.CancelCloudKeyDeletion`) and
  asserts Enabled; a second cancel must error.
- IAM, key policies, quotas and real HSM behaviour are untested.
- GCP and Azure legs are not covered here.
