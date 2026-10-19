# W23-14 (GCP leg) — Cloud KMS wire format against an in-repo emulator

```
bash tests/live/kms-gcp/run.sh
```

**Google publishes no Cloud KMS emulator** (checked: no official image or
`gcloud` emulator component), so `emulator/` is a small Go REST server written
for this harness. It generates real ECDSA/RSA keys and real signatures behind
the four routes Kryptkeeper calls: create key, `getPublicKey`,
`:asymmetricSign`, `:destroy`. `run.sh` builds and starts it, sets
`KRYPTKEEPER_GCP_KMS_ENDPOINT` to it, runs the live test, and fails on a skip.

## Proven
Request and response shapes of the four calls, as Kryptkeeper builds and parses
them (key resource names, `digest.sha256|sha384` fields, base64 DER signatures,
PEM public key), and create + sign + verify + delete through `CloudKMSStore`.

## Not proven
The emulator is written from the same understanding of the API as the client, so
it cannot catch a shared misreading of Google's contract. Not covered: IAM and
OAuth, key version states (`DESTROY_SCHEDULED` timing, restore), quotas, HSM
protection level, regional availability. Those need a real project.
