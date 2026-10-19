# Live key-inventory case (W24-34)

`KK_LIVE_KEYINV=1 bash tests/live/key-inventory/run.sh` (add `KK_KEYINV_AZURE=1` for the Azure leg).

## Proven
- A KMS key created through the real AWS SDK against an emulator appears in
  `keyinventory.CollectWithTimeout` with the right algorithm
  (`SYMMETRIC_DEFAULT`, `RSA_2048`), rotation flag and PQC readiness (acceptance 1).
- An SSH user key and AWS keys come back in one result, and a dead provider is
  named in `Errors` (`azure-kv:`) while the rest return (acceptance 2).
- A hung provider is abandoned at the per-provider deadline.
- Azure Key Vault source against Lowkey Vault: EC P-256 key reported as `EC-P-256`.

## Not proven
- Real IAM, quotas, pagination limits or HSM behaviour (emulators only).
- GCP KMS: no free emulator; skipped with a named reason unless
  `KK_LIVE_KEYINV_GCP_URL/_KEYRING/_TOKEN` point at one.
- The HTTP handler (`/api/v1/inventory/keys`) is covered by W24-33 unit tests;
  the optional hub leg runs only with `KK_LIVE_HUB_URL` + `KK_LIVE_HUB_TOKEN`
  (start the hub with `AWS_REGION=us-east-1 AWS_ENDPOINT_URL=<emulator>`).
- The SSH host-key source needs a hub discovery provider (W24-33 unit tests).

## Notes
Emulator default is moto (already used by `tests/live/kms-aws`);
`KK_AWS_EMULATOR=localstack` runs LocalStack 3 (may need an auth token).
Lowkey Vault is an amd64 image: under emulation on Apple silicon it needs ~3 min to boot.
The Azure client trusts the emulator cert through an explicit pool built from
`SSL_CERT_FILE` (Go on macOS ignores that variable).

| Env | Meaning |
|---|---|
| `KK_LIVE_KEYINV=1` | gate |
| `AWS_ENDPOINT_URL`, `AWS_REGION=us-east-1`, `AWS_ACCESS_KEY_ID/SECRET` | emulator + placeholder creds (set by run.sh) |
| `KK_KEYINV_AZURE_URL`, `SSL_CERT_FILE` | Lowkey Vault URL + its cert |
| `KK_LIVE_KEYINV_GCP_URL/_KEYRING/_TOKEN` | optional GCP emulator |
| `KK_LIVE_HUB_URL/_TOKEN` | optional hub leg |
