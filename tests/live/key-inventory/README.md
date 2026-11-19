# Live key-inventory case (W24-34)

`KK_LIVE_KEYINV=1 bash tests/live/key-inventory/run.sh` (add `KK_KEYINV_AZURE=1` for the Azure leg;
`KK_AWS_EMULATOR=aws` for AWS's own emulator, record in `docs/release/LIVE_RESULTS_AWS_EMULATOR_v1.2.md`).

## Proven
- A KMS key created through the real AWS SDK against an emulator appears in
  `keyinventory.CollectWithTimeout` with the right algorithm
  (`SYMMETRIC_DEFAULT`, `RSA_2048`), rotation flag and PQC readiness (acceptance 1).
- An SSH user key and AWS keys come back in one result, and a dead provider is
  named in `Errors` (`azure-kv:`) while the rest return (acceptance 2).
- A hung provider is abandoned at the per-provider deadline.
- Pagination: every one of 1,005 created keys is listed (moto, which returns them
  all in one page), and against AWS's emulator 450 keys across five 100-key
  ListKeys pages (the source follows NextMarker; `KK_KEYINV_REQUIRE_PAGES=1`).
- Against AWS's emulator (not real AWS): an `ML_DSA_65` key is listed with
  `SIGN_VERIFY` usage and `pqc_readiness=quantum_safe`.
- Azure Key Vault source against Lowkey Vault: EC P-256 key reported as `EC-P-256`.

## Not proven
- Real IAM, quotas or HSM behaviour (emulators only).
- 1,000+ keys across real pages: AWS's emulator holds at most 500 KMS keys and
  moto does not paginate; named SKIP lines say which.
- ML-DSA GetPublicKey and Sign: AWS's emulator answers 501 NotImplemented
  (named skips); moto cannot create the key at all (the case skips).
- GCP KMS: no free emulator; skipped with a named reason unless
  `KK_LIVE_KEYINV_GCP_URL/_KEYRING/_TOKEN` point at one.
- The HTTP handler (`/api/v1/inventory/keys`) is covered by W24-33 unit tests;
  the optional hub leg runs only with `KK_LIVE_HUB_URL` + `KK_LIVE_HUB_TOKEN`
  (start the hub with `AWS_REGION=us-east-1 AWS_ENDPOINT_URL=<emulator>`).
- The SSH host-key source needs a hub discovery provider (W24-33 unit tests).

## Notes
Emulator default is moto (already used by `tests/live/kms-aws`);
`KK_AWS_EMULATOR=aws` runs AWS's emulator as a host process (`tests/live/lib/aws-emulator.sh`;
a named SKIP if it is not installed); `KK_AWS_EMULATOR=localstack` runs LocalStack 3 (may need an auth token).
Lowkey Vault is an amd64 image: under emulation on Apple silicon it needs ~3 min to boot.
The Azure client trusts the emulator cert through an explicit pool built from
`SSL_CERT_FILE` (Go on macOS ignores that variable).

| Env | Meaning |
|---|---|
| `KK_LIVE_KEYINV=1` | gate |
| `KK_KEYINV_PAGINATION_KEYS` | keys created by the pagination case (default 1005; 450 on AWS's emulator; 0 skips) |
| `KK_KEYINV_REQUIRE_PAGES=1` | a single ListKeys page fails the pagination case (set for AWS's emulator) |
| `AWS_ENDPOINT_URL`, `AWS_REGION=us-east-1`, `AWS_ACCESS_KEY_ID/SECRET` | emulator + placeholder creds (set by run.sh) |
| `KK_KEYINV_AZURE_URL`, `SSL_CERT_FILE` | Lowkey Vault URL + its cert |
| `KK_LIVE_KEYINV_GCP_URL/_KEYRING/_TOKEN` | optional GCP emulator |
| `KK_LIVE_HUB_URL/_TOKEN` | optional hub leg |
