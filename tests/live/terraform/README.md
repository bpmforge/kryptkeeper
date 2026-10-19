# Terraform provider acceptance tests (W26-15, W32-04)

`run.sh` proves the `kryptkeeper` Terraform provider against a real hub: the
real provider binary, driven by `tofu` (or `terraform`) through `apply`,
`plan` and `destroy`.

```
bash tests/live/terraform/run.sh        # ends ALL STEPS PASSED, writes RESULTS.md
KK_ACC_KEEP=1 bash tests/live/terraform/run.sh   # keep the temp dir for debugging
```

## What it does

- Builds the hub from this checkout and runs it natively (plain HTTP via
  `KRYPTKEEPER_TLS_DISABLE=true`, file/sqlite state, free loopback port, all in a
  `mktemp` dir removed by a cleanup trap). No podman. Two pki-admin identities
  come from `APP_API_KEYS_JSON` (dual control needs two humans). Tokens are never
  printed; the provider gets the token through `TF_VAR_kk_token`.
- Runs `go test ./internal/provider -run TestAcc` in `terraform-provider-kryptkeeper`
  with `TF_ACC=1`, `KK_ACC_HUB_URL`, `KK_ACC_TOKEN`, `KK_ACC_APPROVER_TOKEN`
  (`KK_ACC_TF_BIN` overrides the CLI lookup). Without `TF_ACC=1` the tests skip, so
  `go test ./...` stays offline. No Go dependency was added: the CLI is shelled out
  to with a `dev_overrides` config.
- `TestAcc_CA_Template_Certificate_RoundTrip`: apply a CA, template and certificate;
  the issued PEM parses and chains to the CA; a second plan shows no diff; the test
  revokes the CA out of band (propose with one admin, approve with the other) and
  runs destroy; then it checks residuals through the API.
- `TestAcc_StateHasNoPrivateKey` (W32-04): after apply, neither `terraform.tfstate` nor
  `state pull` contains `PRIVATE KEY` (and both do hold the issued certificate, so the
  check reads real state).
- `TestAcc_DestroyPendingApprovalFails` (W32-04): destroy with no out-of-band revoke makes
  the provider propose the dual-control CA revoke; the hub answers 202 and destroy fails
  with `pending approval, action id <id>`; the second admin approves it and destroy then
  completes.
- `TestAcc_ImportThenPlan` (W32-05): `state rm` then `import` of all three resources, plan shows no
  replacement and no CA/template diff, one adopting apply (certificate `csr_pem` null to config) and
  then an empty plan; the `kryptkeeper_ca` and `kryptkeeper_template` data sources return the same ids.
- `TestAcc_PolicyViolationSurfacesRule`: a 1024-bit CSR against `min_key_size = 2048`;
  apply fails and the diagnostics carry `policy_violation`, the `key_size` rule and
  the hub's text; nothing was issued.

## Findings made visible by the live run (and fixed in the provider)

- `kryptkeeper_ca` sent `common_name`/`validity_days`/`key_size`; the hub wants
  `subject_cn`, `type`, `validity`. Create now maps them; Read no longer blanks
  attributes the hub does not return.
- The hub returns no PEM on issue/get; the certificate resource now fetches
  `certificate_pem` (download) and `chain_pem` (CA chain).
- The template resource gained `min_key_size`.
- API errors keep the hub's `error` code and `message` (formatAPIError).
- The hub never deletes a template that issued a certificate (409) nor a CA row
  (409: the CA's own certificate row references it). The provider deactivates the
  template / drops the revoked CA from state, each with a warning. "0 residual"
  therefore means: CA gone or revoked, template gone or inactive, certificate
  revoked. A hub-side fix (delete a revoked CA; correct the 409 message, which
  says "active certificates" for a foreign-key conflict) is a follow-up.
- The Baseline issuance policy refuses RSA-2048 leaves, so the round trip uses an
  ECDSA-P256 CSR (the CA itself is RSA-2048).

Known gaps: template in-place update needs `If-Match: <revision>` which the
provider's `Put` does not send (out of scope here); registry publish is S-04.

## Result

See `RESULTS.md` (written by the last run).

| Run | CLI | Result |
|---|---|---|
| 2026-10-16, macOS arm64, go 1.27.1 | OpenTofu v1.13.1 | ALL STEPS PASSED, residual=0 |

## CI (W32-04)

`.github/workflows/terraform-provider.yml` job `acceptance` (needs `test`) installs
terraform via `hashicorp/setup-terraform` (pinned SHA, CLI 1.9.8) and runs `run.sh`;
`build` waits for it. Prerequisites locally: go, curl, openssl, python3 and `tofu` or
`terraform` on PATH (or `KK_ACC_TF_BIN`).
