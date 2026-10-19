# Live cloud-certificate inventory UAT (W24-18)

`bash tests/live/cloud-inventory/run.sh` (podman; `CONTAINER_ENGINE` overrides).

Emulator choice: **moto** (`docker.io/motoserver/moto:latest`, as in
`tests/live/kms-aws`). LocalStack images need an account token these days; use
`KK_CLOUD_EMULATOR_IMAGE=docker.io/localstack/localstack:3
KK_CLOUD_EMULATOR_PORT_INNER=4566` when you have one. Env: `KK_CLOUD_EMULATOR_PORT`
(5566), `KK_CLOUD_HUB_PORT` (8097).

## Proven
- Cloud scans write to `scan_jobs.results_summary`, not the `certificates`
  table. With 5 certs imported into ACM, `results_summary.certificates == 5`,
  5 distinct `resource_id` ARNs equal to the imported set, every item has
  `common_name` and `not_after`; a rerun yields the same 5 (0 duplicates).
- Two regions merge (7 certs); a scope with a non-existent profile gives
  `completed_with_errors`, names `aws-acm/does-not-exist/ap-south-1`, and the
  good scopes' certs remain.
- Unreachable AWS endpoint, missing Azure credentials and missing GCP
  credentials each give a `failed` job with a readable message (read through
  `GET /api/v1/discovery/scan-jobs`), no credential value, no stack trace.

## Not proven / skipped (named, never silent)
- moto omits `SubjectAlternativeNameSummaries` from ListCertificates (real ACM
  and LocalStack return it), so `dns_names` is asserted only off moto.
- IAM, real ACM pagination (1000 per page) and the 200-item persisted cap.
- Azure and GCP positive cases need a test tenant/project:
  `KK_LIVE_AZURE_KV_URL`+`AZURE_TENANT_ID/CLIENT_ID/CLIENT_SECRET`;
  `KK_LIVE_GCP_PROJECT`+`GOOGLE_ACCESS_TOKEN`.

`import_certs_test.go` is the helper that imports the certs (gated by
`KK_LIVE_CLOUD_INVENTORY=1`, skips otherwise).
