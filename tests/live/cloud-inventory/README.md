# Live cloud-certificate inventory UAT (W24-18)

`bash tests/live/cloud-inventory/run.sh` (podman; `CONTAINER_ENGINE` overrides).
`KK_AWS_EMULATOR=aws bash tests/live/cloud-inventory/run.sh` runs it against AWS's own
emulator (`tests/live/lib/aws-emulator.sh`; a named SKIP if it is not installed). Record:
`docs/release/LIVE_RESULTS_AWS_EMULATOR_v1.2.md`.

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
- Pending: a requested, DNS-validated certificate is listed with status
  `PENDING_VALIDATION` (and no validity) next to the imported ones.
- Pagination: 1,100 more certificates (1,106 in the region) give
  `results_summary.certificates == 1106`, 200 persisted items, no duplicates.
  Against AWS's emulator the list spans two ListCertificates pages (NextToken).
- Against AWS's emulator (not real AWS): `dns_names` from
  `SubjectAlternativeNameSummaries` on every item, and ECDSA certificates are
  listed at all (ListCertificates now asks for every key type; ACM's default
  filter returns RSA_1024 and RSA_2048 only, which moto ignores).
- moto only: two regions merge (7 certs); a scope with a non-existent profile gives
  `completed_with_errors`, names `aws-acm/does-not-exist/ap-south-1`, and the
  good scopes' certs remain.
- Unreachable AWS endpoint, missing Azure credentials and missing GCP
  credentials each give a `failed` job with a readable message (read through
  `GET /api/v1/discovery/scan-jobs`), no credential value, no stack trace.

## Not proven / skipped (named, never silent)
- moto omits `SubjectAlternativeNameSummaries` from ListCertificates (real ACM,
  AWS's emulator and LocalStack return it), so `dns_names` is asserted only off moto.
  moto also returns every certificate in one page (named SKIP for the NextToken path).
- The two-region merge does not run on AWS's emulator: it does not separate
  Regions (one Region per emulator). It is skipped there by name.
- IAM, and real ACM page sizes and quotas.
- Azure and GCP positive cases need a test tenant/project:
  `KK_LIVE_AZURE_KV_URL`+`AZURE_TENANT_ID/CLIENT_ID/CLIENT_SECRET`;
  `KK_LIVE_GCP_PROJECT`+`GOOGLE_ACCESS_TOKEN`.

`import_certs_test.go` holds the helpers that import certs, request the pending one
and count ListCertificates pages (gated by `KK_LIVE_CLOUD_INVENTORY=1`, skip otherwise).
`KK_CLOUD_PAGINATION_CERTS` (1100) sets the pagination batch. The run reads
`scan_jobs` with `sqlite3`, which must be installed.
