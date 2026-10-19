# W24-28 - inventory-source UAT (DigiCert sandbox + recorded fixtures)

`run.sh` boots a hub (port 8098), registers one inventory source per vendor,
syncs each twice (sync 1 imports N, sync 2 adds 0) and checks per-source
isolation. Gate: `KK_LIVE_INVSRC=1 go test ./tests/live/inventory-sources/...`
(or run `bash tests/live/inventory-sources/run.sh` directly).

## Topology

- DigiCert: the real CertCentral sandbox (`https://demo.digicert.com`), only
  when `KK_DIGICERT_API_KEY` is set. Otherwise `SKIP digicert-sandbox:
  KK_DIGICERT_API_KEY not set`, counted in the final `ALL PASS (n skipped)`.
- Sectigo (3 certs), Entrust (2), AWS Private CA (4 authorities), Google CAS
  (3, two pages): one `fixture_server.py` serving recorded response shapes under
  `/sectigo /entrust /aws /gcp`. PEMs are generated at run time (one EC key,
  distinct serial + CN per cert) into a temp dir; no key material is committed.
- Egress trap: the hub's inventory HTTP client blocks loopback, so the fixture
  server binds a non-loopback RFC1918 address (found via `ipconfig getifaddr en0`
  / `hostname -I`). With none, the four fixture vendors print
  `SKIP fixtures[...]: no non-loopback private address` (decision: CI hosts
  without a private NIC skip them; no production seam added; do not set
  `KRYPTKEEPER_EGRESS_DENY_PRIVATE`).
- Isolation: a fifth source (sectigo, login `kk-bad-login`) is rejected with 401;
  the run asserts a non-2xx without the credential in the response or hub log,
  that entrust and aws_pca still sync, and that only the bad source has an
  `error` in `last_sync_result`.

## Env

`KK_LIVE_INVSRC=1` (Go gate), `KK_DIGICERT_API_KEY`, `KK_DIGICERT_BASE_URL`
(default `https://demo.digicert.com`), `KK_DIGICERT_EXPECTED_ORDERS` (overrides
the independent count: orders with `certificate.id != 0`), `KK_INVSRC_FIXTURE_PORT`
(default 8099), `KK_KEEP=1`. The DigiCert key is never echoed (`key set: yes`) and
reaches curl via stdin config, not argv.

## Re-recording fixtures

Shapes follow `internal/bootstrap/inventory_source_commercial.go` and its tests.
To re-record, capture the vendor responses, replace each certificate with a
`{{PEM_n}}` placeholder (JSON files get it JSON-escaped), keep each file under
20 KB, and keep per-vendor counts in sync with `run.sh` (sectigo 3, entrust 2,
aws 4, gcp 3).

## Defect found by this harness (fixed)

`POST /api/v1/credentials` stores `payload` as raw JSON, so a token saved as a
JSON string reached `gcp_cas` / `digicert` still quoted and every live sync got
401. Fixed by `credentialSecretString` (commit "fix(inventory): unwrap
JSON-string credentials"). `fixture_server.py` keeps rejecting a Google bearer
token containing `"` so a regression shows up here.

## Results

Fixture run on 2026-10-15, macOS arm64, hub base commit 828dcb60 (harness
uncommitted at run time), fixture bound to a private en0 address:

| Item | Result |
|---|---|
| DigiCert sandbox (order count, rerun 0 duplicates) | PENDING-RUN (no sandbox key available) |
| sectigo sync 1 / sync 2 / total delta | PASS (synced 3; synced 0 skipped 3; +3 then +0) |
| entrust | PASS (2; 0/2; +2 then +0) |
| aws_pca | PASS (4; 0/4; +4 then +0) |
| gcp_cas | PASS after the fix (3; 0/3; +3 then +0). Before the fix: FAIL, sync 401 |
| isolation: bad sectigo credential fails, secret not leaked; entrust and aws_pca unaffected | PASS |
| isolation: only the bad source has `error` in last_sync_result | PASS after the fix |

Re-run after the credential fix (2026-10-16, same host): ALL PASS (1 skipped: DigiCert sandbox, no key).
