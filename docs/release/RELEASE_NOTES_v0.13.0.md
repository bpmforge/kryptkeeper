# Kryptkeeper v0.13.0

This release is about deploying and shipping Kryptkeeper: a prebuilt dashboard
image for compose and Helm, Helm high availability by default, an operator
rollback command, scripted SQLite backup, a signed air-gap bundle, signed
apt/yum repositories, a two-arch Homebrew formula and a signed `install.sh`,
plus licence and Terraform gates in CI. It is feature group W25 of the v1.0
release train.

## Upgrade notes (read first)

- **Helm defaults to 2 replicas with a PodDisruptionBudget.** Two replicas need
  `config.dbMode=postgres` (the chart refuses to render sqlite with more than
  one replica), a keystore every replica can mount, and the root CA created
  once (set `KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT` on a single replica first).
  Set `replicaCount: 1` to keep the old shape.
- **Size Postgres for the replicas.** Each hub opens 33 store pools, now capped
  at 3 open / 1 idle connections each with a 60 s idle timeout
  (`KRYPTKEEPER_DB_MAX_OPEN_CONNS`, `KRYPTKEEPER_DB_MAX_IDLE_CONNS`, chart
  `config.db`). Two replicas peaked at 93 connections on kind; give Postgres
  `max_connections >= 200` for the 2-replica default.
- **The hub refuses a database newer than itself.** Booting an older binary
  against a newer schema exits with both versions named. Roll back with
  `kryptkeeper migrate down --to N --backup-id ID` from the newer binary, then
  start the older one (`docs/deployment.md`, "Upgrade and rollback").
- **Compose no longer builds the UI at `up`.** The `ui-build` service is gone;
  `dashboard` is built from `Dockerfile.dashboard` and listens on 8080 inside
  the container (host port 3000 is unchanged).
- **The chart sets `APP_TEMPLATE_FILE`** on the data volume, since the template
  store's default path is on the read-only root filesystem.
- No database migrations in this release.

## New

- **Dashboard image:** `Dockerfile.dashboard` (Node 24 build, unprivileged
  nginx) for compose and Helm; the Helm dashboard verifies the hub's TLS
  against its CA.
- **migrate CLI:** `kryptkeeper migrate status` and `migrate down`, audited as
  `schema.migrate.up|down`; a failed migration emits a `migration.failed`
  alert.
- **SQLite backup and restore** in `scripts/deploy/backup.sh` and
  `restore.sh`, with tamper and engine-mismatch checks.
- **Air-gap bundle v2:** hub, agent, MCP, cert-manager issuer and dashboard
  images with a cosign-signed manifest; `push` verifies the signature and
  every file's digest offline before loading anything.
- **Packages:** signed apt and yum repositories built by
  `.github/workflows/pkg-repo.yml` for `pkg.kryptkeeper.io`; a two-arch
  (arm64 + amd64) Homebrew formula attached to each release; `install.sh` as a
  release asset that verifies cosign and the archive checksum and fails closed
  without cosign.
- **CI:** a licence gate denying GPL, AGPL and SSPL in Go and npm dependencies
  with a generated `THIRD_PARTY_LICENSES.md`, and `terraform validate` plus
  `tflint` on `deploy/terraform`.
- **Docs:** `docs/LICENSING_AND_SUPPORT.md` (no paid tier; fix targets
  Critical 7 days, High 30 days, Medium 90 days, Low next minor) and updated
  supported versions in `SECURITY.md`.

## Fixed

- **Replicas now see each other's certificates.** A hub hydrated its
  certificate list once at startup and later merged only discovery rows, so a
  certificate issued, renewed or revoked on one replica stayed invisible on
  the other until restart and the renewal leader skipped it. Replicas now
  merge peer changes and read through on a lookup miss.
- Each replica held about 60 Postgres connections, so two exhausted the
  default limit and later store opens fell back to in-memory stores.
- `scripts/deploy/by-digest.sh`: the Helm driver dropped the release's values
  on upgrade, and registries with a port were rejected.

## Proven live (records in `docs/release/*_v0.13.md`)

Helm HA on kind with no workarounds: every replica lists every certificate,
the renewal leader paged 5 of 5 with no duplicates across failovers, graceful
failover 9 s and hard kill 124 s, PDB drain kept one replica Ready. Air-gap
install on a deny-egress kind network: 0 egress packets in 600 s. Promote and
rollback by digest on kind. Rollback rehearsal from 0.9.0 on SQLite and
Postgres 16. Listener-cert renewal with agents staying connected. Release
images pulled and verified on amd64 and arm64. deb/rpm install, upgrade and
remove on Debian 12 and Rocky 9 from a locally signed repo. Single-node SQLite
RTO 7 to 10 s.

## Known gaps

- Failover does not meet the board's 30 s target: the lease floor is 60 s.
- Not yet run: the DR drill with HSM-held keys (W25-09, runbook ready), the
  Terraform apply/destroy in a sandbox AWS account (W25-16), the first hosted
  apt/yum publish (needs the repo signing key, Cloudflare secrets and the
  `kryptkeeper-pkg` Pages project), a clean-machine timed compose run, and a
  real `brew install` from a release.
- `backup.sh` cannot export keys while key dual control is on (default); the
  drill ran with it off.
- `promote-by-digest.yml` still verifies with a key, which cannot verify
  keyless release signatures.
- Stores still open one Postgres pool each, and some fall back to in-memory
  stores when the database is unreachable.
