# Rollback rehearsal (v0.13 build, W25-07)

Status: **Rehearsed and recorded for SQLite and PostgreSQL 16; 0 failed assertions on either engine.** Scope limits are in "What this does and does not prove". Every number and output block below is verbatim from the run; nothing is edited except removal of the full per-table dump (rendered as the tables instead) and the per-run secrets, which were generated with `openssl rand` and are not recorded.

## Environment

| Item | Value |
|---|---|
| Host | macOS 27.0.1 arm64, podman 6.1.3 (machine VM), 2026-10-16 UTC |
| Previous release | `ghcr.io/bpmforge/kryptkeeper:0.9.0` (image id `7991009af8b7`, schema version 76) |
| Build under test | this worktree (base `903f5111`) with the W25-06 changes applied in the working tree (built before they were committed, so do not reproduce from a later HEAD; binary sha256 `226751b5da8fbf35...`), `CGO_ENABLED=0 GOOS=linux GOARCH=arm64`, run **inside the 0.9.0 image** via `--entrypoint`, so only the hub binary differs between old and new (schema version 79) |
| SQLite | `KRYPTKEEPER_DB_MODE=sqlite`, data directory bind-mounted from the host |
| PostgreSQL | `postgres:16-alpine` container, backup with the container's own `pg_dump -Fc` and restore with `pg_restore`, not `scripts/deploy/backup.sh` (that script was being edited by another change during the run; using the server container's tools also satisfies the client = server major version rule in DR_RUNBOOK). The encrypted key export half of `backup.sh` was therefore not exercised; the keystore directory persisted on the bind mount |
| Hub config | compose-style: `APP_CERTIFICATE_PROVIDER=ca`, `APP_DISCOVERY_PROVIDER=db`, `APP_NOTIFICATION_PROVIDER=delivery`, self-issued TLS, bootstrap auth, secrets from `openssl rand` |

Why 0.9.0 and not the newest image: `ghcr.io/bpmforge/kryptkeeper:0.9.3` already ships schema 79, the same as the build under test, so an upgrade from it changes no schema and exercises nothing. 0.9.0 is the newest local release at a lower schema (76 to 79: three migrations, 000077 to 000079).

## Procedure

Driven by one script (`rehearse.sh <engine> <port>`, kept outside the repo; the commands it runs are the ones shown in the outputs). Steps follow W25-07:

1. Start the previous release; seed a workload through the API: root CA, one template, 5 certificates, 1 revocation, 1 notification rule.
2. Stop the hub. Back up (SQLite: `cp -a` of the stopped data directory plus `shasum -a 256`; Postgres: `pg_dump -Fc` plus `sha256sum`). Snapshot per-table row counts and the schema version. Digest the existing `audit_log` rows.
3. Upgrade: start the build under test on the same data, wait for `/readyz` 200, record the schema version.
4. Stop the hub. `kryptkeeper migrate status`, then `migrate down` without a backup id (must refuse), then `migrate down --to 76 --backup-id <id>`.
5. Start the previous release: `/readyz` 200, re-snapshot, compare. `openssl verify` one old certificate, issue one new certificate from the old CA, verify it.
6. Restore the step-2 backup into an empty store, start the build under test (rollback of the rollback).
7. Negative (run last; the log headings call it `6` and the restore `7`, after W25-07's numbering): after the upgrade, issue against a `require_approval` template (HTTP 202, writes a `pending_approval` audit row), then `migrate down --to 75` must exit 1 and leave everything but one audit record untouched.

## Results

### SQLite

Row counts, pre-upgrade snapshot against the state immediately after `migrate down` (hub stopped, before the previous release started again):

| Table | Pre-upgrade snapshot | After `migrate down` | Equal |
|---|---|---|---|
| `audit_log` | 9 | 11 | no, append-only growth (see text) |
| `certificate_authorities` | 1 | 1 | yes |
| `certificates` | 6 | 6 | yes |
| `ha_scheduler_locks` | 2 | 2 | yes |
| `notification_deliveries` | 3 | 3 | yes |
| `notification_rules` | 1 | 1 | yes |
| `posture_snapshots` | 1 | 1 | yes |
| `schema_migrations` | 73 | 73 | yes |

53 further tables are 0 rows before and after: `acme_account_eab`, `acme_accounts`, `acme_authzs`, `acme_certs`, `acme_eab_keys`, `acme_orders`, `agent_endpoints`, `agent_inventory`, `agent_results`, `agent_tasks`, `agents`, `api_keys`, `ca_key_rotations`, `ca_tenants`, `cert_approval_requests`, `certificate_endpoints`, `certificate_templates`, `cloud_kms_keys`, `connectors`, `ct_findings`, `custom_roles`, `delivery_plugin_versions`, `delivery_plugins`, `endpoints`, `evidence_schedules`, `finding_exceptions`, `inventory_sources`, `issuance_policies`, `key_ceremonies`, `key_lifecycle`, `managed_targets`, `migration_wave_members`, `migration_waves`, `minted_api_keys`, `nhi_identities`, `notification_policies`, `notification_silences`, `outbound_credentials`, `pending_actions`, `renewal_alert_cooldowns`, `role_sod_constraints`, `runtime_config`, `scan_jobs`, `scan_results`, `scep_challenges`, `scim_group_members`, `scim_groups`, `ssh_certificates`, `team_members`, `teams`, `template_tenants`, `tenants`, `users`.

Every table other than `audit_log` is identical. `audit_log` grew because it is append-only and the upgrade, the CLI and the hub's own scheduler each write to it; the nine pre-upgrade rows are unchanged (digest of ids 1 to 9 matches before and after).

Verbatim output:

```
### 1. previous release ghcr.io/bpmforge/kryptkeeper:0.9.0: start, seed workload (sqlite)
old schema version: 76
CA id: b9e5529a-0fdb-4aae-99ef-e103bd25f73e
template id: tpl-rehearsal-1792111152781452591
cert 1 fingerprint: 459580325a2ed23c...
cert 2 fingerprint: 0f295b60a87c78b7...
cert 3 fingerprint: 5c5fb6004effa934...
cert 4 fingerprint: fd5fc05ff9908900...
cert 5 fingerprint: 74421e84b474c8ca...
revoke HTTP 200
notification rule HTTP 201
PASS: seed workload created

### 2. stop hub, back up, snapshot
backup id: db-20261016T003935Z
5670f82abe08641470ca28a792033f423df44e1f86a5409cb57e114a37737faa  ~/.kk-w25-07-sqlite-cfee72/backup-db-20261016T003935Z/data/kryptkeeper.db
pre-upgrade schema version: 76; audit_log max id: 9; audit digest (ids<=max): 212462b292d321bacdfcbe31be313e62

### 3. upgrade: start current build (W25-06) on the same data
post-upgrade schema version: 79
2026/10/16 00:40:33 migration 000007_seed_baseline_data skipped: CI seed data is off by default; set KRYPTKEEPER_SEED_CI_DATA=true to apply it
tables after upgrade that were not in S1:
audit rows written by the upgrade boot:
10|schema.migrate.up|system|kryptkeeper|success|{"applied":[77,78,79],"count":3}

### 4. migrate status / down --to 76 (hub stopped)
$ kryptkeeper migrate status
engine:           sqlite
database schema:  000079
binary schema:    000079
state:            current
exit=0
$ kryptkeeper migrate down --to 76 (no --backup-id)
migrate down: --backup-id is required and must match ^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$; take a backup first (scripts/deploy/backup.sh) and pass its db-<timestamp> name
exit=1
$ kryptkeeper migrate down --to 76 --backup-id db-20261016T003935Z
rolled back 3 migration(s): 000079 -> 000076
exit=0
schema version after down: 76
schema.migrate.down audit row:
10|schema.migrate.up|system|kryptkeeper|000079|success|{"applied":[77,78,79],"count":3}
11|schema.migrate.down|user|cli:root|000079->000076|success|{"backup_id":"db-20261016T003935Z","from":79,"to":76}

### 5. old image: ready, re-snapshot, verify
PASS: old image /readyz 200 after rollback
schema version seen by old hub: 76
--- diff S1(pre-upgrade) vs S2(right after migrate down), all tables ---
13c13
< audit_log 9
---
> audit_log 11
PASS: every table except audit_log has the pre-upgrade row count right after migrate down
--- diff S1 vs S3(old hub booted again), all tables ---
13c13
< audit_log 9
---
> audit_log 11
PASS: every table except audit_log has the pre-upgrade row count after the old release booted again
PASS: pre-upgrade audit rows (id<=9) byte-identical digest
$ openssl verify (old certificate 1)
~/.kk-w25-07-sqlite-cfee72/work/old-leaf.pem: OK
PASS: old certificate passes openssl verify
PASS: old CA issues a new certificate after rollback (8162767abea18512...)
~/.kk-w25-07-sqlite-cfee72/work/new-leaf.pem: OK
PASS: new certificate passes openssl verify

### 7. rollback of the rollback: restore step-2 backup into an empty store, start current build
restored schema version: 76
PASS: restored store row counts identical to the step-2 snapshot
PASS: current build /readyz 200 on restored data (schema 79)

### 6. negative: pending_approval audit row after upgrade -> migrate down --to 75 refused
approval template id: tpl-rehearsal-approval-1792111335853522703
issue against require_approval template: HTTP 202
PASS: issue returns 202 pending approval
$ kryptkeeper migrate down --to 75 --backup-id db-20261016T003935Z
migrate down: refusing to roll back migration 000076: audit_log has 1 rows using the migration 000076 vocabulary; they cannot be represented after rollback (audit is append-only, rows are never deleted)
exit=1
PASS: migrate down --to 75 exits 1
13c13
< audit_log 12
---
> audit_log 13
(only audit_log may differ above: the denied schema.migrate.down record)
schema version after refusal: 79
13|schema.migrate.down|denied|{"backup_id":"db-20261016T003935Z","detail":"audit_log has 1 rows using the migration 000076 vocabulary; they cannot be represented after rollback (audit is append-only, rows are never deleted)","from":79,"to":75}

=== sqlite rehearsal: 0 failure(s) ===
```

### PostgreSQL 16

| Table | Pre-upgrade snapshot | After `migrate down` | Equal |
|---|---|---|---|
| `audit_log` | 9 | 11 | no, append-only growth (see text) |
| `audit_log_2026_10` | 9 | 11 | no, append-only growth (see text) |
| `certificate_authorities` | 1 | 1 | yes |
| `certificates` | 6 | 6 | yes |
| `ha_scheduler_locks` | 2 | 2 | yes |
| `notification_deliveries` | 3 | 3 | yes |
| `notification_rules` | 1 | 1 | yes |
| `posture_snapshots` | 1 | 1 | yes |
| `schema_migrations` | 73 | 73 | yes |

55 further tables are 0 rows before and after: `acme_account_eab`, `acme_accounts`, `acme_authzs`, `acme_certs`, `acme_eab_keys`, `acme_orders`, `agent_endpoints`, `agent_inventory`, `agent_results`, `agent_tasks`, `agents`, `api_keys`, `audit_log_2026_11`, `audit_log_2026_12`, `ca_key_rotations`, `ca_tenants`, `cert_approval_requests`, `certificate_endpoints`, `certificate_templates`, `cloud_kms_keys`, `connectors`, `ct_findings`, `custom_roles`, `delivery_plugin_versions`, `delivery_plugins`, `endpoints`, `evidence_schedules`, `finding_exceptions`, `inventory_sources`, `issuance_policies`, `key_ceremonies`, `key_lifecycle`, `managed_targets`, `migration_wave_members`, `migration_waves`, `minted_api_keys`, `nhi_identities`, `notification_policies`, `notification_silences`, `outbound_credentials`, `pending_actions`, `renewal_alert_cooldowns`, `role_sod_constraints`, `runtime_config`, `scan_jobs`, `scan_results`, `scep_challenges`, `scim_group_members`, `scim_groups`, `ssh_certificates`, `team_members`, `teams`, `template_tenants`, `tenants`, `users`.

`audit_log_2026_10` is the monthly partition of `audit_log` that holds the rows, so the two rows of the table move together. Every other table is identical.

Verbatim output:

```
### 1. previous release ghcr.io/bpmforge/kryptkeeper:0.9.0: start, seed workload (postgres)
old schema version: 76
CA id: ddd4a928-74f2-4d3e-b1b2-ffcc4aeb832c
template id: tpl-rehearsal-1792111754103517600
cert 1 fingerprint: e2f82006606ca5a0...
cert 2 fingerprint: d8f12af82f08bac1...
cert 3 fingerprint: bab71108cf74a2e1...
cert 4 fingerprint: 46662cd2af92e98b...
cert 5 fingerprint: a59318ae18852822...
revoke HTTP 200
notification rule HTTP 201
PASS: seed workload created

### 2. stop hub, back up, snapshot
backup id: db-20261016T004915Z
2b4aec71e91c07eeed8d8e951f6df8e952687ded0732e7dcff5b48092e909bd2  /tmp/db-20261016T004915Z.dump
;
; Archive created at 2026-10-16 00:49:15 UTC
;     dbname: kk
pre-upgrade schema version: 76; audit_log max id: 9; audit digest (ids<=max): 8b8b0db5ea13f34ff8b7feca4fb5efd6

### 3. upgrade: start current build (W25-06) on the same data
post-upgrade schema version: 79
2026/10/16 00:49:40 migration 000007_seed_baseline_data skipped: CI seed data is off by default; set KRYPTKEEPER_SEED_CI_DATA=true to apply it
tables after upgrade that were not in S1:
audit rows written by the upgrade boot:
10|schema.migrate.up|system|kryptkeeper|success|{"applied":[77,78,79],"count":3}

### 4. migrate status / down --to 76 (hub stopped)
$ kryptkeeper migrate status
engine:           postgres
database schema:  000079
binary schema:    000079
state:            current
exit=0
$ kryptkeeper migrate down --to 76 (no --backup-id)
migrate down: --backup-id is required and must match ^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$; take a backup first (scripts/deploy/backup.sh) and pass its db-<timestamp> name
exit=1
$ kryptkeeper migrate down --to 76 --backup-id db-20261016T004915Z
rolled back 3 migration(s): 000079 -> 000076
exit=0
schema version after down: 76
schema.migrate.down audit row:
10|schema.migrate.up|system|kryptkeeper|000079|success|{"applied":[77,78,79],"count":3}
11|schema.migrate.down|user|cli:root|000079->000076|success|{"backup_id":"db-20261016T004915Z","from":79,"to":76}

### 5. old image: ready, re-snapshot, verify
PASS: old image /readyz 200 after rollback
schema version seen by old hub: 76
--- diff S1(pre-upgrade) vs S2(right after migrate down), all tables ---
13,14c13,14
< audit_log 9
< audit_log_2026_10 9
---
> audit_log 11
> audit_log_2026_10 11
PASS: every table except audit_log has the pre-upgrade row count right after migrate down
--- diff S1 vs S3(old hub booted again), all tables ---
13,14c13,14
< audit_log 9
< audit_log_2026_10 9
---
> audit_log 11
> audit_log_2026_10 11
PASS: every table except audit_log has the pre-upgrade row count after the old release booted again
PASS: pre-upgrade audit rows (id<=9) byte-identical digest
$ openssl verify (old certificate 1)
~/.kk-w25-07-postgres-d9493c/work/old-leaf.pem: OK
PASS: old certificate passes openssl verify
PASS: old CA issues a new certificate after rollback (61243169d72302e5...)
~/.kk-w25-07-postgres-d9493c/work/new-leaf.pem: OK
PASS: new certificate passes openssl verify

### 7. rollback of the rollback: restore step-2 backup into an empty store, start current build
pg_restore ok
restored schema version: 76
PASS: restored store row counts identical to the step-2 snapshot
PASS: current build /readyz 200 on restored data (schema 79)

### 6. negative: pending_approval audit row after upgrade -> migrate down --to 75 refused
approval template id: tpl-rehearsal-approval-1792112000579157703
issue against require_approval template: HTTP 202
PASS: issue returns 202 pending approval
$ kryptkeeper migrate down --to 75 --backup-id db-20261016T004915Z
migrate down: refusing to roll back migration 000076: audit_log has 1 rows using the migration 000076 vocabulary; they cannot be represented after rollback (audit is append-only, rows are never deleted)
exit=1
PASS: migrate down --to 75 exits 1
13,14c13,14
< audit_log 12
< audit_log_2026_10 12
---
> audit_log 13
> audit_log_2026_10 13
(only audit_log may differ above: the denied schema.migrate.down record)
schema version after refusal: 79
13|schema.migrate.down|denied|{"backup_id":"db-20261016T004915Z","detail":"audit_log has 1 rows using the migration 000076 vocabulary; they cannot be represented after rollback (audit is append-only, rows are never deleted)","from":79,"to":75}

=== postgres rehearsal: 0 failure(s) ===
```

## Verdict

Both engines: the previous release came back up on the rolled-back database (`/readyz` 200, schema 76), every table except the append-only audit log has its pre-upgrade row count, the pre-upgrade audit rows are byte-identical, an old certificate still passes `openssl verify`, and the old CA issues and verifies a new one. Restoring the step-2 backup reproduced the snapshot exactly and the current build started on it (schema 79 after its own migrations). `migrate down --to 75` was refused with the 000076 vocabulary reason and exit 1 once a `pending_approval` row existed, leaving the schema at 79; the refusal is recorded as a `denied` `schema.migrate.down` audit row.

Acceptance 2 of W25-07 (backup, upgrade, rollback, verify row counts identical to the pre-upgrade snapshot) is met, with the audit log excepted as above.

## What this does and does not prove

- The rolled-back range was 79 to 76. Migrations 000077 to 000079 add or change columns only; none creates a table, so "tables created by the upgrade are gone" was vacuously true (the "tables after upgrade that were not in S1" list is empty on both engines). A rollback across 000076 (the audit rebuild) was exercised only through the refusal path here; its down migration is covered by `internal/db/migrate_audit_vocabulary_test.go`.
- The rollback used the newer binary's `migrate down` (the 0.9.0 image has no `migrate` command and does not embed the 000077 to 000079 down files). This is also what the operator documentation says.
- The audit actor recorded for the CLI is `cli:root` because the container user was root; on a host it is `cli:<os user>`.
- Single-node, local podman, one run per engine. The first Postgres run reported 2 failed assertions that were a harness error, not a product result: it excluded only the `audit_log` row from the strict comparison and so flagged the `audit_log_2026_10` partition of the same table (the diff in that run showed exactly those two lines and nothing else). The comparison was corrected to exclude both and the whole Postgres run was repeated from scratch; the output above is the repeat. An earlier SQLite run used a 30-day notification threshold that made the renewal scheduler write 4 alert-cooldown rows on the upgraded hub; the threshold was changed to 7 days and the run repeated. Neither affected the product.
- Host `sqlite3` read a private copy of the database file and WAL (never the `-shm`, which the Linux VM writes): reading the live files directly made the macOS `sqlite3` report "database disk image is malformed" after the hub was stopped. The hub itself ran normally on those files.
