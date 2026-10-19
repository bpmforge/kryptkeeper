# v0.13 upgrade test results

Scope: the forward leg for the v0.13 build only. The full forward matrix (SQLite and PostgreSQL 16, several release candidates, the carried-over assertion set) is **not** re-run here; [UPGRADE_TEST_v0.9.md](UPGRADE_TEST_v0.9.md) remains the validated matrix. This page records the one forward upgrade that the rollback rehearsal needed, plus the new behaviours of W25-06.

## Forward leg (from the rollback rehearsal, 2026-10-16 UTC)

| Engine | From | To | Result |
|---|---|---|---|
| SQLite | `ghcr.io/bpmforge/kryptkeeper:0.9.0`, schema 76 | v0.13 build, schema 79 | `/readyz` 200; migrations 000077 to 000079 applied; one `schema.migrate.up` audit row `{"applied":[77,78,79],"count":3}`, actor `system`/`kryptkeeper` |
| PostgreSQL 16 | same | same | same |

The seed workload (root CA, template, 5 certificates, 1 revocation, 1 notification rule) survived on both engines: every table other than the append-only `audit_log` kept its row count through upgrade and rollback. Details, per-table counts and verbatim output: [ROLLBACK_REHEARSAL_v0.13.md](ROLLBACK_REHEARSAL_v0.13.md).

## New in this build, exercised in the same runs

| Behaviour | Evidence |
|---|---|
| `kryptkeeper migrate status` prints the four lines and exits 0 when current | rehearsal step 4, both engines |
| `migrate down` without `--backup-id` is refused (exit 1) | rehearsal step 4, both engines |
| `migrate down --to 76 --backup-id <id>` rolls back 3 migrations and writes a `schema.migrate.down` audit row with the backup id | rehearsal step 4, both engines |
| `migrate down --to 75` is refused (exit 1, `denied` audit row) once a `pending_approval` audit row exists | rehearsal step 7, both engines |
| An older binary refuses to boot on a newer schema, naming both versions, within 5 s | `TestBootRefusesNewerSchema` (SQLite, real binary); `TestRunMigrations_RefusesNewerSchema_Postgres` (PostgreSQL 16) |

## Not run

- The v0.9 forward matrix (see above).
- A clean-machine, human-paired upgrade of a production-shaped deployment.
- Rollback across migration 000076 on a live hub (only its refusal path was rehearsed; the down migration has its own unit tests).
