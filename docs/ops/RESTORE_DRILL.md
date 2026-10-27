# Backup & Restore Runbook + Executed Drill

Ticket **S-01** (G-8, kin D-051/FR-P13). Companion to `docs/ops/DR_RUNBOOK.md`
(the original W10-03 DR writeup, which this runbook does not duplicate in
full — see "Relationship to DR_RUNBOOK.md" below) and to
`docs/ops/KEY_ROTATION.md` / `docs/ops/INCIDENT_RESPONSE.md` for the
key-rotation and CA-compromise procedures this backup/restore path underpins.

## What's covered

- The hub's core database (Postgres in production — the CA/certificate/
  template/user/audit records).
- Every software-backed CA/key in the keystore, exported encrypted under a
  backup passphrase via `keystore.BackupAll`/`RestoreAll`
  (`internal/bootstrap/handlers_backup.go`, `POST /api/v1/admin/backup` /
  `POST /api/v1/admin/restore`).

## What's NOT covered

- **Non-extractable key backends** (PKCS#11/HSM, cloud KMS, HashiCorp Vault
  transit) — `ExportEncryptedKey` returns a `skipped_non_extractable` status
  for these rather than failing the whole backup. For those backends, DR
  means the DB backup (which records the key *reference*, not the key
  itself) plus that backend's own DR procedure. `backup.sh` reports any
  skipped/errored keys in its output — do not treat a silent-looking bundle
  as complete without checking.
- **Sqlite-mode deployments** (superseded: scripted since W25-08, see Drill 3 below) had no scripted DB-backup path — `backup.sh`
  hard-requires `DATABASE_URL` + `pg_dump`. The keystore itself can still be
  backed up via the same admin endpoints; the sqlite file needs an ad hoc
  file-copy backup.

## Prerequisites

- `pg_dump`/`psql` matching your Postgres server's major version (see
  "Version-skew" below — a mismatch aborts the restore, fail-closed, but the
  restore does not complete).
- `jq`, `curl`, `sha256sum`.
- A `pki-admin`-role bearer token for `/api/v1/admin/backup` and `/restore`.
- A **backup passphrase**, separate from the keystore's own store
  passphrase, stored independently of the backup artifacts (a secrets
  manager, not next to the `.json`/`.sql.gz` files).

## Backup

```bash
export DATABASE_URL="postgres://kryptkeeper:...@postgres:5432/kryptkeeper?sslmode=require"
export KRYPTKEEPER_API="https://kryptkeeper.internal"
export API_TOKEN="<pki-admin bearer token>"
export BACKUP_PASSPHRASE="<a strong, separately-stored secret>"

scripts/deploy/backup.sh /var/backups/kryptkeeper/$(date -u +%Y%m%d)
```

Produces `db-*.sql.gz`, `keys-*.json`, `manifest.json`, `SHA256SUMS`. Keep at
least the last 7 daily backups and 4 weekly backups, off-instance — a backup
on the same disk as the DB/keystore it protects defends against nothing.

## Restore

**Ordering is load-bearing.** A `pg_dump` replays full `CREATE TABLE` and
seed-data `COPY` statements. If a hub has already booted against the target
database, W10-01's migration run has already created that schema, and
replaying the dump on top aborts on the first "relation already exists"
(`psql -v ON_ERROR_STOP=1`). Restore into a database **nothing has ever
booted a hub against**, THEN boot the hub — its migration run sees
`schema_migrations` already populated by the restored dump and safely no-ops.

1. Provision a genuinely empty Postgres database and a fresh, empty
   `KRYPTKEEPER_KEYSTORE_DIR`. Do not point a hub at the database first "to
   create the schema" — that is exactly the ordering this procedure exists
   to prevent. Do not restore into an instance that already has data.
2. Run `restore.sh`, which restores the DB dump into that empty database
   FIRST:
   ```bash
   export DATABASE_URL="postgres://kryptkeeper:...@postgres:5432/kryptkeeper?sslmode=require"   # empty DB
   export KRYPTKEEPER_API="https://kryptkeeper-fresh.internal"
   export API_TOKEN="<pki-admin bearer token on the FRESH instance>"
   export BACKUP_PASSPHRASE="<the same passphrase backup.sh used>"

   scripts/deploy/restore.sh /var/backups/kryptkeeper/20260728
   ```
   `restore.sh` verifies `SHA256SUMS`, restores the DB dump via `psql`, then
   prints a prompt to boot the hub — do that now, pointed at the same
   `DATABASE_URL` — while the script polls `/readyz`. Once ready, it
   re-imports every exported key via `/api/v1/admin/restore`.
3. Run `scripts/deploy/smoke.sh <target_env>` against the restored instance.
4. **Manually verify** at least one CA can still issue a certificate (see
   the drill output below for the exact request shape) before considering
   the restore complete.

## Version-skew: `pg_dump`/`psql` must match the server

A `pg_dump` client one major version ahead of the target server emits
session-level `SET` statements the older server's `psql` doesn't recognize
(e.g. `transaction_timeout`, a Postgres 17+ GUC), and the restore aborts
immediately — fail-closed, not silent corruption, but the restore does not
complete. Use a `pg_dump`/`psql` build matching your Postgres server's major
version on whatever machine runs `backup.sh`/`restore.sh`. Reproduced live
during this ticket's drill below.

## Relationship to `DR_RUNBOOK.md`

`docs/ops/DR_RUNBOOK.md` (W10-03/G-36) is the original disaster-recovery
writeup and contains two prior executed drills against real Postgres/SQLite,
plus the discovery and fix of the restore-ordering bug this runbook's
"Ordering is load-bearing" section describes. That document is out of this
ticket's `write_scope` and is not modified here. This file exists so
`docs/ops/` has a backup/restore runbook alongside the key-rotation and
incident-response runbooks this ticket adds, with its own independently
executed drill (below) rather than only pointing at DR_RUNBOOK's.

---

## EXECUTED DRILL (2026-07-28, real output — not fabricated)

Run as an automated drill (ticket S-01), with no human at the
keyboard for individual steps. Per [SECURITY_PRINCIPLES.md](../design/SECURITY_PRINCIPLES.md), this used a
**disposable local environment with synthetic key material generated fresh
for the drill** — real `pg_dump`/`psql`/Postgres and a real built
`kryptkeeper` binary, but no production infrastructure and no production key
material, consistent with "private key material never leaves its boundary"
and "test keys are generated in-test." The ticket's `notes` field carries a
`HUMAN-PAIR` flag from the same lineage as DR_RUNBOOK's original W10-03
ticket; see "What's still open" at the end of this section for exactly what
that flag still asks for beyond what an unattended drill can prove.

**Setup**: a disposable `postgres:18-alpine` container via Podman
(`kk-drill-postgres`, port 15532), `pg_dump`/`psql` v18.4 from a local
Homebrew `libpq` keg (matching the server's major version — see the
version-skew note above), and the real `kryptkeeper` hub binary built from
this branch (`go build -o kryptkeeper ./cmd/kryptkeeper`).

**1. Booted a "source" hub against real Postgres 18**
(`KRYPTKEEPER_DB_MODE=postgres`, fresh `KRYPTKEEPER_KEYSTORE_DIR`). Boot log:
```
key backend: software (AES-GCM + Argon2id)
CA store: database
certificate provider: ca engine
starting kryptkeeper on 127.0.0.1:18091
```
`/readyz` → `{"status":"ready"}`, confirming W10-01's migration run applied
cleanly against a real, freshly created Postgres database.

**2. Created a real root CA:**
```
POST /api/v1/cas {"name":"s01-drill-root","type":"root","key_storage_type":"software","subject_cn":"S-01 Drill Root CA","algorithm":"ECDSA-P256"}
-> {"data":{"id":"efb60f8d-929e-439f-841c-8200431515c8","status":"active",
     "certificate_fingerprint_sha256":"c2645c579b7cc06ad9d847080a4832c96961c73177e29915107828b77fa38aa5", ...}}
```

**3. Ran the real `backup.sh`:**
```
$ scripts/deploy/backup.sh /tmp/kk-drill/backup-out
[backup] dumping database...
[backup] database dump written: /tmp/kk-drill/backup-out/db-20260728T210657Z.sql.gz ( 16K)
[backup] exporting keystore...
[backup] keystore bundle written: /tmp/kk-drill/backup-out/keys-20260728T210657Z.json (exported=1 skipped_non_extractable=0 error=0)
[backup] manifest + checksums written: /tmp/kk-drill/backup-out/manifest.json, /tmp/kk-drill/backup-out/SHA256SUMS
[backup] done
```
`manifest.json`: `{"schema_version":1,"created_at":"20260728T210657Z","db_dump":"db-20260728T210657Z.sql.gz","keys_bundle":"keys-20260728T210657Z.json"}`.
`SHA256SUMS` recorded a checksum per artifact (verified again by `restore.sh`
in step 5).

**4. Stopped the source instance. Confirmed the destination database was
genuinely empty** (`psql ... \dt` → "Did not find any tables"). **Ran the
real `restore.sh`**, exactly in the ordering this runbook prescribes:
```
$ scripts/deploy/restore.sh /tmp/kk-drill/backup-out
[restore] verifying checksums...
db-20260728T210657Z.sql.gz: OK
keys-20260728T210657Z.json: OK
manifest.json: OK
[restore] restoring database from db-20260728T210657Z.sql.gz into DATABASE_URL ...
... (real pg_dump SQL replayed: CREATE EXTENSION x2, CREATE TABLE x46+, COPY rows
     incl. schema_migrations, CREATE INDEX x~90, CREATE TRIGGER x8, CREATE POLICY, ALTER TABLE ...)
[restore] database restored
[restore] >>> now boot a Kryptkeeper hub instance against DATABASE_URL if you have not already ... <<<
[restore] waiting for http://127.0.0.1:18092/readyz (boot the hub against DATABASE_URL now if you haven't)...
```

**5. Booted the "destination" hub** (fresh keystore dir, different store
passphrase) against the now-restored, DB-only database — **before the key
bundle had been re-imported**. This is a real, useful negative check: the
G-78 boot-time key-consistency scan (`ca.CheckKeyConsistency`,
`cmd/kryptkeeper/main.go`) correctly flagged the gap instead of silently
serving a broken CA:
```
CA store: database
CA KEY INCONSISTENCY: CA efb60f8d-929e-439f-841c-8200431515c8 ("s01-drill-root")
keystore key key-efb60f8d-929e-439f-841c-8200431515c8: keystore has no public
key for key-efb60f8d-929e-439f-841c-8200431515c8: key not found -- do NOT
rotate or issue from this CA; recover it from a pre-rotation backup via the
DR procedure (docs/ops/DR_RUNBOOK.md)
```
`/readyz` still returned `{"status":"ready"}` (readiness is DB/HTTP liveness,
not per-CA key consistency — the warning is advisory, logged not fatal).
`restore.sh`'s poll then picked up the ready instance and completed:
```
[restore] importing keystore bundle...
{"data":{"imported":1}}
[restore] done — run scripts/deploy/smoke.sh against http://127.0.0.1:18092 to verify
```

**6. Confirmed the recovered CA via `GET /api/v1/cas`** on the destination —
`s01-drill-root` present, `status: active`, with the **same
`certificate_fingerprint_sha256`** as step 2
(`c2645c579b7cc06ad9d847080a4832c96961c73177e29915107828b77fa38aa5`),
recovered purely from the dump + key bundle.

**7. Rebooted the destination instance a second time** (after the key
import) to confirm the G-78 check now finds no inconsistency:
```
CA store: database
```
— no `CA KEY INCONSISTENCY` line this time, confirming the recovered
keystore key and CA record are back in sync.

**8. Issued a real leaf certificate from the recovered CA** (real ECDSA
P-256 key + CSR via `openssl`):
```
POST /api/v1/certificates {"ca_id":"efb60f8d-...","template_id":"tpl-s01-drill-template-...","csr_pem":"..."}
-> HTTP 200
{
  "data": {
    "fingerprint_sha256": "b03751d88451127b4227785131a8e80a5dea393a4382a4b570da1d511d7781f1",
    "common_name": "s01-drill-leaf.example.com",
    "issuer_cn": "S-01 Drill Root CA",
    "chain_complete": true,
    "chain_trusted": true,
    "signature_algorithm": "ECDSA-SHA256",
    ...
  }
}
```

**9. Ran `scripts/deploy/smoke.sh` against the restored instance**:
```
[smoke] env=production base_url=http://127.0.0.1:18092
[smoke] PASS live (http://127.0.0.1:18092/healthz)
[smoke] PASS ready (http://127.0.0.1:18092/readyz)
[smoke] all checks passed
```

**Result: the full documented procedure — real `pg_dump`, real `psql`
restore into an empty database, real hub boot, a real (and correctly
flagged) key-consistency gap before key import, real key re-import, a
second boot confirming the gap closed, and real certificate issuance with
`chain_complete: true, chain_trusted: true` — worked end to end.** All drill
infrastructure (the Podman container, temp binary, temp directories) was
torn down afterward; nothing from this drill persists outside this
transcript.

### What's still open

This drill proves the mechanism — a genuinely lost/corrupted instance can be
brought back from a `backup.sh` bundle with zero data loss, verified by
issuing a real certificate from the recovered CA. What it does not prove,
matching DR_RUNBOOK's own "Human-paired production drill" caveat:

- It ran against disposable local infrastructure (a Podman container), not
  this deployment's real staging/production Postgres.
- It used a passphrase in a shell variable — fine for a drill, not for a
  production secrets-management process.
- No human ran the commands themselves in real time; an operator directing
  each step (or running it solo) against real staging infrastructure at
  least once is still worth doing before treating this as fully proven for
  *this* deployment's production environment — this is what the ticket's
  `HUMAN-PAIR` note asks for beyond what an autonomous drill can provide.

---

## Release checklist: re-run the DR drill

Run this before every release (W23-20, UC-A06). Targets: **RTO < 60 minutes, RPO < 24 hours**
(the single DR targets shared with J05/M12; `DR_RUNBOOK.md` states none).

1. Restore the latest backup into a clean hub, following "Restore" above, and time it against the RTO.
2. Compare the newest backup's age at the moment of loss against the RPO.
3. Run the escrow and BYOK drill: `bash tests/live/escrow-byok/run.sh` (podman; starts moto and Lowkey Vault, stops them on exit).
4. Commit the generated record as `docs/release/DRILL_ESCROW_BYOK_vX.Y.md` with its date, git SHA and tool versions (the script writes it; never hand-edit results). Include the restore timing from steps 1-2.
5. Block the release if the record for the current version is missing, or if a leg that passed in the previous record now fails. Legs recorded as PARTIAL or NOT IMPLEMENTED stay listed under "Not proven" until closed.

## EXECUTED DRILL 3 (SQLite)

W25-08. Real hub binary (`go build -o kryptkeeper ./cmd/kryptkeeper`, 2026-10-15, macOS arm64,
sqlite3 3.54.0), `KRYPTKEEPER_DB_MODE=sqlite`, software keystore, loopback port 19080. Each run
seeds a fresh hub with 1 root CA (`KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT`) + 1 issuing CA + 50
certificates, saves the root PEM as the pre-disaster trust anchor, runs the real `backup.sh`, then
declares disaster (T0: hub stopped, data and keystore directories deleted), runs the real
`restore.sh`, boots a replacement hub, and finishes by issuing a new certificate from the restored
issuing CA and verifying it against the saved root.

Run 1 output (paths shortened):
```
run1: seeded certs=50
[backup] database snapshot written: .../backup/db-20261016T002613Z.sqlite.gz ( 64K)
[backup] keystore bundle written: .../keys-20261016T002613Z.json (exported=2 skipped_non_extractable=0 error=0)
.../full.pem: OK
run1 RESULT db_bytes=1093632 gz_bytes=65168 keys=2 restore_db=1 hub_ready_recovery=0 key_import_done=8 normal_restart_ready=1 issue_verify=0 RTO=10
```
`restore.sh` (run 3):
```
[restore] verifying checksums...
db-20261016T002641Z.sqlite.gz: OK
keys-20261016T002641Z.json: OK
manifest.json: OK
[restore] database restored
[restore] importing keystore bundle...
{"data":{"imported":2}}
[restore] done
```
Runs 2 and 3: RTO 8 s and 7 s (min 7, median 8, max 10); per-phase table in
`docs/ops/DR_RUNBOOK.md` under `## Recovery time (RTO)`.

Findings from running it for real:
1. **Dual control blocks `backup.sh`.** On a default hub the key export returned HTTP 202
   (`dual control is on - after approval, retry with approved_action_id`) and the script failed.
   The drill hub set `KRYPTKEEPER_KEY_DUAL_CONTROL=false` (drill only). `backup.sh` has no
   approved-action support yet.
2. **A restored database plus an empty keystore does not boot.** The hub exits with
   `refusing to start: 2 active CA(s) have no usable key in the keystore`; earlier drills
   described this as an advisory warning. The drill boots the replacement with
   `KRYPTKEEPER_ALLOW_MISSING_CA_KEYS=true`, imports keys, then restarts without it
   (restart counted in the RTO). After the normal restart the log had no `CA KEY INCONSISTENCY`.
3. The first harness attempt measured nothing: a stale hub kept answering on the port after the
   "disaster". The harness now fails if the old hub still answers after the kill.

Automated row-count round trip (no hub): `bash scripts/deploy/backup_sqlite_test.sh`.

### What's still open (after drill 3)

SQLite DR is now scripted and timed on one node. Still open: Postgres RTO, dual-control approval
in `backup.sh`, an off-instance restore, and a drill with an operator at the keyboard.
