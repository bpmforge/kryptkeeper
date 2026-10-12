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
- **Sqlite-mode deployments** have no scripted DB-backup path — `backup.sh`
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

Run solo by the implementing agent for ticket S-01, no human at the
keyboard for individual steps. Per `MASTER_PROMPT.md`/CLAUDE.md, this used a
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
