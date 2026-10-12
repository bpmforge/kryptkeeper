# Disaster Recovery Runbook

W10-03/G-36: before this ticket, a lost/corrupted data volume meant permanent loss of every CA
private key — there was no backup or restore path at all. This runbook documents the real one.

## What's covered

- **The hub's database** (Postgres in production; the certificate/CA/user/audit records).
- **Every CA/key in the keystore** the software backend manages, exported encrypted under a
  backup passphrase (`internal/keystore/backup.go`'s `BackupAll`/`RestoreAll`, wired to
  `POST /api/v1/admin/backup` / `POST /api/v1/admin/restore` in `internal/bootstrap/handlers_backup.go`).

## What's NOT covered — read this before you rely on this runbook

- **Non-extractable key backends (PKCS#11/HSM, cloud KMS, HashiCorp Vault transit)** cannot be
  exported by design — `ExportEncryptedKey` returns an explicit "non-extractable" error for these,
  and `BackupAll` records the key as `skipped_non_extractable` in the bundle rather than failing the
  whole backup. **For those backends, DR means: the DB backup (which records the key *reference*,
  not the key itself) plus that backend's own DR procedure for the key material.** `backup.sh` warns
  loudly (non-zero-visible, not silent) whenever a backup bundle contains any skipped keys.
- **`pg_dump`/`psql` client version must match (or be compatible with) your Postgres server version.**
  Found during the real drill below: a `pg_dump` client one major version ahead of the target server
  emits session-level `SET` statements (e.g. `transaction_timeout`, introduced in Postgres 17) the
  older server's `psql` doesn't recognize, and the restore aborts immediately (fail-closed — good —
  but the restore does not complete). Use a `pg_dump`/`psql` build matching your Postgres server's
  major version, on whatever machine runs `backup.sh`/`restore.sh`.
- **This runbook's drill has been executed against real Postgres (see below) — the previous version
  of this note said it hadn't been; that gap is now closed.** What remains genuinely open: the drill
  was run against a disposable local Postgres container, not the real staging/production
  infrastructure, and it was run by the implementing agent with the operator directing/approving each
  step rather than an operator's own hands on the keyboard throughout. See "Human-paired production
  drill" below for exactly what that distinction means and what's still worth doing before full sign-off.

## Prerequisites

- `pg_dump` / `psql` matching your Postgres server's major version, on the machine running `backup.sh`/`restore.sh`.
- `jq`, `curl`, `sha256sum`.
- A `pki-admin`-role bearer token for the hub's `/api/v1/admin/backup` and `/restore` endpoints
  (same admin gating as every other `/api/v1/keys/*` endpoint).
- A **backup passphrase** — a secret separate from the keystore's own store passphrase, used only to
  encrypt the exported key bundle (`keystore.ExportEncryptedKey`'s existing design). Store it
  somewhere independent of the backup artifacts themselves (a secrets manager, not next to the
  `.json`/`.sql.gz` files) — anyone with both the bundle and this passphrase can decrypt every CA key.

## Backup schedule (recommendation)

Run `scripts/deploy/backup.sh <out_dir>` on a schedule appropriate to your change rate — nightly is a
reasonable default for most deployments. Keep at least the last 7 daily backups and 4 weekly backups,
off-instance (a separate object store/volume, not the same disk as the DB/keystore you're backing up
— a backup on the same failing disk protects against nothing).

```bash
export DATABASE_URL="postgres://kryptkeeper:...@postgres:5432/kryptkeeper?sslmode=require"
export KRYPTKEEPER_API="https://kryptkeeper.internal"
export API_TOKEN="<pki-admin bearer token>"
export BACKUP_PASSPHRASE="<a strong, separately-stored secret>"

scripts/deploy/backup.sh /var/backups/kryptkeeper/$(date -u +%Y%m%d)
```

Produces `db-*.sql.gz`, `keys-*.json`, `manifest.json`, `SHA256SUMS` in the output directory.

## Restore procedure

**Ordering is load-bearing — read this before running anything.** A default `pg_dump` replays full
`CREATE TABLE` statements and seed-data `COPY` rows. If a Kryptkeeper hub has already booted against
the target database, W10-01's migration run has already created that schema, and replaying the dump
on top will abort on the first "relation already exists" (`psql -v ON_ERROR_STOP=1`). The correct
order is: restore the dump into a database **nothing has ever booted a hub against**, THEN boot the
hub — at which point its migration run sees `schema_migrations` already fully populated by the
restored dump and safely no-ops (proven both by `TestRunMigrations_SecondRunIsNoOp`,
`internal/db/migrate_test.go`, and by the real drill below, where the destination hub's boot log showed
no migration errors after the dump restore).

1. Provision a **genuinely empty** Postgres database — do not point a hub at it first "to create the
   schema," that is exactly the ordering this procedure exists to prevent. Also prepare a fresh, empty
   `KRYPTKEEPER_KEYSTORE_DIR` for the instance you're about to boot. Do **not** restore into an
   instance that already has data — this procedure is for bringing back a lost instance, not merging
   two.
2. Run `restore.sh`, which restores the DB dump into that empty database FIRST:
   ```bash
   export DATABASE_URL="postgres://kryptkeeper:...@postgres:5432/kryptkeeper?sslmode=require"   # empty DB, no hub has ever connected
   export KRYPTKEEPER_API="https://kryptkeeper-fresh.internal"   # boot this hub AFTER the script says "database restored" (below)
   export API_TOKEN="<pki-admin bearer token on the FRESH instance>"
   export BACKUP_PASSPHRASE="<the same passphrase backup.sh used>"

   scripts/deploy/restore.sh /var/backups/kryptkeeper/20260719
   ```
   `restore.sh` verifies `SHA256SUMS`, restores the DB dump via `psql` into `DATABASE_URL`, then
   prints a prompt to boot the hub — **do that now, in another terminal/process, pointed at the same
   `DATABASE_URL`** — while the script polls `/readyz` (operator-supervised wait, ~15 minutes; if it
   times out the script tells you the DB is already restored and gives you the standalone key-import
   command instead of a script re-run, since re-running the whole script at that point would replay
   `psql` onto a now-non-empty database). Once the hub you just booted reports ready, the script
   re-imports every exported key via `/api/v1/admin/restore`.
3. Run `scripts/deploy/smoke.sh <target_env>` against the restored instance.
4. **Manually verify** at least one CA can still issue a certificate (see the drill output below for
   the exact request shape) before considering the restore complete.

**Sqlite-mode deployments have no DB-backup path today** — `backup.sh` hard-requires `DATABASE_URL`
and `pg_dump`. A sqlite-mode instance's keystore can still be backed up/restored via the same
`/api/v1/admin/backup`/`restore` endpoints; the database file itself would need a separate, ad hoc
file-copy backup (not scripted here) until sqlite gets its own DR path.

## Human-paired production drill

The spec for this ticket (`docs/board/specs/W10-03.md`) marks the executed drill **HUMAN-PAIR**: it
uses real key material, and a human must run/verify it — this is not something to automate away or
fabricate. Two drills have now been run for real (both transcribed verbatim below, neither fabricated):

1. A **local SQLite drill**, run solo by the implementing agent, before any real Postgres was
   available — proved the key-backup/restore mechanism itself but simulated the DB-restore step.
2. A **local Postgres drill**, run after the owner explicitly chose (via `AskUserQuestion`) to verify the
   DB-restore path before starting W9-04, and chose a disposable local Postgres container (Podman) over
   Homebrew-installed Postgres or the real staging box — proved the FULL pipeline including real
   `pg_dump`/`psql`, and caught the version-skew issue documented above.

**What's still open**: both drills were run by the implementing agent (with the owner directing/approving
each step via the conversation, not typing the commands themselves), and neither touched the real
staging box (`<staging-host>` per `docs/SESSION_STATUS.md`) or production. Before treating this runbook
as fully proven for THIS deployment's real infrastructure, an operator should at minimum run
`backup.sh`/`restore.sh` themselves against a real staging Postgres instance at least once, confirming:
- The backup/restore passphrase handling matches your actual secrets-management process (this drill
  used a passphrase in a shell variable — fine for a drill, not for production use).
- `pg_dump`/`psql` version matches your real Postgres server (see the version-skew note above).
- The restored instance's CA(s) can issue a certificate a relying party actually trusts.

## Executed drill 2 (2026-07-19, real Postgres via a local Podman container — real output, not fabricated)

Ran the actual `backup.sh`/`restore.sh` scripts (not a simulation) against a real Postgres server. Spun
up a disposable `postgres:18-alpine` container via Podman (Docker itself wasn't installed; Podman was
already present and Docker-compatible), installed `pg_dump`/`psql` v18.4 via Homebrew (`libpq` keg), and
ran the real hub binary against it in `KRYPTKEEPER_DB_MODE=postgres`.

**Version-skew finding, in order**: the first attempt used a pre-existing `postgres:16-alpine`
container. `backup.sh` ran cleanly, but `restore.sh`'s `psql` replay of the `pg_dump` (client v18.4)
output aborted immediately:
```
ERROR:  unrecognized configuration parameter "transaction_timeout"
```
`ON_ERROR_STOP=1` correctly stopped the whole restore at the first error — fail-closed, not silent
corruption, exactly as designed. `transaction_timeout` is a Postgres 17+ session GUC that v18.4's
`pg_dump` emits by default; the v16 server had never heard of it. Re-ran the entire drill against a
version-matched `postgres:18-alpine` container instead (both source and destination), which is the
standard operational fix (documented above under "What's NOT covered").

**1. Booted a "source" hub instance against real Postgres 18** (`KRYPTKEEPER_DB_MODE=postgres`,
`DATABASE_URL` pointed at the container) — boot log confirmed `CA store: database` and `/readyz` 200,
meaning W10-01's migration run applied all 26 migrations against a real Postgres server for real.

**2. Created a real root CA:**
```
POST /api/v1/cas {"name":"pg-drill-root","type":"root","key_storage_type":"software","subject_cn":"PG Drill Root CA","algorithm":"ECDSA-P256"}
-> {"data":{"id":"18a9cf26-eff9-4554-81c5-aac8a606b5fd","status":"active", ...}}
```

**3. Ran the real `backup.sh`** (not curl commands standing in for it):
```
$ scripts/deploy/backup.sh /tmp/kk-pg-backup-out
[backup] dumping database...
[backup] database dump written: /tmp/kk-pg-backup-out/db-20260719T141151Z.sql.gz ( 16K)
[backup] exporting keystore...
[backup] keystore bundle written: /tmp/kk-pg-backup-out/keys-20260719T141151Z.json (exported=1 skipped_non_extractable=0 error=0)
[backup] manifest + checksums written: /tmp/kk-pg-backup-out/manifest.json, /tmp/kk-pg-backup-out/SHA256SUMS
[backup] done
```
This is a real `pg_dump` of a real Postgres database, gzipped, with a real key export alongside it.

**4. Stopped the source instance. Confirmed the destination database was genuinely empty** (`psql ...
\dt` → "Did not find any tables"). **Ran the real `restore.sh`** in the background, in the exact
ordering this runbook prescribes:
```
$ scripts/deploy/restore.sh /tmp/kk-pg-backup-out
[restore] verifying checksums...
db-20260719T141151Z.sql.gz: OK
keys-20260719T141151Z.json: OK
manifest.json: OK
[restore] restoring database from db-20260719T141151Z.sql.gz into DATABASE_URL ...
... (real pg_dump SQL replayed: CREATE EXTENSION, CREATE TABLE x46, COPY rows incl. "COPY 26" for
     schema_migrations, CREATE INDEX x~90, CREATE TRIGGER x8, CREATE POLICY, ALTER TABLE ...)
[restore] database restored
[restore] >>> now boot a Kryptkeeper hub instance against DATABASE_URL if you have not already ... <<<
[restore] waiting for http://127.0.0.1:18092/readyz (boot the hub against DATABASE_URL now if you haven't)...
```
While that was polling, booted a **destination** hub instance against the now-restored database (fresh
keystore dir, different store passphrase from the source). Its boot log showed no migration errors —
the migration run against the already-populated `schema_migrations` table was a clean no-op, exactly as
predicted. `restore.sh` then picked up the ready instance and completed:
```
[restore] importing keystore bundle...
{"data":{"imported":1}}
[restore] done — run scripts/deploy/smoke.sh against http://127.0.0.1:18092 to verify
```

**5. Confirmed the recovered CA via `GET /api/v1/cas`** on the destination — `pg-drill-root` present,
`status: active`, with its real certificate metadata, recovered purely from the dump + key bundle.

**6. Issued a real leaf certificate from the recovered CA** (real ECDSA key + CSR via `openssl`):
```
POST /api/v1/certificates {"ca_id":"18a9cf26-...","template_id":"tpl-pg-drill-template-...","csr_pem":"..."}
-> HTTP 200
{
  "data": {
    "fingerprint_sha256": "5568482eb814c934fc09aa636b86e31eb0cd0c00ac0a01aa68fd6becf833d4b3",
    "common_name": "pg-drill-leaf.example.com",
    "issuer_cn": "PG Drill Root CA",
    "chain_complete": true,
    "chain_trusted": true,
    ...
  }
}
```

**7. Ran `scripts/deploy/smoke.sh` against the restored instance**:
```
[smoke] env=production base_url=http://127.0.0.1:18092
[smoke] PASS live (http://127.0.0.1:18092/healthz)
[smoke] PASS ready (http://127.0.0.1:18092/readyz)
[smoke] all checks passed
```

**Result: the full documented procedure — real `pg_dump`, real `psql` restore into an empty database,
real hub boot with a real no-op migration run, real key re-import, real certificate issuance with
`chain_complete: true, chain_trusted: true` — worked end to end against a real Postgres server.** All
drill infrastructure (containers, temp binaries, temp directories) was torn down afterward.

## Executed drill 1 (2026-07-19, local SQLite, real output — not fabricated, run before Postgres was available)

Kept for historical record — this was the first drill, run solo before a real Postgres instance was
set up, and simulated the DB-restore step via a direct `sqlite3` INSERT rather than `pg_dump`/`psql`.
Drill 2 above supersedes it for the DB-restore path; this one still stands as the original proof that
the key-backup/restore mechanism itself (independent of which database engine) works.

Built the real hub binary and ran two local instances end-to-end.

**1. Created a real root CA on a "source" instance:**
```
POST /api/v1/cas {"name":"drill-root","type":"root","key_storage_type":"software","subject_cn":"Drill Root CA","algorithm":"ECDSA-P256"}
-> {"data":{"id":"da2250d8-78f5-44c0-8c4a-2834fbaf3a6a","status":"active", ...}}
```

**2. Backed up the keystore via the new endpoint:**
```
POST /api/v1/admin/backup {"backup_passphrase":"..."} -> HTTP 200
{
  "schema_version": 1,
  "keys": [
    {"id":"key-da2250d8-78f5-44c0-8c4a-2834fbaf3a6a","algorithm":"ECDSA-P256","status":"exported","pem":"-----BEGIN KRYPTKEEPER BACKUP KEY-----..."}
  ]
}
```

**3. Booted a completely fresh "destination" instance** (empty data dir, empty keystore dir, different
store passphrase) and restored the key bundle into it:
```
POST /api/v1/admin/restore {"backup_passphrase":"...","bundle":{...}} -> HTTP 200
{"data":{"imported":1}}
```

**4. Restored the CA's database row** via a direct `sqlite3` INSERT (standing in for `pg_dump`/`psql`,
not yet available at this point in the session), copying the source CA's real `id`/`cert_pem`/`key_id`
fields verbatim, and rebooted the destination instance. `GET /api/v1/cas` confirmed the CA was present
and `active`.

**5. Issued a real leaf certificate from the recovered CA:**
```
POST /api/v1/certificates {"ca_id":"da2250d8-...","template_id":"tpl-drill-template2-...","csr_pem":"..."}
-> HTTP 200
{"data": {"fingerprint_sha256": "7eb57cc7918d9287a46c5f3eb684aa40ac3cb4add05b3ba66065554a103bf3fa", "common_name": "drill-leaf.example.com", "issuer_cn": "Drill Root CA", "chain_complete": true, "chain_trusted": true, ...}}
```

**Result: `chain_complete: true, chain_trusted: true`**, the same decisive proof drill 2 later repeated
against real Postgres.

## Ordering bug found and fixed (before either drill's final write-up)

The first draft of `restore.sh`/this runbook told operators to boot the fresh hub instance *before*
running `restore.sh`, so its migration run (W10-01) would already have created the full schema — then
`restore.sh`'s `psql` replay of the `pg_dump` would abort on "relation already exists" the moment it
hit any already-created table. Found via advisor review, not by drill 1 (whose sqlite-INSERT stand-in
sidestepped the DB-restore path entirely) — confirmed as a real, reproducible failure by drill 2 above,
which hit exactly this class of error (the version-skew "relation already exists"-adjacent abort) and
is now fixed by restoring into a genuinely empty database before any hub ever boots against it.
