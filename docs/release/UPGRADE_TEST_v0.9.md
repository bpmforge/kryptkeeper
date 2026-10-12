# v0.9.0 upgrade test results

## Spot-check on v0.9.0-rc.7 (2f9e766), 2026-10-11 UTC

`main` at `2f9e766` (= `0.9.0-rc.7`), image `localhost/kryptkeeper:0.9.0-rc.7`. Scope: the changes
since rc.5, which are PR #110 (non-delivering notification providers, rule send cap, validity bound,
fatal key-check error) and PR #112 (migration `000076`, typed audit outcomes, `?outcome=` filter). The
rc.5 matrix below was not repeated in full; three scenarios were re-run with the rc.5 assertion set
(schema now 76) plus the new audit assertions. Same method as rc.5 (compose-style hubs, TLS, secrets
from `openssl rand`, one keep-alive connection, unique `ut7-<run>-*` names, cleaned up afterwards). No
product code was changed by the test run.

### Verdict

**Clean. No defect found.** All three scenarios pass every assertion (0 FAIL; the INFO lines are
informational).

| # | Scenario | Result | Notes |
|---|----------|--------|-------|
| A1 | sqlite rc.1 -> rc.7 | PASS (31 PASS, 3 INFO) | schema 71 -> 76; audit default db, rc.1 `audit.json` untouched (array, 7228 B); note 45 target `set_by` NULL until re-armed; missing-CA-key refusal and `KRYPTKEEPER_ALLOW_MISSING_CA_KEYS=true` override both hold |
| A2 | sqlite rc.2 -> rc.7 | PASS (29 PASS) | schema 73 -> 76; the 22 `audit_log` rows written on rc.2 survive the table rebuild (82 total after the checks) |
| B3 | postgres 16 rc.4 -> rc.7 | PASS (28 PASS, 3 INFO) | schema 74 -> 76; 22 `audit_log` rows written on rc.4 are still there (82 total after the checks); minted key from rc.4 still authenticates; `POST /api-keys` 201 and `GET /users` 200 |

All carried-over rc.5 assertions pass on both: state identical to the pre-upgrade snapshot, revoked
certs in CRL and OCSP `revoked`, issuance under the old root and intermediate verifies with `openssl
verify`, static key 200 and bogus key 401, minted-key mint/restart/revoke/restart, root-CA ceremony
(pending, not active, 2 of 2 approvals, active), ceremony state across restarts, P30D and P7D template
validity (30.0 and 7.0 days), notification rule created and still listed after restarts, minted-key
secret absent from the DB and WAL bytes (sqlite).

### New assertions for 000076 (PASS on sqlite and postgres)

After the upgrade, with the default dual-control and approval settings:

| Step | Result |
|------|--------|
| `POST /api/v1/keys` then `POST /api/v1/keys/{id}/rotate` | 202 `proposed` (dual control), so the hub writes an audit row with outcome `proposed` |
| Template with `require_approval=true`, then `POST /api/v1/certificates` | 202 `pending_approval`, so the hub writes `certificate.issue` with outcome `pending_approval` |
| `GET /api/v1/audit?outcome=proposed` | 200; one row, `key.rotate` for that key id; every returned row has the requested outcome |
| `GET /api/v1/audit?outcome=pending_approval` | 200; a `certificate.issue` row; all rows filtered |
| `GET /api/v1/audit?outcome=bogus` | 400 |
| Rows in the table itself (not only the API) | `audit_log` holds one `proposed` and one `pending_approval` row on both engines |
| Rows written before the upgrade | preserved (A2 sqlite rc.2 and B3 postgres rc.4: 22 rows each present afterwards) |
| Schema | 76 on both |

Not run here: the 000076 down migration (refusal with new-vocabulary rows is covered by
`internal/db/migrate_audit_vocabulary_test.go`); `APP_AUDIT_DB_DSN` on its own database; the C scenarios (non-`ca` provider first); the
missing-key check on PostgreSQL. rc.2 and rc.3 sources were not re-run.

### Live set and Go suites on rc.7

Plain `bash <harness>/run.sh`, sequential, 2026-10-11 UTC, no container leftovers:

```
smoke       exit=0  [smoke] SUMMARY 331 assertion(s) run, 331 passed, 0 failed, 0 skipped
autopilot   exit=0  === autopilot summary: 29 passed, 0 failed ===  AUTOPILOT: ALL PASS
agent       exit=0  === W19-04 summary: 18 passed, 0 failed ===
plugins     exit=0  ALL STEPS PASSED (27 checks)
protocols   exit=0  ALL STEPS PASSED
acme        exit=0  === RESULT: 28 passed, 0 failed ===
tls         exit=0  ALL STEPS PASSED
sshca       exit=0  ALL STEPS PASSED
ssh-install exit=0  ALL PASS
go test ./...                                   50 packages ok
KRYPTKEEPER_TEST_POSTGRES_DSN=... go test -p 1  50 packages ok (throwaway postgres:16-alpine, database kk_rc7_test)
make test-race                                  50 packages ok, 0 fail
```

`go test ./internal/bootstrap` failed twice earlier on 2026-10-11 under machine load and did not
reproduce. Re-run with a PostgreSQL test suite running concurrently: `go test -count=3 -race
-timeout 120m ./internal/bootstrap` passed (1,514 s; the default 10 minute timeout is too short for
three race iterations, since one takes about 500 s), and `go test -count=1 -p 8 ./...` passed twice, on
50 packages each time. No timing-dependent test was identified. One robustness gap was fixed: the
default SQLite DSN had no `busy_timeout` (see CHANGELOG). After that change `make lint` reports 0
issues, `go test -count=1 -p 8 ./...` passes twice with load and `go test -race ./internal/bootstrap`
passes.

### Cleanup

All `ut7-*` containers, volumes and networks, the throwaway postgres container and all
live-harness containers were removed. Local images were not touched.

---

## Re-run on v0.9.0-rc.5 (5ec48ff), 2026-10-11 UTC

Branch `kk/rc5-validation` from `origin/main` 5ec48ff (= `0.9.0-rc.5`), with the rc.4
report merged in as history. Images `localhost/kryptkeeper:0.9.0-rc.{1,2,3,4,5}`. No
product code was changed.

### Verdict

**Clean. No defect found.** Both rc.4 findings are fixed: scenario C (non-`ca` provider
first, then `ca`) starts on SQLite and PostgreSQL, and on PostgreSQL `POST /api/v1/api-keys`
and `GET /api/v1/users` work with the default user provider. 9 scenarios were run;
every assertion passed (A1 29 PASS, A2 27, A3 26, A4 27, B1 29, B2 26, B3 26, Cs 23, Cp 24;
the remaining lines per scenario are INFO).

### Method

As in the rc.4 run below (compose-style hubs: read-only root fs, tmpfs `/tmp`, `cap_drop
ALL`, `no-new-privileges`, TLS on, `APP_CERTIFICATE_PROVIDER=ca`, named volume at
`/var/kryptkeeper`, secrets from `openssl rand -hex 32` in mode-600 env files, unique
`ut5-<run>-*` names, one keep-alive TLS connection per phase, low volume). Differences:

- Target is rc.5. The new hub runs with `APP_NOTIFICATION_PROVIDER=delivery` (the compose
  default); the old hub used `db` so there was a rule to compare (the rc.5 delivery
  provider stores rules in the same notification database).
- A second admin (`pki-admin`) is declared in `APP_API_KEYS_JSON` for the ceremony.
- PostgreSQL scenarios no longer need `APP_USER_PROVIDER=file`; the old (rc.1, rc.3, rc.4)
  hubs still did for populating, the rc.5 hub runs with the default user provider.
- Per scenario the old image was populated (1 template P30D, 1 intermediate CA, 5 CSR-in
  certs of which 1 root-issued and 1 intermediate-issued revoked, 1 `auto_renew` target,
  1 notification rule, 1 API-minted key), snapshotted, stopped, then rc.5 started on the
  same volume with the same env (apart from the notification provider).

### Scenario results

| # | Scenario | Result | Notes |
|---|----------|--------|-------|
| A1 | sqlite rc.1 -> rc.5 | PASS | schema 71 -> 75; audit default db, rc.1 `audit.json` untouched (array, 7228 B); note 45 target `set_by` NULL until re-armed |
| A2 | sqlite rc.2 -> rc.5 | PASS | schema 73 -> 75 |
| A3 | sqlite rc.3 -> rc.5 | PASS | schema 74 -> 75; key minted on rc.3 still authenticates |
| A4 | sqlite rc.1 `APP_AUDIT_PROVIDER=file` -> rc.5 | PASS | 22 legacy records migrated to JSONL, `.bak` byte-identical |
| B1 | postgres rc.1 -> rc.5 | PASS | schema 71 -> 75; mint 201 and `GET /users` 200 with the default user provider |
| B2 | postgres rc.3 -> rc.5 | PASS | schema 74 -> 75 |
| B3 | postgres rc.4 -> rc.5 | PASS | schema 74 -> 75 |
| Cs | sqlite rc.5 default provider, then `ca` | PASS | starts; 13 `statement already satisfied, skipping` lines (e.g. 000020 `duplicate column name: tenant`); root persists across restart (same fingerprint) |
| Cp | postgres rc.5 default provider, then `ca` | PASS | starts; 13 `statement already satisfied, skipping` lines (e.g. 000023); root persists |

Carried-over assertions (all PASS in A1-A4, B1-B3): hub starts without a migration error;
schema 75 and `minted_api_keys` exists; certs, CAs (fingerprints), templates (revision),
targets and rules identical to the pre-upgrade snapshot; revoked root- and
intermediate-issued certs are in their CRLs and active ones are not; OCSP `revoked` /
`good` correct for both; issuance under the old root and the old intermediate verifies with
`openssl verify`; the static `APP_API_KEYS_JSON` key returns 200 and a bogus key 401;
a key minted on rc.1/rc.2 returns 401 (memory-only, re-mint) while a key minted on
rc.3/rc.4 survives; the minted key's secret is not in the sqlite DB or WAL.

### New assertions in this run (all PASS on sqlite and postgres)

| Assertion | Result |
|-----------|--------|
| Minted API key survives a container restart (200), listed after restart; `DELETE` 204; 401 immediately; 401 after a further restart; static key unaffected through both restarts | PASS on A1-A4, B1-B3, Cs, Cp |
| `GET /api/v1/users` | 200 on all scenarios, including every PostgreSQL one (rc.4: 503) |
| Postgres `POST /api/v1/api-keys` with the default user provider | 201 on B1, B2, B3, Cp (rc.4: 503) |
| Root-CA key ceremony (`POST /api/v1/ceremonies`, approvers = bootstrap admin + second admin, quorum 2) | start 201, status `pending`, new root CA status `pending_ceremony`; issuance from it refused (503); non-admin start 403; approval 1/2 leaves it pending and the CA not active; a duplicate approval by the same principal is 400; approval 2/2 by the second admin completes it, CA becomes `active`, issuance from it 201. Same on all 9 scenarios |
| Ceremony state across restarts | a second ceremony left pending: after two restarts it is still `pending` with its CA `pending_ceremony` (not active), and the first ceremony is `completed` with its CA `active` |
| Template validity | a `P30D` template issues a 30.0-day certificate, a `P7D` template a 7.0-day certificate (rc.4: 90 days regardless) |
| Notification rule via API with `APP_NOTIFICATION_PROVIDER=delivery` | created 201, listed immediately and still listed after two restarts; the pre-upgrade rule is listed too (rc.4: not persisted) |
| Missing CA keys (A1 sqlite, B1 postgres; keystore dir pointed at an empty directory) | hub exits non-zero with `startup: refusing to start: 3 active CA(s) have no usable key in the keystore` and the hint naming `KRYPTKEEPER_ALLOW_MISSING_CA_KEYS`; with `KRYPTKEEPER_ALLOW_MISSING_CA_KEYS=true` it starts |
| Schema | 75 on every scenario |

Operator note from this run: the ceremony approver identity is the authenticated principal
id (the bootstrap token's principal is `bootstrap`; keys use their `principal_id`), and the
`approvers` list must contain the initiator if the initiator is meant to count toward
quorum. Only `pki-admin` may start or approve; a `service-account` key gets 403.

### Live set on rc.5

Run sequentially on this worktree (be239d2, which is 5ec48ff plus the rc.4 report), each
under `perl -e 'alarm 1500; exec @ARGV' bash tests/live/<h>/run.sh`, 2026-10-11 UTC.
Container leftovers: none.

```
acme        exit=0  === RESULT: 28 passed, 0 failed ===
protocols   exit=0  ALL STEPS PASSED
tls         exit=0  ALL STEPS PASSED
sshca       exit=0  ALL STEPS PASSED
plugins     exit=0  ALL STEPS PASSED
autopilot   exit=0  === autopilot summary: 29 passed, 0 failed ===  AUTOPILOT: ALL PASS
agent       exit=0  === W19-04 summary: 18 passed, 0 failed ===
ssh-install exit=0  ALL PASS
smoke       exit=0  [smoke] SUMMARY 331 assertion(s) run, 331 passed, 0 failed, 0 skipped
make test-race  exit=0  50 packages ok, 0 fail
```

### Cleanup

All `ut5-*` containers, volumes and networks and all live-harness containers were removed.
Local images were not touched.

---

# History: re-run on v0.9.0-rc.4 (18af178), 2026-10-11 UTC

Branch `kk/upgrade-test-rc4` from `origin/main` 18af178 (= `0.9.0-rc.4`). Images
`localhost/kryptkeeper:0.9.0-rc.{1,2,3,4}`. No product code was changed.

### Verdict

**Not clean: two real defects, both in the PostgreSQL / first-use-provider paths. The
direct sqlite upgrade paths are clean.**

1. **FAIL - non-`ca` provider first, then `ca` on the same data dir (scenario C).** It no
   longer hits 000020, but now fails on 000070 (sqlite) and 000071 (postgres) and the hub
   exits (note 54 made this fatal; it used to degrade). Note 54's claim that such a data
   directory "now migrates cleanly" is false for rc.4. Root cause below.
2. **FAIL - on PostgreSQL, `POST /api/v1/api-keys` returns 503 on rc.3 and rc.4**
   (`cannot verify principal_id against the user store`), and `GET /api/v1/users` returns
   503 on rc.4. API-key minting is unusable on Postgres with the default user provider.
   Root cause below. The persistence/restart checks on Postgres were run with
   `APP_USER_PROVIDER=file` as a workaround and pass.

Everything else passes: schema 74, CAs/templates/certs/targets/rules preserved,
CRL + OCSP, issuance with the old root and intermediate, `APP_API_KEYS_JSON` key,
note 45, note 50, API-key restart persistence and revoke-stays-revoked (sqlite and
postgres), keystore default and legacy fallback.

### Method

Same as the earlier run (below): compose-style hubs (read-only root fs, tmpfs `/tmp`,
`cap_drop ALL`, `no-new-privileges`, TLS on, `APP_CERTIFICATE_PROVIDER=ca`,
`KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true`, `KRYPTKEEPER_KEYSTORE_DIR=/var/kryptkeeper/keys`,
`KRYPTKEEPER_DATA_DIR=/var/kryptkeeper/data`, named volume at `/var/kryptkeeper`),
secrets from `openssl rand -hex 32` in a mode-600 env file, unique `ut4-<run>-*` names,
one keep-alive TLS connection per phase. Added versus the earlier run:
`APP_DISCOVERY_PROVIDER=scanner`, `APP_NOTIFICATION_PROVIDER=db` (see observation 3),
`APP_AUDIT_FILE` on the volume, `APP_API_KEY_AUTH_ENABLED=true` with a static key in
`APP_API_KEYS_JSON`. Postgres scenarios use `postgres:16-alpine` on a private network.

Per scenario: the old image was populated through the API (1 template, 1 intermediate CA,
5 CSR-in certs of which 1 root-issued and 1 intermediate-issued were revoked, 1
`auto_renew` target, 1 notification rule, 1 API-minted key), a snapshot taken, the
container stopped, and rc.4 started on the same volume with identical env, then the
assertions. After the assertions, on the upgraded hub: mint a key, restart the container,
authenticate; DELETE (204); 401; restart; 401. The DB was read after a clean stop (sqlite
via `podman cp`, postgres via `psql`). The driver was a throwaway script outside the repo.

### Scenario results

| # | Scenario | Result | Notes |
|---|----------|--------|-------|
| A1 | sqlite rc.1 -> rc.4 | PASS | schema 71 -> 74; audit default db, rc.1 `audit.json` untouched (array, 7228 B) |
| A2 | sqlite rc.2 -> rc.4 | PASS | schema 73 -> 74; target already stamped by rc.2 (`auto_renew_set_by=bootstrap`), see note 45 below |
| A3 | sqlite rc.3 -> rc.4 | PASS | schema 74 -> 74 (code-only); an API key minted on rc.3 still authenticates on rc.4 |
| A4 | sqlite rc.1 `APP_AUDIT_PROVIDER=file` -> rc.4 | PASS | 22 legacy records migrated to JSONL, `.bak` byte-identical to the pre-upgrade file, API shows old + new events |
| B1 | postgres rc.1 -> rc.4 | **FAIL** (finding 2) | every upgrade assertion passes; API-key mint 503 with the default user provider; restart checks pass with `APP_USER_PROVIDER=file` |
| B2 | postgres rc.3 -> rc.4 | **FAIL** (finding 2) | same; rc.3 itself cannot mint on postgres |
| A3b | rc.4 fresh, `KEYSTORE_DIR` unset, `DATA_DIR` set | PASS | log `keystore directory: /var/kryptkeeper/data/keys`; keys land there, none in `/var/kryptkeeper/keys` |
| A3c | rc.2 with `./var/keys` layout -> rc.4 (`KEYSTORE_DIR` unset) | PASS | legacy fallback warning logged ("key files found in ./var/keys ... continuing to use ./var/keys"); old root and intermediate still issue. rc.3 already defaults to `<DATA_DIR>/keys`, so rc.2 (or rc.1) is the source that has the legacy layout |
| A3d | rc.3 (keys in `/var/kryptkeeper/keys`) -> rc.4 with `KEYSTORE_DIR` dropped | hazard, expected | hub stays up, logs `CA KEY INCONSISTENCY`, issuance 503, CRL/OCSP empty. Compose sets `KEYSTORE_DIR` explicitly so this needs an operator edit; a fatal start would be safer |
| Cs | sqlite rc.4 default provider, then `ca` | **FAIL** (finding 1) | `apply migration 000070_ssh_certificates_template_id: duplicate column name: template_id`; hub refuses to start |
| Cp | postgres rc.4 default provider, then `ca` | **FAIL** (finding 1) | `apply migration 000071_managed_targets_verify_host_port: column "verify_host_port" ... already exists (42701)`; hub refuses to start |

Per-assertion detail for A1-A4, B1, B2 (all PASS unless marked): hub starts without a
migration error; schema = 74 and `minted_api_keys` exists; certs, CAs (fingerprints),
templates (revision), targets and rules identical to the pre-upgrade snapshot; revoked
root- and intermediate-issued certs are in their CRLs and active ones are not; OCSP says
`revoked` / `good` correctly for both; new issuance under the old root and the old
intermediate verifies with `openssl verify`; the `APP_API_KEYS_JSON` key returns 200 and a
bogus key 401; the minted key's secret is not in the sqlite DB or WAL (verifier only).

### API-key persistence and restart (note 56)

| Step | sqlite (A1-A4, A3c) | postgres (B1, B2) |
|------|---------------------|-------------------|
| `POST /api/v1/api-keys` on the upgraded rc.4 hub | 201 | **503** with the default user provider; 201 with `APP_USER_PROVIDER=file` |
| authenticate with it | 200 | 200 (workaround) |
| restart the container, authenticate again | **200** | **200** (workaround) |
| `DELETE /api/v1/api-keys/{kid}` | **204** | **204** (workaround) |
| authenticate | 401 | 401 |
| restart, authenticate | **401** | **401** (workaround) |
| static `APP_API_KEYS_JSON` key across both restarts | 200 | 200 |

Pre-upgrade minted keys behave as note 57 says: a key minted on rc.1 or rc.2 returns 401
on rc.4 (memory-only, re-mint); a key minted on rc.3 (already schema 74) survives the
rc.3 -> rc.4 upgrade (sqlite A3 and postgres B2).

### Upgrade notes checked

- **Note 45 (A1, A4, B1; rc.1 source):** after the upgrade `auto_renew=true` and
  `auto_renew_set_by` is NULL; `PATCH /targets/{id} {"auto_renew":true}` as the bootstrap
  admin stamps `bootstrap`. The scheduler's "NOT pushing" log line was **not exercised**:
  it needs a due certificate bound to the target, and hub-issued certificates are 90 days
  with the scan threshold capped at half the lifetime. On rc.2 (A2) the row is already
  stamped by rc.2 (000072 shipped in rc.2), so only rc.1-armed targets go notify-only.
- **Note 50 (audit):** provider unset: log `audit provider: db (default)`, the legacy
  file is left byte-identical, a new trail starts in `audit_log` (A1, B1); rc.2/rc.3
  already used the database (A2, A3, B2). `APP_AUDIT_PROVIDER=file`: converted to JSONL
  with `.bak` (A4).
- **Note 54:** see finding 1 (000020 is fixed, 000070/000071 are not).
- **Note 55:** A3b and A3c above.
- **Notes 56/57:** table above.

### Finding 1: first use under another provider, then `ca`, fails on 000070/000071/000072 (fatal)

Reproduce: fresh volume, start rc.4 without `APP_CERTIFICATE_PROVIDER` (and
`KRYPTKEEPER_TLS_DISABLE=true`), stop, start rc.4 with `ca` on the same volume (sqlite),
or the same against one Postgres database. rc.4 logs `refusing to start with
APP_CERTIFICATE_PROVIDER=ca: core database unavailable (migration ... failed)` and exits.

Candidate causes, most to least likely:

1. **Migrations 000070, 000071, 000072 are blind `ALTER TABLE ... ADD COLUMN` statements
   that are not in `migrationsTolerateAlreadySatisfied`** (`internal/db/migrate.go`,
   currently `11 20 21 23 24 32 47 53 55 56 57 59`), while the stores' `EnsureSchema` /
   `ensureSchema` create or alter the same tables full-shape on first use under the
   default provider: `ssh_certificates.template_id` (000070, `handlers_ssh_certs.go`),
   `managed_targets.verify_host_port` (000071) and `managed_targets.auto_renew_set_by`
   (000072) (`managed_target_store.go`). This is the same class as the 000020 bug that note
   54 fixed. **Verified:** after phase 1 alone (sqlite, default provider) `ssh_certificates`
   already has `template_id` and `managed_targets` already has `verify_host_port` and
   `auto_renew_set_by`; phase 2 stops at `schema_migrations` max 69; sqlite fails on 000070
   (`duplicate column name: template_id`), postgres on 000071 (000070 there uses
   `ADD COLUMN IF NOT EXISTS`, 000071 does not). The comment in
   `sqlite/000070_ssh_certificates_template_id.up.sql` ("The migration runner tolerates
   'duplicate column'") is wrong for the same reason.
2. Other post-000059 migrations with `ADD COLUMN` that a store also pre-creates (sqlite
   000058, 000069; postgres 000072) would fail next, once 70-72 are tolerated. **Not
   verified** (the hub stops at the first failure). Fixing 70-72 alone may not be enough,
   so re-run scenario C after the fix.
3. Ordering rather than tolerance: the stores run before `RunMigrations` when the provider
   is not `ca`. A design alternative (run migrations before any store), not a separate
   defect; not verified.

Impact: the hub now refuses to start (safer than the earlier silent in-memory CA), but an
evaluator who ran the unconfigured binary and then followed the compose setup on the same
`KRYPTKEEPER_DATA_DIR` is stuck. Note 54's sentence is inaccurate until fixed.

### Finding 2: PostgreSQL user store listing fails, so API-key creation returns 503

`POST /api/v1/api-keys` calls `principalIDReserved` -> `ListUsers`
(`internal/bootstrap/principal_reserved.go`, `handlers_auth.go`). On Postgres `ListUsers`
always errors, so the handler returns 503 `cannot verify principal_id against the user
store`, and `GET /api/v1/users` returns 503 `users unavailable`.

Candidate causes:

1. **SQL type error in `dbUserProvider.ListUsers`** (`internal/bootstrap/user_db_provider.go`):
   `COALESCE(last_login_at,'')` on a `timestamptz` column. **Verified:** running the exact
   query by `psql` against the hub's Postgres returns `ERROR: invalid input syntax for type
   timestamp with time zone: ""`, with zero rows in `users`, so it fails regardless of
   data. A second latent mismatch is `active` scanned into an `int` while the Postgres
   column is `boolean` (not reached because the query fails first).
2. A connection/DSN problem for the user store (`APP_USER_DB_DSN`, `KRYPTKEEPER_DB_DSN`):
   ruled out, the same DSN serves every other store and `users` exists with the expected
   columns.
3. `errUserStoreNotProvisioned` mis-classification: ruled out, the table exists.

rc.1 mints fine on Postgres; rc.3 and rc.4 do not. The reserved-principal check on mint
turns a latent `GET /users` Postgres defect into a hard failure of note 56. No Postgres
test covers `ListUsers`.

### Other observations

3. **`APP_NOTIFICATION_PROVIDER=delivery` (the compose default) does not persist
   notification rules.** `deliveryNotificationProvider.CreateRule` returns a synthetic
   rule and `ListRules` returns an empty list (`notification_delivery_provider.go`), so
   `POST /api/v1/notifications/rules` returns 201 and the rule is never listed or stored.
   The file provider on a read-only root also loses the rule on restart. The upgrade
   scenarios therefore ran with `APP_NOTIFICATION_PROVIDER=db` to have a rule to compare.
   Not an upgrade regression (identical on rc.1); not fixed here.
4. Certificates issued by `POST /api/v1/certificates` are valid 90 days whatever the
   template's `validity_period` (P2D, P7D and P30D all gave 90 days).
5. In A3d (operator drops `KEYSTORE_DIR` on rc.3 -> rc.4) the hub starts and logs
   `CA KEY INCONSISTENCY` but cannot sign. Consider failing the start when a CA's key is
   missing from the resolved keystore.

### Post-upgrade smoke

`bash scripts/test/run.sh --suite smoke` on this worktree (18af178):
`[smoke] SUMMARY 331 assertion(s) run, 331 passed, 0 failed, 0 skipped`.

### Cleanup

All `ut4-*` containers, volumes and networks were removed. Local images were not touched.

---

# History: earlier run on 72712ba (rc.1 / rc.2 -> main)

Date: 2026-10-11. Branch `kk/upgrade-test` from `origin/main` 72712ba.
Images: `kryptkeeper:0.9.0-rc.1`, `kryptkeeper:0.9.0-rc.2`, and `kryptkeeper:upgrade-main`
(built from 72712ba with `podman build ... -f Dockerfile .`).
Host: podman on macOS. No product code was changed.

### Verdict

No upgrade bug found. Every rc.1 -> main and rc.2 -> main path tested passes on SQLite and
PostgreSQL. Four findings are worth reading before release (section "Findings"): one
reproduction of the `duplicate column name: tenant` failure (not on the upgrade path), one
operator-surprise (API-minted keys are in memory only), and two notes on audit behaviour.

### Method

Hubs ran compose-style: read-only root filesystem, tmpfs `/tmp`, `cap_drop ALL`, TLS on
(self-issued), `APP_CERTIFICATE_PROVIDER=ca`, `KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true`,
named volume at `/var/kryptkeeper`. Secrets (bootstrap token, keystore passphrase, API-key
pepper) came from `openssl rand -hex 32` into a mode-600 env file and were never printed.
Client used `curl -k` against 127.0.0.1 only. Additions beyond compose:
`APP_API_KEY_AUTH_ENABLED=true`, a static key in `APP_API_KEYS_JSON`, and
`APP_AUDIT_FILE=/var/kryptkeeper/data/audit.json` (see finding 3).

Per scenario, the old image was populated through the API, a snapshot taken (certs with
status, CAs with fingerprints, templates with revision, API keys, targets, notification
rules), the container stopped, and the new image started on the same volume with identical
env. State: 1 template, N CSR-in certificates (one revoked), 1 intermediate CA, 1 target
with `auto_renew=true` (bootstrap/admin), 1 notification rule, 1 API-minted key.

Scenarios: A1 sqlite rc.1 -> main (20 certs, audit provider unset); A2 same with
`APP_AUDIT_PROVIDER=file` explicitly (6 certs); A3 rc.2 -> main (5 certs); A4 rc.1 with
`APP_AUDIT_PROVIDER=db` -> main (3 certs); B postgres:16-alpine rc.1 -> main (8 certs);
D duplicate-column reproduction (below).

### Results

| # | Assertion | A1 | A2 | A3 | A4 | B |
|---|-----------|----|----|----|----|---|
| 1 | Hub starts; no migration error, no "duplicate column" | PASS | PASS | PASS | PASS | PASS |
| 2 | Migrations 000070-000073 applied (max version 73; rc.1 was at 71, rc.2 already at 73) | PASS | PASS | PASS (no-op) | PASS | PASS |
| 3 | Certs, CAs (fingerprints), templates (revision), rules, targets identical to the pre-upgrade snapshot | PASS | PASS | PASS | PASS | PASS |
| 4 | Revoked cert still in CRL (serial match) | PASS | PASS | PASS | PASS | PASS |
| 5 | OCSP: revoked cert `revoked`, other cert `good` | PASS | PASS | PASS | PASS | PASS |
| 6 | Issuance with the pre-upgrade root and with the pre-upgrade intermediate | PASS | PASS | PASS | PASS | PASS |
| 7 | Persisted (APP_API_KEYS_JSON) API key still authenticates; bogus key gets 401 | PASS | PASS | PASS | PASS | PASS |
| 8 | API-minted key survives | n/a (in-memory, finding 2) | n/a | n/a | n/a | n/a |

The only snapshot difference in every run is the API-minted key (finding 2).

#### Upgrade note 45 (targets re-arm) - PASS (A1)

After the upgrade the target row has `auto_renew=1` and `auto_renew_set_by` NULL (column from
000072, no backfill). `GET /targets/{id}` returns `auto_renew=true, auto_renew_set_by=null`.
The scheduler logs: `renewal scheduler: target "ut-target" (ssh) has auto_renew set but is
skipped: auto_renew was not armed by a principal holding certificate.renew (re-save
auto_renew=true as a pki-admin; ...)`. `PATCH /targets/{id}` `{"auto_renew":true}` as the
bootstrap admin then stamps `auto_renew_set_by="bootstrap"`. Postgres (B): `1 | NULL`, as
expected. Not tested: an actual scheduled push (needs a due cert on a reachable SSH host).

#### Upgrade note 50 (audit store) - PASS

- A1 (provider unset, rc.1 file trail): log `audit provider: db (default)`. The rc.1
  `audit.json` (a JSON array) is untouched (same size, still an array) and is no
  longer served by `GET /api/v1/audit`; new events land in `audit_log` (0 rows before,
  15 after) and the API shows only those. This matches the note: a new trail starts.
- A2 (`APP_AUDIT_PROVIDER=file` already set on rc.1): log `migrated 27 legacy records to
  JSON Lines (original kept as ".../audit.json.bak")`. `.bak` is byte-identical to the
  pre-upgrade file. All 27 records are present in the JSONL file with identical content;
  the array was newest-first and the JSONL is oldest-first (timestamps ascending), as
  documented. `GET /api/v1/audit` returned 40 events after the post-upgrade checks (old +
  new, one continuous trail); `audit_log` stays at 0 rows.
- A4 (rc.1 already on `db`): trail continues in place, 24 rows before, 39 after.
- A3 (rc.2 already defaults to db): 26 rows before, 41 after.
- B (postgres): provider db (default), 0 rows before (rc.1 wrote the file), 15 after.

### Duplicate column in migration 000020 (D): reproduced, not on the upgrade path

Observed earlier by another agent: `apply migration 000020_tenant_scoping: SQL logic error:
duplicate column name: tenant`. Candidate causes, most to least likely:

1. The pending-action store (`NewPendingActionStoreFromEnv` ->
   `dbPendingActionStore.EnsureSchema`) creates `pending_actions` WITH the `tenant` column
   in the same SQLite file (`kryptkeeper.db`) before the core migrations have run;
   migration 000020 then does a blind `ALTER TABLE pending_actions ADD COLUMN tenant`.
   000020 is not in `migrationsTolerateAlreadySatisfied` (`internal/db/migrate.go`, which
   lists only 11, 21, 53, 55, 56).
2. The DB audit store (`APP_AUDIT_PROVIDER=db`) initialising the file first. Its own
   best-effort `ALTER` on `audit_log` is already tolerated and it only touches `audit_log`.
3. Another store self-healing a shared table (discovery, ACME). These cover tables whose
   migrations are in the tolerated list.

Verification:
- Cause 1 reproduced three ways on a fresh volume: run with `APP_CERTIFICATE_PROVIDER=mock`
  (no core DB is opened, so `main.go` never runs migrations; the stores still create
  tables in `kryptkeeper.db`), stop, then start with `APP_CERTIFICATE_PROVIDER=ca` on the
  same volume. Result for main -> main, rc.1 -> rc.1 and rc.1 -> main:
  `warning: core DB unavailable (run sqlite migrations: apply migration 000020_tenant_scoping:
  SQL logic error: duplicate column name: tenant (1)) - CA state will not persist across
  restarts`. DB state after the failed start: `schema_migrations` max 19, so 000020 onward
  never apply.
- Cause 2 ruled out: rc.1 with `ca` + `APP_AUDIT_PROVIDER=db` on a fresh volume starts
  clean and upgrades to main with no error (A4). `OpenCoreDB` is the first DB access in
  `main()` when the provider is `ca`, so migrations run before any store.
- The direct rc.1 -> main path never hits it: the schema is already at 19+ so 000020 does
  not re-run (A1-A4, B).

Can real deployments hit it? Only when a data directory was first used with a provider
other than `ca` (the default when `APP_CERTIFICATE_PROVIDER` is unset) and is then switched
to `ca`: for example an evaluator running the unconfigured binary, then following the
compose/`env.example` setup against the same `KRYPTKEEPER_DATA_DIR`. The compose default
and every `ca`-from-day-one install are safe. It is not a regression (identical on rc.1)
and is not an rc.1/rc.2 -> main upgrade defect.

Impact if hit: the hub stays up, logs a single warning, runs with an in-memory CA store,
and `KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT` mints a fresh root that is lost on restart. That is
a silent loss of CA persistence in a PKI product. Suggested follow-ups (not done here, per
the brief): add 20 to `migrationsTolerateAlreadySatisfied` (000020 is ADD COLUMN plus
IF NOT EXISTS statements), and/or make an `OpenCoreDB` failure fatal when the provider is
`ca` instead of a warning.

### Other findings

2. **API-minted keys are in memory only.** `POST /api/v1/api-keys` stores the key in a map
   in the process (`Authenticator.CreateAPIKey`), so it is lost on every restart. Control:
   rc.1 -> rc.1 restart, no upgrade involved, key goes from HTTP 200 to 401. Keys declared in
   `APP_API_KEYS_JSON` survive and are what assertion 7 checks. Worth a line in the upgrade
   notes so operators know to re-mint or move keys to `APP_API_KEYS_JSON`
   (`secret_verifier` = hex HMAC-SHA256 of the secret keyed with `APP_API_KEY_PEPPER`).
3. **rc.1 file audit under the compose layout writes nothing.** Compose does not set
   `APP_AUDIT_FILE`, the default is `./var/bootstrap-audit.json`, and the container root
   is read-only, so rc.1 logged `audit append failed ... mkdir var: read-only file system`
   for every event (first probe, without `APP_AUDIT_FILE`). An rc.1 compose deployment may
   therefore have no file trail to carry over. The new db default fixes this; operators who
   pin `file` on a read-only container must set `APP_AUDIT_FILE` on the volume. This test
   set it so there was a trail to migrate.
4. **Audit file semantics changed (note 50), confirmed.** Tools parsing `audit.json` as an
   array break after migration (now JSONL, order reversed).
5. rc.2 is already at schema 73 and a DB audit default, so rc.2 -> main is a code-only
   upgrade.

### Not covered

PostgreSQL duplicate-column reproduction (only SQLite exercised); scheduled push after
re-arm; multi-tenancy mode; upgrade from the internal pre-rc milestones; a Helm install.

### Commands (no secrets)

```
git fetch origin main && git checkout -b kk/upgrade-test origin/main
podman build -t localhost/kryptkeeper:upgrade-main --build-arg VERSION=upgrade-main \
  --build-arg COMMIT=$(git rev-parse HEAD) -f Dockerfile .
podman run -d --name ut-a1-old -p 127.0.0.1:18101:8080 --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges --env-file <mode-600 secrets file> -v ut-a1-vol:/var/kryptkeeper \
  -e AUTH_MODE=bootstrap -e APP_BIND_ADDR=0.0.0.0 -e PORT=8080 -e APP_CERTIFICATE_PROVIDER=ca \
  -e KRYPTKEEPER_KEYSTORE_DIR=/var/kryptkeeper/keys -e KRYPTKEEPER_DATA_DIR=/var/kryptkeeper/data \
  -e KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true -e APP_API_KEY_AUTH_ENABLED=true \
  -e APP_AUDIT_FILE=/var/kryptkeeper/data/audit.json localhost/kryptkeeper:0.9.0-rc.1
# populate via /api/v1 (templates, certificates, revoke, cas, api-keys, targets,
#   notifications/rules), stop, then the same command with the upgrade-main image.
# CRL: GET /crl/<ca-id>.crl   OCSP: POST /ocsp (application/ocsp-request)
# Duplicate column repro: same volume, APP_CERTIFICATE_PROVIDER=mock then =ca.
# Postgres: podman network + postgres:16-alpine, KRYPTKEEPER_DB_MODE=postgres + DSN env.
```

Cleanup: all `ut-*` containers, volumes and the postgres network were removed. The local
`kryptkeeper:upgrade-main` image remains.
