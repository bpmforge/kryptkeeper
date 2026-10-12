# RC3 delta review: v0.9.0-rc.3 (fce40e1), 2026-10-10

Scope: `git diff 6200a0d fce40e1` (RC2 to RC3: 35 commits, 98 files, +5060/-220), branch `kk/rc3-delta-review`.
Read-only on code. No hub started, no `tests/live/*` run. Unit tests and static tools only.
Baselines: `docs/security/rc2/README.md`, `docs/reviews/rc2/CODE_HEALTH_RC2.md`, `docs/reviews/rc2/ANTI_SLOP_RC2.md`.

## Verdicts

- **Security: PASS.** 0 CRITICAL, 0 HIGH. 1 MEDIUM and 6 LOW, none blocking (section 1).
- **Code health: PASS.** 0 HIGH, 0 MEDIUM. 6 LOW. Tool counts equal or better than RC2 (section 2).
- **Anti-slop: FAIL.** 3 blocking documentation defects (A1 to A3), each an XS wording fix. Everything else checked holds (section 3).
- Perf: not re-run. `docs/perf/rc3` was measured on `26e17cac`, before the 12 post-scan commits (see "Perf caveat").

Release gate: the tag is blocked only by A1 to A3. Once those three sentences are corrected, anti-slop is PASS and all
four scans pass. No code change is required to tag.

## Blockers

| ID | Where | Defect | Fix (XS) |
|---|---|---|---|
| A1 | `docs/perf/rc3/README.md` "Remaining items" 1; `docs/perf/rc3/03-measurements.md:105` | Says Argon2id login verifications are "not capped" / "uncapped" and that "a bounded semaphore would fix it". False at `26e17cac` and at `fce40e1`: `auth_login_state.go:23,81,102` caps concurrent KDF runs at `min(4, GOMAXPROCS)` via `withKDFSlot`. CHANGELOG note 51 and `docs/deployment.md` say "capped", so the release docs now contradict the perf docs. The 325 MB figure is real; the cause given is wrong (4 x 64 MiB live plus runtime-retained buffers). | Rewrite item 1 and line 105: capped at 4 concurrent; the RSS rise is the 4 x 64 MiB working set plus buffers the Go runtime retains. |
| A2 | `docs/release/FEATURE_VALIDATION_v0.9.md` section 3.9 "API keys; local login/session/refresh" row | Says API-key persistence is "pending on branch `kk/rc3-fixes`, not yet on main" and "memory-only through rc.2 and main 26e17ca". At `fce40e1` the branch is merged (PR #105, 373d6159), migration 000074 is in the tree, and CHANGELOG notes 56 and 57 say so. The same row also promises "a live restart check" that no document records. | State persistence is on main as of 373d6159, backed by unit tests (`TestMintedAPIKeySurvivesRestart`, `TestRevokedAPIKeyStaysRevokedAfterRestart`); drop "live restart check" unless a log is attached. |
| A3 | `docs/release/RELEASE_NOTES_v0.9.0.md` "What's validated" ("Upgrades to this tree passed"); `README.md` Validation status upgrade paragraph | The upgrade run was on `72712ba` (`UPGRADE_TEST_v0.9.md` header; `LIVE_RESULTS` says "not `26e17ca`"), which predates `kk/rc3-fixes`. The release tree adds migration 000074, the 000020/23/24/32/47/57/59 tolerance, the keystore-dir default and API-key persistence, none of which any upgrade run exercised. "This tree" is false; the live-results caveat is accurate but is not carried into the two top-level docs. | Say "to main `72712ba`; the RC3 changes (000074, migration tolerance, keystore default, API-key persistence) are covered by unit tests only, not by a container upgrade run", or re-run the upgrade test on the release commit. |

## 1. Security

### 1.1 Tool results (all on `fce40e1`)

| Tool | RC2 | RC3 | Triage |
|---|---|---|---|
| opengrep 1.30.2, bpm-rulepacks owasp/secrets/slop/framework/house, same flags and targets | 296 | **297** (2 added, 1 removed) | Added: `db_core.go:79` (`failedMigrationName` returns "" when no regexp match) and `keystore_dir.go:48` (`dirHasFiles` returns false on a read error), both `slop-fallback-hides-failure-go`. Benign predicate returns; see S-L2 for the second. Removed: `principal_reserved.go` (the RC2-N-02 fail-open is now fail-closed). 0 new security-rule hits; the 13 triaged security hits are unchanged. |
| gitleaks 8.30.1, `6200a0d..fce40e1` (25 commits, 1.51 MB) | 0 | **5 reported, 0 real** | `tests/smoke/run.sh:586` x4 (2 commits x 2 rules): hex HMAC verifiers (`APP_AUTH_LOGIN_PASSWORD_HASH`, `secret_verifier`) for the smoke hub's fixed test password and key, on a line edited by RC2-N-02 commits (same family as RC1's four test-constant false positives). `docs/security/rc2/raw/live_probe2.txt:3`: a generated key id (`key-<uuid>`), an identifier, not a secret. |
| `GOTOOLCHAIN=go1.26.9 govulncheck ./...` | 0 affecting | **0 affecting**; 1 in a required module not called (GO-2026-5932, x/crypto openpgp, no fix) | Identical to RC2. |
| grype on `sbom_0.9.0-rc.3.cdx.json` | 1 | **1** (x/crypto v0.57.0, GO-2026-5932, severity Unknown, no fix) | Same known false positive (openpgp not imported). |
| grype on `localhost/kryptkeeper:0.9.0-rc.3` (oci-archive via `podman save`; image id `3ec9a113...` equals `rc3/image-id.txt`) | 0 | **0** ("No vulnerabilities found") | Fixable HIGH/CRITICAL: none. |
| `go test ./cmd/... ./internal/...` | 50 pkgs (`./...`) | **40 packages ok, 0 failed** | `./sdk/...` matches no packages from the root module; the tests/live offline packages were not run here (scope instruction). |

### 1.2 Delta review

**API-key persistence (`api_key_store.go`, `auth_identity.go`, `000074`).**
- Secret never stored: `CreateAPIKeyAs` stores `apiKeyVerifier(secret, pepper)` (HMAC-SHA256, hex) only; the table has `secret_verifier` and no secret column; `TestMintedAPIKeySecretIsNeverStored` pins it. Constant-time compare in `validateAPIKeyToken` (`subtle.ConstantTimeCompare`) is unchanged and still runs against the in-memory record, which is loaded from the DB verbatim. HELD.
- SQL: every statement is a constant string with `?`/`$n` placeholders from `ph(n)`; the only interpolation is the engine literal (`1`/`TRUE`/`0`/`FALSE`) from `activeLiteral()`. No injection path. HELD.
- kid collision: kid is `kid` + 9 random base64url characters (about 54 bits) with `_` stripped. A collision with a persisted kid fails the primary key, so the mint returns 503 and no key is issued. A collision with an `APP_API_KEYS_JSON` kid is resolved at load in favour of the configured key (logged, `TestConfiguredAPIKeyWinsKidCollision`). Mint does not check the in-memory map before overwriting (only reachable by a 2^-54 collision with a JSON-configured kid). HELD, informational.
- Tenant and role: stored and reloaded as minted (`tenant`, `role`, `scopes` JSON); loading does not re-validate the role against the compiled set. A tampered DB row is a DB compromise, out of the threat model.
- Revocation fail-closed: `RevokeAPIKey` removes the key from memory first, then writes (one retry). On failure the kid is parked in `revokePending`, the handler returns 503 ("repeat the DELETE"), and a repeat retries instead of answering 404. The key is rejected in-process throughout. A restart before the retry succeeds resurrects the key (documented in note 56 as "repeat until 204"). `last_used_at` writes are throttled to one per key per minute under `apiKeyMu`, the DB write is outside the lock, and a touch after a revoke is a no-op because `persistedKids` is cleared. No lost-revocation race found. HELD.
- **S-M1 (MEDIUM, non-blocking): DB I/O under the global auth lock with an unbounded context.** `CreateAPIKeyAs` (`auth_identity.go` mint block) and `RevokeAPIKey` call `Insert`/`Revoke` (twice) with `context.Background()` while holding `apiKeyMu` write-locked. Every authenticated request calls `apiKeysSnapshot()` (`auth.go:237`, RLock), for all auth types, not only API keys. If the core DB stalls (a Postgres network partition, a locked SQLite file), one mint or revoke blocks authentication hub-wide until the driver gives up; it fails hung, not closed. Needs an authorised mint/DELETE during a DB stall, so it is an availability defect, not a bypass. Fix before GA: do the DB write before taking the lock (or use a 5 s `context.WithTimeout`), then publish to the map under the lock. Also `apiKeysSnapshot` copies the whole map on every request (pre-existing O(keys) per request).
- S-L1 (LOW): no Postgres test for `dbAPIKeyStore` (`api_key_store_test.go` is SQLite only). The Postgres path (BOOLEAN `active`, `$n` placeholders) is reviewed by reading, not run; the upgrade test (rc.1 to main on PostgreSQL) predates 000074.
- S-L3 (LOW): multi-replica. Persisted keys are loaded at boot only, so a key minted or revoked on replica A is not seen by replica B until it restarts. Note 56 does not say so. Single-node is the documented v0.9 shape, so this is a documentation gap for HA operators, not a regression.

**Migration tolerance (`migrate.go`).** The set grows from {11,21,53,55,56} to {11,20,21,23,24,32,47,53,55,56,57,59}. I read the up files for all 12 in both engines. Every statement is `ALTER TABLE ... ADD COLUMN`, `CREATE TABLE IF NOT EXISTS` or `CREATE INDEX [IF NOT EXISTS]`; there is no `DROP`, `UPDATE`, `INSERT` or rename, so re-running a statement is idempotent. Each statement runs in autocommit and any error other than a duplicate-column or already-exists still aborts the migration (`applyUpTolerant`). The splitter now drops whole-line `--` comments; I confirmed none of the 24 tolerated files has an inline `--` comment or a `;` inside a literal. A real partial application (crash mid-migration) is repaired by the next run, which is the intended effect. `TestOpenCoreDBAfterStoresSelfHealedSchema` builds every self-healing store's schema first and then runs `OpenCoreDB` (SQLite only).
- S-L2 (LOW): tolerance hides drift in column shape, not only presence. A pre-existing column with a different type, default or CHECK (for example 000032's `CHECK (renewal_threshold_days > 0)`, which a store's `EnsureSchema` copy may lack) satisfies "already exists" without being compared. The tolerated errors are not logged, so an operator cannot see which statements were skipped. Suggest one `log.Printf` per tolerated statement. Not a security bypass.

**Keystore dir (`keystore_dir.go`).** `KRYPTKEEPER_KEYSTORE_DIR` wins; else `<DATA_DIR>/keys`; else `./var/keys`. Legacy keys are never stranded: if `./var/keys` holds files and the new default holds none, the legacy directory is kept with a warning. `EnsureWritableKeystoreDir` does `MkdirAll(0o700)` and a `CreateTemp` probe (0600, removed). Symlinks are followed (operator-controlled path, same as before). HELD, with two LOW notes: S-L4, `MkdirAll` does not tighten an existing directory's mode (key files are Argon2id-encrypted at rest, so exposure is limited); S-L5, `dirHasFiles` returns false on a permission error, so an unreadable new directory plus a populated legacy directory silently selects the legacy one (with the warning); an unreadable directory should be fatal.

**`CoreDBStartupDecision`.** `needsCrypto := certMode == "ca"` (`main.go:93`), and the core DB is opened only in that branch, so with a non-`ca` provider `OpenCoreDB` is never called at boot and there is nothing to fall back from. With `ca`, any open or migration error is now `log.Fatal`. The only other `OpenCoreDB` caller is `--remove-ci-seed` (fatal on error). Audit fails closed separately (`ResolveAuditProvider`, RC2). API-key store load error is `log.Fatalf`; without a core DB the hub warns that minted keys are memory-only. No provider path silently falls back to an in-memory CA. HELD. S-L6 (LOW): `failedMigrationName` parses the string "apply migration NNNNNN_name" out of `internal/db`'s error text, and its test uses a hand-written error rather than the real producer; if the wrapper text changes the hint silently degrades (the fatal itself does not).

**Other delta items, all verified.**
- Typed `AuthType` and exhaustive `egressStamp` switch: no `AuthType == "..."` string comparisons remain in non-test code (grep). Unknown kinds return `("", false)` and `armStamp` answers audited 403. jwt/oidc keep the documented `token:` stamp (RC2-N-06, now in SECURITY.md and note 45). HELD.
- `principalIDReserved` now returns an error: a real user-store error gives 503 on `POST /api-keys`; a missing `users` table is treated as "no users" (`errUserStoreNotProvisioned`). RC2-N-02 closed.
- SIEM syslog: `SetWriteDeadline` 5 s on UDP, TCP and the framed path; `syslogSafe` maps control characters and U+2028/2029 to spaces on EventType, ResourceType, ResourceID, ActorID and Timestamp. CEF extensions keep their own escaping. RC2-N-03 closed. Residual (INFO): the RFC 5424 structured-data values use `%q`, which does not escape `]`.
- Rate-limit sweep: now at most once per window, so a full-map flood no longer costs O(maxKeys) per request. RC2-N-01 closed. Eviction at the cap still drops an arbitrary live key (accepted, documented).
- `rejectOversizeBody` consolidation: 21 call sites; the remaining `isBodyTooLarge` uses are parser sentinels (`errBodyTooLarge`) and SCIM. No inline 413 copies remain (`payload_too_large` appears only in `request_body.go`). RC2-M1 closed.

### 1.3 Security conclusion
No open CRITICAL/HIGH, no regression of an RC1/RC2 fix, and four RC2 LOW/doc items are now fixed (N-01, N-02, N-03, N-07). New: 1 MEDIUM (S-M1), 6 LOW. The RC2 verdict stands.

## 2. Code health on the delta

| Metric | RC2 | RC3 |
|---|---|---|
| `gofmt -l cmd internal sdk plugins` | clean | **clean** (0 files) |
| `staticcheck ./...` (go1.26.9) | 75 lines | **75 lines** (non-SA1019 content unchanged: SA4023 `main.go:137`, S1011, S1024, U1000 in tests) |
| `deadcode -test ./...` | 40 | **39** |
| Packages passing (`cmd`, `internal`) | n/a | 40 ok, 0 failed |

Findings (all LOW):
- **CH-1 `DeleteAPIKey` is now a test-only production function.** Handlers moved to `RevokeAPIKey`; `DeleteAPIKey` (and its swallowed `persistErr`) is called only from `_test.go` files, so `deadcode -test` hides it. A future caller would silently get a non-durable revoke reported as success. Delete it and port the 6 test call sites to `RevokeAPIKey`.
- **CH-2 Inaccurate comment on `RenewalStatus`** (`certificate_provider.go:211-214`): "these constants are the only spellings code uses". 10 raw status literals remain (`certificate_ca_provider.go:392,467,474,600,631,762,821` and others) against 3 constant uses outside the declaring file. Either adopt the constants or soften the comment. The type is currently documentation, not enforcement.
- **CH-3 Engine detection by placeholder** (`api_key_store.go`): `activeLiteral()` infers Postgres from `s.ph(1) == "?"`. The store already receives `postgres bool`; keep it as a field. Other stores take `isPostgres` directly.
- **CH-4 Duplicated retry in `RevokeAPIKey`**: two identical `Revoke(..., time.Now())` calls; a 4-line loop would also timestamp once.
- **CH-5 Complexity**: `RevokeAPIKey` (about 8 branches), `ResolveKeystoreDir` (5) and `touchAPIKey` (6) are small and under threshold; no function in the delta crossed 15 cyclomatic. `registerAuthHandlersWithUsers` grew by two branches (reserved error, persist error, revoke persist error) and is already the largest closure in `handlers_auth.go`; schedule extraction with RC2-M1's list.
- **CH-6 Carried from RC2 and now closed by the delta**: N-09 (stringly-typed auth) FIXED; RC2-M1 (413 duplication) FIXED; RC2-M2 largely FIXED (one `AuthType` vocabulary, two switches that now share it). Still open from RC2: N-05, N-06, N-08, N-10, N-12, N-13 (unchanged, no regression).

Verdict reasoning: no HIGH or MEDIUM, counts equal or better than RC2, delta tests present for every new unit (`api_key_store_test.go` 9 tests, `keystore_dir_test.go` 3, `db_core_fatal_test.go`, `db_core_migrations_order_test.go`, `siem_syslog_test.go`, `principal_reserved_test.go` 109 lines, `ratelimit_full_test.go`).

## 3. Anti-slop

### 3.1 RC2 blockers B1 to B4

| RC2 | Status at `fce40e1` | Evidence |
|---|---|---|
| B1 smoke count | FIXED | 331 in README:434, RELEASE_NOTES:47, FEATURE_VALIDATION:28, LIVE_RESULTS:10, CHANGELOG:402. The old 332 survives only in `docs/STATUS.md:462`, a dated 2026-10-09 log entry; the smoke script has been edited since (3 commits), so 331 is plausible but the 332 to 331 step is unexplained (LOW). |
| B2 live results dated | FIXED | `docs/release/LIVE_RESULTS_v0.9.md` exists, dated 2026-10-11, tree `26e17ca`, per-harness rows including autopilot (29 checks) and agent (18/18); README, RELEASE_NOTES and FEATURE_VALIDATION cite it. The file states the results are "as reported to the author" (no logs attached); that is disclosed, not hidden. Dates appear to be UTC (the commit is 19:27 EDT on 2026-10-10 and the run is stamped 2026-10-11); the timezone is not stated (LOW). |
| B3 note 45 token exception | FIXED | CHANGELOG note 45 now carries the jwt/oidc `token:` exception, the pki-operator 403 correction and "any other auth kind cannot arm (403)"; code agrees (`egress_stamp.go`, `armStamp`); SECURITY.md lists RC2-N-06. The scheduler log string was corrected too (`renewal_scheduler.go:669`). |
| B4 FEATURE_VALIDATION counts | FIXED | Scripted recount of the section 3 tables: 77 rows (LIVE 21, INTEGRATION 19, UNIT-ONLY 26, UNVALIDATED 7, HIDDEN/NOT-WIRED/EXPERIMENTAL 4). Section 4 says 77 and 4; RELEASE_NOTES says 77. |

### 3.2 New claims verified (35 checked, 32 hold, 3 false: A1 to A3)

| # | Claim | Result |
|---|---|---|
| 1 | CHANGELOG note 44: migrations 000070 to 000074 incl. `000074 minted_api_keys` | Holds (`000074_*.up.sql` in both engines, `.down.sql` present). |
| 2 | Note 45: pki-operator has `certificate.renew` but not `discovery.manage`, so 403 on `/targets` | Holds (`authz_custom_roles.go:308` permissions; `/api/v1/targets/**` gated by `discovery.manage`, `authz_write_gate.go:101`). |
| 3 | Note 45: other auth kinds cannot arm (403) | Holds (`armStamp`, `egressStamp` default branch). |
| 4 | Note 51: idle RSS 629 to 665 MB at 55k to 61k certs | Holds (`perf/rc3/README.md` table). |
| 5 | Note 51: about 1.0 GB (964 to 1,066 MB) after the four reports | Holds. |
| 6 | Note 51: 970 MB peak, 8-way issue burst | Holds. |
| 7 | Note 51: about 11 KB idle growth per certificate | Holds (perf item 2). |
| 8 | Note 51: 30-way bad-login spray +325 MB (664 to 989 MB) | Holds (measurement); cause statement in perf doc is A1. |
| 9 | Note 51 / deployment.md: "login hashing concurrency is capped" | Holds in code (`loginKDFConcurrency = 4`); contradicts the perf docs (A1). |
| 10 | Note 51: 2Gi reaches about 100k certs, labelled an extrapolation | Holds (labelled). Arithmetic: 665 MB + 40k x 11 KB + 380 MB transient is about 1.5 GB. |
| 11 | deployment.md: 172 MB idle at 10.5k certs | Holds. |
| 12 | CHANGELOG: `IssueCertificate` 67.2 MB/op to 28 KB/op, 17.9 ms to 0.14 ms, "as recorded in commit 155acbac" | Holds (commit body matches verbatim); "not stored under docs/" is honest. |
| 13 | Note 54: migrations 000020, 23, 24, 32, 47, 57, 59 tolerate existing columns | Holds (map in `migrate.go`; also 11, 21, 53, 55, 56 as before). |
| 14 | Note 54: CA-mode core DB failure is fatal | Holds (`CoreDBStartupDecision`, `main.go:99`). |
| 15 | Note 54: "now migrates cleanly when you switch to ca" | Holds on SQLite (`TestOpenCoreDBAfterStoresSelfHealedSchema`); not exercised on PostgreSQL (UPGRADE_TEST "Not covered"). Unqualified wording is slightly broad (LOW). |
| 16 | Note 55: keystore default `<DATA_DIR>/keys`, legacy `./var/keys` kept with warning, path logged, refuses non-writable | Holds (`keystore_dir.go`, `main.go:117-124`). |
| 17 | Note 56: POST 503 with no key issued; DELETE 503 "already rejected; repeat until 204" | Holds (`handlers_auth.go`, `TestMintFailsClosedWhenPersistenceFails`, `TestDeleteAPIKeyHandlerReturns503WhenRevocationNotDurable`). |
| 18 | Note 56: `APP_API_KEYS_JSON` keys win on kid collision; verifier only | Holds (`SetAPIKeyStore`; `TestConfiguredAPIKeyWinsKidCollision`; `TestMintedAPIKeySecretIsNeverStored`). |
| 19 | Note 57: earlier builds (incl. rc.1, rc.2) lost minted keys on restart | Holds (UPGRADE_TEST control run on rc.1; code at 6200a0d was a map). |
| 20 | SECURITY.md Known limitations: all ids exist in `docs/security/rc2/02-findings.md` (B-03, A-05 to A-09, B-05 to B-09, C-03 to C-06, I-1, I-2, M-3, RC2-N-04, N-05, N-06, N-08) | Holds: all 22 ids found. |
| 21 | SECURITY.md: "19 JSON request decoders still have no body cap" | Holds (`02-findings.md:28` lists 19 sites). |
| 22 | SECURITY.md RC2-N-05 and N-06 descriptions | Hold (match `02-findings.md:75,83`). |
| 23 | README/RELEASE_NOTES/FEATURE_VALIDATION: upgrade scope = rc.1 to main and rc.2 to main on SQLite, rc.1 to main on PostgreSQL 16, rc.2 on PostgreSQL not run | Holds against `UPGRADE_TEST_v0.9.md` (A1 to A4 SQLite incl. rc.2 in A3; B Postgres rc.1 only). |
| 24 | RELEASE_NOTES: "Upgrades **to this tree** passed" | FALSE, blocker A3. |
| 25 | LIVE_RESULTS: plugins 27 checks, 2026-10-09 run had 26 | Holds against the old docs (26/26). |
| 26 | FEATURE_VALIDATION Helm row: `helm lint`/`template` pass (ANTI_SLOP_RC2) | Holds (RC2 report states it). |
| 27 | FEATURE_VALIDATION API-key row: persistence "pending on branch `kk/rc3-fixes`, not yet on main" | FALSE at this commit, blocker A2. |
| 28 | UPGRADE_TEST: 000020 absent from the tolerated set (11, 21, 53, 55, 56) at `72712ba` | Holds (pre-diff map). Wording nits: "four findings" then five numbered; verdict sentence "every rc.1 to main and rc.2 to main path tested passes on SQLite and PostgreSQL" is true only because rc.2 on PostgreSQL was not tested (LOW). |
| 29 | `migrate.go` comment: "000057 has a `;` in a header comment" | Holds (`000057` line 6). |
| 30 | `siem_integration.go`: "RC2-N-03 / RC1-B-04" write deadline rationale | Holds. |
| 31 | `ratelimit.go` comment: RC2-N-01 amortised sweep | Holds (code matches comment). |
| 32 | `certificate_provider.go`: "constants are the only spellings code uses" | FALSE as worded (CH-2); code comment, LOW, not counted as a release-doc blocker. |
| 33 | `perf/rc3` "H4 fixed at the sizing level; Helm 512Mi/2Gi, GOMEMLIMIT 1600MiB" | Holds against the chart values cited in note 51 and deployment.md. |
| 34 | `perf/rc3`: "Argon2id verifications are uncapped" | FALSE, blocker A1. |
| 35 | CHANGELOG Fixed entries for core-DB fatal, keystore default and API-key persistence | Hold (each maps to a merged commit and a test). |

### 3.3 Other anti-slop checks
- No new dependency: `go.mod`, `go.sum` and `ui/package*.json` are not in the diff (R-21 clean).
- New code has tests alongside; no vacuous test, no TODO/FIXME added, no new stub or unreachable production function other than CH-1.
- Evidence quality (LOW): LIVE_RESULTS and the smoke 331 figure are coordinator-reported, with no raw logs under `docs/`, unlike `docs/security/rc2/raw/`. I could not reproduce them (hubs and live suites were out of scope). They are consistent across five documents and the caveat is stated in LIVE_RESULTS.
- Perf caveat: `docs/perf/rc3` measured `26e17cac`. Commits after it include persistence (`touchAPIKey` takes the write lock on every API-key request after validation; S-M1), the limiter sweep change and syslog deadlines. None is on the issue/list hot path, but the perf verdict is a statement about `26e17cac`, not `fce40e1`. One 10-minute re-measure of an API-key-authenticated list at c=8 would close it.

## 4. Recommended order
1. A1 to A3 (three doc edits; blocks anti-slop).
2. S-M1 (move DB I/O out of the auth lock, add a timeout) and CH-1 (delete `DeleteAPIKey`); both small, neither blocks the tag.
3. S-L2 (log skipped migration statements), S-L5 (fatal on an unreadable keystore directory), CH-2/CH-3/CH-4.
4. Add a note to 56 that persisted keys load at boot (multi-replica), and a PostgreSQL case for `dbAPIKeyStore`.

## 5. Method
Branch `kk/rc3-delta-review` at `fce40e1`. Read the full diff of the code listed in scope; read every tolerated migration file in both engines; verified doc claims against code, tests, commits and the RC2 findings. Tool outputs were kept under the session scratchpad (`rcrev/`), not committed. Tools: opengrep 1.30.2, gitleaks 8.30.1 (`detect --log-opts`, equivalent to `git --log-opts`), govulncheck (go1.26.9), grype (SBOM and OCI archive), staticcheck, deadcode, gofmt, `go test` (cmd, internal). No code was changed.
