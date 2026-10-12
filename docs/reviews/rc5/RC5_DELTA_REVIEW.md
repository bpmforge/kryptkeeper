# RC5 delta review: v0.9.0-rc.5 (5ec48ff), 2026-10-11

Scope: `git diff fce40e1 5ec48ff` (RC3 to RC5: 50 files, +3045/-185), branch `kk/rc5-delta-review`.
Read-only on code. No hub started, no `tests/live/*`, no containers run (`podman save` only, for grype).
Baseline: `docs/reviews/rc3/RC3_DELTA_REVIEW.md`. Postgres-gated tests skip without `KRYPTKEEPER_TEST_POSTGRES_DSN`; none ran here.

## Verdicts

- **Security: PASS.** 0 CRITICAL, 0 HIGH. 1 MEDIUM (conditional, multi-tenant only) and 6 LOW. RC3 S-M1 is closed.
- **Code health: PASS.** 0 HIGH, 0 MEDIUM, LOW items only. gofmt regressed from clean to 1 file (comment-only, XS).
- **Anti-slop: FAIL.** 1 blocker (A1): the new rule alerts are reported "sent" under the `file` and `db` notification providers, which deliver nothing. The 3 RC3 doc blockers are fixed (commit `ef6715ed`).
- **Perf-risk: LOW-MEDIUM.** Rule evaluation is O(certs x rules) of trivial compares; the expensive work (cooldown read, send, cooldown write, audit) is per matched (cert, rule) pair, with an unbounded goroutine per send and an unbounded in-memory delivery log (P1, P2).

## Blockers

| ID | Where | Defect | Fix |
|---|---|---|---|
| A1 | `renewal_scheduler.go` `dispatchRuleNotifications`; `notification_file_provider.go:80` and `notification_db_provider.go:482` (`TestDelivery`); `README.md:155` | Rule alerts go through `notifProvider.TestDelivery`. The `file` provider (default when `APP_NOTIFICATION_PROVIDER` is unset) returns `queued` and does nothing; the `db` provider inserts a `queued` row that nothing dequeues. The scheduler then records the cooldown and emits audit `renewal_notification_sent` (`rule_id=...`) as `success`. Rules under those providers are evaluated, audited as sent and never delivered: the same stub class as the earlier notification stubs, one layer up. No comment, README row or release note says so. README:155 lists only `file` or `db` and omits `delivery`, the only provider that sends (`cmd/kryptkeeper/main.go:313`); only `docs/ops/PILOT_RUNBOOK.md:59` mentions it. The container image defaults to `delivery`, so the shipped pilot path works; a bare binary does not. | XS, both parts: (a) skip rule dispatch and log once at boot when the provider does not deliver (or audit as `queued_not_sent`); (b) say in README:155 and the release notes that `file`/`db` record only and `delivery` sends. |

## 1. Security

### 1.1 Tools (all on `5ec48ff`)

| Tool | RC3 | RC5 | Triage |
|---|---|---|---|
| opengrep 1.30.2, bpm-rulepacks owasp/secrets/slop/framework/house, same flags and targets | 297 | **297** | Diffed against `opengrep_rc2.json`: +2 / -1, the same 2 added and 1 removed rules RC3 reported (`db_core.go`, `keystore_dir.go`; `principal_reserved.go` gone). **0 new hits in the delta**, 0 security-rule hits. |
| gitleaks 8.30.1, `fce40e1..5ec48ff` (16 commits, 130 KB) | 5 (0 real) | **0** | "no leaks found". |
| `GOTOOLCHAIN=go1.26.9 govulncheck ./...` | 0 affecting | **0 affecting**; 1 in a required module not called (GO-2026-5932, x/crypto openpgp, no fix) | Unchanged. |
| grype on `sbom_0.9.0-rc.5.cdx.json` | 1 | **1** (x/crypto v0.57.0, GO-2026-5932, severity Unknown, no fix) | Same known false positive. |
| grype on `localhost/kryptkeeper:0.9.0-rc.5` (docker-archive from `podman save`; id `e0a9f30d...` equals `rc5/image-id.txt`) | 0 | **0** | "No vulnerabilities found". |
| `go test ./cmd/... ./internal/...` | 40 ok | **40 packages ok, 0 failed** | Postgres-gated tests skip (see 3.2). |

### 1.2 Migration auto-tolerance (`internal/db/migrate.go`)

Can it mask a real partially applied or divergent schema?

- **The classifier fails strict in every direction I could construct.** A migration is tolerant only if it has no pre/post section and every statement matches `ALTER TABLE x ADD COLUMN`, `CREATE TABLE IF NOT EXISTS` or `CREATE [UNIQUE] INDEX IF NOT EXISTS`, with none containing `drop|rename|alter column|add constraint`. DROP, UPDATE, INSERT, plain CREATE, triggers, PRAGMA rebuilds (000075) and mixed files return false and keep the strict single-transaction path (`TestMigrationIsAllAdditive_Classification`, 13 shapes). Parser weaknesses all fail strict: the splitter breaks on `;` inside literals, trigger bodies or block comments and the fragments fail the anchored regex; a leading `/* */` also fails the anchor. A `;`-split `DROP` is its own statement and rejected; `ADD COLUMN a, DROP COLUMN b` is caught by the clause regex. Only whole-line `--` comments are dropped, so an inline trailing `-- x; DROP` splits into a rejected second statement.
- **Skipped statements are now logged** per statement (`migrate.go` applyUpTolerant): RC3 S-L2 (silent skip) is fixed.
- **S-L2b (LOW, carried): column-shape drift is still invisible.** "Already exists" is not compared with the intended type, default or CHECK. A store `EnsureSchema` that created `col TEXT` where the migration says `INTEGER NOT NULL DEFAULT 0 CHECK (...)` is accepted. Autotolerance widens this from 12 hand-listed migrations to every future ADD COLUMN migration. The mitigation is tests (`TestOpenCoreDBAfterStoresSelfHealedSchema` SQLite plus Postgres twin), not a runtime check.
- **Atomicity (INFO).** Tolerant apply is statement-by-statement autocommit: a non-duplicate failure mid-file leaves earlier statements applied and the migration unrecorded; the next boot re-applies. Intended, same as the pre-existing explicit list.
- **`isAlreadySatisfiedDDLError` is substring based** (`already exists`, `duplicate column name`). Within the four allowed statement shapes no unrelated "already exists" can arise. HELD.
- **LOW: the self-heal guard is weaker than its name.** `TestSelfHealingStoreListIsExhaustive` scans `internal/bootstrap/*.go` for `CREATE|ALTER TABLE` and requires the filename in a map, but that map is separate from `constructAllSelfHealingStores`: a name added to the map without constructing the store passes. DDL-issuing stores in other packages (acme, ctmonitor) are hand-listed and not scanned; construction errors are discarded (`_ =`).

### 1.3 Notification rules (new in delta)

- **No webhook SSRF through rules.** A rule's `target` reaches a channel only as `Event.Target`. Slack, PagerDuty and webhook channels post to the operator-configured URL or routing key (`deliveryChannelsFromEnv`: config store or env), not to `Event.Target`, and HTTP goes through `egress.NewClient` with the egress policy (`internal/notifications/delivery/delivery.go:45-60`). Only email uses the rule target as a destination (SMTP recipient). A rule cannot make the hub call an arbitrary URL; for slack/pagerduty/webhook the stored target is decorative.
- **Authz.** `/api/v1/notifications/**` needs `notification.manage` (`authz_write_gate.go:106`); the matrix test pins POST `/notifications/rules` to pki-operator, notification-operator and `bot+ops:write` and denies service-account and discovery-operator. Create now validates channel in {email, slack, pagerduty, webhook}, threshold 1 to 3650, target at most 320 bytes, name length. CRLF in a recipient is neutralised by `sanitizeHeader` and refused by `net/smtp`.
- **S-M2 (MEDIUM, conditional on multi-tenancy; non-blocking, document or fix before GA).** Rules are hub-global (no tenant on `NotificationRule`; nothing in the rule handlers or the scheduler path is tenant-scoped) and the scan iterates every tenant's certificates. A principal with `notification.manage` can create an `email` rule to an arbitrary external address and receive common name, fingerprint and days-to-expiry for every certificate in the hub, including other tenants'. CLAUDE.md treats cross-tenant leaks as security defects. The content is low sensitivity (no key material) and the role is privileged, so this is a gap in the flag-gated tenancy posture, not a single-tenant auth bypass. Fix: document that `notification.manage` must not go to tenant-scoped principals, or add `tenant` to the rule and filter with `caVisibleToTenant` (already used by the scheduler).
- **S-L7 (LOW).** The email target is not syntax-checked (`mail.ParseAddress`); a malformed value is stored and fails at send time (logged only).

### 1.4 Validity parser (`template_validity.go`)

- Negative and zero are rejected (`d <= 0`; `-5h`, `P0D`; `P`, `PT` and a trailing `T` excluded). Unparseable values are rejected at template create/update (`validateTemplateUpsertRequest`, used by the file provider and `handlers_templates.go:543`) and again at issue and renew (wrapped in `ca.ErrPolicyViolation`).
- Ceiling: ISO components are each capped at 100 years, `<n>d` at 36500, Go durations at the 292-year int64 limit. There is no product-level maximum; the only upper clamp is the issuing CA's NotAfter (`engine.go:658`). The template's own value is also its policy `MaxValidity` (`templateItemToPolicy`), so the policy cannot be tighter than the template. INFO: a template can ask for a 100-year certificate from a 100-year CA, and `P100Y` is now easy to write.
- **S-L8 (LOW): per-component range checks do not bound the sum.** Seven components each at their cap add to 1,007,376 h (about 115 years, after the int64 nanosecond total wraps; confirmed by running the arithmetic), so a crafted multi-unit string passes the "out of range" check and yields a wrapped positive duration. Impact is nil in practice (CA NotAfter clamps, template authors are privileged) but the check does not mean what its message says. Fix: overflow-checked accumulation.
- Short-lived templates are capped at 7 days in the helper and in `templateItemToPolicy`. Renewal now carries the template lifetime (was a hard-coded default) but, per its comment, does not enforce the template as a cap; the CA clamp still applies.

### 1.5 Other delta items

- **Ceremony / 000075.** The CHECK now allows `pending_ceremony`; an unknown status is still rejected (tested). The engine births the root `active` and `StartRootCACeremony` downgrades it in the same call before returning the id (documented G-41); before 000075 that downgrade failed on a real DB and the root stayed active (the bug). Activation now happens only in `Approve` at quorum of at least 2, with eligible, distinct approvers. Dual control preserved. Residual (LOW, pre-existing design): between `CreateRootCA` and `UpdateCAStatus` the CA exists active in-process, and a crash there leaves an active root with no ceremony. `TestRootCACeremonyAgainstMigratedSQLiteSchema` now exercises the real schema.
- **000075 SQLite rebuild preserved everything.** Compared with 000002 + 000009: all 19 columns, both named CHECKs, the self-FK, `idx_ca_parent`, `idx_ca_status`, the `updated_at` trigger and both fingerprint-FK triggers are recreated; no later migration adds indexes or triggers to the table (grep). Foreign keys are handled by the pre/post split (000058 template); child FKs (`certificates.ca_id`, `ca_key_rotations`) reference the table by name and survive the rename. The test checks data, four named objects, rollback to `suspended` and re-apply. The Postgres pair drops and re-adds the CHECK by the generated name `certificate_authorities_status_check`; `IF EXISTS` would hide a different name, but the Postgres test would catch it (only when a DSN is set).
- **User provider.** Every statement is a constant with `?` rebound to `$n`; the only dynamic text is the `SET` clause joined from three fixed literals. Postgres ids are pre-validated against a UUID regexp (malformed gives not-found, not a driver error). HELD. LOW: `LinkOIDCIdentity` returns nil when no row matched (success without effect for an unknown id); `UpdateUser` treats any status other than `deactivated` as active (verify the handler enumerates statuses).
- **`StartupKeyDecision`.** Fatal only when a finding has `Missing=true` and `KRYPTKEEPER_ALLOW_MISSING_CA_KEYS` is not `true`; the opt-out is explicit and named in the error. Gaps (LOW): if `CheckKeyConsistency` itself errors, `main.go` warns and continues (fail-open on the check not running); a present-but-mismatched key stays a log line (documented); only active CAs are checked. A transient KMS/PKCS#11 error is indistinguishable from "missing" and refuses boot (fails closed; availability only).
- **API-key lock restructure (RC3 S-M1): closed.** `CreateAPIKeyAs` inserts with a 5 s timeout before taking the lock and publishes under it afterwards (the kid is unguessable and not yet visible: no race). `RevokeAPIKey` removes the key and sets `revokePending` under a brief lock, runs the DB write (two attempts, one timestamp) outside it, then clears the mark; a failed write keeps the mark so a repeat DELETE retries, and a touch after revoke is a no-op because `persistedKids` is cleared. `last_used_at` moves to a goroutine per API-key request, so a stalled DB cannot delay authentication. `DeleteAPIKey` is removed (RC3 CH-1). No lost-revocation race found.
- **Notification UUID ids.** The Postgres store lets the database mint ids (`RETURNING id`) and validates ids with `uuidRe` on ack and retry; parameterized. HELD.
- **ct_findings.** `NewStore` runs `EnsureSchema` (idempotent DDL at construction), closing the ca-mode "relation does not exist" failure.

## 2. Code health

| Metric | RC2 | RC3 | RC5 |
|---|---|---|---|
| `gofmt -l cmd internal sdk plugins` | clean | clean | **1 file**: `internal/bootstrap/user_db_provider.go` |
| `staticcheck ./...` (go1.26.9) lines | 75 | 75 | **75** |
| `deadcode -test ./...` | 40 | 39 | **39** |
| Packages passing (`cmd`, `internal`) | n/a | 40 | **40**, 0 failed |

Findings (all LOW):
- **CH-7 gofmt regression.** The only diff is a comment: `COALESCEd to ''` becomes the single character `”` under gofmt's doc-comment pass. `gofmt -w` fixes it; it would fail a `gofmt -l` gate. XS; ship with the A1 fix.
- **CH-8 Rule validation lives in the handler.** The channel switch and bounds are inline in `handlers_notifications.go`; no store's `CreateRule` enforces them, so any other caller (CLI, importer) bypasses them. Move them next to `NotificationRule`.
- **CH-9 Test seam in production code.** `touchWG` in `Authenticator` (`auth.go:109`) exists for tests; one goroutine is also spawned per API-key request even when the throttle will skip the write (the throttle runs inside the goroutine).
- **CH-10 Complexity.** `RevokeAPIKey` (about 9 branches) and `dispatchRuleNotifications` (about 7) are in bounds; no function crossed 15 cyclomatic. The notification create closure now has 5 early returns.
- **CH-11 The `file` provider is in-memory.** Rules live in a map and deliveries are a seeded fixture, though the name implies persistence; documented nowhere (see A1).
- RC3 items closed: CH-1 (`DeleteAPIKey`), CH-2 (RenewalStatus comment and constants), CH-4 (retry loop), S-M1, S-L2. Still open: CH-3 (engine detection by placeholder) and RC2 N-05/06/08/10/12/13.

## 3. Anti-slop

### 3.1 Notification providers (the explicit question)

| Provider | Delivers? | Documented? |
|---|---|---|
| `delivery` | Yes, through `delivery.Worker`, asynchronously (`queued`, then `sent`/`failed` in an in-memory log). Rules now persist via the DB store; the previous no-op rule stubs are replaced. | Pilot runbook only. |
| `db` | No. `TestDelivery` and `RetryDelivery` insert `queued` rows that nothing consumes. Rules persist. | No. |
| `file` (default) | No. `TestDelivery` returns a fabricated id and `queued`; deliveries are a seeded fixture; rules are in memory. | No. |

The `delivery` stubs are fixed and tested end to end (`TestRuleCreatedViaProviderDrivesDelivery`: one alert for the matching cert only, cooldown suppresses a repeat, a disabled rule sends nothing). `file` and `db` are neither fixed nor marked: blocker A1.

### 3.2 Other checks
- **A-2 (LOW) "sent" means enqueued, even for `delivery`.** `TestDelivery` runs the worker in a goroutine and returns `queued`; the scheduler records the cooldown and `renewal_notification_sent` at that moment. A permanent failure (bad SMTP, webhook 500) is not audited as failed and the cooldown suppresses a retry for the whole window. The worker retries transient failures (3 attempts).
- Comments versus code: the new comments hold (validity parser, additive classifier, API-key lock, `StartupKeyDecision`, 000075). One understated: `splitSQLStatements` still says it serves only `migrationsTolerateAlreadySatisfied`, but it now also feeds the auto-classifier (fails strict, so safe).
- Tests assert behaviour: spot-checked `api_key_lock_test.go`, `notification_delivery_rules_test.go`, `migrate_ca_status_test.go`, `reconcile_startup_test.go`. No vacuous test, no TODO/FIXME added, no new dependency (`go.mod`, `go.sum` untouched).
- **A-3 (LOW) Postgres-sweep tests skip silently.** Most of the new `db_stores*_postgres_test.go`, `db_providers_postgres_test.go`, `ca_lifecycle_postgres_test.go` and the Postgres half of `migrate_ca_status_test.go` call `t.Skip` when `KRYPTKEEPER_TEST_POSTGRES_DSN` is unset, so a local "40 packages ok" includes none of them. CI sets the variable and the `-p 1` change is right (the helper runs `DROP SCHEMA public CASCADE`, guarded by a `test` substring in the database name). Count Postgres coverage from the CI log only.
- Docs: `README.md:155` omits `delivery` (A1). No release-note entry for rule persistence or the new CA-key fatal; `KRYPTKEEPER_ALLOW_MISSING_CA_KEYS` appears only in code and its error text.

## 4. Perf risk

- **P0 Rule evaluation is cheap for non-matches.** One `ListRules` per tick, then per certificate a loop of `expiry.After(now+N days)` over enabled rules: O(certs x rules) integer compares, no allocation unless matched. 50k certs x 20 rules is about 1M compares, well under 50 ms. It runs before the renewal-window `continue`, so it covers every non-revoked, non-expired certificate.
- **P1 The expensive work is per matched pair, serial, with unbounded fan-out.** Each match does `isSilenced` (CA and template verdicts memoised per tick, the certificate-level lookup is not), a `LastAlertedAt` read, a `TestDelivery`, a `RecordAlerted` write and an audit emit. The first tick after an operator creates a wide rule (say 365 days) matches most of the estate: 50k certs x 1 rule is about 50k cooldown reads, 50k writes and 50k audit events in one scan and, under `delivery`, 50k goroutines each calling `Worker.Deliver` (SMTP or webhook) on `context.Background()` with no concurrency cap. That is a burst on the relay or webhook and a goroutine and memory spike. Recommend a per-tick send cap (for example 500) and a bounded worker pool.
- **P2 The in-memory delivery log is unbounded.** `deliveryNotificationProvider.deliveries` is appended on every `TestDelivery` and never trimmed, so it now grows by (matched pairs per cooldown window) entries for the life of the process. Estimated ~200 bytes each (not measured): about 10 MB per 50k alerts. The `docs/perf/rc3` RSS profile does not include it.
- **P3 Auth path.** One extra goroutine per API-key request (CH-9); `apiKeysSnapshot` still copies the key map per request (unchanged since RC3). Not measured; `docs/perf/rc3` predates both. No re-measure exists for `5ec48ff`.

## 5. Recommended order
1. A1 (provider honesty in the rule path; README:155 and release notes). Blocks anti-slop.
2. CH-7 (`gofmt -w`), S-M2 (document or scope rules by tenant), P1 and P2 (per-tick cap, bounded delivery log).
3. S-L8 (overflow-checked sum), `StartupKeyDecision` fail-open on check error, `LinkOIDCIdentity` zero-row result, email address syntax check.
4. Attach the CI log for the Postgres-gated tests; bind the self-heal guard map to the constructor list.

## 6. Method
Branch `kk/rc5-delta-review` at `5ec48ff`. Read the full diff of every file named in scope (migrate.go and its tests; both 000075 pairs against 000002/000009; notification delivery, db and file providers and the scheduler; template validity and issue/renew; user provider; API-key lock files; `StartupKeyDecision`; ct_findings; CI diff). Tools: opengrep 1.30.2 (same packs and targets as RC2/RC3; diffed against `docs/security/rc2/opengrep_rc2.json`, since no RC3 JSON is committed the equality with RC3 rests on the count of 297 and the identical added/removed rules), gitleaks 8.30.1, govulncheck (go1.26.9), grype (SBOM and `docker-archive` from `podman save`), staticcheck, deadcode, gofmt, `go test ./cmd/... ./internal/...`. A scratch Go program (scratchpad, not committed) confirmed the ISO sum wrap. No code was changed.
