# v1 final security scan (scan + triage) — 2026-10-18

Branch `qa/v1-final` at a302b3b1. Scope: the whole repo by tool, plus manual review of
everything changed since c9e0e766 (`git diff c9e0e766..HEAD -- '*.go' 'ui/src'`, 129 files).
This is the scan/triage half of phase 3: findings only, nothing fixed here. Builds on
`V1_SCAN_2026-10-17.md` (D-202..D-204). Next decision id: D-290 (accepted below as the lead default; owner may override).

## Summary

| Severity | Count |
|---|---|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 5 |
| LOW | 5 |
| INFO | 5 |

No tool reports a real vulnerability. The MEDIUMs are fail-open / fail-soft semantics
(WSTEP enroll lists, quorum policy parsing, in-memory store fallbacks) and the new
migration update path; none is an unauthenticated or single-actor bypass.

| ID | Sev | File:line | Finding | Exploit precondition | Recommended fix | Status |
|---|---|---|---|---|---|---|
| S-01 | MEDIUM | internal/wstep/server.go (`EnrollPermitted`) | A template's enroll list is enforced over XCEP/WSTEP only when it contains a `protocol:wstep*` entry. A template an admin restricted to `["pki-admin"]` (which EST/SCEP/ACME/API enforce fail-closed via `ca.CheckEnrollment`) stays offered to, and issuable by, every Kerberos-authenticated domain machine. The engine does not re-check `TemplatePolicy.EnrollRoles` (no callers in `internal/ca`). Deliberate for pre-B5 compat (932b742e) but not recorded as a decision. | WSTEP enabled; domain-joined machine; template with a non-empty, API-roles-only enroll list | D-290-B (proposed): non-empty list without any `protocol:wstep*` entry = Windows refused; one-time migration adds `protocol:wstep` to existing lists that should stay open, or at minimum surface the semantics in the template API/UI | **FIXED** (D-291: every non-empty enroll list enforced on WSTEP/XCEP; one-time startup upgrade keeps autoenrolled templates working) |
| S-02 | MEDIUM | internal/bootstrap/approval_quorum.go:73 | An unparsable `APPROVAL_QUORUM_POLICY` silently degrades every action class (e.g. `revoke=2/3`) to 1-of-1, per proposal, with only an error log. No startup validation exists in `cmd/` (W22-10 spec deferred it). Fail-open of dual control. | Operator typo in the env (no attacker needed); any single approver then suffices | Validate at startup in `cmd/kryptkeeper` and refuse to start on a parse error; keep the per-call fallback only as unreachable defence | FIXED (qa/v1-final): `ValidateApprovalQuorumPolicyFromEnv` called first thing in `main`; a bad entry is fatal and named |
| S-03 | MEDIUM | internal/bootstrap/agent_store_db.go:800-807 | With a DSN configured but the DB unreachable (or `EnsureSchema` failing) at startup, the agent store falls back to the process-wide in-memory store, which its own comment (line 174) calls "plaintext, non-constant-time". Agent tokens minted during the outage are held plaintext and lost on restart; HA replicas diverge. | DB open/schema failure at startup (connection-limit exhaustion did this in the lab before the pool fix) | D-290-A: fail closed — 503 the agent routes (or refuse start) when a DSN is configured; memory only when explicitly requested | FIXED (qa/v1-final, D-290-A): agent store fails closed (503, `/readyz` not ready, throttled reopen); memory only via `APP_AGENT_STORE_PROVIDER=memory` |
| S-04 | MEDIUM | internal/bootstrap/breakglass.go:750 | Break-glass falls back to memory with a warn. `CreateActivationIfFree` is a per-process singleton, so in HA each replica can hold its own active elevation; `UseReview`/`CompleteReview` (the post-use review obligation) are lost on restart, so an emergency elevation can go unreviewed. | DB open/schema failure at startup; multi-replica or a restart before review | D-290-A, break-glass tier (see item 4): refuse activation (503) when the configured DB is unavailable, or allow memory activation only single-replica with a mandatory audit row and refuse review completion until persisted | FIXED (qa/v1-final, D-290-A): break-glass fails closed (503, `/readyz` not ready, throttled reopen); memory only via `APP_BREAKGLASS_PROVIDER=memory` |
| S-05 | MEDIUM | internal/migration/framework.go:414,435; internal/bootstrap/handlers_migration.go:107 | New `update` action: a re-applied import, or any import naming an existing template's name + OID, replaces that template's mapped fields (EKUs, key usage, algorithms, `require_approval`, `approval_roles`, name policy) and **reactivates** it, even a hub-native or admin-disabled template. The diff shows "update" (Migration.tsx badge), but rolling the batch back then *disables* the template rather than restoring it (documented at framework.go Apply). Import content is caller-supplied, OIDs are visible. | A migration proposer plus an approver who approves an `update` diff without reading it | Restrict `update` to templates whose provenance is a migration batch (`it.ContentHash` path) and keep name+OID match on a non-migrated or disabled template a `conflict`; show field-level before/after for updates; snapshot prior content so rollback restores | FIXED 060b91e9 |
| S-06 | LOW | internal/bootstrap/tenant_store.go:131, handlers_tenants.go:48 | A certificate with no hub CA (`CAID == ""`: imported/discovered/synced) resolves to `DefaultTenant`. Under MULTI_TENANCY it is visible to, and (new this session) revocable by, default-tenant certificate admins, and invisible to the tenant that imported it. Revocation is inventory-only (no CRL/OCSP effect). | MULTI_TENANCY on; a non-default tenant imports/discovers certificates | Tenant column on `certificates` (same follow-up as D-203 tables); until then document that CA-less certs are default-tenant | ACCEPTED (limitation documented in `docs/v2.2_MULTI_TENANCY_SCOPE.md`; no tenant derivable without a schema column) |
| S-07 | LOW | internal/bootstrap/certificate_ca_provider.go:589 | Revoking a CA-less certificate returns the same `CertificateRevokeResult` (`renewal_status: revoked`) as a real CRL/OCSP revocation. The UI explains it (EXTERNAL_REVOKE_NOTE), but API, MCP, bulk revoke, anomaly remediation and the key-compromise sweep (key_lifecycle.go:580) cannot tell; a compromised key's externally issued certs look handled. | Operator relies on API/automation output after a key compromise | Add `inventory_only: true` (openapi + types) to the revoke result and the key-compromise report; audit detail `inventory_only` | FIXED (`revocation_scope` ca\|inventory_only on revoke result, bulk items, pending-action results, key-compromise report `inventory_only`; UI text) |
| S-08 | LOW | internal/xcep/server.go:192 (`auditServed`) | `xcep.policy` dedupe map is bounded (keyed by authenticated principal, pruned), but the prune walks the whole map on every new principal under `auditMu`; a large estate's GPO refresh is O(n²) serialized work. Denials are not deduped, so the security trail is complete (dedupe documented in docs/ops/WSTEP_AUTOENROLLMENT.md, f6e9e76f). | Tens of thousands of machines polling in one window | Prune at most once per minute (or when len > threshold) | FIXED 5f5a1938 |
| S-09 | LOW | internal/ca/policy_engine.go:249 (`AcceptedRSABits`), xcep/server.go:240 | Each authenticated GetPolicies runs up to 5 `Evaluate` calls per offered template, each loading policies from the DB. Authenticated amplification only. | Authenticated domain machine polling repeatedly | Load policies once per request, or a short-TTL cache keyed (caID, atLeast, algos) | FIXED 071783e8 |
| S-10 | LOW | internal/bootstrap/access_review_campaign.go:482 | Access-review campaigns fall back to memory: decisions and the finish SHA (compliance evidence) are lost on restart; HA replicas diverge. No privilege effect. | DB open/schema failure at startup | D-290-A: fail closed (503) | FIXED (qa/v1-final, D-290-A): access review fails closed (503, `/readyz` not ready, throttled reopen); memory only via `APP_ACCESS_REVIEW_PROVIDER=memory` |
| S-11 | INFO | internal/bootstrap/db_pool_config.go:119 | Shared pool cache holds `pgPoolsMu` across `db.Ping()` (no timeout), and ~15 credential-store holders now share one 3-connection pool. A hung DB serializes store construction; pool contention queues requests. Correctness fix (connection exhaustion) outweighs it. | Hung Postgres at startup / heavy credential-store load | `PingContext` with a short timeout; consider per-service MaxOpen for the credential store | FIXED 30fe51a2 (by H-F3: 3 s `PingContext`, ping outside `pgPoolsMu`; was ACCEPTED) |
| S-12 | INFO | internal/wstep/server.go:~396 | WSTEP policy-refusal SOAP fault and audit row include policy name and rule text. Deliberate (Windows operators read it in the client event log); no key material. | Authenticated client | none | ACCEPTED |
| S-13 | INFO | internal/bootstrap/handlers_integrations.go:57 | `scep_off_reason` names the configured SCEP CA id; endpoint requires authentication. | Authenticated user | none | ACCEPTED |
| S-14 | INFO | internal/bootstrap/state_file.go:47-60 | With `KRYPTKEEPER_DATA_DIR` set, a legacy `./var/<name>` file is still preferred when the data-dir file is absent (relative to cwd, warned). Names are constants and the dir is operator config: no traversal. | Operator config | Remove the legacy branch in a later release | ACCEPTED |
| S-15 | INFO | internal/bootstrap/handlers_keys_lifecycle.go:30 | 503 key-policy path logs the raw store error (may contain DB host/user) server-side only; client body is uniform. | Log access | none | ACCEPTED |

## Tools (versions and results)

| Tool | Version | Result |
|---|---|---|
| govulncheck | v1.9.0, built and run with GOTOOLCHAIN=go1.26.9; DB 2026-10-08 | 0 called vulnerabilities; 1 advisory in a required module whose symbols are not reached (same `x/crypto/openpgp` class as the prior scan). |
| gosec | v2 @latest (dev build), go1.26.9 | 385 issues (prior scan 380), 33 in files changed since c9e0e766, 0 in tests (excluded by default). Triage below. |
| opengrep | 1.27.1, in-house `bpm-rulepacks` owasp + secrets + framework packs (59 rules; no registry rules) | 24 findings, all FP/ACCEPTED (below). Needs `LANG=en_US.UTF-8` (rule files are UTF-8). 2 TS files only partially parsed (`new` used as a property name in api-types.ts:5841, models.ts:288) — type-only files, low risk. |
| npm audit | `npx npm@11 audit --omit=dev` in ui/ | found 0 vulnerabilities |
| gitleaks | 8.30.1 | working tree 43 hits; `c9e0e766..HEAD` (100 commits) 3 hits. All FP (below). |
| go vet | go1.26.9, `./internal/... ./cmd/...` | clean |
| go test -race | go1.26.9 | xcep, wstep, migration/... (6 pkgs), ca, egress, cmd/kryptkeeper: ok. internal/bootstrap: the 165 test functions in test files changed this session: ok (225s). No races. |

## Triage notes

**gosec, the 33 in changed files**
- G201/G202 inventory_source.go, api_key_store.go, audit_db_provider.go:471 — FALSE-POSITIVE: interpolate only `s.ph(n)` placeholders, a constant literal, or `ORDER BY` direction from a two-value switch. The new audit `ActionPrefix` filter binds both values and escapes `\ % _` (`escapeLIKE`) with `ESCAPE '\'` on both drivers; `$n` numbering verified to advance by 2.
- G703/G304/G301 state_file.go, audit_file_provider.go, template_file_provider.go, db_provider_helpers.go, inventory_source.go:122 — ACCEPTED: paths are operator env / `KRYPTKEEPER_DATA_DIR` joined with constant file names (S-14).
- G124 handlers_auth.go:159,523 — FALSE-POSITIVE: `HttpOnly`, `SameSite=Strict`, `Secure` conditional on TLS/forwarded https.
- G101 main.go:931 — FALSE-POSITIVE: help text naming `KRYPTKEEPER_SCEP_CA_ID`.
- G115 adcs.go:256 (deliberate sign check on an ADCS FILETIME), main.go:1082 (validity from a positive duration) — FALSE-POSITIVE.
- G401/G505 main.go:12,1528 — ACCEPTED: SHA-1 key hash mandated by RFC 6960 (OCSP CertID).
- G104 xcep 514, wstep 778, siem 326, key_lifecycle 400, main 75/78 — ACCEPTED: response-write / best-effort close errors.

**gosec, the remaining 352 (unchanged code, same categories as the 2026-10-17 triage):** G104 unhandled
best-effort errors; G201/G202 SQL builders with placeholders/allowlisted fragments; G304/G703 operator file
paths; G115 bounded integer conversions; G402 InsecureSkipVerify only in discovery scanners, cipher auditor and
fingerprint-pinned agent verify; G401/G505/G501 SHA-1/MD5 for protocol-mandated digests (OCSP, NTLM, IIS
thumbprint); G404 math/rand for jitter. No new category.

**opengrep** — weak-hash (5): protocol-mandated SHA-1/MD5 (OCSP CertID, NTLM, IIS thumbprint): ACCEPTED.
tls-verify-disabled (9): scanners/auditors and fingerprint-compare verify, by design: ACCEPTED. insecure-random
(1): renewal jitter: FP. hardcoded-secret / generic-assignment (6): empty-string initialisers, config key names,
credential type constants, the public Google token URL: FP. target-blank (3): all carry `rel="noreferrer"`
(implies noopener): FP. pem-private-key (1): a form field label: FP.

**gitleaks** — commit range: `tests/smoke/run.sh:599` ×2 (test password hash and verifier in a smoke-test
launch line; the line changed for the demo flag, values pre-existing and already pinned for older commits) and
`docs/board/plan.json:18028` (prose): FP. Both new fingerprints are now in `.gitleaksignore` (F3, `gitleaks git c9e0e766..HEAD` clean).
Working tree: the same test fixtures, fake keys, doc examples and live-test bearer placeholders as the
2026-10-17 history scan, plus `ui/dist` (git-ignored build output) and `docs/security/rc2/raw/live_probe2.txt`
(a lab key id and action id, not secrets): FP.

**UI diff** — no new `dangerouslySetInnerHTML`, `innerHTML`, dynamic `href`, `window.open` or storage writes.
`canDecidePendingActions` is a display gate mirroring `canApproveActions`; the hub remains the authority.

## Manual review of this session's changes

| Area | Result |
|---|---|
| Shared Postgres pool cache | Keyed by service + DSN, never returned across services; `compliance-attestation` (closes its pool) is excluded and test-enforced. DSN held in memory only. S-11. |
| Key-op 503 path | Still fails closed; only the status code changes (403→503) for a store outage; client body uniform; audit `failure`. OK. |
| SQLite refresh deadlock + nextRowStamp | Cursor drained before `p.mu`; lock order now consistent; stamps strictly increase. No authz effect. Race tests clean. OK. |
| Imported-cert revoke by fingerprint | Handler gates (team scope, tenant via `caVisibleToTenant`) unchanged and run before the provider. UPDATE parameterized. Branches on `CAID == ""`; the hub's issue and renew paths always set CAID; only a row stored with NULL `ca_id` (none expected for hub-issued certs) would take the inventory-only path — worth a one-line assertion in the fix for S-07. S-06, S-07. |
| Approver role scope (approval_role_scope.go) | Widens *visibility* only: own requests + templates whose `approval_roles` name the role. Decide handlers still enforce template role, `approverRefusal` (proposer ≠ approver), delegation and tenant; tenant filter applied after scoping in list, get and inbox. Unreadable template grants nothing; `mcp-agent` excluded. `approver` cannot see or decide key/CA pending actions (`canApproveActions`). Cache is per request. OK. |
| XCEP key-size probing, xcep.policy dedupe | Probes the real `Evaluate`; template minimum is a floor, never lowered; probe error faults the request generically. S-08, S-09. |
| WSTEP refusal audit / B5 enroll lists | Refusals audited with template as resource; identity DNS names come from the Kerberos principal or a hub-issued renewal certificate, never the CSR; `protocol:wstep:restricted` cannot match an FQDN (always contains a dot). S-01, S-12. |
| Shutdown drain + lease release hook | `/readyz` 503 during drain, hook bounded (15s), leases released before listener close; Shutdown timeout no longer fatal so deferred stops run. OK. |
| Egress failure_reason text | Replaces raw guard text with a fixed explanation; raw delivery errors stay in logs. No relaxation of the guard. OK. |
| File-store defaults under KRYPTKEEPER_DATA_DIR | Constant names, `filepath.Join`; no user input. S-14. |
| ADCS infrastructure filter, estate revert renewal path | Infra templates get `pki-admin` + `protocol:wstep:restricted`, autoenroll off; admin-set enroll lists survive re-apply. Revert only changes management state / method / connector, audited with a JSON transition (values `%q`-quoted). Re-sync no longer reverts a takeover; lookup failure counts as managed (safe direction). Migration update path: S-05. |
| Audit action family filter | Parameterized, LIKE-escaped (see gosec triage). Export summary echoes the filter. OK. |
| SCEP off reason, dashboard demo flag | Authenticated endpoint (S-13); demo rows now opt-in, removing fabricated history from real hubs. OK. |
| Custom-role error mapping | Driver text now logged, not returned (fixes a minor leak); unique violation → 409. OK. |

## Prior follow-ups (V1_SCAN_2026-10-17) — current state

| Follow-up | State |
|---|---|
| Refresh token in sessionStorage | OPEN — unchanged (`ui/src/lib/api.ts:293-295`). No XSS sink added this session. |
| Retired CA key destruction not wired | OPEN — `RetireRotatedKeys` / `RetiredKeyGraceFromEnv` still have no production caller (`internal/ca/rotation_hooks.go:72,113`); KEY_ROTATION.md still promises destruction. Owner decision pending. |
| `logging.WithTenant` unused | OPEN — defined at `internal/logging/logging.go:105`, no callers. |
| Tenant columns for D-203 (agent/NHI/SPIFFE) | OPEN — migrations 000015/000035 create the tables without a tenant column; no later migration adds one. D-203 restriction stays. S-06 extends the same gap to CA-less certificates. |

## Item 4 — in-memory fallback of security-relevant stores

Survey of `*FromEnv` constructors: four fall back to memory (agent store, break-glass, access review, and the
user provider — the last only when `APP_USER_PROVIDER=file` is asked for, S-40). Approvals and pending
actions return nil and their handlers 503 (`handlers_pending_actions.go:60,136`); the tenant store fails closed
(D-202); the audit provider refuses to start. So the hub already has a fail-closed precedent for every class
except the three below.

The original rationale for break-glass ("stays available in an outage") does not hold up: an outage that
stops the break-glass store from opening also takes down certificates, approvals, pending actions and tenants,
so an in-memory elevation buys little and costs the singleton guarantee and the review trail.

**D-290 (ACCEPTED — lead default; owner may override)** — store fallback policy. Implemented: A (S-03/S-04/S-10) and B (S-02) on `qa/v1-final`; C (S-01) fixed as D-291. The break-glass alternative below was not taken.
- **A. Fail closed, no memory fallback when a DSN is configured** (configured-but-unavailable is a fault, not
  a mode): agent store (S-03, secret material), access review (S-10, compliance evidence), break-glass (S-04).
  Handlers answer 503 with a uniform body; the store retries the open lazily so recovery needs no restart, and
  `/readyz` reports the store down. Memory stays available only when named explicitly (`APP_<STORE>_PROVIDER=memory`,
  as S-40 did for users), for tests and offline dev.
- Break-glass alternative if the owner wants outage availability: allow activation from memory only when
  `HA` is off, write an audit row before granting, and refuse `CompleteReview` until persisted so the review
  obligation cannot be lost silently. Either way, not the current silent warn.
- **B. Startup validation for policy env** (S-02): a malformed `APPROVAL_QUORUM_POLICY` refuses start.
- **C. WSTEP enroll-list semantics** (S-01): align with `ca.CheckEnrollment` (non-empty list = enforced) via a
  one-time migration, or record the opt-in semantics as an explicit decision and surface it in the template UI.

## Ranked fix list

1. S-02 — refuse start on a bad `APPROVAL_QUORUM_POLICY` (small, removes a dual-control fail-open).
2. S-03 / S-04 / S-10 — D-290-A fail-closed store fallback (agent store first: plaintext tokens).
3. S-05 — restrict migration `update` to migration-provenance templates; keep disabled/native name+OID matches as conflicts; rollback restores content.
4. S-01 — decide D-290-C; implement the migration or the UI/API disclosure.
5. S-07 — `inventory_only` flag on revoke results and the key-compromise report.
6. S-06 — tenant column on `certificates` (with the D-203 tables).
7. S-08 / S-09 — XCEP prune throttling and per-request policy load.
8. Housekeeping: ~~add the two new gitleaks fingerprints to `.gitleaksignore`~~ (done, F3); S-11 `PingContext` timeout.

## Rescan 2026-10-18

Rescan of fix waves F1-F3 (`git diff 6d9e8ea6..HEAD -- '*.go' 'ui/src' 'internal/db/migrations' 'tests/live/lib'`,
64 files, plus 9a0102be H-F4 which landed during the rescan). Three new defects were found and fixed on
`qa/v1-final` (R-01..R-03); the rest are recorded below for the owner.

### New findings

| ID | Sev | File:line | Finding | Status |
|---|---|---|---|---|
| R-01 | MEDIUM | internal/migration/framework.go `classifyNameMatch` | The S-05 fix dropped the old non-empty-OID guard: two OID-less exports (vault, keyfactor, venafi, certcentral carry no OID) with the same template name matched, and the second overwrote and reactivated the first's migrated template. It also ignored the item `FindItemByTemplate` returned, so a template still owned by an active item under another source key (e.g. admin-disabled, then re-exported with a new ADCS DN) was updated and reactivated, bypassing `classifyImported`'s admin-disabled check. Same precondition as S-05. | FIXED fb274208: empty OID, or an owning item still active, is a conflict (2 tests) |
| R-02 | LOW | internal/bootstrap/{agent_store_db,breakglass,access_review_campaign}.go `open*Store` | The D-290-A lazy stores retry every 10 s. When the open succeeded but `EnsureSchema` failed, the SQLite pool (one pinged connection) was dropped without `Close`: one leaked connection/fd per retry for the outage. | FIXED 88a729f9: `releaseFailedOpenDB` closes SQLite / unshared pools, never a shared Postgres pool (test) |
| R-03 | LOW | ui/src/pages/Migration.tsx | After S-05 the undo dialog still said rollback only disables, and the toast dropped the new `restored` count. | FIXED f8484a0c (type, text, test) |
| R-04 | LOW | internal/bootstrap/breakglass_login.go:49 | The break-glass local login is mounted through `breakGlassRouteHooks` on the raw mux, outside the D-290-A gate. With the break-glass DB down the login still succeeds; the audit row and alert fire (`recordUse` alerts before `UseReview`), but the review row is not written, only logged. That is the S-04 "unreviewed elevation" gap for this one path (the override path fails closed: `Active` errors to not-live). Deliberate per its comment (an SSO outage must not lock out the operator). | ACCEPTED (lead default): break-glass login exists for emergencies when dependencies are down, so it must keep working with the break-glass DB down. Compensating controls: the audit row and the alert (both before the review row). The lost review row is logged at error level naming the elevation (086c95a8, test) |
| R-05 | LOW | internal/migration/rollback.go `Rollback` / `SaveBatch` | Rolling back an update restores the template (active) but leaves the item it superseded retired, so nothing owns the template afterwards. If an admin then disables it, a re-import with the same name and OID reaches `classifyNameMatch` with a retired newest item and reactivates it. Needs the supersedes link persisted so a restore can re-activate the superseded item (then `classifyImported` applies). | FIXED 505e7b1c: supersedes link stored (migration 000326, `migration_item_supersedes`); `MarkItemRestored` retires the item and reactivates the superseded one in one transaction (only if its batch is still applied); `FindItemByTemplate` prefers an active owner (3 tests) |
| R-06 | INFO | internal/xcep/server.go `auditServed` | At the 50 000-entry cap with all entries live, every principal not remembered triggers a full prune scan under `auditMu` (bounded O(n), not O(n²); fails toward more audit rows). | ACCEPTED |
| R-07 | INFO | internal/bootstrap/required_store.go | `/readyz` reflects only a store that has never opened; once up, a later DB failure surfaces through the inner store's own errors, not readiness. No flapping (up is sticky); one reopen goroutine at most per store per 10 s, none while up. When a required store is down every replica leaves rotation, by design (D-290-A). | ACCEPTED |
| R-08 | INFO | cmd/kryptkeeper/cmp_admin.go:53 | CMP `rr` discards the revoke result, so `revocation_scope` is not reported over CMP (inventory-only revocation of a CA-less cert looks like a CA revocation to a CMP client). | FIXED eb00ba18: `cmp.Revoker` returns the scope; recorded in the `cmp.rr` audit detail (rp has no field for it) (2 tests) |

### Re-run tools (changed files / touched packages)

| Tool | Result |
|---|---|
| govulncheck v1.9.0, GOTOOLCHAIN=go1.26.9 | 0 called vulnerabilities (1 required-module advisory not reached, as before) |
| gosec v2 @latest on bootstrap, migration, wstep, xcep, ca, cmd/kryptkeeper | 197 issues in those trees; **0 on lines added since 6d9e8ea6** (all hits are pre-existing SQL-builder / G104 / G115 / SHA-1 classes triaged above). Re-run on migration + bootstrap at 7b044d2e (after R-01/R-02): 166 issues, still 0 on added lines |
| opengrep 1.27.1, bpm-rulepacks owasp+secrets+framework, 44 changed files | 1 finding: weak-hash at main.go:1541 (OCSP CertID SHA-1, ACCEPTED). Partial parse of the generic embedded `*lazyStore[...]` wrappers in 3 files and api-types.ts (delegation code; reviewed by hand) |
| go vet ./... | clean |
| go test -race | xcep, wstep, ca, migration (6 pkgs), cmd/kryptkeeper: ok; internal/bootstrap: the 94 test functions in test files changed since 6d9e8ea6 plus R-02's: ok. 0 races |
| staticcheck (touched pkgs) | SA4023 main.go:160 (H-F19), 9x ST1005 wstep (H-F20), SA1012 approval_channel_test.go:55 (pre-existing): nothing new; SA4000 (H-F12) gone |
| gocyclo -over 25 / gocognit -over 40 (internal, cmd) | 100 -> 99 / 99 -> 97. Touched: `serveRST` 13/17, `plan` 8/9, `classifyNameMatch` 10/7, `Rollback` 16/34, `evaluatePolicies` 13/24, `applyKeyPolicy` 8/13, lazy store <= 5 |
| ui lint / vitest | 0 errors (1 pre-existing warning) / 989 tests, 112 files pass |
| go test ./... / make lint (at 7b044d2e) | 85 packages ok, 0 failures / 0 issues |

### Regression checks (no defect)

- **Gated routes:** every `registerAgentHandlers` route (incl. remove and enrollment tokens), renewal-SLO, the break-glass API and access-review campaigns go through `gateRoutes`; the only ungated user of a lazy store is the break-glass login hook (R-04). The scheduler's own `NewAgentStoreFromEnv` (main.go:623) returns 0 work while down.
- **Lazy store:** open runs outside `l.mu`; `trying` serialises reopens; `onUp` (agent change sink) runs under `l.mu` and takes only `sinkMu`, never the reverse: no lock cycle. No goroutine loop.
- **Migration 000325:** version unique on both drivers, up/down pairs present, FK to the `(batch_id, source_key)` PK of 000144; no code deletes `migration_batch_items`, so the FK cannot block. `schemaDDL` matches.
- **Snapshot/Restore:** `templateRequestOf` covers every field `Update` writes (plus `active`, short-lived, SSH policy); restore goes through `ReplaceTemplate` with the current revision.
- **classifyImported:** a migration never updates a template that no longer exists or is inactive with an active item; hub-native name matches are conflicts (`OriginStore` required).
- **SaveBatch:** supersede retire, insert and snapshot rows in one transaction; save failure leaves the old item active (tested).
- **serveRST split:** order unchanged: envelope check -> CSR -> renewal predecessor -> identity-derived request (subject/SANs from Kerberos/renewal identity, never the CSR) -> template resolution -> enrollee + enroll-list authorisation with its denial audit -> policy fields -> issue -> policy-refusal audit -> record -> success audit -> response.
- **RSAProbe:** one `loadPoliciesFor` per GetPolicies (lazily on the first offered template); `Evaluate` is `load + evaluatePolicies`, so advertised = enforced; load error fails the request.
- **revocation_scope:** both providers set it (CA-less and file provider `inventory_only`, else `ca`); single, bulk, pending-action, anomaly batch and key-compromise report propagate it; openapi enum present.
- **isUniqueViolation:** the persist path passes the raw `Exec` error, so `errors.As` sees `*pgconn.PgError` / `*sqlite.Error` (modernc, `Code()` is the extended code); driver test passes.
- **tests/live/lib/podman.sh:** `bash -n` clean; all 7 `kk_wait_dns` call sites fail or `DIE` on non-zero.

### FIXED-status verification

Security doc:
- S-02: confirmed. `ValidateApprovalQuorumPolicyFromEnv` is fatal in `main` before any store is built; test present.
- S-03: confirmed. Agent store is lazy, routes gated, `/readyz` probe registered, memory only by name; R-02 fixed the retry leak.
- S-04: confirmed for the break-glass API and override; login path open as R-04.
- S-05: confirmed, with gaps: R-01 (fixed) and R-05 (open).
- S-07: confirmed (see revocation_scope above); CMP gap is R-08.
- S-08: confirmed. Prune at most once per window or at the cap; map bounded at 50 000 (R-06).
- S-09: confirmed. One policy read per request.
- S-10: confirmed. Access review is lazy, gated, readiness-probed.
- S-11 (now FIXED, 30fe51a2): addressed by H-F3 (3 s `PingContext`, ping outside `pgPoolsMu`).

Code-health doc:
- H-F1: confirmed as a recorded exception (still package-level, comment states why), not removed.
- H-F2: confirmed. `CloseSharedPostgresPools` deferred first in `main`.
- H-F3: confirmed. Ping and open outside the lock, both bounded at 3 s.
- H-F4: now FIXED (9a0102be), the doc said OPEN; fixed by 9a0102be (`ServerConfig.policyEngine`, global removed, read lazily per plan).
- H-F5, H-F16: confirmed (same changes as S-09, S-08).
- H-F6: confirmed (in-transaction retire; failure test).
- H-F7: confirmed. `plan` cognitive 9; the split `classifyNameMatch` carried R-01, now fixed.
- H-F8: confirmed. `serveRST` 13/17, behaviour unchanged. H-F9: confirmed, comments back on their declarations.
- H-F10, H-F13: confirmed (`revertTransitionDetail` uses encoding/json; `logging.Warnf` on template error, still fail-closed).
- H-F11: confirmed. Explicit parameter; `nil` callers handled by `newApprovalRoleScope`.
- H-F12: confirmed (staticcheck no longer reports SA4000).
- H-F14: the two tables disagree (findings FIXED, F3 table OPEN); code: fixed. `ca.IsRSAAlgorithm` is used by migration and codesign_policy; `rsaAlgorithmBits` stays as the size parser.
- H-F17: confirmed. H-F18: confirmed (`rebindPostgres`).
- H-F21: confirmed. H-F22: confirmed (`.gitignore` 89-91, only `last-run.json` tracked).
- Fixed after the rescan: H-F15 (f4ecc48c), H-F19 (ce7160e6), H-F20 (d5439e6f). Still open: H-F23..H-F25.

### Left open

S-01 / D-290-C, S-06, H-F23..H-F25 (R-04 accepted; R-05, R-08, H-F15, H-F19, H-F20 fixed after the rescan), and the prior follow-ups listed above.

## Rescan round 3 2026-10-18

Scope: `git diff 2e11b9e2..HEAD -- '*.go' 'ui/src' 'internal/db/migrations' 'cmd' 'Makefile' 'charts' 'Dockerfile*'`
(34 files at 1bcc9968: R-05, R-08, R-04 logging, H-F15/H-F19/H-F20, D-291, WinRM argument fixes eb056a6e/82cdcb5b,
Windows agent LocalMachine stores and default scan paths, Makefile ldflags), plus `internal/agentinstall/iis.go`
because it builds the WinRM arguments. Not in this range (landed before 2e11b9e2, covered by the earlier rounds):
the readiness drain and lease release hook (723d5a13; the env is `KRYPTKEEPER_READINESS_DRAIN_SECONDS`, matching
`charts/kryptkeeper/templates/configmap.yaml`), the chart `terminationGracePeriodSeconds` guard (bf4b4a15), and the
XCEP `AcceptedRSABits` / `algorithmAllowed` change (eb765c4d, 071783e8). `charts/` and `Dockerfile*` have no
changes in the range.

### New findings

| ID | Sev | File:line | Finding | Status |
|---|---|---|---|---|
| R-09 | LOW | internal/agentdiscovery/agentless_winrm.go `cmdQuote` / `RunExit`; internal/agentinstall/iis.go `showBinding` | `cmdQuote` escapes an embedded `"` as `\"`, which is an escape for the launched program's argv parser but closes the quote for cmd.exe, so the rest of the value is parsed bare and an `&` in it starts a second command. Before 82cdcb5b a quote travelled as `&#34;` and never reached cmd as a quote; now it does. No operator-supplied argument can carry one (`validateIISRequestFields` pins ipport/appid/store), but two IIS paths reuse values read back from the host's `netsh http show sslcert` output: the inherited appid (when the request has none) and the rollback restore (`certhash=`, `appid=`, `certstorename=`). HTTP.sys stores the store name as a free string. Precondition: the attacker already changed the target's HTTP.sys SSL configuration, i.e. is already admin there; the command runs on that same host as the hub's WinRM account, so there is no privilege gain. | FIXED 1dff907e: `RunExit` refuses an argument containing `"`, CR, LF or NUL before a shell is created (no caller needs them: scripts travel as `-EncodedCommand`); 25da43f8: `showBinding` pins the read-back hash (hex), appid (GUID) and store (alphanumeric, the same bar as the request) and refuses before anything on the host changes. Known limit: a LocalMachine store with a space (e.g. `Remote Desktop`) is refused, as it already was on the request side (tests in both packages) |
| R-10 | INFO | internal/agentdiscovery/windows_defaults.go:12; agentless_winrm.go `cmdQuote` | Comment said `windows.go` asserts the store-flag constants at compile time; it is a Windows-only test (`windows_flags_windows_test.go`). Flags checked against windows.h: LOCAL_MACHINE 0x20000, READONLY 0x8000, OPEN_EXISTING 0x4000. `cmdQuote`'s comment claimed `\"` is what cmd.exe expects (the R-09 error). | FIXED 75830f56; 3317c001 (`cmdQuote` comment) |
| R-11 | INFO | internal/bootstrap/template_enroll_upgrade_test.go | D-291 upgrade had no test for "store present but unreadable leaves no marker" (the retry-next-start branch). | FIXED ef44dc69: `TestUpgradeWindowsEnrollListsUnreadableStoreNotMarked`. Save-failure branch remains untested (returns before the marker; read by hand) |

### WinRM argument trace (every production `RunExit` / `Run` caller)

| Caller | Arguments | Source |
|---|---|---|
| `AgentlessWinRMScanner` (agentless_winrm.go:460) | `powershell -NonInteractive -EncodedCommand <base64>` | `certEnumScript` constant |
| `WinRMPreflight` (winrm_preflight.go:49) | `whoami /groups /fo csv` | constants |
| `WinRMExecutor.powershell` (Exists/ReadFile/WriteFile) | `powershell ... -Command <script>`, re-encoded by `encodeInlinePowerShell` to `-EncodedCommand <base64>` | paths via `psQuote` inside the encoded script |
| `IISInstaller` (iis.go) | `netsh http show/add/delete sslcert ipport= certhash= appid= certstorename=`; `certutil -f -p <pw> -importpfx <store> <pfx>`; `cmd /C mkdir/rmdir <stage>`; `icacls <stage> ... *S-1-5-18:(OI)(CI)F`; `iisreset /noforce` | request fields validated; thumbprint computed hex; password/stage token `crypto/rand` hex; stage root constant `C:\ProgramData\Kryptkeeper\iis-stage`; read-back binding values now validated (R-09) |
| Plugin `remote_exec` (plugins/delivery/host.go:341) | plugin argv | not reachable: `renewal_plugin.go` never sets `delivery.Env.Executor`, so the call returns "no remote executor" |

No hub-built argument carries `%` (cmd.exe expands `%VAR%` even inside quotes) or `!`. Dropping `= , ;` from the
quote triggers is safe: they only delimit arguments for cmd builtins, never chain commands. `argTextEscape` leaves
`"` literal and still escapes `& < >`; with CR/LF/NUL refused, no XML-invalid control character other than tab can
reach it from these callers.

### Re-run tools

| Tool | Result |
|---|---|
| go vet ./... ; GOOS=windows go vet agentdiscovery, kryptkeeper-agent; GOOS=windows test build agentdiscovery | clean |
| staticcheck (10 touched pkgs incl. agentinstall) | 17 hits, all pre-existing (16 SA1019 deprecations, SA1012 approval_channel_test.go:55); **0 on added lines**; H-F19 SA4023 and H-F20 ST1005 gone |
| gosec v2 @latest (same 10 pkgs) | 248 issues in those trees, **0 on lines added since 2e11b9e2** |
| opengrep 1.27.1, bpm-rulepacks owasp+secrets+framework, 36 changed files + iis.go | 4 hits, all accepted/FP: weak-hash main.go:1542 (OCSP CertID SHA-1, ACCEPTED), iis.go:581 + iis_test.go:264 (Windows thumbprint lookup key), hardcoded-secret revoke_poll_test.go:205 (the literal "wrong" MAC secret of a negative test, pre-existing line). 0 parse errors |
| govulncheck v1.9.0, GOTOOLCHAIN=go1.26.9 | 0 called vulnerabilities (1 required-module advisory not reached, as before) |
| gitleaks, 2e11b9e2..HEAD (29 commits) | no leaks |
| go test -race | migration (6 pkgs), wstep, xcep, cmp, agentdiscovery, agentinstall, keystore, `cmd/kryptkeeper -run Cmp`, `bootstrap -run 'Enroll|BreakGlass'`: ok, 0 races |
| go build -tags pkcs11 ./internal/keystore/ | ok (`ErrPKCS11NotCompiled` is stub-only and unreferenced) |
| gocyclo -over 25 / gocognit -over 40 (internal, cmd) | 99 / 97 (unchanged). Touched: `RunExit` 18/27, `Rollback` 17/37, `UpgradeWindowsEnrollLists` 17/20, `SaveBatch` 12/21, `showBinding` 10/10, `EnrollPermitted` 7/11, `MarkItemRestored` 5/5, `winrmArgumentsXML` 3/3 |
| make lint | 0 issues |
| ui lint / vitest | 0 errors (1 pre-existing warning) / 989 tests, 112 files pass |
| go test ./... -count=1 (at ef44dc69) | 85 packages ok, 0 failures |

### Regression checks (no defect)

- **R-05 / 000326:** version unique on both drivers, up/down pairs, FK to the `migration_batch_items` PK; `schemaDDL`
  matches. `MarkItemRestored` reactivates only the item the supersede itself retired (`disabled_at` equal to the
  rolling-back batch's `created_at`) and only while that item's batch is `applied`; a chain A <- B <- C rolls back
  one link at a time. Restore then mark is not one transaction (a mark failure after a restore leaves the item
  active and the template restored; rerunning the rollback repeats an idempotent restore). Tests run on SQLite;
  `ORDER BY (disabled_at = '') DESC` is a boolean sort on Postgres too.
- **R-08:** `cmp.Revoker` returns the scope; the `cmp.rr` audit detail carries `revocation_scope`; error paths unchanged
  (one answer for unknown and not-revocable).
- **D-291:** `EnrollPermitted` is open only for an empty list; the upgrade touches only the file provider (the only
  provider), widens only autoenrolled role-only lists without `pki-admin`, does not bump revisions, writes the marker
  after a successful save, and leaves no marker for an unreadable store. A missing store gets the marker (no default
  templates are seeded, so nothing is missed).
- **S-01:** FIXED by D-291 (b972f9de, bf57790e, dabccd28); `EnrollPermitted` confirmed above. It no longer belongs
  in the round-2 "Left open" list.
- **Break-glass login:** log text only; R-04 acceptance unchanged.
- **Windows agent:** `CertOpenStore(CERT_STORE_PROV_SYSTEM, ..., LOCAL_MACHINE|READONLY|OPEN_EXISTING)` cannot
  create or modify a store; store closed per iteration; only `RawData`-equivalent DER is read, no key access.
  Default scan paths are directories the walker skips when missing.
- **Makefile ldflags:** `main.version`, `main.commit`, `main.date` exist in both `cmd/kryptkeeper` and
  `cmd/kryptkeeper-agent`, so no `-X` is a silent no-op.

### Verdict

**CLEAN** (no open MEDIUM+). Open below MEDIUM: S-06 (LOW, ACCEPTED), R-04 (LOW, ACCEPTED), R-06/R-07 (INFO,
ACCEPTED), H-F23..H-F25 (code health, LOW, deferred). H-F1 (code health, MEDIUM) stands as a recorded exception
(package-level pool cache, comment states why), not an open defect.
