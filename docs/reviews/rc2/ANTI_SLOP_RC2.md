# Anti-Slop Re-Audit: Kryptkeeper v0.9.0-rc.2 (6200a0d)

Date 2026-10-10. Read-only audit, branch `kk/rc2-antislop`, rules R-01..R-31.
Delta reviewed: `git diff d74edf3 6200a0d -- '*.go' 'ui/src/**'` (114 files,
+4901/-641) plus the six release docs named by the owner gate.

## Verdict

**FAIL (documentation only: 4 blocking items, each an XS wording or number fix).**
No CRITICAL, HIGH or MEDIUM code slop in the RC1-to-RC2 delta. Once B1..B4 are
corrected the verdict is PASS.

Counts: 0 CRITICAL, 0 HIGH, 4 blocking doc defects (B1..B4), 1 MEDIUM
non-blocking (RC2-05), 6 LOW/INFO new plus the carried RC1 LOWs.

Doc-claim sample: 45 concrete claims checked, 41 hold, 4 false or contradicted
(B1..B4), plus 1 recommendation that cannot be verified from the repo (RC2-05).

Tooling that ran on the RC2 tree: `deadcode -test ./...` 40 lines (RC1: 39),
`deadcode ./...` 150 (RC1: 149), `staticcheck ./...` 75 lines (RC1: 75; 33 SA1019,
1 SA4023), `gofmt -l cmd internal` clean (RC1: 4 files), TODO/FIXME grep clean,
`helm lint` and `helm template` pass on both charts. `go.mod`, `go.sum`,
`ui/package.json` and `ui/package-lock.json` are unchanged since RC1, so there is
no new dependency (R-21 clean). Go and UI test suites were not re-run (other RC2
reviewers own the gate).

## 1. RC1 findings: status

| ID | RC1 sev | Status | Evidence at 6200a0d |
|---|---|---|---|
| AS-01 placeholder keystore passphrase | MEDIUM | FIXED | `auth_validation.go:25-35` `RejectPlaceholderSecret` (case-insensitive `change-me` prefix, value never echoed). Called for the keystore passphrase at `main.go:159`, and for the bootstrap token and signing secrets at `auth_validation.go:106,111`. `env.example:14,111` still ships `change-me-generate-...`, which now fails start. Test `TestValidationReportRejectsPlaceholderSecrets`. |
| AS-02 RS256 verifier, thin negative tests | MEDIUM | FIXED (2 residuals) | `auth_jwks_table_test.go` covers alg none, HS256 keyed with the DER public key and with the modulus bytes, and more. `auth_jwks.go:19,145` adds `minJWKSRSAKeyBits = 2048`. Residuals: the JWK RSA decode still exists twice (`acme/jws.go`, `auth_jwks.go`, now the same floor); RS256-only is not named in any release doc (0 hits for ES256/PS256). |
| AS-03 agentless SSH discovery claim | MEDIUM, blocking | FIXED in wording; new count drift (B4) | README:15,446,452; RELEASE_NOTES:30; FEATURE_VALIDATION:75-76 (one row split into "Agentless SSH install LIVE" and "Agentless SSH certificate discovery NOT-WIRED"); CHANGELOG Fixed entry. `AgentlessSSHScanner` is still unreachable in `deadcode`, and the docs now say so. |
| AS-04 phantom imports `_ =` | LOW | STILL PRESENT | `internal/keystore/vault.go:467-473`, unchanged. |
| AS-05 test-only error var in production | LOW | STILL PRESENT | `certs_summary_db_provider.go:31`; only caller is `certs_summary_store_test.go:39`. |
| AS-06 vacuous test | LOW | STILL PRESENT | `cloudinventory/aws_acm_test.go:15-18` `_ = ACMConnector{}`. |
| AS-07 unwired features | LOW | STILL PRESENT, SSH one now disclosed | Same `deadcode` entries: ctmonitor `List`/`Acknowledge`, `agentdiscovery/keystores.go`, `configparser.go:78`, `agentless_ssh.go`, `sshkeys/inventory.go`, `NewThresholdEvaluator`, `RegisterEnrollmentService`, `newFindingExceptionID`. Only the SSH discovery row is labelled NOT-WIRED; the JKS/PKCS12/kubeconfig parsers and SSH key inventory stay UNIT-ONLY (true, not the whole story). |
| AS-08 gofmt, `.bak`, eslint-disable | LOW | PARTLY FIXED | `gofmt -l` clean (8e549ec6). `ui/src/index.css.bak` is still tracked. The four `exhaustive-deps` suppressions were not re-counted. |
| AS-09 deprecated ECDSA raw coords | LOW | STILL PRESENT | `acme/jws.go:214-215`; 33 SA1019 lines; `main.go:136` SA4023 (PKCS#11 default stub). |
| AS-10 hand-rolled TTL maps | INFO | UNCHANGED | The rate limiter now evicts and caps (RC1 M5); the others are a v0.10 item. |
| AS-11 LDR | INFO | OK | Section 2. |

The prior fixes (SIEM, renewal connector registry, `publicKeyBits`) remain fixed:
`main.go:253-258` wires `ResolveAuditProvider` and `WithSIEMForwarding`.

## 2. RC1-to-RC2 code delta, R-01..R-31

| Rule group | Result |
|---|---|
| R-01..R-04 error handling | PASS. The audit file open/migrate/scan path returns wrapped errors and the hub exits on them. An unparseable failure timestamp backs off from now instead of resetting. `memoizedIsSilenced` never caches an error. The new `_ =` are `Close()` on cleanup paths only. |
| R-05..R-08 abstraction | PASS. `certificateIterator` is an optional interface with real implementers (`caCertificateProvider`, `fileCertificateProvider`) plus a paging fallback; not single-impl slop. |
| R-09..R-11 defensive bloat | PASS. `stampVerifier == nil` skips the re-check (comment: tests); production wires it. Ratelimit "drop one key at the cap" is a commented trade-off (RC2-08). |
| R-12..R-16 comments | 1 LOW (RC2-09). Other new comments state threats and ordering (`egress_stamp.go`, `request_body.go`, `clientip.go`). |
| R-17..R-20 structure | PASS. `certificate_index.go` (309 lines) has one concern. `renewal_scheduler.go` grew +143 lines (stamp, tenant check, threshold cap, silence memo), each cohesive. |
| R-21 slopsquatting | PASS. Zero Go or npm dependency changes. |
| R-22 privilege escalation | PASS, improved. `targetEgressChanges` and `authorizeTargetEgress` require `certificate.renew` (pki-admin for `credential_ref`); the request-body install override is pki-admin only; `principal_reserved.go` blocks reserved principals. |
| R-23 credential leakage | PASS. The placeholder check never echoes the value; tests generate keys in-test. |
| R-24 docstring inflation | PASS. LDR below. |
| R-25 phantom imports | AS-04 only (carried). No new suppressions. |
| R-26 disconnected pipelines | PASS for all new code (wiring table). |
| R-27 stubs returning success | PASS. The "not implemented" strings in `byok_targets.go:108,110` return errors that say why. |
| R-28 LLM output unvalidated | N/A, not in the delta. |
| R-29 prose padding | PASS. Release notes are specific and candid. |
| R-30 vendoring | PASS. No vendored dirs; no new library-shaped code. |
| R-31 confabulated claims | FAIL on B1..B4 (section 3). |

### Wiring of new pipelines (R-26)

| New code | Production caller | Verdict |
|---|---|---|
| `Authenticator.StampVerifier`, `RenewalScheduler.WithStampVerifier` | `main.go:322`; used in `renewal_scheduler.go` `stampStillValid`, which audits `certificate.renew_execute_denied` | wired |
| `ResolveAuditProvider` | `main.go:253`, wrapped by `WithSIEMForwarding` at `:258` | wired |
| `ForEachCertificate` (CA provider `certificate_index.go:269`, file provider `:65`) | `certificate_iter.go:25` type-asserts it. Production `certificateProvider` is `WithTemplateProvider(NewCACertificateProvider(...))`, which returns the same `*caCertificateProvider`, so no decorator hides the iterator. 9 callers incl. `main.go:351`, `anomaly_wiring.go:96`, `slo_wiring.go:110`, `handlers_certificates.go:859` | wired |
| `attachmentDisposition` | `handlers_certificates.go:759`, `handlers_key_custody_ops.go:129` | wired |
| `rejectOversizeBody`, `capBody` | certificates, credentials, templates, keys, BYOK, plugins, SCEP challenges, estate, code-signing; `oversize_413_test.go` (10 routes) and `handlers_oversize_body_test.go` (9 routes) assert 413 and keep 400 for malformed | wired |
| silence memo, ratelimit eviction, clientip memo, login KDF slots, keystore cached-signer `Metadata` | hot paths | wired |
| Migrations 000070..000073 | sqlite and postgres up/down pairs all present; `migrate_renewal_status_*_test.go` plus a live-Postgres up/down/up test | OK |
| UI (`api-types.ts` regenerated, `Certificates.tsx` +15 lines) | small | OK |

### Tests on security paths (delta)

Meaningful: `handlers_targets_egress_test.go` (206 lines),
`separation_of_duties_entrypoints_test.go` (172), `renewal_threshold_bounds_test.go`,
`siem_actions_test.go`, `ratelimit_evict_test.go` (idle eviction, live key stays
limited, map capped), `software_metadata_cache_test.go` (a wrong passphrase makes any
re-decrypt fail, so success proves the cache was used), `clientip_cache_test.go`,
`auth_jwks_table_test.go`. One gap: nothing pins "token stamps are accepted as stamped"
(B3). No new vacuous test (AS-06 is the only one).

### LDR (python heuristic; comment, blank, import and brace lines count as overhead)

| File | Logic | Overhead | LDR |
|---|---|---|---|
| `egress_stamp.go` | 67 | 57 | 0.54 |
| `certificate_index.go` | 170 | 140 | 0.55 |
| `certificate_iter.go` | 31 | 42 | 0.42 |
| `audit_file_provider.go` | 212 | 146 | 0.59 |
| `handlers_targets_egress.go` | 64 | 70 | 0.48 |
| `ratelimit.go` | 56 | 60 | 0.48 |

All above 0.3.

## 3. Doc-claim verification

### Blocking: false or contradicted

**B1 [blocking] The smoke suite count differs between release docs.**
README:433, RELEASE_NOTES (What's validated) and FEATURE_VALIDATION:25 say
**331/331**. CHANGELOG Fixed ("Smoke OIDC section was silently skipped") says the
suite "now runs **332** assertions". `docs/STATUS.md` (FG-5, 2026-10-09) records 332;
331 appears only in FEATURE_VALIDATION's "supplied by coordinator" table. They cannot
both describe the same tree. Fix: run `tests/smoke/run.sh` once on the release commit
and use that number everywhere, or write "332 at the time of the fix" in the CHANGELOG.
Effort XS.

**B2 [blocking] Autopilot 29/29 and Agent 18/18 are presented as 2026-10-09 results;
FEATURE_VALIDATION says the opposite.**
RELEASE_NOTES opens "Results from 2026-10-09 against real clients" and lists both.
FEATURE_VALIDATION:32 says agent "17-18/18 ... (dated, not re-run today)", and its
2026-10-09 table has no autopilot or agent row. The repo records no autopilot run
anywhere (`grep -i autopilot docs/STATUS.md` is empty; `tests/live/autopilot/` has no
README). The last recorded agent 18/18 is 2026-10-08 (`STATUS.md:417`). The harnesses were
edited during RC1 fixes (13b56eaa, c8eb1ded), so a later run is plausible, but nothing in
the tree evidences it. 29 also equals the count of `PASS "` call sites in the autopilot
script, which RC1 noted is a site count, not a run. Fix: attach the run log under `docs/`
and date the rows, or drop the two rows. Effort XS.

**B3 [blocking, security-relevant overstatement] Upgrade note 45 says a stamped principal
who is deleted, deactivated or loses `certificate.renew` stops the push. That is false for
externally issued bearer tokens.**
`egress_stamp.go:35,44-54`: any AuthType other than bootstrap, api-key or local becomes a
`token:` stamp, and `verifyEgressStamp` returns nil for it ("accepted as stamped", per the
code comment). A token principal who armed a target keeps pushing after losing
`certificate.renew`. jwt/oidc bearers are viewer-only until a role claim is mapped, so the
exposure is narrow, but the release note promises more than the code does and no test pins
the exception. Fix (docs): add "except externally issued jwt/oidc bearer tokens, which the
hub cannot re-check; arm targets with an API key or a login session". Effort XS. A test
documenting the exception would be a good companion.

**B4 [blocking] FEATURE_VALIDATION counts are stale after the AS-03 row split.**
Section 3 now has **77** rows and **4** HIDDEN/NOT-WIRED/EXPERIMENTAL rows (SSH discovery,
issuer connectors, finding exceptions, tenancy; counted by script). Section 4 still says
total **76** and **3**, and RELEASE_NOTES says "all 76 inventoried features". Cause: the
single "Agentless SSH discovery/install" row became two in c4ccc715 and section 4 was not
updated. Fix: 77 and 4, and "77" in RELEASE_NOTES. Effort XS.

### Non-blocking doc issues

**RC2-05 [MEDIUM] Memory-sizing guidance rests on pre-fix measurements.**
`docs/deployment.md:131-134` and upgrade note 51 recommend 512Mi/2Gi and
`GOMEMLIMIT=1600MiB`, citing "1-1.5 GB under list / issue / dashboard load" from
`03-measurements.md` (1,511 MB, pre-fix tree). The only post-fix RSS figure in the repo,
`AFTER_FIX.md` Caveats, says an 8-way issue burst at 50k "peaked near 3 GB". Commit
155acbac (cached signer, about 67 MB to 28 KB per issue) removes most of that garbage and
landed after AFTER_FIX was written, but no run on the RC2 tree exists. The quoted numbers
are true of the doc they cite; the 2Gi recommendation is untested for the load shape that
produced 3 GB. Fix: one 10-minute re-measure (50k inventory, c=8 issue burst, read RSS) and
record it, or soften the wording to "starting point". Not a false claim, so not blocking.

**RC2-06 [LOW] "67 MB to 28 KB" has no measurement document.**
The CHANGELOG figure matches commit 155acbac's message ("IssueCertificate bench: 67.2 MB/op,
17.9 ms -> 28 KB/op, 0.14 ms"), but `AFTER_FIX.md` still says each issuance allocates "about
65 MB ... in both trees", now superseded. Fix: add the bench line and correct that caveat. XS.

**RC2-07 [LOW] FEATURE_VALIDATION sections 5 and 6 read as current but are as of 3a0b4fb.**
Section 6 lists "README claims that do not match the code" (APP_JWT_SECRET, APP_AUTH_MODE,
Helm flags, "Go 1.25+", container-logs token). I grepped README at RC2: all fixed (0 hits;
the Helm example uses `secrets.*` and `ingress.hosts[0]`). Section 5 gap 1 ("Helm chart never
linted/templated") is also out of date: `helm lint` and `helm template` pass here and the
README says so. The header carries the snapshot date, so this is dated, not false, but a
reader cannot tell which gaps remain. Fix: a banner or RESOLVED/OPEN tags. XS.

### Verified claims (41 holding)

| # | Claim (source) | Evidence |
|---|---|---|
| 1 | List page "29 ms to 0.3 ms" at 50k (CHANGELOG) | `AFTER_FIX.md`: 28.8 to 0.34 ms, c=1 p50 |
| 2 | Compliance evidence "14 s to 40 ms" | 14,006 to 39.6 ms |
| 3 | HTTP list keeps its 100-row cap | `AFTER_FIX.md` "What changed" |
| 4 | "25 for CA compromise" | `01-findings-high.md:41` (by inspection, not run); now iterates |
| 5 | "about 99.8 percent" of audit trail wiped by 4 clients | `01-findings-high.md:16` |
| 6 | Keystore KDF is 64 MiB Argon2id | commit 155acbac, test comment |
| 7 | Login KDF bounded, waiting login gives up on request end | `auth_login_state.go` `withKDFSlot(ctx, ...)`, 4 slots capped to GOMAXPROCS |
| 8 | Rate limiter evicts idle keys and caps its table | `ratelimit.go` `maxKeys = 100_000`, 3 tests |
| 9 | Migration `000073` widens the status constraint | `000073_...up.sql:43` CHECK has `reissue_required` |
| 10 | Migration names 000070..000073 (note 44) | files match, both engines |
| 11 | `renewal_status` gains `reissue_required`; four previous values (note 53) | same CHECK: active, renewed, expired, revoked |
| 12 | Unknown expiry counted: `expiry_buckets.unknown`, `expiry_unknown`, `unknown_expiry` | `handlers_reports.go:84,514,725` |
| 13 | 413 on certificates, credentials, templates; templates 256 KiB; `/targets` still 400 | `maxTemplateBodyBytes = 256 << 10`; `handlers_targets.go:97,313` use a 16 KiB `MaxBytesReader` and the generic 400 |
| 14 | SIEM forwards every action; `KRYPTKEEPER_SIEM_ACTIONS` exact or `prefix.*`; payload has no change summary, user agent or session | `siem_integration.go:502-600`, `env.example:390` |
| 15 | Audit appends detached with a 5 s bound | `audit_events.go:21` |
| 16 | DB audit by default when a core DB exists; log `audit provider: db (default)` | `audit_provider.go:85-112`, `main.go:253-256` |
| 17 | File store is JSON Lines; legacy array converted; original kept as `<file>.bak`; unparseable legacy file stops start | `audit_file_provider.go:94-135` (also `.<ns>.bak` if a `.bak` exists; undocumented, harmless) |
| 18 | `APP_AUDIT_DB_DSN` overrides; DB follows core DSN and driver | `audit_db_provider.go:223-235` |
| 19 | `audit_log` has append-only triggers | `000004_audit_log_append_only.up.sql:28,35` |
| 20 | Key size real; Ed25519 = 256; zero rows recomputed on load | `ca/key_strength.go:59-60`, `certificate_ca_provider.go:~262` |
| 21 | Hub exits when `KRYPTKEEPER_KEYSTORE_DIR` cannot be created | `main.go:121` |
| 22 | Placeholder `change-me` secrets refused at startup | AS-01 |
| 23 | Note 46: egress arming needs `certificate.renew`, `credential_ref` needs pki-admin, refs must exist, host/profile changes on armed targets | `handlers_targets_egress.go:26-93`; the field list matches the note |
| 24 | Note 47: install override pki-admin only (403), stored profile used | `handlers_renewal_execute.go:28,125-129` |
| 25 | Note 48: `verify_host_port` not loopback/link-local; hub dial refuses; private allowed; agent verifies over loopback | `managed_target_store.go:233-246`, `agentinstall/verify.go:36-50`, `HubVerifier` at `renewal_executor.go:124`, `renewal_plugin.go:176` |
| 26 | Note 49: threshold 1-365, 0 = default; successor capped at half its lifetime | `managed_target_store.go:195,200`, `effectiveThresholdDays` |
| 27 | Note 45: unstamped rows go notify-only, log "NOT pushing ... notify-only", PATCH re-arms, audit `certificate.renew_execute_denied` | `renewal_scheduler.go` (except token class, B3) |
| 28 | Note 51 Helm: requests 512Mi, limit 2Gi, `config.goMemLimit` `1600MiB` | `values.yaml:52-59,106`; `helm template` renders both |
| 29 | Note 51 Compose: `mem_limit: 2g`, `GOMEMLIMIT=1600MiB` | `docker-compose.yml:101-102` |
| 30 | Note 52 Compose: pinned network, only the dashboard address trusted | `docker-compose.yml:97,157-161,181-187`; `nginx.conf:24` appends XFF |
| 31 | Note 52 Helm: `trustedProxyCIDRs` empty, warns when ingress is used | `values.yaml:116`; `helm install --dry-run --set ingress.enabled=true` prints the warning |
| 32 | Compose needs a keystore passphrase different from the token | `docker-compose.yml:33` guard; Terraform enforces inequality (`user_data.sh.tpl:114`); the hub itself does not compare them (INFO) |
| 33 | Key dual control on by default, `=false` opts out | `key_dual_control.go:95-105` |
| 34 | Secrets under 32 bytes are startup errors | `minHS256SecretBytes = 32` (unchanged since RC1) |
| 35 | standard-environment defaults: 30 days, 24 h, 24 h; `AGENT_RENEWAL_SWEEP_MINUTES` 15; `RENEWAL_POLL_MINUTES` | `renewal_scheduler.go:149-188`, `renewal_agent_driver.go:76-93`, `config_store.go:69-71` |
| 36 | Hub renewals are issued for 90 days | `certificate_ca_provider.go:306,519` |
| 37 | 5 attempts, backoff capped at 1 h, `pending_installs`, `gave_up_installs` | `renewal_scheduler.go:39-40,731,779` |
| 38 | SSH host key pinned; `host` matches CN or SAN | `executor_ssh.go:43-50`; `renewal_scheduler.go:152,587` |
| 39 | README Helm example flags exist; chart bundles no PostgreSQL | `values.yaml:41,96,129-131`; `helm lint` passes |
| 40 | README: Go 1.26+, Node 24, `AUTH_MODE`, `APP_JWT_HS256_SECRET` | `go.mod`, `ui/.nvmrc` |
| 41 | SCEP one-time challenges (migration 000066) | `scep/challenges.go:64,127` |

## 4. Other new findings

**RC2-08 [LOW/INFO] The rate limiter drops one arbitrary live key at the cap.**
`ratelimit.go` `makeRoomLocked`: with 100k live keys resident, deleting one resets that
client's count. Whoever can mint 100k keys already owns 100k buckets, and the comment states
the bounded-memory intent. The "103 B/key measured" figure in that comment has no artifact in
the repo. No action for RC.

**RC2-09 [LOW] Stale package comment after the SIEM widening.**
`siem_integration.go:12-13` lists seven "Supported event types", including
`cert.expiry_warning`, which is not in `siemKnownActions`; `mapAuditActionToSIEM` now forwards
every action. R-15. Fix: point the comment at `siemKnownActions`. XS.

**RC2-10 [INFO] SSO sessions and the stamp re-check.** `local` AuthType stamps are resolved
against the user store. I did not trace whether every SSO login user exists there; if not,
their armed targets go notify-only each tick (fail closed, audited). One test in v0.10.

**RC2-11 [INFO] RS256-only** (AS-02 residual) is not named in the release docs. An ES256 or
PS256 IdP fails closed with "unsupported jwt alg".

## 5. Disposition

Blocking before tag: **B1, B2, B3, B4** (documentation, XS). Recommended before tag: RC2-05
(re-measure RSS or soften), RC2-06, RC2-07. Carry to v0.10: AS-04..AS-09, RC2-08..RC2-11.

Not done: test suites were not re-run, no live harness ran, no memory measurement, no Go
proxy or npm query. B1 and B2 resolve by running the smoke, autopilot and agent harnesses
once and recording the output.
