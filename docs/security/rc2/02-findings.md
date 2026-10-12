# RC2 findings (`6200a0d` vs RC1 `d74edf3`)

Status: FIXED (code + test cited), OPEN (unchanged, severity as RC1), ACCEPTED (where documented). Confidence in
brackets for new items. Paths are under `internal/bootstrap/` unless stated. "Live" refers to `03-live-probes.md`.

## 1. RC1 finding status

### HIGH / MEDIUM
| ID | Sev | Status | Evidence |
|---|---|---|---|
| A-01 discovery role arms key egress | HIGH | **FIXED** | `handlers_targets_egress.go` `authorizeTargetEgress`: arming `auto_renew`, naming a credential or plugin, or changing host/install/verify fields on an armed target needs `certificate.renew`; a new credential needs pki-admin. `validateTargetReferences` rejects unknown credential/plugin (cross-tenant too). Stamp `AutoRenewSetBy` (`egress_stamp.go`), required by `autoRenewSkipReason` (`renewal_scheduler.go:663`), re-checked every sweep by `StampVerifier` (wired `cmd/kryptkeeper/main.go:322`); tenant check `targetMayReceiveCert`. Migration 000072 deliberately does not backfill, so pre-RC2 armed targets go notify-only. Tests `TestDiscoveryOperatorCannotArmKeyEgress`, `TestArmingStampsTheAuthorizedPrincipalAndPinsTheBinding`, `TestTargetReferencesMustExist`, `TestSchedulerSkipsAutoRenewTargetWithoutAuthorizedStamp`, `TestRenewalSweepSkipsWhenStampedPrincipalLostAuthority`. **Live: all 6 arming routes 403 for discovery-operator; nonexistent credential 400 even for admin; path tricks 403; denials audited.** |
| A-02 unbounded threshold | MED | **FIXED** | `validateRenewalThresholdDays` 1..365 (live: 3650 -> 400) and `effectiveThresholdDays` caps successors at half their lifetime (`renewal_scheduler.go:605`). `renewal_threshold_bounds_test.go`. |
| A-03 install profile from body | MED | **FIXED** | `installProfileForCaller` (`handlers_renewal_execute.go:48`): stored profile unless pki-admin; same rule on `/renewal/rollout` (`handlers_rollout.go`). `TestRenewalExecuteInstallOverrideNeedsAdmin`, `TestInstallProfileForCaller`. Not exercised live (see 03). |
| A-04 verify dial unguarded | MED | **FIXED** | `agentinstall/verify.go` `HubVerifier` = egress policy (loopback/link-local refused on the dialed address), generic errors. All hub-side pushers get it via `WithVerifier(e.verifier)` (`renewal_executor.go:336,354,759,768,794,826`, default `:124`); `defaultVerifier` (loopback ok) is only the agent-host default. Config-time literal check `verifyHostForbidden`; hostnames are caught at dial time (live: `*.nip.io` accepted at create by design). `TestHubVerifierRefusesLoopbackAndMetadata`, `TestValidateVerifyHostPort`. |
| B-01 bootstrap-minted key approves | MED | **FIXED** | `separation_of_duties.go`: `canonicalHuman` = `bootstrap` for the token and every key minted with it; `mayDecide`/`approverRefusal` refuse it; also applied to certificate approvals (`handlers_approvals.go`). `separation_of_duties_entrypoints_test.go`. **Live: 403 for token and for bootstrap-minted pki-admin key.** |
| B-02 grant bound to free-text id | MED | **FIXED** | `key_dual_control.go` `grantBoundTo` binds proposer human + auth type + kid (unbound grants unredeemable); `principalIDReserved` refuses key `principal_id` equal to a user/built-in. `grant_binding_test.go`. **Live: third admin, bootstrap key, approver and proposer's own minted key all 403 on redemption; proposer session 200; replay 403; `principal_id=probe-admin`/`bootstrap` 400** (email form: N-02). |
| B-03 SPIFFE body | MED | **FIXED** | `spiffe_workload.go:298` `decodeJSONBodyOrReject(... maxAuthBodyBytes)`; `TestWorkloadSVIDRejectsOversizedBody` (413). Not live (SPIFFE unconfigured, 503). Other routes: see B-03 residual below. |
| C-01 CN bypasses DNS policy | MED | **FIXED** | `ca/name_policy.go:142-165`: a CN not among the SANs must satisfy the DNS restriction. `name_policy_test.go:131-133` (default flags). Not live. Limitation: a policy that only restricts IP/URI SANs does not constrain the CN (INFO). |
| M-1 shared limiter bucket | MED | **FIXED / DOCUMENTED** | `docker-compose.yml`: nginx pinned to `172.29.231.10`, `APP_TRUSTED_PROXY_CIDRS=172.29.231.10/32` (not the subnet, so the host gateway cannot pick its bucket); `nginx.conf:24` appends via `$proxy_add_x_forwarded_for`, and the hub's right-to-left walk ignores forged left entries. Helm: `config.trustedProxyCIDRs` with `values.yaml` comment and `NOTES.txt` warning (default empty = trust nobody; chart cannot know the ingress CIDR). Live: 10 bad logins then 429 per source. |
| M-2 binaries on go1.27.1 | MED | **FIXED** | 12/12 `dist/` binaries report go1.26.9 (`go version -m`); `go.mod` `toolchain go1.26.9`; `release.yml`/`release-candidate.yml` use `go-version-file: go.mod`. govulncheck 0 (01). |

### LOW and INFO (carried from RC1)
| ID | Status | Note |
|---|---|---|
| C-02 Content-Disposition from CN | **FIXED** | `content_disposition.go` `attachmentDisposition` (sanitize + `mime.FormatMediaType`), used by download and escrow routes. `content_disposition_test.go`. |
| U-1 `/users` readable by all | **FIXED** | `handlers_users.go:42` needs `user.manage`; `TestUserHandlerListForbiddenForLowRoles`. Live: viewer, discovery-operator, pki-operator 403; admin 200. |
| N-01/N-02 (RC1 perf) retry state, audit store | **FIXED** | DB audit default, fail closed (`audit_provider.go`), unparseable timestamp backs off (`renewal_scheduler.go:758`). |
| B-03 residual: other routes uncapped | OPEN LOW | 19 `json.NewDecoder(r.Body)` sites remain without a cap (custom roles x3, evidence x2, notifications x2, pending-action reject, pqc waves x2, handlers_spiffe, tenants x3, users invite/PATCH, nhi propose, pqc_wave_execute). Authenticated, bounded by the 15 s `ReadTimeout` (`server.go:103`); no global `MaxBytesHandler`. `/targets` still answers 400, not 413 (CHANGELOG:319). Certificates, credentials, templates, estate, rollout, pending-actions now 413 (live). |
| A-05 HA lease shorter than scan | OPEN LOW | `renewal_scheduler.go` unchanged. |
| A-06 successor race | OPEN LOW | unchanged (`certificate_ca_provider.go:596-629`). |
| A-07 pushers on `http.DefaultClient` | OPEN LOW | `agentinstall/f5.go:43`, `citrix.go:46`, `k8s.go:106`; request context bounds them. |
| A-08 elevation deny-list | OPEN LOW | `plugins/delivery/escalation.go:62` unchanged. |
| A-09 scanner deny-list literal IPs | OPEN LOW | `discovery/scanner/scanner.go:435-461` unchanged. |
| B-04 TCP syslog no deadline | OPEN LOW | 0 deadline calls in `siem_integration.go`. Heavier now (N-03). |
| B-05 SIEM test echoes `url.Error` | OPEN LOW | `siem_integration.go:191` `err.Error()`. |
| B-06 SAML login CSRF | OPEN LOW | unchanged. |
| B-07 pending-SAML table 4096 | OPEN LOW | `auth_saml_guard.go:30`. |
| B-08 fail-open pre-checks | OPEN LOW | `handlers_users.go:17-21` returns nil on store error. |
| C-03 key floor only in ACME/CMP | OPEN LOW | unchanged. |
| C-04/B-09 `/inventory/keys` to viewer | OPEN LOW | live: viewer 200 (empty inventory here). |
| C-05 ACME http-01 `AllowPrivate` | OPEN LOW | `acme/http01.go:31`; loopback/metadata blocked, RFC1918 allowed by design (FG-1). |
| C-06 MCP error wrapper | OPEN LOW | unchanged. |
| I-1 OCSP good with nil store, I-2 cache race | OPEN LOW | unchanged. |
| M-3 nginx CSP `frame-ancestors` only | OPEN LOW | `nginx.conf:53`, no HSTS/script-src. |

## 2. New findings in RC2 code
No CRITICAL, HIGH or MEDIUM.

**RC2-N-01 LOW [80] limiter at capacity does an O(100k) sweep per new key under the global mutex.**
`ratelimit/ratelimit.go` `makeRoomLocked`: when the map holds 100k live keys it sweeps, deletes one arbitrary key, and the
next unknown key sweeps again. Measured on a copy of the package: 0.66 ms per new-key call (2000 calls, 1.32 s). An
attacker with an IPv6 /64 (already non-aggregated, RC1 INFO) or a botnet can keep the table full and serialize every
limiter-protected route (login, ACME, OCSP) at about 1.5k new keys/s. Not a bypass; an availability amplifier.
Fix: when full, evict a batch (e.g. 5%) or the oldest bucket, and aggregate IPv6 to /64.

**RC2-N-02 LOW [85] `principalIDReserved` gaps.** `principal_reserved.go`: (a) the env login admin matches by subject only, so
`principal_id=probe@example.com` mints (live 201) while `probe-admin` is refused; the effect is audit `actor_id` spoofing,
not approval bypass (grants bind human + auth type + kid). (b) A user-store error returns false (comment states it is
deliberate; opengrep flags it as `fallback-hides-failure`). Fix: also reserve the login email; fail closed on store error.

**RC2-N-03 LOW [70] SIEM now forwards every audit action; syslog MSG tail is unescaped and TCP still has no deadline.**
`siem_integration.go:366-374` appends raw `event.ResourceID` to the RFC 5424 MSG (the SD params use `%q`; CEF escapes).
A resource id taken from a decoded URL path (`%0a`) may carry a newline, which a line-splitting collector reads as a
second record (log forging; not live-verified). The wider event set also makes B-04 (stalled TCP collector wedges the
single drain worker, then events are dropped and counted in `SIEMEventsDropped`) lose far more. No new data leaves: the
payload carries actor, resource type/id, source IP, trace id, outcome only (`EmitFromAuditEntry`), not `change_summary`,
user agent or session. Fix: escape or strip control characters in the MSG, add write deadlines.

**RC2-N-04 LOW [60] report endpoints materialize the whole inventory per request.** `handlers_reports.go`
`reportVisibleCertificates` now walks everything (ceiling 1,000,000, was 10k-50k) into one slice; `report.read` is held by
viewer. Parallel requests multiply memory toward the 2 GiB limit / 1600 MiB `GOMEMLIMIT` (OOM kill = outage). Not measured
here (RC1 perf notes: 1-1.5 GB RSS at 52.6k certs under load). Fix: single-flight or a small concurrency semaphore on the
report routes, or stream-aggregate instead of collecting.

**RC2-N-05 LOW [65] arming checks permission, not ownership.** `authorizeTargetEgress` needs `certificate.renew` but does not
compare the matched certificate's team/owner with the caller; the scheduler matches by CN/SAN only (tenant is checked,
team is not). Built-in roles cannot reach it (only pki-admin holds `discovery.manage` + `certificate.renew`); a custom role
with both, and a team scope, can arm a host that matches another team's certificate. With `plugin_id` no credential (so no
admin) is needed. Fix: reuse `authorizeCertificateResourceAccess` for the matched certs at arm time, or document that
`discovery.manage` + `certificate.renew` is an admin-equivalent pairing.

### INFO / documentation
- **RC2-N-06** `token:` stamps (external jwt/oidc bearers) are never re-verified (`egress_stamp.go:62`, stated in the code);
  an OIDC admin who loses the role keeps the target armed until it is re-saved. Accepted; document in the runbook.
- **RC2-N-07 (doc defect)** `CHANGELOG.md:716-720` and the scheduler skip message (`renewal_scheduler.go:669`) tell a
  "pki-admin or pki-operator" to re-save `auto_renew=true`. Live: pki-operator gets 403 on `/targets` (no `discovery.manage`).
- **RC2-N-08** Audit file store: directory created 0755 (file 0600); `.bak`/`.migrating` names are fixed and opened without
  `O_NOFOLLOW` (needs write access to the audit directory, so out of model); every list scans the whole file, so file mode
  is O(file) per renewal candidate (DB is the default; file mode is single-node).
- **RC2-N-09** Placeholder check matches `change-me*` only; `POSTGRES_PASSWORD` defaults to `changeme` in the opt-in
  `postgres` compose profile (no published port). Chart `secrets.*` default empty and `required`.
- **RC2-N-10** `GET /targets` still returns `credential_ref` ids to any `discovery.manage` caller (RC1 note). With A-01 fixed an
  id alone is not usable without admin, so INFO. Upgrade note: 000072 is not backfilled, existing armed targets stop pushing
  until re-armed (CHANGELOG:716). 000073 rebuilds `certificates`, recreates its one trigger (same count as 000064), indexes preserved.
- Cursor iteration (`ForEachCertificate`) can skip a row inserted mid-pass that sorts before the cursor; acceptable for the
  scheduler and reports, noted for exports.
- IIS/keychain/agent installers keep the loopback-permitting verifier; they run on the managed host.

## 3. New-surface review, checked and held
- **ForEachCertificate / tenant+team filtering**: one predicate `certFilter` shared by page and full pass
  (`certificate_index.go:33-77`); `reportVisibleCertificates` still runs `authorizeCertificateListQuery` then
  `reportScopeCertificates`; `listCertificatesTenantFiltered` still batches through `filterCertificatesByTenant`. Chunked
  copy under RLock, no lock held while the callback runs. Held.
- **Audit store**: DB default when a core DB exists, file store otherwise, startup refuses on failure; JSON Lines is
  append-only with one `write(2)` per record, torn-tail handling, legacy migration keeps `.bak`, refuses to discard an
  unparseable legacy file; same driver and DSN as the core DB (a postgres hub cannot audit to sqlite). json.Marshal
  escapes newlines, so a record cannot forge a legacy `[` header or a second line. Held.
- **Keystore signer cache**: unchanged lifetime/zeroization; RC2 only reads `signer.Public()` from the cached entry
  (`software.go:594-606`). Held (`TestMetadataUsesCachedSignerWithoutRedecrypt`).
- **Login KDF semaphore**: slots = min(4, GOMAXPROCS), context-aware wait, per-IP limit and account backoff before the KDF.
  Live flood of 80 concurrent logins with rotating source: all 401, slowest 0.32 s, health/API latency and RSS unchanged. Held.
- **clientip memo**: immutable value keyed by the raw env string; atomic pointer. Held. **Release workflow**: build args only.
- **Compose/Helm**: pinned subnet and /32 trust, memory limits, `GOMEMLIMIT`. Held. **UI**: `Certificates.tsx` adds a
  status label via text rendering only (no HTML sinks); `api-types.ts` regenerated.
