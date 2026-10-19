# Guide capture report (qa/v1-final)

Captured 2026-10-18 by guide-scribe against real seeded hubs (production bundle via `scripts/dev/serve-real.mjs`, never `npm run dev`). Every step lives in a replayable spec at `docs/guide/specs/<id>.json`; screenshots are at `docs/guide/screenshots/<id>/NN-<slug>.png` (clean) and `NN-<slug>-annotated.png` (highlight box + step badge at the target's recorded bounding box). Each story also has `final-dark-1440.png` and `final-light-375.png` (the story's recorded final URL re-opened in dark theme at 1440 and light at 375; transient dialogs are not reproduced there).

## Result

- 60 stories: 60 with specs and screenshots, 0 blocked, 0 fully skipped. 45 captured in full; 15 captured for their UI portion only (LAB / EXTERNAL remainder listed below).
- 495 steps, 478 gated screenshots, 254 annotated copies, 144 final-state shots (dark 1440 + light 375). Multi-part stories have extra specs (U-09b/c, U-15b, U-19x, U-26b, U-28b, U-41b, U-43b, U-44b, U-47a, U-54b, U-58b).
- Recapture (second pass): the whole set was re-run on a freshly reset and reseeded hub built from HEAD 46ac3c12 after the CB-01..15 fixes and the approver-role change. The BUG-01..BUG-04 evidence specs were dropped because the bugs are fixed; the first-pass evidence is in git history (commit 84c5e426). Screenshots are now gitignored and ship in `kk-v1-guide-screenshots.zip`.

## Method and deviations

- Hubs: fresh data dir and fresh working directory per hub (see trap CB-13), `APP_NOTIFICATION_PROVIDER=delivery APP_DISCOVERY_PROVIDER=db SPIFFE_TRUST_DOMAIN=acme.test KRYPTKEEPER_TLS_DISABLE=true`, `APP_API_KEY_PEPPER` set, `KRYPTKEEPER_ANOMALY_SWEEP_MINUTES=2 KRYPTKEEPER_SLO_SWEEP_MINUTES=2` (this is how the TIME story U-54 was captured), seeded with `scripts/dev/seed-demo.sh`.
- Personas: password login allows one principal per hub process, so the hub is restarted on the same data dir with a different login identity to mint each persona's token (ada.admin pki-admin; marcus.webb pki-admin as the second person; alice and bob pki-admin as ceremony approvers; dana.approver with the `approver` role). Tokens are minted by API login and injected into sessionStorage; U-01 and U-60 use the real login form. Both sides of every MULTI-USER story are captured.
- CONFIG hubs on separate data dirs: SCEP (`KRYPTKEEPER_SCEP_ENABLED` plus an RSA CA in `KRYPTKEEPER_SCEP_CA_ID`), `SPIFFE_SIGNING_CA_ID`, `SIEM_WEBHOOK_URL`, and `MULTI_TENANCY=on` with `KRYPTKEEPER_MULTI_TENANCY_EXPERIMENTAL=accept-risk`.
- Sinks: a Mailpit container `kk-guide-mailpit` (removed) and a local webhook receiver, both on the Mac's LAN address because the hub egress policy always refuses loopback (CB-14).
- Gates (docs/guide/tools/run-spec.mjs): A blank (pixel stddev, dominant-colour ratio, size floor), B error (console/pageerror, HTTP >=400, role=alert, error text; allow-listed for deliberate documented errors), C premature (loaders absent, expected element visible, two-shot stability), 3 attempts then BLOCKED. All shipped shots are all-PASS; no step is BLOCKED or NOT-RUN. One-time secrets (EAB key, enrolment token, EST/PBM secrets, join token, SCEP challenge, SVID) are masked in the images.
- Deviations: all stories now run at 1440x900 (U-10 and U-11 no longer need 1440x1150 since CB-01 is fixed); U-59 runs at 375x812; screenshots are taken after each action (annotation marks the target if it is still on screen); the CSR/PEM inputs are generated test material; U-52 uses the repo's AD CS test fixture as the export file; U-05 uses the new parent CA picker (CB-06).
- Replay: `RUN=<work dir> BIN=<hub binary> bash docs/guide/tools/run-all.sh` (fresh hub, personas, ordered run, config hubs, finals). Single spec: `node docs/guide/tools/run-spec.mjs --base <ui url> --tokdir <dir> docs/guide/specs/U-xx.json`.

## Per story

| Story | Title | Specs | Status | Steps | Screenshots | Annotated | Finals (dark 1440 + light 375) | Flags |
|---|---|---|---|---|---|---|---|---|
| U-01 | Sign in and find your way around | U-01 | captured | 9 | 9 | 5 | 2 | - |
| U-02 | See what needs attention on the dashboard | U-02 | captured | 5 | 5 | 3 | 2 | - |
| U-03 | Find anything with global search and the command palette | U-03 | captured | 7 | 5 | 3 | 2 | - |
| U-04 | Create a root CA | U-04 | captured | 9 | 9 | 5 | 2 | - |
| U-05 | Create an intermediate (issuing) CA under a root | U-05 | captured | 7 | 7 | 3 | 2 | - |
| U-06 | Import an external root CA (trust anchor) | U-06 | captured | 7 | 6 | 2 | 2 | - |
| U-07 | Inspect a CA and read the hierarchy | U-07 | captured | 6 | 6 | 4 | 2 | - |
| U-08 | Suspend, update, re-key or revoke a CA (guarded) | U-08 | captured | 18 | 15 | 6 | 2 | DESTRUCTIVE |
| U-09 | Run a root key ceremony (M-of-N) | U-09, U-09b, U-09c | captured | 14 | 14 | 7 | 6 | MULTI-USER |
| U-10 | Create a certificate template | U-10 | captured | 11 | 11 | 7 | 2 | - |
| U-11 | Edit a template and read its revisions | U-11 | captured | 5 | 5 | 2 | 2 | - |
| U-12 | Draft an issuance policy from plain English | U-12 | captured | 9 | 9 | 3 | 2 | - |
| U-13 | Issue a certificate with the guided wizard (own CSR) | U-13 | captured | 15 | 15 | 10 | 2 | - |
| U-14 | Issue a certificate with a generated key (local openssl) | U-14 | captured | 9 | 9 | 8 | 2 | - |
| U-15 | Request a certificate that needs approval, then track it | U-15, U-15b | captured | 14 | 14 | 9 | 4 | - |
| U-16 | Browse, filter and inspect certificates | U-16 | captured | 11 | 11 | 8 | 2 | - |
| U-17 | Approve a pending request (second person) | U-17 | captured | 5 | 5 | 4 | 2 | MULTI-USER |
| U-18 | Reject a request | U-18 | captured | 4 | 4 | 2 | 2 | DESTRUCTIVE (irreversible decision) |
| U-19 | Approve a proposed policy or exception (pending action) | U-19, U-19x | captured | 8 | 8 | 2 | 4 | MULTI-USER |
| U-20 | Take ownership of an unmanaged certificate and edit ownership | U-20 | captured | 13 | 13 | 6 | 2 | - |
| U-21 | Bulk import existing certificates | U-21 | captured | 5 | 5 | 3 | 2 | - |
| U-22 | Renew certificates (single and bulk) | U-22 | captured | 12 | 12 | 6 | 2 | - |
| U-23 | Revoke a certificate (single and bulk) | U-23 | captured | 14 | 13 | 6 | 2 | DESTRUCTIVE |
| U-24 | Export the certificate inventory as CSV | U-24 | captured | 3 | 3 | 1 | 2 | - |
| U-25 | Run a discovery scan and read the results | U-25 | captured | 8 | 8 | 4 | 2 | - |
| U-26 | Inspect an endpoint and accept a finding as risk | U-26, U-26b | captured | 6 | 6 | 2 | 4 | MULTI-USER (accept risk becomes a pending action) |
| U-27 | Set up ACME for a server (provisioner, EAB key, client) | U-27 | captured (UI portion; lab/external remainder skipped) | 15 | 14 | 8 | 2 | LAB (ACME client host) |
| U-28 | Enroll devices with SCEP, EST or CMP | U-28, U-28b | captured (UI portion; lab/external remainder skipped) | 23 | 20 | 10 | 4 | CONFIG + LAB DEVICE |
| U-29 | Enroll a satellite agent | U-29 | captured (UI portion; lab/external remainder skipped) | 7 | 7 | 4 | 2 | LAB (host running the agent) |
| U-30 | Bring an agentless target under management | U-30 | captured (UI portion; lab/external remainder skipped) | 8 | 8 | 7 | 2 | CONFIG + LAB HOST |
| U-31 | Set renewal policy per target | U-31 | captured | 8 | 8 | 7 | 2 | - |
| U-32 | Roll a certificate out to a cluster (rollout group, canary first) | U-32 | captured (UI portion; lab/external remainder skipped) | 9 | 9 | 6 | 2 | LAB (to execute rollout) |
| U-33 | Watch automation and the failed-renewal queue | U-33 | captured (UI portion; lab/external remainder skipped) | 3 | 3 | 0 | 2 | LAB |
| U-34 | Install a delivery plugin (WASM) | U-34 | captured (UI portion; lab/external remainder skipped) | 2 | 2 | 0 | 2 | EXTERNAL ARTIFACT (build) |
| U-35 | Configure notifications (email, Slack, webhook, PagerDuty) | U-35 | captured | 13 | 13 | 8 | 2 | LOCAL SINK |
| U-36 | Send test deliveries, build alert rules, retry failures | U-36 | captured | 13 | 13 | 8 | 2 | LOCAL SINK |
| U-37 | Connect Jira or ServiceNow (ITSM) for ticket-based alerts | U-37 | captured (UI portion; lab/external remainder skipped) | 5 | 5 | 4 | 2 | EXTERNAL SERVICE |
| U-38 | Invite a user and assign a role | U-38 | captured | 6 | 6 | 2 | 2 | - |
| U-39 | Create a custom role with least privilege | U-39 | captured | 12 | 12 | 10 | 2 | - |
| U-40 | Run a periodic access review | U-40 | captured | 6 | 6 | 3 | 2 | - |
| U-41 | Turn on multi-tenancy and manage tenants | U-41, U-41b | captured | 6 | 6 | 4 | 4 | CONFIG |
| U-42 | Create issuance policies and dry-run a request | U-42 | captured | 6 | 6 | 3 | 2 | - |
| U-43 | Propose a machine identity and approve it (NHI) | U-43, U-43b | captured | 8 | 8 | 3 | 4 | MULTI-USER |
| U-44 | Issue SPIFFE SVIDs for workloads | U-44, U-44b | captured (UI portion; lab/external remainder skipped) | 4 | 4 | 2 | 4 | CONFIG + LAB WORKLOAD |
| U-45 | Check the blast radius before a destructive change | U-45 | captured | 9 | 9 | 8 | 2 | - |
| U-46 | Issue an SSH user or host certificate | U-46 | captured | 7 | 7 | 5 | 2 | - |
| U-47 | Use the Code Signing inventory | U-47, U-47a | captured | 2 | 2 | 0 | 4 | MULTI-USER |
| U-48 | Generate, back up, import and rotate keys | U-48 | captured | 11 | 9 | 4 | 2 | DESTRUCTIVE for rotate/delete |
| U-49 | Escrow, recover and BYOK-export a root key (dual control) | U-49 | captured (UI portion; lab/external remainder skipped) | 8 | 5 | 0 | 2 | MULTI-USER + EXTERNAL KMS |
| U-50 | Review cloud KMS key inventory | U-50 | captured (UI portion; lab/external remainder skipped) | 1 | 1 | 0 | 2 | EXTERNAL CLOUD |
| U-51 | Sync certificates from another CA (inventory sources) | U-51 | captured (UI portion; lab/external remainder skipped) | 4 | 4 | 2 | 2 | EXTERNAL CA (live sources) |
| U-52 | Migrate templates from another CA product | U-52 | captured (UI portion; lab/external remainder skipped) | 5 | 5 | 3 | 2 | EXTERNAL EXPORT FILE |
| U-53 | Monitor Certificate Transparency findings | U-53 | captured (UI portion; lab/external remainder skipped) | 3 | 3 | 1 | 2 | EXTERNAL (public CT logs) |
| U-54 | Review issuance anomalies | U-54, U-54b | captured | 4 | 4 | 0 | 4 | TIME |
| U-55 | Read the PKI risk reports | U-55 | captured | 12 | 11 | 2 | 2 | - |
| U-56 | Produce compliance evidence (packs, CBOM, scheduled delivery) | U-56 | captured | 9 | 9 | 7 | 2 | LOCAL SINK (for email) |
| U-57 | Investigate with Audit Evidence, Change Audit and History | U-57 | captured | 7 | 7 | 3 | 2 | - |
| U-58 | Forward security events and manage discovery sources (Settings) | U-58, U-58b | captured (UI portion; lab/external remainder skipped) | 9 | 9 | 5 | 4 | CONFIG + EXTERNAL |
| U-59 | Use the app on a phone-sized screen | U-59 | captured | 4 | 4 | 0 | 2 | - |
| U-60 | See empty, error and not-found states | U-60 | captured | 12 | 12 | 4 | 2 | - |


## Documented error states captured (for Troubleshooting)

- U-12 `phrase-not-applied`: "Require hardware tokens for all keys." is not a rule the parser knows; the dialog lists it under "These phrases were not applied". The RSA sentence from the story now parses (CB-11).
- U-19x now shows an approver deciding a certificate request on a template whose approval_roles name `approver`; the inbox explains which requests an approver sees (CB-04 fix).
- U-30 `credential-required-validation`: agentless Next is blocked without a credential.
- U-39 `duplicate-role-error` (now a friendly 409), U-60 `wrong-password` / `not-found-404` / `history-not-found` / off-state pages (tenants, SPIFFE, cloud keys, CT), U-28 `scep-not-enabled`, U-41/U-44/U-50/U-53 off or empty states.
- Dual control: importing an external root (U-06), migration apply (U-52), policy activation (U-12), exceptions and NHI approvals all wait for a second pki-admin; pending actions need an admin role, not `approver`.

## Bugs and suspects (status per row)

| # | Class | Route | Repro | Expected vs actual | Evidence | Status |
|---|---|---|---|---|---|---|
| CB-01 | bug | /templates | At 1440x900 click New template (or select a template and Edit) | Dialog scrolls or fits; actual: dialog is 1048px tall, fixed and unscrollable (top -74, bottom 974), so Close and Create/Save cannot be reached with the pointer | bugs/templates-new-dialog-clipped-1.png, templates-edit-dialog-clipped-2.png (BUG-01, BUG-02) | **Status: fixed (470b7e43): the shared Dialog caps its height at the viewport, scrolls the body, and pins header and footer; Templates uses the pinned footer** |
| CB-02 | bug | /certificates/<fp> | Bulk-import a PEM (U-21), open it, Revoke, type REVOKE, Confirm revoke | Revoked or a clear "cannot revoke external certificate"; actual: POST /certificates/<fp>/revoke 503, "certificate unavailable", plus an uncaught page error | bugs/certificates-revoke-imported-503-4.png (BUG-04) | **Status: fixed (47d90924): a certificate with no issuing CA in this hub is recorded revoked in the inventory by fingerprint (revStore matched on serial+ca_id, ca_id empty, hence the 503); the UI states it is an inventory record only and the uncaught rejection is gone** |
| CB-03 | suspect | /roles | Create role cert-reader twice | Friendly "name already exists" (templates return 409 with one); actual: raw `custom role: persist: constraint failed: UNIQUE constraint failed: custom_roles.name (1555)` | bugs/roles-duplicate-name-sql-5.png | **Status: fixed (b4627dc4): duplicate name answers 409 "a role named ... is already defined"; other persist failures answer a generic 503 and log the driver text** |
| CB-04 | suspect | /inbox | Sign in with role `approver`, click Approve on a pending action | Buttons hidden or disabled, or the action allowed; actual: Approve is offered, hub answers 403. The same role also never sees certificate approvals | bugs/inbox-approver-role-403-6.png | **Status: fixed (00a2c0bf, fdffd30a)** |
| CB-05 | suspect | /audit | Filter action `certificate`, Apply | Substring match, or a "no matches" message; actual: exact match only (`certificate.issue` works) and the empty table says "No audit entries yet" | bugs/audit-action-filter-3.png (BUG-03) | **Status: fixed (67b0139a): `action` matches an exact action or its dotted family (certificate matches certificate.issue); internal callers keep exact `Action`; the empty state says "No entries match these filters" when filtered** |
| CB-06 | UX | /cas New CA | Type Intermediate | Parent selector (story expects one); actual: free-text "Parent CA ID" with placeholder `ca-...` while ids are UUIDs | bugs/cas-intermediate-parent-id-7.png | **Status: fixed (aa752ffe): Parent CA is a picker of active CAs by name (offline roots marked as producing a CSR)** |
| CB-07 | suspect | /login | Wrong password | Announced to assistive tech; actual: styled text "invalid credentials", not role=alert | bugs/login-error-not-alert-8.png | **Status: fixed (f401b722): the error is role="alert"** |
| CB-08 | suspect | /cas | Import external root (U-06), approve elsewhere, reload | Redeem still possible; actual: "Redeem approved action" lives in React state only, so a reload or second tab loses it (captured only because the same session stays open) | U-06 step 7 | **Status: fixed (aa752ffe, lint follow-ups 92d17589, 6a2cb9a1): the prompt is derived from the proposer's pending/approved key_ca_import, key_ca_trust_anchor_remove and key_ca_rotate actions (approved ones within the 10-minute grant TTL). Removal redeems in one click; import and re-key reopen their dialog because the hub stores only a fingerprint (import) or a mode+algorithm hash (re-key), never the request body. Residual: a grant already redeemed within the TTL reappears after a reload and redeeming it answers "already redeemed"** |
| CB-09 | suspect | /reports/anomalies | After a sweep (U-54b) | CA names; actual: raw CA UUIDs, and one finding has an empty CA id and an empty bullet | bugs/reports-anomalies-raw-ids-9.png | **Status: fixed (05b0673e): the detector no longer pools certificates with no hub CA under an empty CA id (that was the empty finding and bullet); the page shows CA names and drops empty bullets** |
| CB-10 | cosmetic | /templates | Select a template | Formatted date; actual: raw ISO `2026-10-18T03:16:41Z` in Revision history | bugs/templates-revision-iso-timestamp-10.png | **Status: fixed (8a71331b): uses the shared formatDateTime** |
| CB-11 | docs | policy draft | See documented errors | Story example phrase is not understood by the parser | U-12 step 5 | **Status: fixed (81b92a60): the parser accepts the RSA size anywhere in the same clause (up to 40 characters, no comma or semicolon in between). U-12 step 5 now parses; the documented-error example for U-12 needs a different unparsed phrase** |
| CB-12 | docs | /tenants | Sign in as password user with role super-admin on a MULTI_TENANCY=on hub | Tenant admin; actual: "restricted to super-admins" - only the raw bootstrap-token session resolves as super-admin | U-41b used a bootstrap-token session | **Status: intended, UI now says why (0f720251): super-admin is set only for the raw bootstrap token (resolvePrincipalTenancy, S-34); a named user is tenant-scoped even as pki-admin. D-202/D-203 cover tenant-store failure and agent/NHI/SPIFFE APIs, not this. Authorization not widened** |
| CB-13 | recipe trap | hub | Wipe the data dir and restart from the repo root | Fresh state; actual: templates live in `./var/bootstrap-templates.json` relative to the working directory, so old templates survive. Run each hub from its own cwd (or set APP_TEMPLATE_FILE). The screenshot-tour recipe should say so | n/a | **Status: fixed (d63b82c6): the five file-provider stores (templates, CAs, certificates, audit, certs summary) default to $KRYPTKEEPER_DATA_DIR/<name>; an existing ./var file is kept, with a startup warning, until the data dir holds its own copy; documented in env.example** |
| CB-14 | docs | integrations | SMTP, webhook or SIEM to 127.0.0.1 | Delivered; actual: `egress: destination blocked: 127.0.0.1`, no env knob; use a LAN address | U-58b | **Status: fixed (f30191d4): a delivery refused by the egress guard shows why and what to change on its Alerts row (additive `failure_reason`), the SIEM test returns the same text. There is no allowlist setting and the guard is unchanged: use a LAN address (private ranges work unless KRYPTKEEPER_EGRESS_DENY_PRIVATE=true); see docs/ops/EGRESS.md** |
| CB-15 | docs | /enrollment | KRYPTKEEPER_SCEP_ENABLED with the default ECDSA root | SCEP on; actual: log-only "SCEP disabled: CA key is not RSA"; set KRYPTKEEPER_SCEP_CA_ID to an RSA CA | U-28b | **Status: fixed (f7cfb47d): the startup log states the reason at warn level and `GET /integrations/microsoft` returns scep_enabled=false with an additive `scep_off_reason`, shown on the SCEP tab** |

## Needs the lab (remainder not captured)

U-27 certbot/lego run and EAB "Uses > 0"; U-28 device-side SCEP/EST/CMP enrolment; U-29 running kryptkeeper-agent and agent Active row; U-30 steps 5-6 (host key, review; needs SSH credential and host); U-32 rollout execution; U-33 non-zero automation values (agent heartbeat plus a renewal run); U-34 signed WASM plugin install; U-37 live Jira/ServiceNow test; U-44 workload attestation; U-49 BYOK delivery to a cloud KMS and escrow recovery with custodians; U-50 cloud key inventory; U-51 live CA sources; U-53 CT findings (public logs); U-58 a real SIEM (a local webhook stood in).

## Recapture notes

No new product bugs were found in the recapture. Observations: approvers now see and decide certificate requests on templates naming the role (U-19x); key/CA pending actions need pki-admin or pki-operator; U-06 follows the new redeem prompt after the approver acts.
