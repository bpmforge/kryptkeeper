# Tenant isolation validation, v0.9.3 (live, 2026-10-15)

Validation only. No product code was changed. Input to the v0.10 tenancy fix plan (FG-6a / FG-6b).

## 1. Scope and method

- **Code under test:** `origin/main` at `6561651f` (Merge PR #135, site v0.9.3), detached checkout, built with `GOTOOLCHAIN=go1.26.9`.
- **Hub A (API-key hub):** `AUTH_MODE=bootstrap`, `APP_API_KEY_AUTH_ENABLED=true`, `MULTI_TENANCY=on`, `KRYPTKEEPER_MULTI_TENANCY_EXPERIMENTAL=accept-risk`, SQLite, loopback TLS (the hub self-issues its listener cert, so `https://127.0.0.1:18480`). Secrets from `openssl rand`, never printed.
- **Hub B (JWT hub):** same, but `AUTH_MODE=jwt` (HS256, issuer + audience set, `APP_AUTH_ROLE_CLAIM=role` + role map, tenant from the `tenant` claim). Needed because the only way to get a **named approver bound to a tenant** is a bearer token with a tenant claim: API keys minted from the bootstrap token are "setup credentials" and can never approve (`separation_of_duties.go:24`), and the single configured login user carries no tenant (resolves to `default`). Tenants were created on a bootstrap-mode start of the same DB, then the hub was restarted in jwt mode (in jwt mode the bootstrap token does not authenticate, so there is no super-admin).
- **Tenants:** `acme` (attacker) and `globex` (victim) plus the implicit `default` tenant. Per tenant on Hub A: API keys for `pki-admin`, `pki-operator`, `viewer`, `auditor` (and `approver`), all minted with `tenant` bound. A CA, an active template, a certificate, an approval-required template with a pending approval request, a notification rule and silence, an outbound credential, a managed target, a discovery scan, an SSH template + SSH certificate, a pending action, a connector and an inventory source were created through the real API. The `default` tenant has the hub's root CA plus one template and one certificate.
- **Probes:** 4 acme roles x about 90 GET endpoints (status + count of globex markers in the body), then targeted write probes per resource family, header spoofing, escalation attempts, and bootstrap (global admin) behaviour. Every leak was confirmed by a follow-up read of the victim's state where the response alone was ambiguous.
- Scripts and raw outputs are in the session scratch dir only (not committed). Tokens appear nowhere in this report.

Verdict vocabulary: **isolated** = cross-tenant request refused/hidden (403/401/404 or filtered); **LEAKS (read)** = another tenant's data returned; **LEAKS (write)** = another tenant's state changed or another tenant's key/CA used; **N/A** = no such operation; **UNVERIFIED** = not exercised live (reason given).

## 2. Headline

- **21 distinct cross-tenant leaks** found: **14 can change state (write)**, 7 are read-only.
- **3 critical-class** (full cross-tenant takeover paths): L-01 key minting, L-03 approval execution, L-04 CA key export. **7 HIGH**. **9 MEDIUM/LOW**.
- **Not in the v0.9 posture doc's gap table:** L-06 bulk-revoke, L-07 sub-CA under another tenant's CA, L-09c credential reuse via a target, L-10 notification rules/silences, L-11 discovery, L-16 connectors, L-17 inventory sources, L-19 custom roles, L-21 `/protected/certs/summary`.
- Of the 8 deferred findings asked about: **A01-001 REPRODUCES, A01-002 REPRODUCES, A01-004 PARTIAL, A01-005 REPRODUCES, A01-006 REPRODUCES, A01-007 PARTIAL, A01S-3 PARTIAL (reachable), A01S-6 REPRODUCES, OWASP-002 REPRODUCES.** Nothing is FIXED outright; FG-6a/6b have not landed.
- What does hold: cert/CA/template/approval/target single-resource reads and writes, the direct cert issue path, `X-Tenant` mismatch rejection, super-admin gating of the dashboard and the aggregate reports, and the tenant-scoped report family (section 3 and 5).

## 3. Matrix: resource x operation

Attacker = a tenant-`acme` principal (viewer/operator/auditor/admin as noted) acting on tenant-`globex` data, no `X-Tenant` unless stated. "L-nn" points to section 4.

| Resource | list | get | create | update | delete | other |
|---|---|---|---|---|---|---|
| Certificates | isolated (total also correct) | isolated (get, chain, download: 403) | isolated (direct issue against globex CA or template: 403) | N/A (ownership is POST-only 405) | N/A | revoke: isolated (403). **bulk-revoke: LEAKS (write) L-06**. renew (direct): isolated, but the 403 is the *team* check, not tenant. renew/issue/revoke via pending action: **LEAKS (write) L-03**. bulk-reissue: UNVERIFIED (same-tenant control also returns `certificate invalid`). import/bulk-import/estate takeover: UNVERIFIED (payload rejected before any tenant-relevant step) |
| CAs | data isolated; **meta.total/next_cursor LEAK (read) L-20** | isolated (get, chain: 403) | **LEAKS (write) L-07** (`parent_ca_id` of another tenant's CA, or the default root) | isolated (PATCH 403; PUT 405) | isolated (DELETE 403) | suspend/activate: isolated. key export: see Keys |
| Templates | data isolated; **meta.total LEAKS L-20** | isolated | isolated (clone 403) | isolated (PUT/PATCH 403) | isolated (DELETE 403) | N/A |
| Approvals | data isolated; **meta.total LEAKS L-20** | isolated (403) | N/A (created by issuance) | N/A | N/A | approve/reject: isolated (403; control blocked by template approver-role policy, tenant check is `handlers_approvals.go:168,199,301`) |
| Pending actions | isolated (filtered by tenant) | N/A | proposing any target in any tenant: accepted (**L-03**) | N/A | N/A | approve/reject: other tenant's action hidden (404, both directions). **Executing a same-tenant action against another tenant's cert/CA: LEAKS (write) L-03** |
| API keys | **LEAKS (read) L-02** | N/A | **LEAKS (write) L-01** | N/A | **LEAKS (write) L-02** | N/A |
| Users | **LEAKS (read) L-18** | N/A | invite creates a tenant-less global user (**L-18**) | PATCH: UNVERIFIED (404 even for bootstrap) | **LEAKS (write) L-18** | N/A |
| Roles | global (all tenants see all custom roles) | N/A | **LEAKS (write) L-19** | N/A | **LEAKS (write) L-19** | N/A |
| Keys (keystore) | **LEAKS (read) L-05** | **LEAKS (read) L-05** | N/A | rotate/delete: refused for CA keys (409 key backs a CA). Not tenant logic | see left | **export: PARTIAL, reachable L-04** (dual control default-on; 202 grant proposal for another tenant's CA key and for `ssh-ca`; end-to-end export proved with a default-tenant approver). backup/escrow: 202 grant proposal, **UNVERIFIED past approval** |
| Key custody report | **LEAKS (read) L-05** | N/A | N/A | N/A | N/A | N/A |
| Credentials | **LEAKS (read) L-09** | N/A (405) | admin only; stored with empty tenant (**L-09**) | N/A | **LEAKS (write) L-09** | preflight: UNVERIFIED (only for windows_password) |
| Targets | isolated (acme sees only its own) | isolated (403) | **LEAKS (write) L-09c**: target created with another tenant's `credential_ref` accepted (201) | isolated (PATCH 403) | isolated (DELETE 403) | endpoints: isolated (403) |
| Notification rules | **LEAKS (read) L-10** | N/A (405) | admin, global | **LEAKS (write) L-10** (PUT) | **LEAKS (write) L-10** | test-delivery: UNVERIFIED (400 on probe body) |
| Notification silences | **LEAKS (read) L-10** | N/A | **LEAKS (write) L-10** (silence a globex cert) | N/A | **LEAKS (write) L-10** | deliveries/summary: reachable, empty in this run (UNVERIFIED content) |
| Discovery | scan-jobs: **LEAKS (read) L-11**; endpoints + summary: **LEAKS (read) L-11** (unscoped store) | N/A | scan create: admin, global | N/A | N/A | requeue: **LEAKS (write) L-11** (202, new job cloned from globex's). cancel: 202, target already terminal (accepted without tenant check, effect UNVERIFIED) |
| Search | **LEAKS (read) L-13** (viewer) | N/A | N/A | N/A | N/A | N/A |
| CBOM | **LEAKS (read) L-14** (viewer) | N/A | N/A | N/A | N/A | N/A |
| Audit | **LEAKS (read) L-12** (auditor, admin; viewer now 403) | N/A | rows mis-stamped (**L-12**) | N/A | N/A | N/A |
| SSH certificates | **LEAKS (read) L-15** (viewer) | N/A | isolated (globex SSH template: `unknown template_id`) | N/A | N/A | `/ssh/ca`: one global SSH CA, readable by any role (L-22, design) |
| Connectors | **LEAKS (read) L-16** (viewer, incl. `config_json`) | N/A | stamped with creator tenant | N/A | **LEAKS (write) L-16** | N/A |
| Inventory sources | **LEAKS (read) L-17** | N/A | stamped with creator tenant | N/A | **LEAKS (write) L-17** | sync: 404 after delete (effect on a live source UNVERIFIED) |
| Config | readable (global; secrets masked) | N/A | N/A | **LEAKS (write) L-08** (`PUT /config/sso.oidc_jwks_json` = 204, `updated_by=svc-acme-admin`, visible to globex-admin) | N/A | N/A |
| Delivery plugins / ceremonies / SCEP challenges / adsync | reachable (empty in run) | N/A | authz passes, body validation 400 (**UNVERIFIED** for cross-tenant content: no code path scopes them, grep `tenant` in handlers_ceremony.go, handlers_delivery_plugins.go (only a stamp), handlers_scep_challenges.go) | N/A | N/A | N/A |
| Dashboard / dashboard actions / PQC countdown + waves / renewal-SLO / evidence / crypto-posture trend | isolated by gating (403 for any tenant principal, D-102) | N/A | N/A | N/A | N/A | super-admin only |
| Scoped reports (crypto-posture, ca-health, expiry-timeline, revocation-activity, issuance-velocity, change-audit, compliance-evidence, algorithm-sunset, executive-summary, pqc-migration, exports inventory/findings) | isolated (acme saw only its own cert/CA) | N/A | N/A | N/A | N/A | N/A |
| `/protected/certs/summary` | **LEAKS (read) L-21** (fleet total 4, acme owns 1) | N/A | N/A | N/A | N/A | N/A |
| Events (SSE `/events`) | UNVERIFIED live (stream returned no bytes in 5 s). Code filters by tenant (`handlers_sse.go:170`) | N/A | N/A | N/A | N/A | N/A |
| Agents, SCIM, NHI, SPIFFE, MCP, ACME/EST/SCEP/CMP data plane, UI | UNVERIFIED. Agents have no tenant column by design (`handlers_agents.go:850`); SCIM needs its own token (not configured); the protocol endpoints serve the default CA | | | | | |
| Tenant admin (`/tenants`, `/tenants/*-mapping`) | isolated (403 for every non-bootstrap principal) | N/A | isolated | N/A | N/A | N/A |

## 4. Leaks (request, response, root cause)

All requests are against Hub A (`https://127.0.0.1:18480/api/v1`) as acme principals unless stated. Auth headers omitted. `GX` = a globex resource id.

**L-01 (CRITICAL, write): tenant admin mints API keys in any tenant, including `default` and non-existent tenants.** (A01-001: REPRODUCES)
- `POST /api-keys {"role":"pki-admin","tenant":"globex"}` as acme-admin -> `201 {"data":{...,"role":"pki-admin","tenant":"globex"}}`. The new key then does `GET /certificates/{GX}/download` -> `200 -----BEGIN CERTIFICATE-----` (acme-admin itself gets 403).
- `{"tenant":""}` and `{"tenant":"default"}` -> 201; that key reads default-tenant cert `GET /certificates/{default_fp}` -> 200 (acme-admin: 403). `{"tenant":"nonexistent"}` -> 201. `{"role":"bootstrap"}` -> 201 (admin-equivalent, not super-admin: `GET /tenants` 403).
- Also on Hub B: a jwt-acme admin minted a globex pki-admin key and read the globex cert with it (200).
- Root cause: `handlers_auth.go:393` passes the body's `tenant` to `CreateAPIKeyAs`; the only gate is `isAdminRole` (`handlers_auth.go:~330`) and `checkRoleGrant` (permissions, not tenant). No super-admin check, no tenant-existence check.

**L-02 (HIGH, read + write): API key directory shared across tenants.**
- `GET /api-keys` as acme-admin -> 200, lists globex keys (kid, principal_id, role, tenant). `DELETE /api-keys/{kid of a globex key}` -> `204`.
- Root cause: `handlers_auth.go:303` filters only by `isAdminRole(...) || principal match`; the DELETE handler (`handlers_auth.go:442-458`) has no tenant check.

**L-03 (CRITICAL, write): approved pending actions execute against any tenant's certificates and CAs.** (A01-002: REPRODUCES; revoke, bulk_revoke, issue, renew)
- Hub B: `POST /pending-actions {"action_type":"revoke","params":{"fingerprint":"{GX cert}"}}` as acme-op (stamped `tenant:acme`), then `POST /pending-actions/{id}/approve` as a second acme operator -> `200 {"status":"approved","result":{"fingerprint":"...","revoked":1}}`. globex-admin then reads the cert: `revoked_at` set.
- `bulk_revoke` with `ca_id` = globex CA -> `200 {"revoked":1,"failed":0,"ca_id":"{globex CA}"}`; cert revoked.
- `issue` with `ca_id` = globex CA, `template_id` = globex template and an acme CSR -> `200 {"issued":"<fp>"}`. Same issuance via `POST /certificates` is refused (403 "certificate authority is not visible in your tenant"), so the queue is a bypass. The issued cert is readable by globex-admin and 403 for acme.
- `renew` of that cert -> `200 {"renewed":..., "successor":...}`.
- Cross-direction is isolated: a globex approver gets 404 for an acme action. Self-approval is refused (403).
- Root cause: `pending_action_exec.go:37-130` executes by fingerprint / `ca_id` with no tenant resolution of the target; the proposal handler (`handlers_pending_actions.go:72-87`) stamps only the proposer's tenant and never validates the target against it. `validActionType` (`pending_action_exec.go:200`) also still allows `issue`, `renew`, `rotate`.
- Note: on Hub A the same attack is blocked only incidentally, because bootstrap-minted keys are "setup credentials" and cannot approve (`separation_of_duties.go:24`). Any tenant principal that can approve (jwt/oidc with a tenant claim) can do it.

**L-04 (CRITICAL when an approver exists, write): another tenant's CA private key can be exported.** (A01S-3: PARTIAL)
- Hub A: `GET /keys` as acme-admin lists `key-{GX CA}` and `ssh-ca`; `GET /keys/key-{GX CA}` -> 200 metadata. `POST /keys/key-{GX CA}/export {"passphrase":...}` -> `202 {"status":"proposed","message":"dual control is on..."}` (same for `ssh-ca`, the default root key, `/keys/escrow`, `/admin/backup`). So the one-admin export from the audit is closed by D-122 (dual control on by default). `rotate`/`DELETE` of a CA key return 409 (key backs a CA).
- Hub B end to end: acme-admin proposes export of `key-{globex CA}`; the grant (`key_export`) is stamped with **no tenant**, so tenant approvers cannot see it (acme operator: 404), but a default-tenant operator sees it in `GET /pending-actions` and approves (200 `export_granted:true`); acme-admin redeems it -> `200 -----BEGIN KRYPTKEEPER BACKUP KEY----- Key-ID: key-{globex CA}`. The approver sees only a key id, with nothing showing which tenant owns it.
- Root cause: `handlers_keys.go:47,160` gate on `isAdminRole` only; keystore has no key -> CA -> tenant mapping; `key_dual_control.go:160` creates the grant `PendingAction` without a `Tenant`.

**L-05 (MEDIUM, read): keystore metadata and key-custody report cross tenants.**
- `GET /keys` (admin) -> all keys incl. `key-{GX CA}`, `ssh-ca`. `GET /reports/key-custody` -> 200, lists globex CA key with `access_count` / `last_accessed_at`. Root cause: `handlers_keys.go:47-54`, `handlers_key_custody.go:72` (no tenant reference).

**L-06 (HIGH, write, NEW): bulk-revoke ignores tenant.**
- `POST /certificates/bulk-revoke {"fingerprints":["{GX cert}"]}` as acme-admin -> `200 {"succeeded":[{"fingerprint":"{GX}"}],"failed":[]}`; bootstrap read shows `revoked_at` set. Single `POST /certificates/{GX}/revoke` is refused (403) for the same caller.
- Root cause: `handlers_bulk.go:30-81`: only `authorizeCertificateMutationRequest(pd, nil)` (role) then `provider.RevokeCertificate`; no CA/tenant visibility check (no `tenant` reference in the file).

**L-07 (HIGH, write, NEW): a tenant admin can create an intermediate CA under another tenant's CA (or the default root).**
- `POST /cas {"type":"intermediate","parent_ca_id":"{GX CA}",...}` as acme-admin -> 201 (a sub-CA signed by globex's root key, auto-mapped to acme); same with `parent_ca_id` = default root CA -> 201.
- Root cause: `handlers_cas.go:~90` validates only the caller's own tenant, never `parent_ca_id` visibility.

**L-08 (HIGH, write): tenant admin rewrites global configuration.** (A01-006)
- `PUT /config/sso.oidc_jwks_json {"value":"{}"}` as acme-admin -> `204`; `GET /config` as globex-admin shows `"source":"database","updated_by":"svc-acme-admin"`. Root cause: `handlers_config.go:81-86` (`isAdminRole` only). The same applies to the global custom-role store (L-19).

**L-09 (HIGH): outbound credentials are global.**
- (a, read) `GET /credentials` as acme-admin lists `globex-cred` (id, name, type; payload never returned). (b, write) `DELETE /credentials/{GX}` -> 204. (c, write, NEW) `POST /targets {"credential_ref":"{GX cred}",...}` as acme-admin -> `201` (the egress check "credential you may use" passes for any pki-admin).
- Root cause: `handlers_credentials.go:96,176` (no tenant); credentials are stored with `tenant:""` (`handlers_credentials.go` passes `""` to `store.Create`), so `validateTargetReferences` (`handlers_targets_egress.go:111-115`, comment "Credentials are tenant "" today (FG-6a)") only refuses credentials explicitly bound to another tenant, and none are.

**L-10 (MEDIUM, read + write): notification rules and silences are global.**
- `GET /notifications/rules` (admin) lists globex's rule. `PUT /notifications/rules/{GX}` -> 200 with `"target":"evil@x.test"`. `DELETE /notifications/rules/{GX}` -> 204. `POST /notifications/silences {"target_type":"certificate","target_id":"{GX cert}"}` -> 201 (silences globex expiry alerts); `DELETE /notifications/silences/{GX}` -> 204; `GET /notifications/silences?target_type=certificate&target_id={GX}` -> 200 with the row.
- Root cause: `handlers_notifications.go:390,501,520,655-675` (no tenant); `NotificationRule` has no tenant field (`notification_provider.go:83`).

**L-11 (MEDIUM, read + write, NEW): discovery has no tenant dimension.**
- `GET /discovery/scan-jobs` as acme-admin lists globex's scan job. `POST /discovery/scan-jobs/requeue {"scan_job_id":"{GX scan}"}` -> `202` with a new `scan_job_id`; `cancel` -> 202 (job already terminal). `/discovery/endpoints` and `/discovery/summary` are one global store (an endpoint with `last_seen_at` from globex's scan appears for acme).
- Root cause: `handlers_discovery.go:38,105,183,388,467` (`tenant` only used for event bus topics at `:322,:405,:484`); `DiscoveryScanJob` has no tenant (`discovery_provider.go:123`).

**L-12 (MEDIUM/HIGH, read): audit is cross-tenant and mis-stamped.** (A01-004, OWASP-002)
- `GET /audit` as acme-auditor/admin -> other tenants' rows (`?actor_id=svc-globex-admin` -> globex template/scan/ssh rows; `?resource_id={GX cert}` -> 2 rows). Viewer now gets `403 your role does not have the audit.read permission` (FG-3: this part is fixed).
- Every row written for an authenticated tenant principal has `"tenant":"default"` (100 of 100 rows in a 500-row pull). Rows are stamped from the raw header, so an **anonymous** `GET /api-keys` with `X-Tenant: globex` filed `api-key.list denied` under `"tenant":"globex"` (OWASP-002), while a super-admin with `X-Tenant: acme` is stamped `acme`.
- Root cause: `handlers_audit.go` (no tenant filter); `audit_events.go:120` `auditRequestTenant` reads the header, not the principal.

**L-13 (MEDIUM, read): search.** `GET /search?q=globex` as acme-viewer -> 200: globex cert (id, CN), CA, template, etc. Root cause: `handlers_search.go:49,65,120` call the unscoped providers (no `tenant` reference in the file).

**L-14 (MEDIUM, read): CBOM.** `GET /cbom` as acme-viewer -> 200 with globex cert/key components (7 matches). Root cause: `cbom_export.go:156,190,222` (`listAllCertificates`, `keys.List`, `ListEndpoints`, all unscoped).

**L-15 (MEDIUM, read): SSH certificate list.** `GET /ssh/certificates` as acme-viewer -> 200 incl. globex's cert (principals, key_id, `certificate_line`). The row has a `tenant` column (`handlers_ssh_certs.go:45`) that the list handler (`:226`) ignores.

**L-16 (MEDIUM, read + write, NEW): connectors.** `GET /connectors` as **acme-viewer** -> 200 incl. globex's connector and its `config_json`; `DELETE /connectors/{GX}` as acme-admin -> 204 (gone for globex). Root cause: `handlers_connectors.go:82` (list), `:165` (delete); only the create path stamps `Tenant`.

**L-17 (MEDIUM, read + write, NEW): inventory sources.** `GET /inventory-sources` as acme-admin lists globex's source (incl. `credential_ref`); `DELETE` -> 204. Root cause: `handlers_inventory_sources.go:31,139` (create stamps `Tenant`, list/delete ignore it).

**L-18 (HIGH, read + write): user directory shared; users have no tenant.** (A01S-6)
- `GET /users` as acme-admin lists every user. `DELETE /users/{id of a user invited elsewhere}` -> 204. `POST /users/invite {"role":"pki-admin"}` as acme-admin -> 201 (a global pki-admin account). Hub A's single login user resolves to `default`, and invited users have no tenant at all, so a tenant-bound human cannot exist except through jwt/oidc claims.
- Root cause: `handlers_users.go:50,129-164`; `UserRecord` has no tenant.

**L-19 (MEDIUM, write): custom roles are global.** `POST /roles {"name":"acme-super","permissions":["ca.manage","user.manage"]}` -> 201, visible to every tenant; `DELETE /roles/{name}` -> 204. Root cause: `authz_custom_roles_handlers.go:119,199`.

**L-20 (LOW, read): counts and cursors ignore the tenant filter.** (A01-007: PARTIAL)
- `GET /cas` as acme-admin: `data` has 4 rows, `meta":{"total":7,"next_cursor":"4"}`. `GET /templates`: 3 rows vs total 7. `GET /approvals`: 1 row vs total 2. `GET /certificates` is **fixed** (total 1 = rows 1). Root cause: `handlers_cas.go:184`, `handlers_templates.go:131`, `handlers_approvals.go:107` (provider total used after post-filtering).

**L-21 (LOW, read, NEW): fleet-wide certificate counts.** `GET /protected/certs/summary` as acme-admin -> `"total":4` while acme owns 1 cert. Root cause: `handlers_protected_certs_summary.go:28` (`LoadSummary`, unscoped).

**L-22 (INFO, design): one SSH CA key for the whole hub.** `GET /ssh/ca` returns the same authority fingerprint to every tenant, and SSH certs of any tenant are signed by it. Not counted above.

## 5. What is isolated (live-verified)

- Certificate single reads (get/chain/download), single revoke, direct issue by `ca_id` or `template_id` of another tenant (403 "...not visible in your tenant"), and the certificate list (data and total).
- CA get/chain/suspend/activate/patch/delete; template get/put/patch/delete/clone; target get/patch/delete/endpoints; approval get/approve/reject; pending-action list and decide (other tenant's actions return 404 in both directions); SSH issuance against another tenant's template.
- `X-Tenant` handling for non-bootstrap principals: any header naming another tenant (`globex`, `GLOBEX`, ` globex`, `acme,globex`, and `default`) -> `401 {"error":"unauthorized","message":"invalid or missing bearer token"}` on both reads and writes; `X-Tenant: *` and the own tenant are no-ops. (The status is 401 with a misleading message instead of 403, but the request is refused, `errTenantMismatch`, `auth.go:337`.)
- Tenant administration (`/tenants`, `/tenants/ca-mapping`, `/tenants/template-mapping`) is super-admin only (403 for every API-key and JWT principal, including `pki-admin` and an API key with role `bootstrap`).
- Dashboard, dashboard actions, crypto-posture trend, PQC countdown/waves, renewal-SLO and evidence reports return 403 for every tenant principal (D-102); the tenant-scoped report family returned only the caller's data (acme: `total_certs:1`, `total_cas:1`).
- Default tenant: a `default`-tenant pki-admin cannot read acme's cert (403) or CA (403) and sees only the default root CA, the default template/cert and unmapped CAs; acme cannot read the default cert (403) or CA.
- Identity-bound tenant: a JWT with no `tenant` claim resolves to `default` (cannot read globex certs); a claim for a non-existent tenant can read nothing and cannot create a CA (400 "unknown tenant").

## 6. Escalation and global admin

- **Tenant admin -> global admin:** not achieved. `SuperAdmin` is true only for `AuthType == bootstrap` (`auth.go:~315`); a key minted by any admin (even with `role:"bootstrap"`) gets 403 on `/tenants` and on `/dashboard/summary`. `X-Tenant: *` does not unscope a tenant principal. `principal_id:"bootstrap"` is refused (400). Reaching "platform admin" is instead done sideways by minting a `default`-tenant pki-admin key (L-01), which is the platform's own tenant (hub root CA, unmapped resources).
- **Global admin (bootstrap token):** sees all tenants without a header; with `X-Tenant: acme` gets acme's view (view-as, no membership check); with an unknown tenant name gets empty lists (not rejected). A CA created with `X-Tenant: acme` is mapped to acme and its audit row is stamped `acme`; without a header it is unmapped, i.e. `default`. Dashboard works unscoped and returns 403 once a tenant is selected (D-102). Keys minted with the bootstrap token are not super-admin and cannot approve actions.

## 7. Deferred findings, one by one

| ID | Status | Exact evidence |
|---|---|---|
| A01-001 | **REPRODUCES** | `POST /api-keys {"role":"pki-admin","tenant":"globex"}` as acme-admin -> 201, key reads globex cert download 200. Also `tenant:""`/`"default"`/`"nonexistent"` -> 201. (L-01) |
| A01-002 | **REPRODUCES** (needs an approver bound to a tenant; Hub B) | acme-op proposes revoke/bulk_revoke/issue/renew on globex targets, a second acme operator approves -> 200 with `revoked:1` / `issued` / `successor`. Direct issue is refused (403), the queue bypasses it. (L-03) |
| A01-004 | **PARTIAL** | Viewer: FIXED (403 `audit.read`, FG-3). Auditor/admin: REPRODUCES (`GET /audit?actor_id=svc-globex-admin` returns globex rows). Tenant never recorded: all 100 rows `tenant:"default"`. (L-12) |
| A01-005 | **REPRODUCES** | `GET /search?q=globex`, `GET /cbom`, `GET /ssh/certificates` as acme-viewer return globex data. (L-13/14/15) |
| A01-006 | **REPRODUCES** | `GET /credentials` lists globex, `DELETE /credentials/{GX}` 204, `GET /keys` lists all, `PUT /config/sso.oidc_jwks_json` 204 (global). Delivery plugins/ceremonies: authz passes, cross-tenant content UNVERIFIED. (L-08/09) |
| A01-007 | **PARTIAL** | `/certificates` total fixed. `/cas` total 7 vs 4 rows (+ `next_cursor":"4"`), `/templates` 7 vs 3, `/approvals` 2 vs 1. (L-20) |
| A01S-3 | **PARTIAL (reachable)** | One-admin export is gated by default-on dual control (202 proposal for another tenant's CA key and `ssh-ca`). With any default-tenant approver the key is exported (Hub B: 200 BACKUP KEY, `Key-ID: key-{globex CA}`). Listing/metadata leak unchanged. (L-04/05) |
| A01S-6 | **REPRODUCES** (list, delete) | `GET /users` lists all; `DELETE /users/{id}` -> 204 for a user belonging to no acme resource; PATCH UNVERIFIED (404 even as bootstrap). (L-18) |
| OWASP-002 | **REPRODUCES** | Anonymous `GET /api-keys` with `X-Tenant: globex` -> audit row `api-key.list` / `denied` / `tenant:"globex"`; authenticated tenant calls are stamped `default`. (L-12) |
| FG-6a / FG-6b | **NOT LANDED** | Every item above that FG-6a/6b scopes is still open; no tenant checks were added since the audit. |
| A01S-4 (observed, not asked) | FIXED | SSH issuance requires `template_id` with an `ssh_policy`; another tenant's template -> 400 `unknown template_id`. |

## 8. Corrections needed in `docs/design/TENANCY_POSTURE.md`

The known-gaps table is missing: bulk-revoke (L-06), sub-CA under another tenant's CA (L-07), reuse of another tenant's credential through a target (L-09c), notification rules/silences (L-10), discovery (L-11), connectors (L-16), inventory sources (L-17), custom roles (L-19), `/protected/certs/summary` (L-21), key-grant approvals with no tenant (L-04), and that A01-002 also covers `issue`/`renew`. The "enforced" list is accurate for the items checked in section 5.

## 9. Ranked fix list for v0.10

Effort: S = under a day, M = 1-3 days, L = a week or more.

| # | Severity | Fix | Closes | Effort |
|---|---|---|---|---|
| 1 | CRITICAL | API keys: force `tenant` = caller's tenant unless the caller is super-admin; reject unknown tenants and `default` for tenant callers; filter `GET /api-keys` and authorise `DELETE /api-keys/{kid}` by tenant (`handlers_auth.go:303,393,442`) | L-01, L-02 | S |
| 2 | CRITICAL | Pending actions: resolve each action's target (cert fingerprint(s) / `ca_id` / key id) to its tenant at proposal and again at execution; refuse if it differs from `action.Tenant`; drop or tenant-check `issue`/`renew`/`rotate`; reuse `caVisibleToTenant` (`handlers_pending_actions.go:72-87`, `pending_action_exec.go:37-130`) | L-03 | M |
| 3 | CRITICAL | Keystore: map key -> CA -> tenant; scope `/keys*` and `/reports/key-custody` with `caVisibleToTenant`; make `ssh-ca` and unmapped keys super-admin only; stamp `Tenant` on key-grant `PendingAction`s and show the owning tenant to the approver (`handlers_keys.go`, `key_dual_control.go:160`, `handlers_key_custody.go`) | L-04, L-05 | M |
| 4 | HIGH | Bulk revoke/reissue: per-fingerprint CA visibility check before acting (`handlers_bulk.go`) | L-06 | S |
| 5 | HIGH | CA create: require `parent_ca_id` visible to the caller (`handlers_cas.go:~90`) | L-07 | S |
| 6 | HIGH | Gate global configuration (`/config/**`, `/delivery-plugins/**`, `/ceremonies`, custom roles, `/scep/challenges`, `/adsync`) to super-admin, or give each a tenant column | L-08, L-19, L-23 | M |
| 7 | HIGH | Credentials: write the creator's tenant, filter list/delete by it, make `validateTargetReferences` compare tenants (`handlers_credentials.go`, `handlers_targets_egress.go`) | L-09 | M |
| 8 | HIGH | Users: add a tenant to user records; scope list/invite/patch/delete; resolve a session principal's tenant from it (`handlers_users.go`) | L-18 | M |
| 9 | HIGH/MED | Audit: stamp `tenant` from the resolved principal, never the raw header; filter `GET /audit` by tenant for non-super-admins (`audit_events.go:120`, `handlers_audit.go`) | L-12 | M |
| 10 | MEDIUM | Add tenant filters to search, CBOM, SSH-cert list, connectors, inventory sources, notification rules/silences (list + mutate) using one shared helper | L-10, L-13..17 | M |
| 11 | MEDIUM | Discovery: add a tenant column to scan jobs/endpoints and scope list, requeue, cancel, summary (touches the discovery store) | L-11 | L |
| 12 | LOW | Compute `meta.total` and cursors after tenant filtering for `/cas`, `/templates`, `/approvals`; scope `/protected/certs/summary` or gate it | L-20, L-21 | S |
| 13 | LOW | Return 403 (not 401 "invalid or missing bearer token") for `X-Tenant` mismatch; update the posture doc; add live regression tests for every row in section 3 | hygiene | S |

Items 1-3 are what "treat every tenant admin as a platform admin" actually means today and should block removing the experimental gate. Items 4-5 are one-line-class fixes that the earlier audit did not cover.

## 10. UNVERIFIED / not tested

- Live SSE stream filtering (no bytes returned in the probe window); code does filter.
- `bulk-reissue` cross-tenant behaviour (same-tenant control also errors `certificate invalid`).
- `PATCH /users/{id}` (404 even for the bootstrap token).
- Content of delivery plugins, ceremonies, SCEP challenges, adsync, SCIM (no seeded data or token), agents/NHI/SPIFFE.
- `/admin/backup`, `/keys/escrow` past the dual-control grant (proposal accepted, grant redemption not exercised).
- Notification test-delivery, credential preflight, inventory source sync on a live source.
- ACME/EST/SCEP/CMP data-plane issuance per tenant (serves the default CA), the MCP server, and the UI.
- OIDC login/SAML paths (tenant claim handling was tested only through HS256 JWTs and API keys).
- Postgres mode (SQLite only).
- A01-003 (concurrent approvals) and A01S-7 (path normalisation) were out of scope.

## 11. Cleanup

Both hubs were stopped; the working dirs and scripts live only in the session scratch dir. All keys, tokens and passphrases in this run were generated for throwaway hubs and were not recorded here.
