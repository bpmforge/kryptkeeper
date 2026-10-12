# Live probes (local hub from the RC2 artifact, plain HTTP, random secrets)

Hub: `dist/kryptkeeper_0.9.0-rc.2_darwin_arm64/kryptkeeper` (go1.26.9), `KRYPTKEEPER_TLS_DISABLE=true`,
`APP_CERTIFICATE_PROVIDER=ca`, fresh sqlite data dir, `audit provider: db (default)`. Secrets (pepper, keystore passphrase,
signing secret, bootstrap token, API-key pepper, login password) were generated per run and never printed or committed.
Principals: env login admin (pki-admin session) and four config API keys (`APP_API_KEYS_JSON`, token `kk_<kid>_<secret>`,
verifier = HMAC-SHA256(pepper, secret)): viewer, discovery-operator, pki-operator, pki-admin. Stopped afterwards.
Transcripts (tokens redacted): `raw/live_probe1..4.txt`. A trusted-proxy CIDR of 127.0.0.0/8 was set only so the flood
probe could rotate source addresses.

| Probe | Result |
|---|---|
| **A-01** discovery-operator POST /targets with `auto_renew:true` + nonexistent credential | **403** |
| discovery-operator POST with `auto_renew:true` + a real credential id (created by admin) | **403** |
| discovery-operator POST `credential_ref` only (auto_renew false) | **403** |
| discovery-operator PATCH a plain target: `auto_renew`, `credential_ref`, `plugin_id` | **403 / 403 / 403** |
| discovery-operator PATCH an admin-armed target: `host`, `verify_host_port` | **403 / 403** |
| discovery-operator POST /targets with `install_mode=plugin` + `plugin_id` | **403** (needs certificate.renew) |
| `//targets`, `/targets/../targets`, `/TARGETS` as discovery-operator | 403 each (write gate and handler) |
| pki-operator POST /targets (plain and armed) | 403 (no `discovery.manage`) |
| discovery-operator plain target, no egress fields | 201 (still allowed, inert) |
| admin POST armed target with nonexistent credential | **400** "credential_ref does not name a credential you may use" |
| admin POST armed target with real credential | 201 (stamped) |
| discovery-operator GET /credentials | 403 "admin role required" |
| Audit: 5 `target.create` denied rows for the discovery-operator with `needs=... fields=...` | present, via GET /audit |
| **A-04** `verify_host_port` = 169.254.169.254:80, 127.0.0.1:22, [::1]:443, localhost:8080, 0.0.0.0:443, [::ffff:127.0.0.1]:443 | **400** each, also as discovery-operator |
| `10.0.0.1:443` and `169.254.169.254.nip.io:443` | 201. By design: RFC1918 is a valid managed host; a hostname is judged at dial time on the resolved address (`HubVerifier`), covered by unit test, not dialed live |
| **A-02** `renewal_threshold_days` 3650 / 89 | **400** / 201 |
| **B-01** bootstrap token approves a pending action | **403** "the bootstrap token and keys minted with it ... cannot approve" |
| **B-01** pki-admin key minted with the bootstrap token approves | **403** (same message) |
| proposer session approves own; key minted by the proposer approves | 403 / 403 |
| **B-02** key `principal_id` = `probe-admin` (login subject) / `bootstrap` | **400** / **400** |
| second human (config key `svc-pki-admin`) approves the escrow grant | 200 `export_granted` |
| redeem the proposer's grant as: third admin's key, bootstrap-minted key, the approver, the proposer's own minted key | **403 x4** "belongs to a different principal" |
| redeem as the proposer's own session | 200 (bundle redacted in transcript); replay **403** "single-use" |
| **U-1** GET /users: viewer, discovery-operator, pki-operator / admin | **403 x3** / 200 |
| pki-operator mints a pki-admin key | 403 (FG-3 holds) |
| viewer GET /audit | 403 |
| **B-03 residual** 2 MiB JSON: /credentials, /certificates, /templates, /pending-actions, login (unauth) | **413** |
| 2 MiB JSON: /targets, /users/invite, /tenants, /notifications/silences | 400 (rejected, but still 400 and read in full; B-03 residual) |
| Login KDF flood: 80 concurrent wrong-email logins, rotating source | all 401, max 0.32 s; /health 0.3-0.5 ms and authenticated GET unchanged; RSS 327.7 MB to 328.2 MB |
| Login limiter, one source, 14 bad logins | 10x 401 then 429 |
| Headers on /api | nosniff, X-Frame-Options DENY, CSP `frame-ancestors 'none'`, Referrer-Policy no-referrer, Cache-Control no-store |
| Bootstrap token as bearer | accepted as pki-admin (documented), but cannot approve |

## Not exercised live (the probe was inconclusive, a unit test is cited instead)
- **A-03**: pki-operator POST /renewal/execute with an `install` override returned **404** (the certificate lookup runs before
  the profile check), so the refusal was not reached. Cited: `TestRenewalExecuteInstallOverrideNeedsAdmin`,
  `TestInstallProfileForCaller`.
- **B-03**: `/spiffe/workload-svid` returned **503** (SPIFFE not configured). Cited: `TestWorkloadSVIDRejectsOversizedBody` (413).
- **C-01**: not run live. Cited: `ca/name_policy_test.go:131-133` (CN-only, default flags).
- **A-04 dial**: the post-install verify dial needs a real install target. Cited: `TestHubVerifierRefusesLoopbackAndMetadata`.
- Scheduler pushes, stamp re-verification against a real user store, SAML/OIDC, SCIM, SIEM sinks, Postgres, HA: need devices or
  services not present here; covered by `egress_stamp_test.go`, `renewal_push_sweep_test.go`, `siem_actions_test.go`.
- The login-subject path in the probe hub has an empty user table (`GET /users` admin: 0 items), so the user-store branch of
  `principalIDReserved` was not exercised live.
