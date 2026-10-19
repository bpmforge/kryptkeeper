# Kryptkeeper v0.21.0

This release is adoption UX plus the v1 review: a Playwright harness and
journeys, onboarding and config improvements, break-glass protection for SSO
overrides, team policies and quotas, a Requester role, on-behalf-of requests,
tenant-aware single-use agent enrollment, WCAG tooling and an ACR, migration
playbooks, a whole-UI UX review, and a v1 security and code-health scan. It is
feature group W33 of the v1.0 release train (26 of 34 tickets `done`, 6
`blocked`, 2 `todo`) and is the last release before the v1.0 gate. Decisions:
D-195 to D-204.

## Upgrade notes (read first)

- **Migrations 000320 to 000324 run on upgrade (both engines):** `team_policies`
  (000320), `team_request_counters` (000321), `approval_on_behalf_of` (000322),
  `agent_enrollment_tokens` tenant column (000323: only adds `tenant_id` to the
  v0.17 table from 000240, D-198), `user_prefs` (000324).
- **Unmounted `/api/` paths now return 404 JSON** instead of the 200 text banner
  (or 405 on POST). With SCEP off, `GET /api/v1/scep/challenges` used to answer
  200 text/plain. Clients that treated 200 as "feature present" must handle 404.
- **A fresh hub starts with zero CAs.** With no CA, no
  `KRYPTKEEPER_DEFAULT_CA_ID` and `KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT` off, the hub
  logs `[FIRST-RUN]` and starts so the onboarding wizard can create the root,
  instead of exiting. ACME, EST, CMP and WSTEP answer 503 `no CA configured yet;
  create a root CA` until one exists. The listener serves an ephemeral
  self-signed certificate (never plain HTTP) until a CA can issue its
  certificate; **SCEP and XCEP need a restart after the root exists** (D-197).
- **Team policy semantics:** no policy row = unrestricted; empty allow-list = no
  restriction on that axis; `max_validity_days` 0 = no cap; `monthly_quota` 0 =
  unlimited. Loosening (delete, emptying or adding to a list, raising a cap or
  quota) goes through the pending-action queue, proposer not approver; lookup
  errors fail closed (503). A non-admin can read only its own team's policy
  (D-195, D-196). New issuance refusals use specific 403 codes.
- **On-behalf-of requests always need approval,** are checked against the
  delegator's team policy and quota, and the delegate cannot approve (D-199).
  The new fixed **Requester role** has `certificate.read` and `certificate.issue`
  and sees only Request and My Requests (D-201).
- **SSO overrides are guarded.** A `sso.oidc_*` override is refused (409, audited)
  unless an enabled local admin exists and the IdP discovery probe passes (https
  only, no redirects, no loopback, link-local or metadata addresses, 3 s, 1 MiB).
  In oidc mode a local break-glass session still authenticates (D-200).
- **Agent enrollment** uses the v0.17 tokens: tenant scoped, a per-IP rate limit
  on `/agent/register` (429), 401 when no credential is sent and one identical
  403 for unknown, used, expired or revoked tokens. The agent reads
  `KRYPTKEEPER_ENROLL_TOKEN` from the environment or its env file only (never
  argv). Open self-registration stays off (D-198).
- **Security fixes with behaviour changes (v1 scan, `docs/security/V1_SCAN_2026-10-17.md`):**
  - Tenant gates fail closed when the tenant store is unavailable under
    `MULTI_TENANCY`, including certificate list and search (D-202).
  - Agent, NHI identity and SPIFFE SVID admin APIs are **global super-admin only
    under multi-tenancy**; tenant admins lose fleet visibility until those tables
    get a tenant column (D-203).
  - SCIM can never assign `break-glass`, `bootstrap` or `mcp-agent`; `pki-admin`
    and `super-admin` need `SCIM_ALLOW_ADMIN_ROLES=true` (default off). Under
    multi-tenancy SCIM touches only default-tenant users (D-204).
  - Code-signing inventory and policy-check are tenant scoped (F1); one vote per
    physical approver so a delegate cannot vote twice (F2); `/reports/change-audit`
    needs `audit.read` (F5); approval reject needs the same role as approve (F8);
    cookie-authenticated writes need a same-origin check (F9).
  - F5, Citrix and Kubernetes push use the egress-guarded client and require an
    `https` `base_url` (M-1); OIDC runtime fetches use the egress guard (M-2); the
    SAML ACS body is capped at 512 KB; evidence-pack recipients are validated and
    list limits capped.
  - The dashboard CSP is no longer `frame-ancestors` only.
- **UI and API shape:** the UI uses a navigation drawer below the `md`
  breakpoint, and an empty PQC migration roadmap now encodes `items: []`, not
  `null`.
- `docs/openapi.yaml` `info.version` reads `0.12.0` at the time of writing; release
  prep must bump it or `scripts/check-spec-version.sh` fails the release (D-182).

## New

- **Browser E2E:** a Playwright harness against a compose hub (W33-01) with
  journeys for first-run wizard to first certificate to target setup (W33-02), a
  role matrix with a bulk revoke/reissue smoke (W33-10) and adding agent and
  agentless Linux targets (W33-26).
- **Onboarding and config:** onboarding dismissal stored per user plus an optional
  SSO and notifications step (W33-03); the config registry covers SAML, SCIM and
  key-backend settings with env/override source badges in Integrations (W33-04,
  W33-05); a Keycloak harness for OIDC and SAML login against a real IdP (W33-07).
- **Team self-service:** policy store and admin API (W33-20), enforcement at
  issuance (W33-21), Requester role and My Requests page (W33-22), on-behalf-of
  requests (W33-23). Agent exchange client and UI token mint flow (W33-24,
  W33-25).
- **Accessibility:** `eslint-plugin-jsx-a11y` (W33-11); an axe sweep of every
  route in light and dark at 375/768/1440 gated in CI (W33-12); keyboard-only
  journeys and a 44x44 target check (W33-13); text alternatives and non-color
  cues for charts and grade badges (W33-14, W33-31); a responsive navigation
  drawer (W33-34).
- **Docs and trust:** `security.txt` (RFC 9116) and a corrected supported-versions
  table (W33-08); migration playbooks for Venafi TPP, DigiCert CertCentral,
  Keyfactor/EJBCA and Vault PKI mounts (W33-16 to W33-18, `docs/guides/migrate-from-*.md`,
  `replace-adcs.md`); an ACR/VPAT 2.5 (W33-15, see Pending).
- **v1 UI/UX review** (17 commits, `git log 74b87483 ^1d47d6dc`): readable names,
  dates and states in place of raw values on estate, ops, admin and report pages;
  theme-token fixes; a login page with an `h1`; an access review that opens on
  the current campaign; a `humanizeEnum` helper; formatted validity dates on
  certificate detail; a demo-data seed script and screenshot-tour recipe.
- **v1 security scan:** 9 numbered findings (F1 to F9), two medium egress items
  (M-1, M-2) and low items fixed, with adversarial re-review of each fix.
  Tools: `govulncheck` 0 called vulnerabilities on the shipping toolchain go1.26.9;
  `npm audit` production tree 0 (dev tree 32 to 7, remaining have no upstream
  fix); gitleaks hits all test fixtures; `go test -race` no data races.

## Decisions

D-195 to D-204. D-203 and D-204 are `locked (vetoable)` in `docs/DECISIONS.md`.

## Pending human runs and blocked tickets (not done)

- **W33-15 blocked, ACR/VPAT:** published from automated evidence only
  (`docs/release/ACR_VPAT_v0.21.md`, 3 Supports, 14 Partially Supports, 31 Not
  Evaluated, 7 Not Applicable). The manual VoiceOver/NVDA pass is PENDING-RUN and
  CI run links in the report are PENDING-RUN. It is a self-assessment, not a
  third-party audit, and says `v0.21.0-pending`.
- **W33-19 blocked, ADCS cutover:** `scripts/migration-verify.sh` and the seeded
  200-certificate test pass; the rehearsal record
  (`docs/release/ADCS_CUTOVER_REHEARSAL_v0.21.md`) is PENDING-RUN and needs a
  human with a Windows AD CS lab. Import alert events are not built.
- **W33-09 blocked, release workflows:** the reproducible double build was
  verified locally (4 Linux binaries match). The post-publish `release-verify` and
  `promote-latest` jobs only run on a real tag push and have not run.
- **W33-27 blocked, proof pack:** FIPS statement and control mapping published;
  the CMVP certificate number is not recorded (human).
- **W33-28 blocked:** competitive matrix published (spot-check before external
  use); reference customers 0 of 3, owner and date need a human.
- **W33-29 blocked, independent pentest:** not commissioned; vendor, budget and
  window are human. No pentest result is claimed.
- **Keycloak SSO live run (W33-07): PASS,** 39 passed 0 failed (OIDC, SAML, SCIM)
  on 2026-10-17 (`docs/release/LIVE_RESULTS_KEYCLOAK_v0.21.md`).

## Known gaps

- W33-30 (todo): SSH credential preflight for `ssh_key` credentials; needs a
  security design for host-key pinning and SSRF limits.
- W33-33 (todo): `POST /certificates/bulk-reissue` renews with an empty CSR and
  the CA provider rejects every item. Bulk reissue does not work.
- W33-32 follow-ups: SCEP/XCEP lazy CA, TLS listener refresh without restart,
  dashboard nginx restart after root creation.
- Scan residuals, accepted: SCIM does not inspect custom roles and `pki-operator`
  stays assignable; the refresh token is in sessionStorage; `/api/v1/meta` is
  unauthenticated and `/metrics` is open unless a bearer is configured;
  `docker-compose.override.yml` defaults `POSTGRES_PASSWORD` to `changeme`; base
  images are pinned by tag, not digest.
- Scan disconnected features: retired CA key destruction never runs (needs an
  owner decision), the NHI authorizer is not wired (D-150), the audit archive has
  no restore handler or CLI, the agent HTTP-01 port preflight is not enabled,
  scanner requeue drops custom ports, tenant never appears in structured logs.
