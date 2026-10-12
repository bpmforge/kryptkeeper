# Analyst report — full UI walk, 2026-07-31

All **31** sidebar destinations were driven against the **production bundle on
the real backend** (`ui/dist` on :5174, API :8080, `APP_CERTIFICATE_PROVIDER=ca`),
with a real PKI on screen. Not `npm run dev`, which serves MSW fixtures.

Each screen was measured with the same probe, so the rows below are comparable
rather than impressionistic: header shape, control count, unnamed controls,
table rows, empty-state text, error text, and per-request HTTP status from
`PerformanceResourceTiming.responseStatus`.

**Liveness.** The access token lives 900s and nothing consumes the refresh
(S-38), and it expires into clean, instructive *empty states* that read exactly
like "this screen has no data". Every row therefore carries a `navCount`
assertion — an authenticated `pki-admin` sees 31 nav items — and any screen not
reporting 31 was discarded and recaptured, never reasoned about.

Findings are ranked **broken > misleading > inconsistent > cosmetic**. A screen
that lies confidently is worse than one that is ugly.

## Correction to the earlier review

`UI_REVIEW_2026-07-31.md` finding #7 claimed three icon-only buttons on `/cas`
expose no accessible name. **It does not reproduce.** A full button inventory of
that screen returns 12 controls, every one carrying text, none containing an
`svg`. That finding came from an accessibility-tree snapshot taken in a
different session state and should be struck.

A real, different defect sits in the same place — see I-4.

## Broken

### B-1. `/reports/algorithm-sunset` renders a blank page

The entire document is empty: `#root` innerHTML is 0 bytes, `navCount` is 0, the
viewport is solid black. All three API calls returned **200**. The console shows:

```
TypeError: Cannot read properties of undefined (reading 'banned_now')
```

`ui/src/pages/AlgorithmSunset.tsx:79` reads `report.sunset_summary.banned_now`.
The server returns that object as **`summary`**, not `sunset_summary`.

This is one endpoint with **three mutually incompatible definitions**:

| Source | Summary field | Group recommendation field |
|---|---|---|
| Go API (verified live) | `summary` | `recommended_replacement` |
| `AlgorithmSunset.tsx:21` | `sunset_summary` | `recommended` (line 14) |
| `mocks/fixtures.ts:436` | neither — has `items[]`, no `groups` | `action` |

Fixing `sunset_summary` alone still leaves `g.recommended` (line 141) rendering
`undefined`, and the page would still crash against the MSW fixture, whose shape
matches neither of the other two.

Why nothing caught it: `lib/api.ts:410` types the response
`ApiDataResponse<Record<string, unknown>>`, so the page's
`as SunsetData` cast is unchecked — the type is a hand-written assertion that
was never compared to the server. `grep` across `src/` and `test/` finds **zero
tests** referencing this page. It has never been rendered by anything, against
either backend.

**Fix:** derive the type from `generated/api-types.ts` rather than hand-rolling
it, drop the `Record<string, unknown>` escape hatch, correct the fixture to the
server's shape, and add a render test.

### B-2. One page's render error blanks the whole application

B-1's blast radius is the point. A property read in a leaf report component
unmounted the router, the sidebar, and the header. There is no error boundary
between a page and the app shell, so any future shape drift on any of 31 screens
produces the same black rectangle with no message and no way back.

**Fix:** an error boundary per routed page that keeps the shell mounted and
renders the existing `StateMessage tone="error"` — a component this page already
imports (line 4) for the `q.error` case, which never fires because the failure
is in render, not fetch.

### B-3. The Issuance Velocity chart draws nothing over real data

"Daily Issuance — Last 30 Days" is roughly 250px of empty panel under the
caption "Bar height proportional to daily count", while 4 certificates were
issued that same day. The API does return the data — `daily_buckets` is
populated and the KPI row above reads 4 / 4 / 4.

Two defects in one panel: no bar renders, and the payload starts at
**2026-05-03** — about 90 days — under a heading that says **30**.

### B-4. Users are read from an in-memory store, so real accounts are invisible

`/users` shows **"No users found"**. The database holds two active accounts:

| id | email | role | active |
|---|---|---|---|
| `…000103` | `ci-seed-admin@example.com` | **pki-admin** | 1 |
| `…000104` | `ci-seed-operator@example.com` | pki-operator | 1 |

`NewUserProviderFromEnv()` (`internal/bootstrap/user_provider.go:29`) returns
`&fileUserProvider{}` for every value of `APP_USER_PROVIDER` except the literal
`"db"`. The default deployment therefore serves user management from an
in-memory dev adapter while login and the database use the real store.

Two consequences: an operator cannot see, audit, or revoke an existing
**pki-admin** account, and any user invited through the UI is lost on restart.

**Fix:** default to the DB provider and make the file adapter opt-in, or refuse
to start when the configured provider cannot see the accounts login authenticates.

## Misleading

### M-1. CI seed data ships to production in an ordinary migration

`internal/db/migrations/{sqlite,postgres}/000007_seed_baseline_data.up.sql`
declares its own purpose in its header — *"deterministic seed data for CI/test"*
— and is an ungated member of the main migration sequence. It runs on every
install. It inserts a notification policy, a team, the two privileged users
above, an API key, a root CA, and a certificate.

Verified in the live database:

```
api_keys:  ci-seed-api-key | prefix kk_ci_ | scopes ["read:certificates"]
           key_hash = 64 'a' characters
certificates: 1 row — fingerprint aaaa…aaaa
certificate_authorities: ci-seed-root-ca | status=active
```

The key hash is a placeholder, so the credential is almost certainly inert — but
it is an active API-key row that no operator can see or revoke through the UI. A
PKI product should not seed a fake root CA and a fake certificate into a real
trust store, and should not create privileged accounts operators cannot list.

This is the upstream cause of M-2, M-3 and M-5.

**Fix:** gate the migration behind an explicit seed flag, or move it to a
test-only migration path.

### M-2. Inventory and reports disagree on how many certificates exist

`GET /api/v1/certificates` returns **3**. `crypto-posture` and `expiry-timeline`
both report `total_certs: 4` with `algorithm_breakdown {ECDSA: 3, RSA: 1}`. The
extra one is the seed certificate — `algorithm-sunset` lists its fingerprint as
`aaaa…aaaa`.

Adjacent screens state different totals, and neither says which is authoritative.
The reports also count a record the inventory will not display, so a user cannot
reconcile the difference from the UI at all.

### M-3. CA status is stored, not derived, so an expired CA stays "active"

`ci-seed-root-ca` is `status=active` in the database while its certificate has
expired — which is why CA Health renders a green **active** badge beside a red
**Expired** in the same row (prior finding #1, now root-caused). Nothing
recomputes status from validity, so any CA that expires in place keeps
advertising itself as healthy indefinitely.

### M-4. Anomaly detection fires on a four-certificate dataset

Issuance Velocity renders a full amber warning panel — "Anomaly detected ·
Unusual issuance spikes on: 2026-07-31" — for 4 certificates issued on the day
the system was set up. A detector with no minimum-sample floor makes the warning
channel meaningless before there is anything to detect.

### M-5. Compliance figures are computed over contaminated data

`pqc_score_percent: 75`, `grade_distribution {A:1, B:3}` and
`risk_breakdown {medium:3, low:1}` all include the seed certificate. Crypto
Posture and Compliance Evidence present these as posture, and Compliance
Evidence maps them to SOC 2, PCI DSS 4.0.1 and NIST SP 800-57. Seed rows
inflating a compliance artifact is the most consequential form of M-1.

### M-6. Session expiry degrades into plausible-looking empty screens

Already filed as **S-38** and unchanged; restated because it is the trap this
audit had to engineer around. Confirmed again here: login returns
`expires_in: 900` **and** a `refresh_token`, and nothing consumes the refresh.

## Inconsistent

### I-1. Three header shapes, split by page author rather than by section

Now counted across all 31 rather than sampled:

| Shape | Count | Examples |
|---|---|---|
| Eyebrow + H1, no icon | 12 | Certificates `INVENTORY`, CAs `TRUST`, Audit `EVIDENCE` |
| Icon + H1, no eyebrow | 13 | Keys, SPIFFE, CA Health, Tenants, Integrations |
| H1 only | 5 | Dashboard, Settings, Crypto Posture, Code Signing, Automation |
| n/a — crashes | 1 | Algorithm Sunset |

The split does not follow the sidebar grouping. Within **Operations** alone,
Certificates/CAs/Templates/Approvals carry eyebrows, Keys/SPIFFE/Pending Actions
carry icons, and Code Signing carries neither. Whatever the intended rule, 18 of
30 rendering screens do not follow the most common one.

### I-2. Raw UUIDs are presented as human labels

Issuance Velocity groups by CA, Team and Template and labels all three with raw
identifiers — `b7f9fcfc-cb40-4b36-8067-ace5662be49e`,
`00000000-0000-0000-0000-000000000102`,
`tpl-drill-template2-1784468345948447000`. Expiry Timeline does the same under
"By Certificate Authority", each with a **Renew** button beside it. The names
exist; the join to them does not. Compounded by the known `display_name`
drop on CA create (prior finding #6), every CA surface shows machine identifiers.

### I-3. Empty states range from excellent to bare label

The good standard is already set — Settings names the exact variables
(`SIEM_WEBHOOK_URL`, `SIEM_SYSLOG_ADDR`), Approvals explains that templates with
`require_approval` route requests there, Change Audit says "No mutation events in
the selected window". Others stop at a label: "No SVIDs yet", "No users found",
"No code-signing certificates found", "No managed targets yet".

The bare ones are where a user most needs the next step, and B-4 shows the risk
directly: "No users found" is not empty, it is wrong.

### I-4. CA rows are buttons whose accessible name is run together

The three CA rows are `<button>` elements whose text content concatenates
without separators, so the accessible name is
`"ci-seed-root-caroot · software…"`, `"acme-rootroot · softwareactive"`,
`"acme-tls-issuingintermediate…"`. Sighted users see the visual layout; a screen
reader announces the run-together string. This replaces the struck finding #7.

### I-5. Raw locale timestamps leak into report headers

Crypto Posture leads with "Generated 7/31/2026, 5:31:49 PM · 4 certificates" and
Expiry Timeline with "4 certificates · 7/31/2026, 5:33:47 PM" — default
`toLocaleString()` output, seconds included, in a product that formats dates
consistently elsewhere.

## Cosmetic

Carried forward from `UI_REVIEW_2026-07-31.md`, still valid: Strength graded
"Acceptable" over an Algorithm of `–` (#2); `Reset` sized like a primary action
at ~345px (#3); disabled controls at near-enabled contrast on dark with no
stated precondition (#5); `display_name` discarded on CA create (#6).

## What is working

Worth stating plainly, because most of this walk was uneventful. 30 of 31
screens render, and **zero** returned a 4xx or 5xx across the whole sweep — every
defect above is a client-side or data-modelling problem, not a broken endpoint.
The page scaffold, semantic colour, split inspect layouts and KPI rows are
coherent and clearly deliberate. Audit Evidence carries 31 rows and 39 controls
without feeling crowded. The best empty states are genuinely instructive.

## Coverage

All 31 sidebar destinations, `navCount: 31` verified on each except where noted.

| # | Path | Rows | Result |
|---|---|---|---|
| 1 | `/` | – | OK |
| 2 | `/certificates` | 3 | OK |
| 3 | `/cas` | 3 CAs | I-4 |
| 4 | `/keys` | 3 | OK |
| 5 | `/code-signing` | 0 | I-3 |
| 6 | `/spiffe` | 0 | I-3 |
| 7 | `/templates` | 4 | OK |
| 8 | `/approvals` | 0 | OK — instructive empty state |
| 9 | `/pending-actions` | 0 | OK — instructive empty state |
| 10 | `/discovery` | 6 | OK |
| 11 | `/search` | 0 | OK |
| 12 | `/crypto-posture` | 5 | M-5, I-5 |
| 13 | `/reports/ca-health` | 3 | M-3 |
| 14 | `/reports/expiry-timeline` | – | I-2, I-5 |
| 15 | `/reports/revocation-activity` | 0 | OK |
| 16 | `/reports/issuance-velocity` | – | **B-3**, M-4, I-2 |
| 17 | `/reports/change-audit` | 0 | OK |
| 18 | `/reports/compliance-evidence` | – | M-5 |
| 19 | `/reports/algorithm-sunset` | – | **B-1, B-2 — blank page** |
| 20 | `/reports/pqc-migration` | 4 | OK |
| 21 | `/alerts` | 3 | OK |
| 22 | `/audit` | 31 | OK |
| 23 | `/history` | 3 | OK |
| 24 | `/users` | 0 | **B-4** |
| 25 | `/tenants` | 0 | OK |
| 26 | `/agents` | 0 | OK |
| 27 | `/targets/setup` | 0 | OK |
| 28 | `/targets/renewal-policy` | 0 | I-3 |
| 29 | `/automation` | 0 | I-3 |
| 30 | `/integrations` | 0 | OK |
| 31 | `/settings` | 0 | OK — best-in-class empty state |

Not covered: the 8 `:id` detail routes, `/certificates/issue` beyond step 1, and
`/login`, all reviewed previously. No interaction beyond navigation was
performed — no mutations were issued during this walk.

## Proposed tickets

| Severity | Finding | Suggested points |
|---|---|---|
| Critical | B-1 Algorithm Sunset blank page + three-way shape drift | 3 |
| Critical | B-4 Users read from in-memory provider by default | 5 |
| High | B-2 No per-route error boundary | 3 |
| High | M-1 CI seed migration runs in production | 5 |
| High | M-3 CA status stored rather than derived from validity | 3 |
| Medium | B-3 Issuance chart draws nothing; 30-day label over 90-day data | 3 |
| Medium | M-2 Inventory and reports disagree on certificate count | 2 |
| Medium | I-2 Raw UUIDs as human labels | 3 |
| Low | M-4 Anomaly detection with no minimum sample | 1 |
| Low | I-1 Header shape inconsistency across 18 of 30 screens | 2 |
| Low | I-3 Empty-state quality; I-4 CA row names; I-5 raw timestamps | 3 |

Already filed and unchanged: **S-36** (certificate mutations authorize on a
hardcoded principal), **S-37** (denied mutations explain nothing), **S-38**
(session expiry).

## Reproducing

```bash
APP_CERTIFICATE_PROVIDER=ca APP_AUTH_LOGIN_ENABLED=true \
APP_AUTH_LOGIN_ROLE=pki-admin KRYPTKEEPER_DATA_DIR=/tmp/kk-guide-data ./dist/kryptkeeper

npm --prefix ui run build && node serve-real.mjs   # NOT `npm run dev` — that is MSW
```

`npm run dev` shows 247 certificates and 84 endpoints that do not exist, and
accepts any credentials. Review against the production bundle or you are
reviewing `src/mocks/fixtures.ts`.
