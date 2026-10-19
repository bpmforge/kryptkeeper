# Kryptkeeper UI: APP_MAP

Page-graph and element inventory for the screenshot tour and user guide. Branch `qa/v1-final`. Crawled 2026-10-17 against a real seeded hub (`dist/kryptkeeper`, production bundle via `scripts/dev/serve-real.mjs`, 1440x900 for pages, 375x812 for mobile), signed in as the password-login admin (role `pki-admin`). Mutating requests were blocked at the network layer during the crawl (0 writes executed).

**Counts:** 124 states, 1043 inventoried element rows (1380 raw interactive nodes before row-collapsing), 88 destructive/guarded rows, 61 route declarations in `ui/src/App.tsx`.

## How to read this

- A **state** is `(route, active tab, open modal, pane/panel)`. State id is `S-<key>`. Element id is `E-<key>-<n>` and is stable: never reuse or renumber an id; append new ids at the end of the state.
- Row-repeating controls (table rows, per-row action buttons) are collapsed to one row with a `<row>` / `<item>` name and an `x N` multiplicity.
- `req` marks inputs with `required`/`aria-required`. Inputs shown with no name have no programmatic label (see Bugs in the hand-off report).
- Detail routes (`/certificates/:fingerprint`, `/cas/:id`, `/discovery/endpoints/:id`, `/history/:actionId`, `/audit/:id`, `/alerts/deliveries/:id`) render the list page with a detail card; they are separate states (`*-detail`).
- Data-dependent pages (needs more than the demo seed) are tagged in section 5.

## 0. Route table (all 61 declarations in App.tsx)

| # | Path | Component / behaviour | State key(s) |
|---|---|---|---|
| 1 | `/login` | Login (outside AppShell) | login |
| 2 | `/*` | AppShell wrapper (auth gate: redirects to /login without session) | shell, shell-mobile, palette |
| 3 | `/` | Dashboard: What needs a human | dash |
| 4 | `/inbox` | Approvals inbox | inbox |
| 5 | `/alerts` | Alerts & Notifications | alerts |
| 6 | `/search` | Global Search | search |
| 7 | `/ssh-certificates` | SSH certificates | ssh |
| 8 | `/nhi` | Machine Identities | nhi |
| 9 | `/reports/anomalies` | Issuance anomalies | anomalies |
| 10 | `/ct-findings` | CT Findings | ct |
| 11 | `/automation` | Automation | automation |
| 12 | `/targets/setup` | Target Setup | targets |
| 13 | `/targets/renewal-policy` | Renewal Policy | renewal |
| 14 | `/renewal/rollout-groups` | Rollout Groups | rollout |
| 15 | `/delivery-plugins` | Delivery Plugins | plugins |
| 16 | `/agents` | Satellite Agents | agents |
| 17 | `/acme` | ACME | acme |
| 18 | `/enrollment` | Enrollment Protocols (SCEP/EST/CMP) | enroll |
| 19 | `/integrations` | Integrations | integ |
| 20 | `/certificates` | Certificates | certs |
| 21 | `/cas` | Certificate Authorities | cas |
| 22 | `/ceremonies` | Key Ceremonies | ceremonies |
| 23 | `/keys` | Key Management | keys |
| 24 | `/code-signing` | Code-Signing Inventory | codesign |
| 25 | `/spiffe` | SPIFFE | spiffe |
| 26 | `/templates` | Certificate Templates | templates |
| 27 | `/discovery` | Discovery | discovery |
| 28 | `/reports/slo` | SLOs and error budget | slo |
| 29 | `/reports/compliance-evidence` | Compliance Evidence | compliance |
| 30 | `/reports/key-custody` | Key Custody | custody |
| 31 | `/audit` | Audit Evidence (Audit Log) | audit |
| 32 | `/reports/change-audit` | Change Audit | changeaudit |
| 33 | `/history` | Action History | history |
| 34 | `/blast-radius` | Blast Radius | blast |
| 35 | `/crypto-posture` | Crypto Posture | posture |
| 36 | `/reports/pqc-migration` | PQC Migration | pqc |
| 37 | `/reports/algorithm-sunset` | Algorithm Sunset | sunset |
| 38 | `/reports/expiry-timeline` | Expiry Timeline | expiry |
| 39 | `/inventory/keys` | Cloud Keys | cloudkeys |
| 40 | `/reports/ca-health` | CA Health | cahealth |
| 41 | `/reports/issuance-velocity` | Issuance Velocity | velocity |
| 42 | `/reports/revocation-activity` | Revocation Activity | revocation |
| 43 | `/users` | Users | users |
| 44 | `/access-review` | Access Review | accessreview |
| 45 | `/policies` | Issuance policies | policies |
| 46 | `/roles` | Roles | roles |
| 47 | `/inventory-sources` | Inventory Sources | invsrc |
| 48 | `/migration` | Migration | migration |
| 49 | `/settings` | Settings | settings |
| 50 | `/tenants` | Tenants | tenants |
| 51 | `/certificates/issue` | Issue certificate wizard (step 1 of 5: CA) | issue |
| 52 | `/my-requests` | My requests | myreq |
| 53 | `/certificates/:fingerprint` | Certificates (detail card) | certs-detail |
| 54 | `/cas/:id` | CAs (detail card) | cas-detail |
| 55 | `/discovery/endpoints/:id` | Discovery (endpoint detail) | discovery-endpoint |
| 56 | `/alerts/deliveries/:id` | Alerts (delivery detail; unknown id falls back to queue) | alerts |
| 57 | `/history/:actionId` | History (detail; unknown id shows "Action not found") | history-detail |
| 58 | `/audit/:id` | Audit (detail card; unknown id shows list) | audit-detail |
| 59 | `/approvals` | Redirect to /inbox | inbox |
| 60 | `/pending-actions` | Redirect to /inbox | inbox |
| 61 | `*` | NotFound (404 inside shell) | notfound |

The table lists 61 entries, matching the 61 `path=` declarations in `ui/src/App.tsx` (including `*`, `/*`, `/login` and the 2 redirects).

## 1. State inventory

| State | Route | Tab | Modal | Pane / panel | How discovered |
|---|---|---|---|---|---|
| `S-login` | `/login` | - | - | - | router-seed (unauthenticated) |
| `S-shell` | `(every authenticated route)` | - | - | sidebar expanded | router-seed |
| `S-shell-mobile` | `(every authenticated route @375px)` | - | - | navigation drawer | viewport resize 375x812 |
| `S-palette` | `(any route; Ctrl/Cmd+K)` | - | command palette | - | keyboard shortcut |
| `S-notfound` | `*` | - | - | - | typed unknown path |
| `S-dash` | `/` | - | - | default | router-seed + sidebar nav-link |
| `S-inbox` | `/inbox` | - | - | default | router-seed + sidebar nav-link |
| `S-alerts` | `/alerts` | - | - | default | router-seed + sidebar nav-link |
| `S-search` | `/search` | - | - | default | router-seed + sidebar nav-link |
| `S-ssh` | `/ssh-certificates` | - | - | default | router-seed + sidebar nav-link |
| `S-nhi` | `/nhi` | - | - | default | router-seed + sidebar nav-link |
| `S-anomalies` | `/reports/anomalies` | - | - | default | router-seed + sidebar nav-link |
| `S-ct` | `/ct-findings` | - | - | default | router-seed + sidebar nav-link |
| `S-automation` | `/automation` | - | - | default | router-seed + sidebar nav-link |
| `S-targets` | `/targets/setup` | - | - | default | router-seed + sidebar nav-link |
| `S-renewal` | `/targets/renewal-policy` | - | - | default | router-seed + sidebar nav-link |
| `S-rollout` | `/renewal/rollout-groups` | - | - | default | router-seed + sidebar nav-link |
| `S-rollout-dlg-new-group` | `/renewal/rollout-groups` | - | New rollout group | - | modal-open (button "New group") |
| `S-plugins` | `/delivery-plugins` | - | - | default | router-seed + sidebar nav-link |
| `S-agents` | `/agents` | - | - | default | router-seed + sidebar nav-link |
| `S-acme` | `/acme` | - | - | default | router-seed + sidebar nav-link |
| `S-acme-tab-eab-keys` | `/acme` | EAB keys | - | - | tab-click |
| `S-acme-tab-provisioners` | `/acme` | Provisioners | - | - | tab-click |
| `S-acme-dlg-new-key` | `/acme` | - | New EAB key | - | modal-open (button "New key") |
| `S-enroll` | `/enrollment` | - | - | default | router-seed + sidebar nav-link |
| `S-enroll-tab-scep` | `/enrollment` | SCEP | - | - | tab-click |
| `S-enroll-tab-est` | `/enrollment` | EST | - | - | tab-click |
| `S-enroll-tab-cmp` | `/enrollment` | CMP | - | - | tab-click |
| `S-enroll-dlg-new-challenge` | `/enrollment` | - | New SCEP challenge | - | modal-open (button "New challenge") |
| `S-integ` | `/integrations` | - | - | default | router-seed + sidebar nav-link |
| `S-certs` | `/certificates` | - | - | default | router-seed + sidebar nav-link |
| `S-certs-pane-edit` | `/certificates` | - | - | inline panel: Edit | button "Edit" |
| `S-certs-dlg-import` | `/certificates` | - | Import certificate | - | modal-open (button "Import") |
| `S-cas` | `/cas` | - | - | default | router-seed + sidebar nav-link |
| `S-cas-dlg-import-external-root` | `/cas` | - | Import external root | - | modal-open (button "Import external root") |
| `S-cas-dlg-new-ca` | `/cas` | - | New Certificate Authority | - | modal-open (button "New CA") |
| `S-ceremonies` | `/ceremonies` | - | - | default | router-seed + sidebar nav-link |
| `S-ceremonies-dlg-start-ceremony` | `/ceremonies` | - | Start key ceremony | - | modal-open (button "Start ceremony") |
| `S-keys` | `/keys` | - | - | default | router-seed + sidebar nav-link |
| `S-keys-dlg-import` | `/keys` | - | Import Key Backup | - | modal-open (button "Import") |
| `S-keys-dlg-generate-key` | `/keys` | - | Generate New Key | - | modal-open (button "Generate Key") |
| `S-keys-dlg-export-backup` | `/keys` | - | Export Key Backup — app-signing-key | - | modal-open (button "Export backup") |
| `S-codesign` | `/code-signing` | - | - | default | router-seed + sidebar nav-link |
| `S-spiffe` | `/spiffe` | - | - | default | router-seed + sidebar nav-link |
| `S-templates` | `/templates` | - | - | default | router-seed + sidebar nav-link |
| `S-templates-dlg-new-template` | `/templates` | - | New template | - | modal-open (button "New template") |
| `S-templates-dlg-edit` | `/templates` | - | Edit template | - | modal-open (button "Edit") |
| `S-discovery` | `/discovery` | - | - | default | router-seed + sidebar nav-link |
| `S-discovery-dlg-new-scan` | `/discovery` | - | Queue discovery scan | - | modal-open (button "New scan") |
| `S-slo` | `/reports/slo` | - | - | default | router-seed + sidebar nav-link |
| `S-compliance` | `/reports/compliance-evidence` | - | - | default | router-seed + sidebar nav-link |
| `S-custody` | `/reports/key-custody` | - | - | default | router-seed + sidebar nav-link |
| `S-audit` | `/audit` | - | - | default | router-seed + sidebar nav-link |
| `S-changeaudit` | `/reports/change-audit` | - | - | default | router-seed + sidebar nav-link |
| `S-history` | `/history` | - | - | default | router-seed + sidebar nav-link |
| `S-blast` | `/blast-radius` | - | - | default | router-seed + sidebar nav-link |
| `S-posture` | `/crypto-posture` | - | - | default | router-seed + sidebar nav-link |
| `S-posture-dlg-open-pqc-wave` | `/crypto-posture` | - | Open PQC wave | - | modal-open (button "Open PQC wave") |
| `S-pqc` | `/reports/pqc-migration` | - | - | default | router-seed + sidebar nav-link |
| `S-pqc-pane-start-migration-wave` | `/reports/pqc-migration` | - | - | inline panel: Start migration wave | button "Start migration wave" |
| `S-sunset` | `/reports/algorithm-sunset` | - | - | default | router-seed + sidebar nav-link |
| `S-expiry` | `/reports/expiry-timeline` | - | - | default | router-seed + sidebar nav-link |
| `S-expiry-dlg-open-pqc-wave` | `/reports/expiry-timeline` | - | Open PQC wave | - | modal-open (button "Open PQC wave") |
| `S-cloudkeys` | `/inventory/keys` | - | - | default | router-seed + sidebar nav-link |
| `S-cahealth` | `/reports/ca-health` | - | - | default | router-seed + sidebar nav-link |
| `S-velocity` | `/reports/issuance-velocity` | - | - | default | router-seed + sidebar nav-link |
| `S-revocation` | `/reports/revocation-activity` | - | - | default | router-seed + sidebar nav-link |
| `S-users` | `/users` | - | - | default | router-seed + sidebar nav-link |
| `S-users-dlg-invite-user` | `/users` | - | Invite user | - | modal-open (button "Invite user") |
| `S-accessreview` | `/access-review` | - | - | default | router-seed + sidebar nav-link |
| `S-accessreview-dlg-open-campaign` | `/access-review` | - | Open campaign | - | modal-open (button "Open campaign") |
| `S-policies` | `/policies` | - | - | default | router-seed + sidebar nav-link |
| `S-policies-pane-new-policy` | `/policies` | - | - | inline panel: New policy | button "New policy" |
| `S-policies-pane-edit-policy` | `/policies` | - | - | inline panel: Edit policy | button "Edit Baseline" |
| `S-roles` | `/roles` | - | - | default | router-seed + sidebar nav-link |
| `S-roles-pane-new-role` | `/roles` | - | - | inline panel: New role | button "New role" |
| `S-roles-pane-edit-role` | `/roles` | - | - | inline panel: Edit role | button "Edit cert-owner-readonly" |
| `S-invsrc` | `/inventory-sources` | - | - | default | router-seed + sidebar nav-link |
| `S-migration` | `/migration` | - | - | default | router-seed + sidebar nav-link |
| `S-settings` | `/settings` | - | - | default | router-seed + sidebar nav-link |
| `S-settings-pane-add-cluster` | `/settings` | - | - | inline panel: Add cluster | button "Add cluster" |
| `S-settings-pane-add-endpoint` | `/settings` | - | - | inline panel: Add endpoint | button "Add endpoint" |
| `S-settings-pane-add-domain` | `/settings` | - | - | inline panel: Add domain | button "Add domain" |
| `S-settings-pane-add-cloud-source` | `/settings` | - | - | inline panel: Add cloud source | button "Add cloud source" |
| `S-tenants` | `/tenants` | - | - | default | router-seed + sidebar nav-link |
| `S-issue` | `/certificates/issue` | - | - | default | router-seed + sidebar nav-link |
| `S-myreq` | `/my-requests` | - | - | default | router-seed + sidebar nav-link |
| `S-certs-detail` | `/certificates/:fingerprint` | - | - | detail card (row selected) | row click in S-certs (or deep link) |
| `S-certs-selected` | `/certificates` | - | - | rows checked | checkbox select |
| `S-cas-detail` | `/cas/:id` | List | - | detail card | row click in S-cas / deep link |
| `S-cas-hierarchy` | `/cas` | Hierarchy | - | - | tab-click (button "Hierarchy") |
| `S-cas-dlg-update` | `/cas/:id` | - | Update CA metadata | - | modal-open (button "Update") |
| `S-cas-dlg-rekey` | `/cas/:id` | - | Re-key CA (step 1 of 3: Blast radius) | - | modal-open (button "Re-key") |
| `S-issue-2` | `/certificates/issue` | - | - | wizard step 2 | wizard Next |
| `S-issue-3` | `/certificates/issue` | - | - | wizard step 3 | wizard Next |
| `S-issue-4` | `/certificates/issue` | - | - | wizard step 4 | wizard Next |
| `S-issue-4-csr` | `/certificates/issue` | - | - | wizard step 4-csr | wizard Next |
| `S-issue-4-gen` | `/certificates/issue` | - | - | wizard step 4-gen | wizard Next |
| `S-issue-5` | `/certificates/issue` | - | - | wizard step 5 | wizard Next |
| `S-policies-dryrun` | `/policies` | - | - | Dry run form (always visible) | scroll |
| `S-nhi-dlg-propose` | `/nhi` | - | Propose machine identity | - | modal-open (button "Propose identity") |
| `S-keys-dlg-escrow` | `/keys` | - | Escrow key | - | modal-open (button "Escrow") |
| `S-keys-dlg-recover` | `/keys` | - | Recover escrowed key | - | modal-open (button "Recover") |
| `S-keys-dlg-byok` | `/keys` | - | BYOK export | - | modal-open (button "BYOK export") |
| `S-templates-dlg-draft` | `/templates` | - | Draft policy from text | - | modal-open (button "Draft policy from text") |
| `S-users-dlg-role` | `/users` | - | Change role | - | modal-open (button "Change role") |
| `S-alerts-tab-rules` | `/alerts` | Alert rules | - | - | tab-click |
| `S-alerts-dlg-newrule` | `/alerts` | Alert rules | New alert rule | - | modal-open (button "New rule") |
| `S-history-detail` | `/history/:actionId` | - | - | detail card | row click / deep link |
| `S-acme-dlg-prov` | `/acme` | Provisioners | New provisioner | - | modal-open (button "New provisioner") |
| `S-enroll-dlg-estuser` | `/enrollment` | EST | New EST user | - | modal-open (button "New user") |
| `S-enroll-dlg-cmpanchor` | `/enrollment` | CMP | Register trust anchor | - | modal-open |
| `S-enroll-dlg-pbm` | `/enrollment` | CMP | New PBM secret | - | modal-open |
| `S-discovery-endpoint` | `/discovery/endpoints/:id` | - | - | endpoint detail card | row click ("127.0.0.1") / deep link |
| `S-posture-dlg-notify` | `/crypto-posture` | - | Notify owner | - | modal-open (button "Notify owner") |
| `S-plugins-dlg-install` | `/delivery-plugins` | - | Install a delivery plugin | - | modal-open (button "Install plugin") |
| `S-targets-agent` | `/targets/setup` | Agent | - | Agent card | card click (default) |
| `S-targets-agentless-1` | `/targets/setup` | Agentless | - | agentless wizard step 1 of 6 | card click then Next |
| `S-targets-agentless-2` | `/targets/setup` | Agentless | - | agentless wizard step 2 of 6 | card click then Next |
| `S-targets-agentless-3` | `/targets/setup` | Agentless | - | agentless wizard step 3 of 6 | card click then Next |
| `S-targets-agentless-4` | `/targets/setup` | Agentless | - | agentless wizard step 4 of 6 | card click then Next |
| `S-targets-agentless-5` | `/targets/setup` | Agentless | - | agentless wizard step 5 of 6 | card click then Next |
| `S-targets-agentless-6` | `/targets/setup` | Agentless | - | agentless wizard step 6 of 6 | card click then Next |
| `S-audit-detail` | `/audit/:id` | - | - | detail card | row click |

## 2. Per-state element inventory

### S-login: Sign in

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-login-1 | textbox | Email | email | req |  |
| E-login-2 | textbox | Password | password | req |  |
| E-login-3 | button | Sign in |  |  |  |

### S-shell: App shell and sidebar

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-shell-1 | link | Skip to main content |  |  |  |
| E-shell-2 | button | Command palette trigger (⌘K) |  |  |  |
| E-shell-3 | link | Nav: What needs a human (/) |  |  |  |
| E-shell-4 | link | Nav: Approvals inbox (/inbox) |  |  |  |
| E-shell-5 | link | Nav: Alerts (/alerts) |  |  |  |
| E-shell-6 | link | Nav: Search (/search) |  |  |  |
| E-shell-7 | link | Nav: SSH Certificates (/ssh-certificates) |  |  |  |
| E-shell-8 | link | Nav: Machine Identities (/nhi) |  |  |  |
| E-shell-9 | link | Nav: Anomalies (/reports/anomalies) |  |  |  |
| E-shell-10 | link | Nav: CT Findings (/ct-findings) |  |  |  |
| E-shell-11 | link | Nav: Automation (/automation) |  |  |  |
| E-shell-12 | link | Nav: Target Setup (/targets/setup) |  |  |  |
| E-shell-13 | link | Nav: Renewal Policy (/targets/renewal-policy) |  |  |  |
| E-shell-14 | link | Nav: Rollout Groups (/renewal/rollout-groups) |  |  |  |
| E-shell-15 | link | Nav: Delivery Plugins (/delivery-plugins) |  |  |  |
| E-shell-16 | link | Nav: Agents (/agents) |  |  |  |
| E-shell-17 | link | Nav: ACME (/acme) |  |  |  |
| E-shell-18 | link | Nav: Enrollment Protocols (/enrollment) |  |  |  |
| E-shell-19 | link | Nav: Integrations (/integrations) |  |  |  |
| E-shell-20 | link | Nav: Certificates (/certificates) |  |  |  |
| E-shell-21 | link | Nav: Certificate Authorities (/cas) |  |  |  |
| E-shell-22 | link | Nav: Key Ceremonies (/ceremonies) |  |  |  |
| E-shell-23 | link | Nav: Keys (/keys) |  |  |  |
| E-shell-24 | link | Nav: Code Signing (/code-signing) |  |  |  |
| E-shell-25 | link | Nav: SPIFFE (/spiffe) |  |  |  |
| E-shell-26 | link | Nav: Templates (/templates) |  |  |  |
| E-shell-27 | link | Nav: Discovery (/discovery) |  |  |  |
| E-shell-28 | link | Nav: SLOs (/reports/slo) |  |  |  |
| E-shell-29 | link | Nav: Compliance Evidence (/reports/compliance-evidence) |  |  |  |
| E-shell-30 | link | Nav: Key Custody (/reports/key-custody) |  |  |  |
| E-shell-31 | link | Nav: Audit Log (/audit) |  |  |  |
| E-shell-32 | link | Nav: Change Audit (/reports/change-audit) |  |  |  |
| E-shell-33 | link | Nav: History (/history) |  |  |  |
| E-shell-34 | link | Nav: Blast Radius (/blast-radius) |  |  |  |
| E-shell-35 | link | Nav: Crypto Posture (/crypto-posture) |  |  |  |
| E-shell-36 | link | Nav: PQC Migration (/reports/pqc-migration) |  |  |  |
| E-shell-37 | link | Nav: Algorithm Sunset (/reports/algorithm-sunset) |  |  |  |
| E-shell-38 | link | Nav: Expiry Timeline (/reports/expiry-timeline) |  |  |  |
| E-shell-39 | link | Nav: Cloud Keys (/inventory/keys) |  |  |  |
| E-shell-40 | link | Nav: CA Health (/reports/ca-health) |  |  |  |
| E-shell-41 | link | Nav: Issuance Velocity (/reports/issuance-velocity) |  |  |  |
| E-shell-42 | link | Nav: Revocation Activity (/reports/revocation-activity) |  |  |  |
| E-shell-43 | link | Nav: Users (/users) |  |  |  |
| E-shell-44 | link | Nav: Access Review (/access-review) |  |  |  |
| E-shell-45 | link | Nav: Policies (/policies) |  |  |  |
| E-shell-46 | link | Nav: Roles (/roles) |  |  |  |
| E-shell-47 | link | Nav: Inventory Sources (/inventory-sources) |  |  |  |
| E-shell-48 | link | Nav: Migration (/migration) |  |  |  |
| E-shell-49 | link | Nav: Settings (/settings) |  |  |  |
| E-shell-50 | button | Theme: Light |  |  |  |
| E-shell-51 | button | Theme: Dark |  |  |  |
| E-shell-52 | button | Theme: System |  |  |  |
| E-shell-53 | button | Log out |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-shell-54 | button | Collapse sidebar |  |  |  |

### S-shell-mobile: Mobile navigation drawer

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-shell-mobile-1 | button | Open <item> |  |  |  |

### S-palette: Command palette

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-palette-1 | textbox | Search pages, certificates, CAs… | text |  |  |
| E-palette-2 | button | Action: Issue certificate… |  |  |  |
| E-palette-3 | button | Action: Renew certificate… |  |  |  |
| E-palette-4 | button | Action: Revoke certificate… |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-palette-5 | button | Page: <each of 21 listed pages> |  |  |  |
| E-palette-6 | button | Close (Esc) |  |  |  |

### S-notfound: 404 page

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-notfound-1 | link | Back to the dashboard |  |  |  |

### S-dash: Dashboard: What needs a human

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-dash-1 | button | Download executive one-pager PDF |  |  |  |
| E-dash-2 | button | Open <item> |  |  |  |
| E-dash-3 | button | # managed |  |  | x2 |
| E-dash-4 | button | # externally managed |  |  |  |
| E-dash-5 | button | # unmanaged |  |  |  |
| E-dash-6 | button | # unowned |  |  |  |
| E-dash-7 | button | # public |  |  |  |
| E-dash-8 | button | # other private CA |  |  |  |
| E-dash-9 | button | # self-signed Needs a decision |  |  |  |
| E-dash-10 | button | # unknown Needs a decision |  |  |  |
| E-dash-11 | button | #Active Certs# revoked not counted |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-dash-12 | button | #Expiring #dneeds renewal |  |  |  |
| E-dash-13 | button | #Expiredaction required |  |  |  |
| E-dash-14 | button | #Endpointsdiscovered |  |  |  |
| E-dash-15 | button | #Riskyendpoints |  |  |  |
| E-dash-16 | button | #Alertspending |  |  |  |
| E-dash-17 | button | CA Health |  |  |  |
| E-dash-18 | button | Expiry Timeline |  |  |  |
| E-dash-19 | button | Compliance Evidence |  |  |  |
| E-dash-20 | button | Algorithm Sunset |  |  |  |
| E-dash-21 | button | View <item> |  |  |  |
| E-dash-22 | button | <CA row> |  |  | x2 |
| E-dash-23 | button | Acme Issuing CAintermediate · 16 certsactive |  |  |  |
| E-dash-24 | button | Acme Internal Services CAintermediate · 9 certsactive |  |  |  |
| E-dash-25 | button | Full log → |  |  |  |
| E-dash-26 | button | # expired |  |  |  |
| E-dash-27 | button | # expiring in #d |  |  |  |
| E-dash-28 | button | # risky endpoints |  |  |  |

### S-inbox: Approvals inbox

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-inbox-1 | button | Refresh |  |  |  |
| E-inbox-2 | select | Type | select |  | options: All, Certificate approvals, Pending actions |
| E-inbox-3 | select | Age | select |  | options: Any, > 1h, > 24h, > 72h |
| E-inbox-4 | button | Approve |  |  | x6; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-inbox-5 | button | Reject |  |  | x6; SKIPPED: destructive (firewalled; never executed by cartographer) |

### S-alerts: Alerts & Notifications

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-alerts-1 | button | Delivery queue |  |  |  |
| E-alerts-2 | button | Alert rules |  |  |  |
| E-alerts-3 | select | Notification test channel | select |  | options: Email, Slack, PagerDuty, Webhook |
| E-alerts-4 | textbox | Notification test target | text |  |  |
| E-alerts-5 | textbox | Notification test message | text |  |  |
| E-alerts-6 | button | Send test delivery |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-alerts-7 | select | Filter deliveries by status | select |  | options: All statuses, Queued, Sending, Sent, Failed, Acknowledged, Retrying |
| E-alerts-8 | select | Filter deliveries by channel | select |  | options: All channels, Email, Slack, PagerDuty, Webhook, ITSM ticket |
| E-alerts-9 | button | ← Previous |  |  | disabled until preconditions met |
| E-alerts-10 | button | Next → |  |  | disabled until preconditions met |

### S-search: Global Search

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-search-1 | textbox | Search all inventory | text |  |  |
| E-search-2 | button | Clear |  |  |  |

### S-ssh: SSH certificates

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-ssh-1 | button | Copy CA public key |  |  |  |
| E-ssh-2 | select | Template | select |  | options: SSH Access (user + host) |
| E-ssh-3 | radio | user | radio |  |  |
| E-ssh-4 | radio | host | radio |  |  |
| E-ssh-5 | textbox | Key ID | text | req |  |
| E-ssh-6 | textbox | Principals (comma separated) | text |  |  |
| E-ssh-7 | textbox | Public key (authorized_keys line) |  |  |  |
| E-ssh-8 | textbox | TTL hours | number |  |  |
| E-ssh-9 | button | Issue certificate |  |  |  |

### S-nhi: Machine Identities

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-nhi-1 | button | Propose identity |  |  |  |
| E-nhi-2 | button | Approve <item> |  |  | x3; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-nhi-3 | button | Reject ci-deployer |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-nhi-4 | button | Revoke <item> |  |  | x3; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-nhi-5 | button | Reject payments-svc |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-nhi-6 | button | Reject triage-copilot |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |

### S-anomalies: Issuance anomalies

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|

### S-ct: CT Findings

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-ct-1 | select | Status filter | select |  | options: Open, Acknowledged, Known issuer, All |
| E-ct-2 | button | Refresh |  |  |  |

### S-automation: Automation

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-automation-1 | button | Refresh |  |  | x2 |
| E-automation-2 | button | Success rate0%0 renewals |  |  |  |
| E-automation-3 | button | Mean time to renew—0 samples |  |  |  |
| E-automation-4 | button | Endpoints managed0 |  |  |  |
| E-automation-5 | button | Agents0/1active / total |  |  |  |
| E-automation-6 | button | Queue depth0 |  |  |  |
| E-automation-7 | button | Drain ETA— |  |  |  |
| E-automation-8 | link | Open SLO dashboard |  |  |  |
| E-automation-9 | button | Renewal threshold30dtrigger window before expiry |  |  |  |
| E-automation-10 | button | Scan interval24h |  |  |  |
| E-automation-11 | button | Last scan— |  |  |  |
| E-automation-12 | button | Next scan— |  |  |  |
| E-automation-13 | button | Candidates (last)0certs within threshold |  |  |  |
| E-automation-14 | button | Auto-renew triggers0 |  |  |  |
| E-automation-15 | button | Notifications sent0 |  |  |  |
| E-automation-16 | button | Expired (skipped)0 |  |  |  |

### S-targets: Target Setup

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-targets-1 | radio | AgentA lightweight agent runs on the host, discovering and auto-renewing certifi |  |  |  |
| E-targets-2 | radio | AgentlessDeclare a target's host and how it should be discovered, renewed, and i |  |  |  |
| E-targets-3 | textbox | Agent name | text |  |  |
| E-targets-4 | select | Host typeLinuxmacOSWindows | select |  | options: Linux, macOS, Windows |
| E-targets-5 | button | Generate token |  |  | disabled until preconditions met |
| E-targets-6 | button | Revoke <item> |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |

### S-renewal: Renewal Policy

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-renewal-1 | button | Refresh |  |  |  |
| E-renewal-2 | select | web-01 renewal method | select |  | options: ACME, EST, SCEP, Manual |
| E-renewal-3 | textbox | web-01 auto-renew threshold days | number |  |  |
| E-renewal-4 | button | Save |  |  | x3; disabled until preconditions met |
| E-renewal-5 | button | Clear override |  |  | x3 |
| E-renewal-6 | select | web-02 renewal method | select |  | options: ACME, EST, SCEP, Manual |
| E-renewal-7 | textbox | web-02 auto-renew threshold days | number |  |  |
| E-renewal-8 | select | lb-edge renewal method | select |  | options: ACME, EST, SCEP, Manual |
| E-renewal-9 | textbox | lb-edge auto-renew threshold days | number |  |  |
| E-renewal-10 | textbox | Group name | text |  |  |
| E-renewal-11 | textbox | Group threshold days | number |  |  |
| E-renewal-12 | checkbox | web-01 (web-01.acme.test) | checkbox |  |  |
| E-renewal-13 | checkbox | web-02 (web-02.acme.test) | checkbox |  |  |
| E-renewal-14 | checkbox | lb-edge (lb-edge.acme.test) | checkbox |  |  |
| E-renewal-15 | button | Save group |  |  | disabled until preconditions met |

### S-rollout: Rollout Groups

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-rollout-1 | button | New group |  |  |  |

### S-rollout-dlg-new-group: Rollout Groups / dialog "New group"

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-rollout-dlg-new-group-1 | button | Close dialog |  |  |  |
| E-rollout-dlg-new-group-2 | textbox | Group name | text |  |  |
| E-rollout-dlg-new-group-3 | checkbox | web-01 (ssh) | checkbox |  |  |
| E-rollout-dlg-new-group-4 | checkbox | web-02 (ssh) | checkbox |  |  |
| E-rollout-dlg-new-group-5 | checkbox | lb-edge (f5) | checkbox |  |  |
| E-rollout-dlg-new-group-6 | textbox | Window start (UTC) | number |  |  |
| E-rollout-dlg-new-group-7 | textbox | Window end (UTC) | number |  |  |
| E-rollout-dlg-new-group-8 | button | Save group |  |  |  |

### S-plugins: Delivery Plugins

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-plugins-1 | button | Install plugin |  |  |  |

### S-agents: Satellite Agents

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-agents-1 | button | Refresh |  |  |  |

### S-acme: ACME

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-acme-1 | tab | EAB keys |  |  |  |
| E-acme-2 | tab | Provisioners |  |  |  |
| E-acme-3 | button | New key |  |  |  |
| E-acme-4 | button | Revoke <item> |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |

### S-acme-tab-eab-keys: ACME / tab EAB keys

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-acme-tab-eab-keys-1 | tab | EAB keys |  |  |  |
| E-acme-tab-eab-keys-2 | tab | Provisioners |  |  |  |
| E-acme-tab-eab-keys-3 | button | New key |  |  |  |
| E-acme-tab-eab-keys-4 | button | Revoke <item> |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |

### S-acme-tab-provisioners: ACME / tab Provisioners

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-acme-tab-provisioners-1 | tab | EAB keys |  |  |  |
| E-acme-tab-provisioners-2 | tab | Provisioners |  |  |  |
| E-acme-tab-provisioners-3 | button | New provisioner |  |  |  |
| E-acme-tab-provisioners-4 | button | Copy directory URL for <item> |  |  |  |
| E-acme-tab-provisioners-5 | button | Edit <item> |  |  |  |
| E-acme-tab-provisioners-6 | button | Delete <item> |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |

### S-acme-dlg-new-key: ACME / dialog "New key"

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-acme-dlg-new-key-1 | button | Close dialog |  |  |  |
| E-acme-dlg-new-key-2 | textbox | Label | text |  |  |
| E-acme-dlg-new-key-3 | select | Provisioner (optional)Anyinternal-acme | select |  | options: Any, internal-acme |
| E-acme-dlg-new-key-4 | textbox | Template id (optional) | text |  |  |
| E-acme-dlg-new-key-5 | button | Cancel |  |  |  |
| E-acme-dlg-new-key-6 | button | Create key |  |  | disabled until preconditions met |

### S-enroll: Enrollment Protocols (SCEP/EST/CMP)

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-enroll-1 | tab | SCEP |  |  |  |
| E-enroll-2 | tab | EST |  |  |  |
| E-enroll-3 | tab | CMP |  |  |  |
| E-enroll-4 | button | New challenge |  |  |  |

### S-enroll-tab-scep: Enrollment Protocols (SCEP/EST/CMP) / tab SCEP

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-enroll-tab-scep-1 | tab | SCEP |  |  |  |
| E-enroll-tab-scep-2 | tab | EST |  |  |  |
| E-enroll-tab-scep-3 | tab | CMP |  |  |  |
| E-enroll-tab-scep-4 | button | New challenge |  |  |  |

### S-enroll-tab-est: Enrollment Protocols (SCEP/EST/CMP) / tab EST

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-enroll-tab-est-1 | tab | SCEP |  |  |  |
| E-enroll-tab-est-2 | tab | EST |  |  |  |
| E-enroll-tab-est-3 | tab | CMP |  |  |  |
| E-enroll-tab-est-4 | button | New user |  |  |  |
| E-enroll-tab-est-5 | button | Rotate password for <item> |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-enroll-tab-est-6 | button | Disable <item> |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-enroll-tab-est-7 | button | Delete <item> |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |

### S-enroll-tab-cmp: Enrollment Protocols (SCEP/EST/CMP) / tab CMP

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-enroll-tab-cmp-1 | tab | SCEP |  |  |  |
| E-enroll-tab-cmp-2 | tab | EST |  |  |  |
| E-enroll-tab-cmp-3 | tab | CMP |  |  |  |
| E-enroll-tab-cmp-4 | button | Register trust anchor |  |  |  |
| E-enroll-tab-cmp-5 | button | New PBM secret |  |  |  |
| E-enroll-tab-cmp-6 | button | Rotate <item> |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-enroll-tab-cmp-7 | button | Revoke <item> |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |

### S-enroll-dlg-new-challenge: Enrollment Protocols (SCEP/EST/CMP) / dialog "New challenge"

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-enroll-dlg-new-challenge-1 | button | Close dialog |  |  |  |
| E-enroll-dlg-new-challenge-2 | textbox | Common name | text |  |  |
| E-enroll-dlg-new-challenge-3 | textbox | DNS names (one per line) |  |  |  |
| E-enroll-dlg-new-challenge-4 | select | Valid for30m1h4h24h | select |  | options: 30m, 1h, 4h, 24h |
| E-enroll-dlg-new-challenge-5 | button | Cancel |  |  |  |
| E-enroll-dlg-new-challenge-6 | button | Create challenge |  |  | disabled until preconditions met |

### S-integ: Integrations

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-integ-1 | button | Refresh |  |  | x2 |
| E-integ-2 | textbox | Slack webhook URL | password |  |  |
| E-integ-3 | button | Save |  |  | x11; disabled until preconditions met |
| E-integ-4 | button | Reset to env default |  |  | x29; disabled until preconditions met |
| E-integ-5 | textbox | Webhook URL | password |  |  |
| E-integ-6 | textbox | Webhook signing secret | password |  |  |
| E-integ-7 | textbox | Previous webhook signing secret (rotation, kept 24 h) | password |  |  |
| E-integ-8 | textbox | SMTP host | text |  |  |
| E-integ-9 | button | Save |  |  | x18 |
| E-integ-10 | textbox | SMTP port | text |  |  |
| E-integ-11 | textbox | SMTP username | text |  |  |
| E-integ-12 | textbox | SMTP password | password |  |  |
| E-integ-13 | textbox | SMTP from address | text |  |  |
| E-integ-14 | textbox | PagerDuty routing key | password |  |  |
| E-integ-15 | textbox | Escalation channel | text |  |  |
| E-integ-16 | textbox | Escalation target | password |  |  |
| E-integ-17 | textbox | notifications.slack_bot_token | password |  |  |
| E-integ-18 | textbox | notifications.slack_team_channels | text |  |  |
| E-integ-19 | textbox | notifications.teams_app_id | text |  |  |
| E-integ-20 | textbox | notifications.teams_app_password | password |  |  |
| E-integ-21 | textbox | notifications.teams_team_channels | text |  |  |
| E-integ-22 | select | Notification test channel | select |  | options: Email (SMTP), Slack, PagerDuty, Webhook |
| E-integ-23 | textbox | Notification test target | text |  |  |
| E-integ-24 | button | Send test |  |  | disabled until preconditions met; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-integ-25 | textbox | Notification test message | text |  |  |
| E-integ-26 | select | ITSM kind | select |  | options: ServiceNow, Jira |
| E-integ-27 | textbox | ITSM name | text |  |  |
| E-integ-28 | textbox | ITSM URL | text |  |  |
| E-integ-29 | textbox | ServiceNow username | text |  |  |
| E-integ-30 | textbox | ITSM credential | password |  |  |
| E-integ-31 | select | Ticket type for renewal_failed | select |  | options: No ticket, incident, change_request |
| E-integ-32 | select | Ticket type for approval_pending | select |  | options: No ticket, incident, change_request |
| E-integ-33 | select | Ticket type for expiry_no_owner | select |  | options: No ticket, incident, change_request |
| E-integ-34 | button | Add connection |  |  |  |
| E-integ-35 | button | Test connection <item> |  |  |  |
| E-integ-36 | textbox | OIDC issuer | text |  |  |
| E-integ-37 | textbox | OIDC audience | text |  |  |
| E-integ-38 | textbox | OIDC discovery URL | text |  |  |
| E-integ-39 | textbox | OIDC JWKS (static, JSON) | password |  |  |
| E-integ-40 | textbox | SAML SP entity ID | text |  |  |
| E-integ-41 | textbox | SAML IdP SSO URL | text |  |  |
| E-integ-42 | textbox | SAML IdP issuer | text |  |  |
| E-integ-43 | textbox | SAML IdP certificate (PEM) | text |  |  |
| E-integ-44 | textbox | SCIM enabled (true/false) | text |  |  |
| E-integ-45 | textbox | SCIM bearer token | password |  |  |
| E-integ-46 | textbox | Key backend kind | text |  |  |
| E-integ-47 | textbox | PKCS#11 module path | text |  |  |
| E-integ-48 | textbox | IdP groups (comma separated) | text |  |  |
| E-integ-49 | button | Preview |  |  |  |

### S-certs: Certificates

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-certs-1 | button | Bulk import |  |  |  |
| E-certs-2 | button | Issue certificate |  |  |  |
| E-certs-3 | textbox | Search certificates | text |  |  |
| E-certs-4 | select | Filter by CA | select |  | options: All CAs, Acme Root CA, Acme Issuing CA, Acme Internal Services CA, Root renewal 2026 |
| E-certs-5 | textbox | Filter by team ID | text |  |  |
| E-certs-6 | select | Filter by certificate status | select |  | options: All statuses, Active, Expired, Revoked, Pending, Reissue required |
| E-certs-7 | select | Filter by grade | select |  | options: All grades, A+, A, A-, B, C, D, F |
| E-certs-8 | select | Filter by management state | select |  | options: All states, Managed, Externally managed, Unmanaged |
| E-certs-9 | select | Filter by origin | select |  | options: All origins, Internal CA, Imported, Discovered, Synced from CA |
| E-certs-10 | select | Filter by trust class | select |  | options: Any issuer, managed, public, other private CA, self-signed, unknown |
| E-certs-11 | select | Sort certificates | select |  | options: Newest first, Oldest first |
| E-certs-12 | button | Apply filters |  |  |  |
| E-certs-13 | button | Unowned only |  |  |  |
| E-certs-14 | button | Reset |  |  |  |
| E-certs-15 | button | Select <row> |  |  |  |
| E-certs-16 | button | Export CSV |  |  | disabled until preconditions met |
| E-certs-17 | button | Bulk renew |  |  | disabled until preconditions met; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-certs-18 | button | Take over selected |  |  | disabled until preconditions met |
| E-certs-19 | button | Bulk revoke |  |  | disabled until preconditions met; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-certs-20 | checkbox | Select <row> | checkbox |  | x42 |
| E-certs-21 | button | <row: item link> |  |  | x41 |
| E-certs-22 | button | Legacy Corp Issuing CA |  |  |  |
| E-certs-23 | button | ← Previous |  |  | disabled until preconditions met |
| E-certs-24 | button | Next → |  |  | disabled until preconditions met |
| E-certs-25 | button | Edit |  |  |  |
| E-certs-26 | button | Take over |  |  |  |
| E-certs-27 | button | Download PEM |  |  |  |
| E-certs-28 | button | Renew |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-certs-29 | button | Revoke |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-certs-30 | button | Import |  |  |  |

### S-certs-pane-edit: Certificates / inline panel "Edit"

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-certs-pane-edit-1 | button | Bulk import |  |  |  |
| E-certs-pane-edit-2 | button | Issue certificate |  |  |  |
| E-certs-pane-edit-3 | textbox | Search certificates | text |  |  |
| E-certs-pane-edit-4 | select | Filter by CA | select |  | options: All CAs, Acme Root CA, Acme Issuing CA, Acme Internal Services CA, Root renewal 2026 |
| E-certs-pane-edit-5 | textbox | Filter by team ID | text |  |  |
| E-certs-pane-edit-6 | select | Filter by certificate status | select |  | options: All statuses, Active, Expired, Revoked, Pending, Reissue required |
| E-certs-pane-edit-7 | select | Filter by grade | select |  | options: All grades, A+, A, A-, B, C, D, F |
| E-certs-pane-edit-8 | select | Filter by management state | select |  | options: All states, Managed, Externally managed, Unmanaged |
| E-certs-pane-edit-9 | select | Filter by origin | select |  | options: All origins, Internal CA, Imported, Discovered, Synced from CA |
| E-certs-pane-edit-10 | select | Filter by trust class | select |  | options: Any issuer, managed, public, other private CA, self-signed, unknown |
| E-certs-pane-edit-11 | select | Sort certificates | select |  | options: Newest first, Oldest first |
| E-certs-pane-edit-12 | button | Apply filters |  |  |  |
| E-certs-pane-edit-13 | button | Unowned only |  |  |  |
| E-certs-pane-edit-14 | button | Reset |  |  |  |
| E-certs-pane-edit-15 | button | Select <row> |  |  |  |
| E-certs-pane-edit-16 | button | Export CSV |  |  | disabled until preconditions met |
| E-certs-pane-edit-17 | button | Bulk renew |  |  | disabled until preconditions met; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-certs-pane-edit-18 | button | Take over selected |  |  | disabled until preconditions met |
| E-certs-pane-edit-19 | button | Bulk revoke |  |  | disabled until preconditions met; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-certs-pane-edit-20 | checkbox | Select <row> | checkbox |  | x42 |
| E-certs-pane-edit-21 | button | <row: item link> |  |  | x41 |
| E-certs-pane-edit-22 | button | Legacy Corp Issuing CA |  |  |  |
| E-certs-pane-edit-23 | button | ← Previous |  |  | disabled until preconditions met |
| E-certs-pane-edit-24 | button | Next → |  |  | disabled until preconditions met |
| E-certs-pane-edit-25 | textbox | Owner email | email |  |  |
| E-certs-pane-edit-26 | textbox | Owner team | text |  |  |
| E-certs-pane-edit-27 | textbox | Service name | text |  |  |
| E-certs-pane-edit-28 | textbox | Labels (comma-separated) | text |  |  |
| E-certs-pane-edit-29 | button | Save ownership |  |  |  |
| E-certs-pane-edit-30 | button | Cancel |  |  |  |
| E-certs-pane-edit-31 | button | Take over |  |  |  |
| E-certs-pane-edit-32 | button | Download PEM |  |  |  |
| E-certs-pane-edit-33 | button | Renew |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-certs-pane-edit-34 | button | Revoke |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-certs-pane-edit-35 | button | Import |  |  |  |

### S-certs-dlg-import: Certificates / dialog "Import"

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-certs-dlg-import-1 | button | Close dialog |  |  |  |
| E-certs-dlg-import-2 | textbox | Certificate PEM |  |  |  |
| E-certs-dlg-import-3 | textbox | Team ID | text |  |  |
| E-certs-dlg-import-4 | textbox | Notes | text |  |  |
| E-certs-dlg-import-5 | button | Confirm import |  |  |  |
| E-certs-dlg-import-6 | button | Cancel |  |  |  |

### S-cas: Certificate Authorities

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-cas-1 | button | Import external root |  |  |  |
| E-cas-2 | button | New CA |  |  |  |
| E-cas-3 | button | List |  |  |  |
| E-cas-4 | button | Hierarchy |  |  |  |
| E-cas-5 | select | Filter by CA type | select |  | options: All types, Root, Intermediate |
| E-cas-6 | select | Filter by CA status | select |  | options: All statuses, Active, Suspended, Retired |
| E-cas-7 | button | Reset |  |  |  |
| E-cas-8 | button | <CA row> |  |  | x4 |
| E-cas-9 | button | ← Previous |  |  | disabled until preconditions met |
| E-cas-10 | button | Next → |  |  | disabled until preconditions met |
| E-cas-11 | button | Activate |  |  | disabled until preconditions met |
| E-cas-12 | button | Suspend |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-cas-13 | button | Revoke <item> |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-cas-14 | button | Update |  |  |  |
| E-cas-15 | button | Re-key |  |  |  |

### S-cas-dlg-import-external-root: Certificate Authorities / dialog "Import external root"

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-cas-dlg-import-external-root-1 | button | Close dialog |  |  |  |
| E-cas-dlg-import-external-root-2 | textbox | Name | text | req |  |
| E-cas-dlg-import-external-root-3 | textbox | Certificate PEM |  | req |  |
| E-cas-dlg-import-external-root-4 | button | Import root |  |  |  |
| E-cas-dlg-import-external-root-5 | button | Cancel |  |  |  |

### S-cas-dlg-new-ca: Certificate Authorities / dialog "New CA"

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-cas-dlg-new-ca-1 | button | Close dialog |  |  |  |
| E-cas-dlg-new-ca-2 | select | TypeRootIntermediate | select |  | options: Root, Intermediate |
| E-cas-dlg-new-ca-3 | textbox | Subject CN | text | req |  |
| E-cas-dlg-new-ca-4 | textbox | Subject Org (optional) | text |  |  |
| E-cas-dlg-new-ca-5 | select | AlgorithmECDSA P-256ECDSA P-384RSA 2048RSA 3072RSA 4096Ed25519 (internal / SSH / | select |  | options: ECDSA P-256, ECDSA P-384, RSA 2048, RSA 3072, RSA 4096, Ed25519 (internal / SSH / workload CAs), ML-DSA-44 (post-quantum), ML-DSA-65 (post-quantum) |
| E-cas-dlg-new-ca-6 | textbox | Validity (e.g. 10y, 365d) | text |  |  |
| E-cas-dlg-new-ca-7 | button | Create CA |  |  |  |
| E-cas-dlg-new-ca-8 | button | Cancel |  |  |  |

### S-ceremonies: Key Ceremonies

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-ceremonies-1 | button | Start ceremony |  |  |  |
| E-ceremonies-2 | button | Approve <item> |  |  | disabled until preconditions met; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-ceremonies-3 | button | Abort <item> |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-ceremonies-4 | link | e6708cae |  |  |  |

### S-ceremonies-dlg-start-ceremony: Key Ceremonies / dialog "Start ceremony"

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-ceremonies-dlg-start-ceremony-1 | button | Close dialog |  |  |  |
| E-ceremonies-dlg-start-ceremony-2 | textbox | Name | text |  |  |
| E-ceremonies-dlg-start-ceremony-3 | textbox | Common name | text |  |  |
| E-ceremonies-dlg-start-ceremony-4 | select | AlgorithmECDSA-P256ECDSA-P384RSA-2048RSA-4096Ed25519ML-DSA-65 | select |  | options: ECDSA-P256, ECDSA-P384, RSA-2048, RSA-4096, Ed25519, ML-DSA-65 |
| E-ceremonies-dlg-start-ceremony-5 | textbox | Validity days | number |  |  |
| E-ceremonies-dlg-start-ceremony-6 | textbox | Approvers | text |  |  |
| E-ceremonies-dlg-start-ceremony-7 | textbox | Quorum | number |  |  |
| E-ceremonies-dlg-start-ceremony-8 | button | Cancel |  |  |  |
| E-ceremonies-dlg-start-ceremony-9 | button | Start |  |  |  |

### S-keys: Key Management

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-keys-1 | button | Escrow |  |  |  |
| E-keys-2 | button | Recover |  |  |  |
| E-keys-3 | button | BYOK export |  |  |  |
| E-keys-4 | button | Import |  |  |  |
| E-keys-5 | button | Generate Key |  |  |  |
| E-keys-6 | button | Select <row> |  |  |  |
| E-keys-7 | button | Bulk rotate |  |  | disabled until preconditions met; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-keys-8 | button | Bulk delete |  |  | disabled until preconditions met; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-keys-9 | checkbox | Select <row> | checkbox |  | x6 |
| E-keys-10 | button | Rotate <item> |  |  | x6; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-keys-11 | button | Export backup |  |  | x6 |
| E-keys-12 | button | Policy app-signing-key |  |  |  |
| E-keys-13 | button | Compromised app-signing-key |  |  |  |
| E-keys-14 | button | Delete <item> |  |  | x6; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-keys-15 | button | Policy key-5c1755b6-a3bf-4425-ba6e-184b201c3283 |  |  |  |
| E-keys-16 | button | Compromised key-5c1755b6-a3bf-4425-ba6e-184b201c3283 |  |  |  |
| E-keys-17 | button | Policy key-a0b681f0-5395-44c9-8277-7472850ec7d5 |  |  |  |
| E-keys-18 | button | Compromised key-a0b681f0-5395-44c9-8277-7472850ec7d5 |  |  |  |
| E-keys-19 | button | Policy key-d8ca5595-9664-4044-9ec3-a5b5ee61bd03 |  |  |  |
| E-keys-20 | button | Compromised key-d8ca5595-9664-4044-9ec3-a5b5ee61bd03 |  |  |  |
| E-keys-21 | button | Policy key-e6708cae-96ed-4f18-b5f9-c3bcf65d1a0a |  |  |  |
| E-keys-22 | button | Compromised key-e6708cae-96ed-4f18-b5f9-c3bcf65d1a0a |  |  |  |
| E-keys-23 | button | Policy ssh-ca |  |  |  |
| E-keys-24 | button | Compromised ssh-ca |  |  |  |

### S-keys-dlg-import: Key Management / dialog "Import"

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-keys-dlg-import-1 | button | Close dialog |  |  |  |
| E-keys-dlg-import-2 | textbox | e.g. root-ca-2026 | text |  |  |
| E-keys-dlg-import-3 | textbox | -----BEGIN KRYPTKEEPER BACKUP KEY----- |  |  |  |
| E-keys-dlg-import-4 | textbox | (no accessible name) | password |  |  |
| E-keys-dlg-import-5 | button | Cancel |  |  |  |
| E-keys-dlg-import-6 | button | Import Key |  |  | disabled until preconditions met |

### S-keys-dlg-generate-key: Key Management / dialog "Generate Key"

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-keys-dlg-generate-key-1 | button | Close dialog |  |  |  |
| E-keys-dlg-generate-key-2 | textbox | e.g. root-ca-2026 | text |  |  |
| E-keys-dlg-generate-key-3 | select | ECDSA-P256ECDSA-P384Ed25519RSA-2048RSA-3072RSA-4096ML-DSA-44ML-DSA-65ML-DSA-87 | select |  | options: ECDSA-P256, ECDSA-P384, Ed25519, RSA-2048, RSA-3072, RSA-4096, ML-DSA-44, ML-DSA-65 |
| E-keys-dlg-generate-key-4 | button | Cancel |  |  |  |
| E-keys-dlg-generate-key-5 | button | Generate |  |  | disabled until preconditions met |

### S-keys-dlg-export-backup: Key Management / dialog "Export backup"

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-keys-dlg-export-backup-1 | button | Close dialog |  |  |  |
| E-keys-dlg-export-backup-2 | textbox | Strong passphrase… | password |  |  |
| E-keys-dlg-export-backup-3 | button | Cancel |  |  |  |
| E-keys-dlg-export-backup-4 | button | Download Backup |  |  | disabled until preconditions met |

### S-codesign: Code-Signing Inventory

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-codesign-1 | button | Refresh |  |  |  |
| E-codesign-2 | button | Code-signing certs0 |  |  |  |
| E-codesign-3 | button | Expired0 |  |  |  |
| E-codesign-4 | button | Revoked0 |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |

### S-spiffe: SPIFFE

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|

### S-templates: Certificate Templates

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-templates-1 | button | Draft policy from text |  |  |  |
| E-templates-2 | button | New template |  |  |  |
| E-templates-3 | button | Edit |  |  |  |
| E-templates-4 | button | Delete |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |

### S-templates-dlg-new-template: Certificate Templates / dialog "New template"

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-templates-dlg-new-template-1 | button | Close dialog |  |  |  |
| E-templates-dlg-new-template-2 | textbox | Name (identifier) | text | req |  |
| E-templates-dlg-new-template-3 | textbox | Display name | text |  |  |
| E-templates-dlg-new-template-4 | textbox | Validity period (e.g. 90d, 1y) | text |  |  |
| E-templates-dlg-new-template-5 | textbox | Extended key usage (comma-separated) | text |  |  |
| E-templates-dlg-new-template-6 | textbox | Allowed algorithms (comma-separated) | text |  |  |
| E-templates-dlg-new-template-7 | select | Issued to — Windows autoenrollment offers a template only to this kind of accoun | select |  | options: Machines (computer accounts), Users |
| E-templates-dlg-new-template-8 | select | StatusActiveInactive | select |  | options: Active, Inactive |
| E-templates-dlg-new-template-9 | textbox | Roles allowed to enroll | text |  |  |
| E-templates-dlg-new-template-10 | button | pki-admin |  |  |  |
| E-templates-dlg-new-template-11 | button | pki-operator |  |  |  |
| E-templates-dlg-new-template-12 | button | approver |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-templates-dlg-new-template-13 | button | viewer |  |  |  |
| E-templates-dlg-new-template-14 | button | auditor |  |  |  |
| E-templates-dlg-new-template-15 | button | service-account |  |  |  |
| E-templates-dlg-new-template-16 | checkbox | Require approval — issuance requests wait in Approvals until a second person (pk | checkbox |  |  |
| E-templates-dlg-new-template-17 | checkbox | Allow SSH certificates from this template — the SSH CA signs only the principals | checkbox |  |  |
| E-templates-dlg-new-template-18 | checkbox | Restrict the names this template may issue — without it a requester can name any | checkbox |  |  |
| E-templates-dlg-new-template-19 | button | Create |  |  |  |
| E-templates-dlg-new-template-20 | button | Cancel |  |  |  |

### S-templates-dlg-edit: Certificate Templates / dialog "Edit"

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-templates-dlg-edit-1 | button | Close dialog |  |  |  |
| E-templates-dlg-edit-2 | textbox | Display name | text |  |  |
| E-templates-dlg-edit-3 | textbox | Validity period (e.g. 90d, 1y) | text |  |  |
| E-templates-dlg-edit-4 | textbox | Extended key usage (comma-separated) | text |  |  |
| E-templates-dlg-edit-5 | textbox | Allowed algorithms (comma-separated) | text |  |  |
| E-templates-dlg-edit-6 | select | Issued to — Windows autoenrollment offers a template only to this kind of accoun | select |  | options: Machines (computer accounts), Users |
| E-templates-dlg-edit-7 | select | StatusActiveInactive | select |  | options: Active, Inactive |
| E-templates-dlg-edit-8 | textbox | Roles allowed to enroll | text |  |  |
| E-templates-dlg-edit-9 | button | pki-admin |  |  |  |
| E-templates-dlg-edit-10 | button | pki-operator |  |  |  |
| E-templates-dlg-edit-11 | button | approver |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-templates-dlg-edit-12 | button | viewer |  |  |  |
| E-templates-dlg-edit-13 | button | auditor |  |  |  |
| E-templates-dlg-edit-14 | button | service-account |  |  |  |
| E-templates-dlg-edit-15 | checkbox | Require approval — issuance requests wait in Approvals until a second person (pk | checkbox |  |  |
| E-templates-dlg-edit-16 | checkbox | Allow SSH certificates from this template — the SSH CA signs only the principals | checkbox |  |  |
| E-templates-dlg-edit-17 | checkbox | Restrict the names this template may issue — without it a requester can name any | checkbox |  |  |
| E-templates-dlg-edit-18 | button | Save changes |  |  |  |
| E-templates-dlg-edit-19 | button | Cancel |  |  |  |

### S-discovery: Discovery

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-discovery-1 | button | New scan |  |  |  |
| E-discovery-2 | select | Filter by protocol | select |  | options: All protocols, TLS, HTTP, LDAP, SMTP, SSH |
| E-discovery-3 | select | Show risky endpoints only | select |  | options: All endpoints, Risky only (expired, self-signed, weak, deprecated TLS...) |
| E-discovery-4 | select | Filter by trust class | select |  | options: Any issuer, managed, public, other private CA, self-signed, unknown |
| E-discovery-5 | select | Filter scan jobs by status | select |  | options: All scan jobs, Queued, Running, Complete, Complete with errors, Failed, Cancelled |
| E-discovery-6 | button | Refresh |  |  |  |
| E-discovery-7 | button | Accept risk for <item> |  |  | x4; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-discovery-8 | button | View <item> |  |  |  |
| E-discovery-9 | button | Queue scan |  |  |  |
| E-discovery-10 | button | Search certs |  |  |  |
| E-discovery-11 | button | #.#.#.# |  |  | x5 |
| E-discovery-12 | button | ← Previous |  |  | disabled until preconditions met |
| E-discovery-13 | button | Next → |  |  | disabled until preconditions met |
| E-discovery-14 | button | Select <row> |  |  |  |
| E-discovery-15 | button | Bulk requeue |  |  | disabled until preconditions met |
| E-discovery-16 | button | Bulk cancel |  |  | disabled until preconditions met |
| E-discovery-17 | checkbox | Select <row> | checkbox |  |  |
| E-discovery-18 | button | Requeue |  |  |  |
| E-discovery-19 | button | Cancel |  |  | disabled until preconditions met |

### S-discovery-dlg-new-scan: Discovery / dialog "New scan"

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-discovery-dlg-new-scan-1 | button | Close dialog |  |  |  |
| E-discovery-dlg-new-scan-2 | select | Scan typeFast — HTTPS/SSH + key protocolsTargeted — common cert portsFull — the  | select |  | options: Fast — HTTPS/SSH + key protocols, Targeted — common cert ports, Full — the whole cert/key catalogue, Deep — full port sweep (slow, finds certs anywhere), WinRM — Windows machine certificate stores (managed target), SSH — Linux/Unix cert files and host keys (managed target) |
| E-discovery-dlg-new-scan-3 | textbox | Target | text |  |  |
| E-discovery-dlg-new-scan-4 | textbox | Custom ports (optional, comma-separated — added to the scan type's ports) | text |  |  |
| E-discovery-dlg-new-scan-5 | button | Queue scan |  |  |  |
| E-discovery-dlg-new-scan-6 | button | Cancel |  |  |  |

### S-slo: SLOs and error budget

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-slo-1 | textbox | Issuance latency p95 (seconds) | number |  |  |
| E-slo-2 | textbox | Renewal success rate | number |  |  |
| E-slo-3 | textbox | Issuance success rate | number |  |  |
| E-slo-4 | button | Save objectives |  |  | disabled until preconditions met |
| E-slo-5 | link | Back to Automation |  |  |  |

### S-compliance: Compliance Evidence

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-compliance-1 | select | Compliance framework | select |  | options: All Frameworks, SOC 2, PCI DSS 4.0.1, NIST SP 800-57, DORA, NIS2, FedRAMP Moderate |
| E-compliance-2 | button | Evidence pack (PDF) |  |  |  |
| E-compliance-3 | button | Download CBOM |  |  |  |

### S-custody: Key Custody

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-custody-1 | textbox | Filter by key | text |  |  |

### S-audit: Audit Evidence (Audit Log)

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-audit-1 | textbox | Filter audit action | text |  |  |
| E-audit-2 | textbox | Filter actor type | text |  |  |
| E-audit-3 | textbox | Filter resource type | text |  |  |
| E-audit-4 | select | Filter audit outcome | select |  | options: All outcomes, Success, Executed, Failure, Issuance failed, Denied, Partial, Skipped |
| E-audit-5 | textbox | Filter after timestamp | text |  |  |
| E-audit-6 | textbox | Filter before timestamp | text |  |  |
| E-audit-7 | checkbox | Hide read-only events(successful list, get, read, view, search — denials, downlo | checkbox |  |  |
| E-audit-8 | button | Apply filters |  |  |  |
| E-audit-9 | button | Reset |  |  |  |
| E-audit-10 | button | Export CSV |  |  |  |
| E-audit-11 | button | report.executive_summary_pdf |  |  |  |
| E-audit-12 | button | Previous |  |  | disabled until preconditions met |
| E-audit-13 | button | Next |  |  |  |

### S-changeaudit: Change Audit

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-changeaudit-1 | textbox | Filter by fingerprint (Enter to apply)… | text |  |  |
| E-changeaudit-2 | select | Time range | select |  | options: Last 7 days, Last 14 days, Last 30 days, Last 90 days, Last 180 days, Last 365 days |
| E-changeaudit-3 | link | <row: item link> |  |  | x31 |
| E-changeaudit-4 | link | certificates |  |  | x4 |
| E-changeaudit-5 | link | 5c1755b6-a3bf-4425-ba6e-184b201c3283 |  |  |  |
| E-changeaudit-6 | link | d8ca5595-9664-4044-9ec3-a5b5ee61bd03 |  |  |  |

### S-history: Action History

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-history-1 | select | Filter history by status | select |  | options: All statuses, Open, Acknowledged, Resolved, Success |
| E-history-2 | select | Filter history by category | select |  | options: All categories, Certificate, Discovery, Notification, Dashboard |
| E-history-3 | button | Refresh |  |  |  |
| E-history-4 | button | Expired certs |  |  |  |
| E-history-5 | button | Expiring certs |  |  |  |
| E-history-6 | button | Risky endpoints |  |  |  |

### S-blast: Blast Radius

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-blast-1 | select | Action | select |  | options: Revoke certificate, Retire CA, Deprecate algorithm |
| E-blast-2 | textbox | Target | text |  |  |
| E-blast-3 | button | Simulate |  |  |  |

### S-posture: Crypto Posture

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-posture-1 | button | Notify owner |  |  |  |
| E-posture-2 | button | Open <item> |  |  |  |
| E-posture-3 | button | Refresh |  |  |  |
| E-posture-4 | button | Export CSV |  |  |  |
| E-posture-5 | button | Total certificates39 |  |  |  |
| E-posture-6 | button | PQC readiness69%Quantum-safe today: 0 of 39 certificates |  |  |  |
| E-posture-7 | button | Automation0%0 auto-renewed |  |  |  |
| E-posture-8 | button | Expiring ≤47 days13incl. 2 already expired |  |  |  |
| E-posture-9 | select | Trend range | select |  | options: Last 30 days, Last 90 days, Last 365 days |
| E-posture-10 | button | Renew |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-posture-11 | link | How risk scores are computed |  |  |  |
| E-posture-12 | button | Accept risk… |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |

### S-posture-dlg-open-pqc-wave: Crypto Posture / dialog "Open PQC wave"

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-posture-dlg-open-pqc-wave-1 | button | Close dialog |  |  |  |
| E-posture-dlg-open-pqc-wave-2 | button | Confirm |  |  |  |
| E-posture-dlg-open-pqc-wave-3 | button | Cancel |  |  |  |

### S-pqc: PQC Migration

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-pqc-1 | button | Refresh |  |  |  |
| E-pqc-2 | button | PQC readiness69%quantum-safe + leaf-only + migration-ready |  |  |  |
| E-pqc-3 | button | Quantum-safe0full chain PQC |  |  |  |
| E-pqc-4 | button | Leaf-only PQC0Leaf-only PQC |  |  |  |
| E-pqc-5 | button | Migration-ready27 |  |  |  |
| E-pqc-6 | button | Vulnerable12 |  |  | x2 |
| E-pqc-7 | button | Countdown PDF |  |  |  |
| E-pqc-8 | button | PQC readiness69% |  |  |  |
| E-pqc-9 | button | Nearest deadline1170d2030-01-01 |  |  |  |
| E-pqc-10 | button | Quantum-safe0 |  |  |  |
| E-pqc-11 | button | Leaf-only PQC0 |  |  |  |
| E-pqc-12 | button | Expire before 203036still to migrate; rotate at renewal |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-pqc-13 | button | Expire after 20303still to migrate; must be replaced early |  |  |  |
| E-pqc-14 | button | Start migration wave |  |  |  |
| E-pqc-15 | button | Show all 39 |  |  |  |
| E-pqc-16 | button | Re-derive waves |  |  |  |
| E-pqc-17 | button | Accept |  |  |  |
| E-pqc-18 | button | (no accessible name) |  |  |  |

### S-pqc-pane-start-migration-wave: PQC Migration / inline panel "Start migration wave"

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-pqc-pane-start-migration-wave-1 | button | Refresh |  |  |  |
| E-pqc-pane-start-migration-wave-2 | button | PQC readiness69%quantum-safe + leaf-only + migration-ready |  |  |  |
| E-pqc-pane-start-migration-wave-3 | button | Quantum-safe0full chain PQC |  |  |  |
| E-pqc-pane-start-migration-wave-4 | button | Leaf-only PQC0Leaf-only PQC |  |  |  |
| E-pqc-pane-start-migration-wave-5 | button | Migration-ready27 |  |  |  |
| E-pqc-pane-start-migration-wave-6 | button | Vulnerable12 |  |  | x2 |
| E-pqc-pane-start-migration-wave-7 | button | Countdown PDF |  |  |  |
| E-pqc-pane-start-migration-wave-8 | button | PQC readiness69% |  |  |  |
| E-pqc-pane-start-migration-wave-9 | button | Nearest deadline1170d2030-01-01 |  |  |  |
| E-pqc-pane-start-migration-wave-10 | button | Quantum-safe0 |  |  |  |
| E-pqc-pane-start-migration-wave-11 | button | Leaf-only PQC0 |  |  |  |
| E-pqc-pane-start-migration-wave-12 | button | Expire before 203036still to migrate; rotate at renewal |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-pqc-pane-start-migration-wave-13 | button | Expire after 20303still to migrate; must be replaced early |  |  |  |
| E-pqc-pane-start-migration-wave-14 | textbox | Wave name | text |  |  |
| E-pqc-pane-start-migration-wave-15 | textbox | Owner (optional) | text |  |  |
| E-pqc-pane-start-migration-wave-16 | button | Back |  |  | disabled until preconditions met |
| E-pqc-pane-start-migration-wave-17 | button | Next |  |  |  |
| E-pqc-pane-start-migration-wave-18 | button | Cancel |  |  |  |
| E-pqc-pane-start-migration-wave-19 | button | Show all 39 |  |  |  |
| E-pqc-pane-start-migration-wave-20 | button | Re-derive waves |  |  |  |
| E-pqc-pane-start-migration-wave-21 | button | Accept |  |  |  |
| E-pqc-pane-start-migration-wave-22 | button | (no accessible name) |  |  |  |

### S-sunset: Algorithm Sunset

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-sunset-1 | link | <row: item link> |  |  | x11 |
| E-sunset-2 | link | +2 more — search the inventory |  |  |  |
| E-sunset-3 | link | +15 more — search the inventory |  |  |  |
| E-sunset-4 | textbox | Policy name | text |  |  |
| E-sunset-5 | textbox | Algorithms | text |  |  |
| E-sunset-6 | textbox | Max key bits | number |  |  |
| E-sunset-7 | textbox | Deadline | date |  |  |
| E-sunset-8 | button | Derive roadmap |  |  |  |

### S-expiry: Expiry Timeline

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-expiry-1 | button | Open <item> |  |  |  |
| E-expiry-2 | button | Renew |  |  | x2; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-expiry-3 | button | Renew |  |  | disabled until preconditions met; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-expiry-4 | button | Notify owner |  |  | disabled until preconditions met |
| E-expiry-5 | button | Notify owner |  |  | x3 |

### S-expiry-dlg-open-pqc-wave: Expiry Timeline / dialog "Open PQC wave"

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-expiry-dlg-open-pqc-wave-1 | button | Close dialog |  |  |  |
| E-expiry-dlg-open-pqc-wave-2 | button | Confirm |  |  |  |
| E-expiry-dlg-open-pqc-wave-3 | button | Cancel |  |  |  |

### S-cloudkeys: Cloud Keys

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-cloudkeys-1 | button | Refresh |  |  |  |

### S-cahealth: CA Health

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-cahealth-1 | link | Acme Root CA |  |  |  |
| E-cahealth-2 | link | Acme Issuing CA |  |  |  |
| E-cahealth-3 | link | Acme Internal Services CA |  |  |  |
| E-cahealth-4 | link | Root renewal 2026 |  |  |  |

### S-velocity: Issuance Velocity

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-velocity-1 | link | Acme Issuing CA |  |  |  |
| E-velocity-2 | link | Acme Internal Services CA |  |  |  |

### S-revocation: Revocation Activity

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-revocation-1 | select | Time range | select |  | options: Last 7 days, Last 14 days, Last 30 days, Last 90 days, Last 180 days, Last 365 days |
| E-revocation-2 | link | Acme Issuing CA |  |  | x4 |
| E-revocation-3 | link | <row: item link> |  |  | x3 |

### S-users: Users

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-users-1 | button | Invite user |  |  |  |
| E-users-2 | button | Change role |  |  | x4 |
| E-users-3 | button | Deactivate |  |  | x4; SKIPPED: destructive (firewalled; never executed by cartographer) |

### S-users-dlg-invite-user: Users / dialog "Invite user"

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-users-dlg-invite-user-1 | button | Close dialog |  |  |  |
| E-users-dlg-invite-user-2 | textbox | Email address | email | req |  |
| E-users-dlg-invite-user-3 | select | Rolepki-adminpki-operatorpki-auditordiscovery-operatornotification-operatorreque | select |  | options: pki-admin, pki-operator, pki-auditor, discovery-operator, notification-operator, requester |
| E-users-dlg-invite-user-4 | button | Send invitation |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-users-dlg-invite-user-5 | button | Cancel |  |  |  |

### S-accessreview: Access Review

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-accessreview-1 | button | Open <item> |  |  |  |
| E-accessreview-2 | button | Q4 access reviewopen |  |  |  |
| E-accessreview-3 | select | Decision for priya.nair@acme.test | select |  | options: Select…, keep, revoke, modify |
| E-accessreview-4 | button | <row: item link> |  |  | x4; disabled until preconditions met |
| E-accessreview-5 | select | Decision for marcus.webb@acme.test | select |  | options: Select…, keep, revoke, modify |
| E-accessreview-6 | select | Decision for lena.okafor@acme.test | select |  | options: Select…, keep, revoke, modify |
| E-accessreview-7 | select | Decision for dev.rao@acme.test | select |  | options: Select…, keep, revoke, modify |
| E-accessreview-8 | button | Close campaign |  |  | disabled until preconditions met; SKIPPED: destructive (firewalled; never executed by cartographer) |

### S-accessreview-dlg-open-campaign: Access Review / dialog "Open campaign"

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-accessreview-dlg-open-campaign-1 | button | Close dialog |  |  |  |
| E-accessreview-dlg-open-campaign-2 | textbox | Campaign name | text |  |  |
| E-accessreview-dlg-open-campaign-3 | button | Start review |  |  | disabled until preconditions met |

### S-policies: Issuance policies

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-policies-1 | button | Refresh |  |  |  |
| E-policies-2 | button | New policy |  |  |  |
| E-policies-3 | button | Edit <item> |  |  | x2 |
| E-policies-4 | button | Delete <item> |  |  | x2; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-policies-5 | select | AlgorithmSelect…RSA-2048RSA-3072RSA-4096ECDSA-P256ECDSA-P384Ed25519ML-DSA-44ML-D | select |  | options: Select…, RSA-2048, RSA-3072, RSA-4096, ECDSA-P256, ECDSA-P384, Ed25519, ML-DSA-44 |
| E-policies-6 | textbox | RSA bits | text |  |  |
| E-policies-7 | textbox | Validity days | text |  |  |
| E-policies-8 | textbox | CA id | text |  |  |
| E-policies-9 | checkbox | Request is a CA certificate | checkbox |  |  |
| E-policies-10 | button | Run dry run |  |  | disabled until preconditions met |

### S-policies-pane-new-policy: Issuance policies / inline panel "New policy"

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-policies-pane-new-policy-1 | button | Refresh |  |  |  |
| E-policies-pane-new-policy-2 | button | New policy |  |  |  |
| E-policies-pane-new-policy-3 | textbox | Name | text |  |  |
| E-policies-pane-new-policy-4 | textbox | CA id (blank = all CAs) | text |  |  |
| E-policies-pane-new-policy-5 | textbox | Allowed algorithms (comma separated; blank = any) | text |  |  |
| E-policies-pane-new-policy-6 | textbox | Min RSA bits | text |  |  |
| E-policies-pane-new-policy-7 | textbox | Max validity days | text |  |  |
| E-policies-pane-new-policy-8 | checkbox | Enabled | checkbox |  |  |
| E-policies-pane-new-policy-9 | checkbox | Allow CA certificates | checkbox |  |  |
| E-policies-pane-new-policy-10 | button | Create policy |  |  |  |
| E-policies-pane-new-policy-11 | button | Cancel |  |  |  |
| E-policies-pane-new-policy-12 | button | Edit <item> |  |  | x2 |
| E-policies-pane-new-policy-13 | button | Delete <item> |  |  | x2; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-policies-pane-new-policy-14 | select | AlgorithmSelect…RSA-2048RSA-3072RSA-4096ECDSA-P256ECDSA-P384Ed25519ML-DSA-44ML-D | select |  | options: Select…, RSA-2048, RSA-3072, RSA-4096, ECDSA-P256, ECDSA-P384, Ed25519, ML-DSA-44 |
| E-policies-pane-new-policy-15 | textbox | RSA bits | text |  |  |
| E-policies-pane-new-policy-16 | textbox | Validity days | text |  |  |
| E-policies-pane-new-policy-17 | textbox | CA id | text |  |  |
| E-policies-pane-new-policy-18 | checkbox | Request is a CA certificate | checkbox |  |  |
| E-policies-pane-new-policy-19 | button | Run dry run |  |  | disabled until preconditions met |

### S-policies-pane-edit-policy: Issuance policies / inline panel "Edit policy"

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-policies-pane-edit-policy-1 | button | Refresh |  |  |  |
| E-policies-pane-edit-policy-2 | button | New policy |  |  |  |
| E-policies-pane-edit-policy-3 | textbox | Name | text |  |  |
| E-policies-pane-edit-policy-4 | textbox | CA id (blank = all CAs) | text |  |  |
| E-policies-pane-edit-policy-5 | textbox | Allowed algorithms (comma separated; blank = any) | text |  |  |
| E-policies-pane-edit-policy-6 | textbox | Min RSA bits | text |  |  |
| E-policies-pane-edit-policy-7 | textbox | Max validity days | text |  |  |
| E-policies-pane-edit-policy-8 | checkbox | Enabled | checkbox |  |  |
| E-policies-pane-edit-policy-9 | checkbox | Allow CA certificates | checkbox |  |  |
| E-policies-pane-edit-policy-10 | button | Save changes |  |  |  |
| E-policies-pane-edit-policy-11 | button | Cancel |  |  |  |
| E-policies-pane-edit-policy-12 | button | Edit <item> |  |  | x2 |
| E-policies-pane-edit-policy-13 | button | Delete <item> |  |  | x2; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-policies-pane-edit-policy-14 | select | AlgorithmSelect…RSA-2048RSA-3072RSA-4096ECDSA-P256ECDSA-P384Ed25519ML-DSA-44ML-D | select |  | options: Select…, RSA-2048, RSA-3072, RSA-4096, ECDSA-P256, ECDSA-P384, Ed25519, ML-DSA-44 |
| E-policies-pane-edit-policy-15 | textbox | RSA bits | text |  |  |
| E-policies-pane-edit-policy-16 | textbox | Validity days | text |  |  |
| E-policies-pane-edit-policy-17 | textbox | CA id | text |  |  |
| E-policies-pane-edit-policy-18 | checkbox | Request is a CA certificate | checkbox |  |  |
| E-policies-pane-edit-policy-19 | button | Run dry run |  |  | disabled until preconditions met |

### S-roles: Roles

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-roles-1 | button | Refresh |  |  |  |
| E-roles-2 | button | New role |  |  |  |
| E-roles-3 | button | Edit <item> |  |  |  |
| E-roles-4 | button | Delete <item> |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |

### S-roles-pane-new-role: Roles / inline panel "New role"

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-roles-pane-new-role-1 | button | Refresh |  |  |  |
| E-roles-pane-new-role-2 | button | New role |  |  |  |
| E-roles-pane-new-role-3 | textbox | Role name | text |  |  |
| E-roles-pane-new-role-4 | textbox | Description | text |  |  |
| E-roles-pane-new-role-5 | checkbox | certificate.read | checkbox |  |  |
| E-roles-pane-new-role-6 | checkbox | report.read | checkbox |  |  |
| E-roles-pane-new-role-7 | checkbox | audit.read | checkbox |  |  |
| E-roles-pane-new-role-8 | checkbox | certificate.issue | checkbox |  |  |
| E-roles-pane-new-role-9 | checkbox | certificate.renew | checkbox |  |  |
| E-roles-pane-new-role-10 | checkbox | certificate.revoke | checkbox |  |  |
| E-roles-pane-new-role-11 | checkbox | ca.manage | checkbox |  |  |
| E-roles-pane-new-role-12 | checkbox | key.manage | checkbox |  |  |
| E-roles-pane-new-role-13 | checkbox | action.propose | checkbox |  |  |
| E-roles-pane-new-role-14 | checkbox | action.approve | checkbox |  |  |
| E-roles-pane-new-role-15 | checkbox | discovery.manage | checkbox |  |  |
| E-roles-pane-new-role-16 | checkbox | notification.manage | checkbox |  |  |
| E-roles-pane-new-role-17 | checkbox | protocol.manage | checkbox |  |  |
| E-roles-pane-new-role-18 | checkbox | dashboard.manage | checkbox |  |  |
| E-roles-pane-new-role-19 | checkbox | tenant.manage | checkbox |  |  |
| E-roles-pane-new-role-20 | checkbox | user.manage | checkbox |  |  |
| E-roles-pane-new-role-21 | button | Create role |  |  | disabled until preconditions met |
| E-roles-pane-new-role-22 | button | Cancel |  |  |  |
| E-roles-pane-new-role-23 | button | Edit <item> |  |  |  |
| E-roles-pane-new-role-24 | button | Delete <item> |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |

### S-roles-pane-edit-role: Roles / inline panel "Edit role"

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-roles-pane-edit-role-1 | button | Refresh |  |  |  |
| E-roles-pane-edit-role-2 | button | New role |  |  |  |
| E-roles-pane-edit-role-3 | textbox | Role name | text |  | disabled until preconditions met |
| E-roles-pane-edit-role-4 | textbox | Description | text |  |  |
| E-roles-pane-edit-role-5 | checkbox | certificate.read | checkbox |  |  |
| E-roles-pane-edit-role-6 | checkbox | report.read | checkbox |  |  |
| E-roles-pane-edit-role-7 | checkbox | audit.read | checkbox |  |  |
| E-roles-pane-edit-role-8 | checkbox | certificate.issue | checkbox |  |  |
| E-roles-pane-edit-role-9 | checkbox | certificate.renew | checkbox |  |  |
| E-roles-pane-edit-role-10 | checkbox | certificate.revoke | checkbox |  |  |
| E-roles-pane-edit-role-11 | checkbox | ca.manage | checkbox |  |  |
| E-roles-pane-edit-role-12 | checkbox | key.manage | checkbox |  |  |
| E-roles-pane-edit-role-13 | checkbox | action.propose | checkbox |  |  |
| E-roles-pane-edit-role-14 | checkbox | action.approve | checkbox |  |  |
| E-roles-pane-edit-role-15 | checkbox | discovery.manage | checkbox |  |  |
| E-roles-pane-edit-role-16 | checkbox | notification.manage | checkbox |  |  |
| E-roles-pane-edit-role-17 | checkbox | protocol.manage | checkbox |  |  |
| E-roles-pane-edit-role-18 | checkbox | dashboard.manage | checkbox |  |  |
| E-roles-pane-edit-role-19 | checkbox | tenant.manage | checkbox |  |  |
| E-roles-pane-edit-role-20 | checkbox | user.manage | checkbox |  |  |
| E-roles-pane-edit-role-21 | button | Save role |  |  |  |
| E-roles-pane-edit-role-22 | button | Cancel |  |  |  |
| E-roles-pane-edit-role-23 | button | Edit <item> |  |  |  |
| E-roles-pane-edit-role-24 | button | Delete <item> |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |

### S-invsrc: Inventory Sources

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-invsrc-1 | button | Sync <item> |  |  |  |
| E-invsrc-2 | button | Delete <item> |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-invsrc-3 | textbox | Source name | text |  |  |
| E-invsrc-4 | select | Source type | select |  | options: AD CS export, AD CS live, DigiCert, Sectigo, Entrust, AWS Private CA, GCP CA Service |
| E-invsrc-5 | select | Credential | select |  | options: Select a credential, demo-jira-token |
| E-invsrc-6 | textbox | Schedule minutes | number |  |  |
| E-invsrc-7 | textbox | Configuration JSON |  |  |  |
| E-invsrc-8 | button | Add source |  |  | disabled until preconditions met |

### S-migration: Migration

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-migration-1 | select | Source system | select |  | options: Adcs, Certcentral, Keyfactor, Vault, Venafi |
| E-migration-2 | file | Export file | file |  |  |
| E-migration-3 | textbox | Paste export |  |  |  |
| E-migration-4 | textbox | Credential reference | text |  |  |
| E-migration-5 | textbox | LDAP URL | text |  |  |
| E-migration-6 | textbox | Base DN | text |  |  |
| E-migration-7 | textbox | Bind DN | text |  |  |
| E-migration-8 | button | Dry run |  |  | disabled until preconditions met |
| E-migration-9 | button | Submit for approval |  |  | disabled until preconditions met; SKIPPED: destructive (firewalled; never executed by cartographer) |

### S-settings: Settings

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-settings-1 | button | Refresh |  |  |  |
| E-settings-2 | button | Send test event |  |  | disabled until preconditions met; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-settings-3 | select | Framework | select |  | options: All frameworks, PCI DSS 4.0.1, SOC 2, NIST SP 800-57 |
| E-settings-4 | select | Cadence | select |  | options: Weekly, Monthly |
| E-settings-5 | textbox | Recipients (comma-separated) | text |  |  |
| E-settings-6 | button | Add schedule |  |  | disabled until preconditions met |
| E-settings-7 | button | Send now |  |  | disabled until preconditions met; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-settings-8 | button | Add cluster |  |  |  |
| E-settings-9 | button | Save Kubernetes clusters |  |  |  |
| E-settings-10 | button | Add endpoint |  |  |  |
| E-settings-11 | button | Save SaaS / API endpoints |  |  |  |
| E-settings-12 | button | Add domain |  |  |  |
| E-settings-13 | button | Save CT monitor domains |  |  |  |
| E-settings-14 | button | Add cloud source |  |  |  |
| E-settings-15 | button | Save Cloud sources |  |  |  |

### S-settings-pane-add-cluster: Settings / inline panel "Add cluster"

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-settings-pane-add-cluster-1 | button | Refresh |  |  |  |
| E-settings-pane-add-cluster-2 | button | Send test event |  |  | disabled until preconditions met; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-settings-pane-add-cluster-3 | select | Framework | select |  | options: All frameworks, PCI DSS 4.0.1, SOC 2, NIST SP 800-57 |
| E-settings-pane-add-cluster-4 | select | Cadence | select |  | options: Weekly, Monthly |
| E-settings-pane-add-cluster-5 | textbox | Recipients (comma-separated) | text |  |  |
| E-settings-pane-add-cluster-6 | button | Add schedule |  |  | disabled until preconditions met |
| E-settings-pane-add-cluster-7 | button | Send now |  |  | disabled until preconditions met; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-settings-pane-add-cluster-8 | textbox | Cluster name | text |  |  |
| E-settings-pane-add-cluster-9 | select | Cluster credential | select |  | options: Select a credential…, demo-jira-token |
| E-settings-pane-add-cluster-10 | textbox | Cluster namespace | text |  |  |
| E-settings-pane-add-cluster-11 | button | Remove cluster <item> |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-settings-pane-add-cluster-12 | button | Add cluster |  |  |  |
| E-settings-pane-add-cluster-13 | button | Save Kubernetes clusters |  |  | disabled until preconditions met |
| E-settings-pane-add-cluster-14 | button | Add endpoint |  |  |  |
| E-settings-pane-add-cluster-15 | button | Save SaaS / API endpoints |  |  |  |
| E-settings-pane-add-cluster-16 | button | Add domain |  |  |  |
| E-settings-pane-add-cluster-17 | button | Save CT monitor domains |  |  |  |
| E-settings-pane-add-cluster-18 | button | Add cloud source |  |  |  |
| E-settings-pane-add-cluster-19 | button | Save Cloud sources |  |  |  |

### S-settings-pane-add-endpoint: Settings / inline panel "Add endpoint"

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-settings-pane-add-endpoint-1 | button | Refresh |  |  |  |
| E-settings-pane-add-endpoint-2 | button | Send test event |  |  | disabled until preconditions met; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-settings-pane-add-endpoint-3 | select | Framework | select |  | options: All frameworks, PCI DSS 4.0.1, SOC 2, NIST SP 800-57 |
| E-settings-pane-add-endpoint-4 | select | Cadence | select |  | options: Weekly, Monthly |
| E-settings-pane-add-endpoint-5 | textbox | Recipients (comma-separated) | text |  |  |
| E-settings-pane-add-endpoint-6 | button | Add schedule |  |  | disabled until preconditions met |
| E-settings-pane-add-endpoint-7 | button | Send now |  |  | disabled until preconditions met; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-settings-pane-add-endpoint-8 | button | Add cluster |  |  |  |
| E-settings-pane-add-endpoint-9 | button | Save Kubernetes clusters |  |  |  |
| E-settings-pane-add-endpoint-10 | textbox | SaaS endpoint | text |  |  |
| E-settings-pane-add-endpoint-11 | button | Remove endpoint 1 |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-settings-pane-add-endpoint-12 | button | Add endpoint |  |  |  |
| E-settings-pane-add-endpoint-13 | button | Save SaaS / API endpoints |  |  | disabled until preconditions met |
| E-settings-pane-add-endpoint-14 | button | Add domain |  |  |  |
| E-settings-pane-add-endpoint-15 | button | Save CT monitor domains |  |  |  |
| E-settings-pane-add-endpoint-16 | button | Add cloud source |  |  |  |
| E-settings-pane-add-endpoint-17 | button | Save Cloud sources |  |  |  |

### S-settings-pane-add-domain: Settings / inline panel "Add domain"

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-settings-pane-add-domain-1 | button | Refresh |  |  |  |
| E-settings-pane-add-domain-2 | button | Send test event |  |  | disabled until preconditions met; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-settings-pane-add-domain-3 | select | Framework | select |  | options: All frameworks, PCI DSS 4.0.1, SOC 2, NIST SP 800-57 |
| E-settings-pane-add-domain-4 | select | Cadence | select |  | options: Weekly, Monthly |
| E-settings-pane-add-domain-5 | textbox | Recipients (comma-separated) | text |  |  |
| E-settings-pane-add-domain-6 | button | Add schedule |  |  | disabled until preconditions met |
| E-settings-pane-add-domain-7 | button | Send now |  |  | disabled until preconditions met; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-settings-pane-add-domain-8 | button | Add cluster |  |  |  |
| E-settings-pane-add-domain-9 | button | Save Kubernetes clusters |  |  |  |
| E-settings-pane-add-domain-10 | button | Add endpoint |  |  |  |
| E-settings-pane-add-domain-11 | button | Save SaaS / API endpoints |  |  |  |
| E-settings-pane-add-domain-12 | textbox | CT domain | text |  |  |
| E-settings-pane-add-domain-13 | button | Remove domain 1 |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-settings-pane-add-domain-14 | button | Add domain |  |  |  |
| E-settings-pane-add-domain-15 | button | Save CT monitor domains |  |  | disabled until preconditions met |
| E-settings-pane-add-domain-16 | button | Add cloud source |  |  |  |
| E-settings-pane-add-domain-17 | button | Save Cloud sources |  |  |  |

### S-settings-pane-add-cloud-source: Settings / inline panel "Add cloud source"

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-settings-pane-add-cloud-source-1 | button | Refresh |  |  |  |
| E-settings-pane-add-cloud-source-2 | button | Send test event |  |  | disabled until preconditions met; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-settings-pane-add-cloud-source-3 | select | Framework | select |  | options: All frameworks, PCI DSS 4.0.1, SOC 2, NIST SP 800-57 |
| E-settings-pane-add-cloud-source-4 | select | Cadence | select |  | options: Weekly, Monthly |
| E-settings-pane-add-cloud-source-5 | textbox | Recipients (comma-separated) | text |  |  |
| E-settings-pane-add-cloud-source-6 | button | Add schedule |  |  | disabled until preconditions met |
| E-settings-pane-add-cloud-source-7 | button | Send now |  |  | disabled until preconditions met; SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-settings-pane-add-cloud-source-8 | button | Add cluster |  |  |  |
| E-settings-pane-add-cloud-source-9 | button | Save Kubernetes clusters |  |  |  |
| E-settings-pane-add-cloud-source-10 | button | Add endpoint |  |  |  |
| E-settings-pane-add-cloud-source-11 | button | Save SaaS / API endpoints |  |  |  |
| E-settings-pane-add-cloud-source-12 | button | Add domain |  |  |  |
| E-settings-pane-add-cloud-source-13 | button | Save CT monitor domains |  |  |  |
| E-settings-pane-add-cloud-source-14 | select | Cloud provider | select |  | options: aws-acm, azure-keyvault, gcp-certmanager |
| E-settings-pane-add-cloud-source-15 | textbox | Cloud region | text |  |  |
| E-settings-pane-add-cloud-source-16 | textbox | AWS profile | text |  |  |
| E-settings-pane-add-cloud-source-17 | button | Remove aws-acm |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-settings-pane-add-cloud-source-18 | button | Add cloud source |  |  |  |
| E-settings-pane-add-cloud-source-19 | button | Save Cloud sources |  |  | disabled until preconditions met |

### S-tenants: Tenants

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-tenants-1 | button | Refresh |  |  |  |

### S-issue: Issue certificate wizard (step 1 of 5: CA)

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-issue-1 | select | Certificate authority | select |  | options: — select a CA —, Acme Root CA, Acme Issuing CA, Acme Internal Services CA, Root renewal 2026 |
| E-issue-2 | button | Back |  |  | disabled until preconditions met |
| E-issue-3 | button | Next |  |  |  |
| E-issue-4 | button | Cancel |  |  |  |

### S-myreq: My requests

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|

### S-certs-detail: Certificate detail card

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-certs-detail-1 | button | Back to list |  |  |  |
| E-certs-detail-2 | button | Edit |  |  |  |
| E-certs-detail-3 | button | Take over |  |  |  |
| E-certs-detail-4 | button | Download PEM |  |  |  |
| E-certs-detail-5 | button | Renew |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-certs-detail-6 | button | Revoke |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-certs-detail-7 | button | Import |  |  |  |

### S-certs-selected: Certificates with bulk actions enabled

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-certs-selected-1 | button | Export CSV |  |  |  |
| E-certs-selected-2 | button | Bulk renew |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-certs-selected-3 | button | Take over selected |  |  |  |
| E-certs-selected-4 | button | Bulk revoke |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |

### S-cas-detail: CA detail card

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-cas-detail-1 | button | Back to list |  |  |  |
| E-cas-detail-2 | button | Activate |  |  | disabled until preconditions met |
| E-cas-detail-3 | button | Suspend |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-cas-detail-4 | button | Revoke <item> |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-cas-detail-5 | button | Update |  |  |  |
| E-cas-detail-6 | button | Re-key |  |  |  |

### S-cas-hierarchy: CA hierarchy tree

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-cas-hierarchy-1 | button | List |  |  |  |
| E-cas-hierarchy-2 | button | Hierarchy |  |  |  |

### S-cas-dlg-update: Update CA metadata dialog

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-cas-dlg-update-1 | button | Close dialog |  |  |  |
| E-cas-dlg-update-2 | textbox | Display name | text |  |  |
| E-cas-dlg-update-3 | textarea | CRL distribution points |  |  |  |
| E-cas-dlg-update-4 | textbox | OCSP service URL | text |  |  |
| E-cas-dlg-update-5 | button | Save changes |  |  |  |
| E-cas-dlg-update-6 | button | Cancel |  |  |  |

### S-cas-dlg-rekey: Re-key CA wizard (Blast radius, Options, Review; ends in submit-for-approval)

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-cas-dlg-rekey-1 | button | Close dialog |  |  |  |
| E-cas-dlg-rekey-2 | button | Acknowledge impact |  |  |  |
| E-cas-dlg-rekey-3 | button | Back |  |  | disabled until preconditions met |
| E-cas-dlg-rekey-4 | button | Next |  |  |  |
| E-cas-dlg-rekey-5 | button | Cancel |  |  |  |

### S-issue-2: Issue wizard step 2: Template

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-issue-2-1 | select | Issuance template |  |  |  |
| E-issue-2-2 | button | Back |  |  |  |
| E-issue-2-3 | button | Next |  |  |  |
| E-issue-2-4 | button | Cancel |  |  |  |

### S-issue-3: Issue wizard step 3: Subject & SANs

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-issue-3-1 | textbox | Subject common name | text |  |  |
| E-issue-3-2 | textbox | Subject alternative names | text |  |  |
| E-issue-3-3 | button | Back |  |  |  |
| E-issue-3-4 | button | Next |  |  |  |
| E-issue-3-5 | button | Cancel |  |  |  |

### S-issue-4: Issue wizard step 4: Key or CSR (choice)

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-issue-4-1 | button | I already have a CSR |  |  |  |
| E-issue-4-2 | button | Generate a new key |  |  |  |
| E-issue-4-3 | button | Back |  |  |  |
| E-issue-4-4 | button | Next |  |  |  |
| E-issue-4-5 | button | Cancel |  |  |  |

### S-issue-4-csr: Issue wizard step 4-csr: Key or CSR (paste CSR)

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-issue-4-csr-1 | button | I already have a CSR |  |  |  |
| E-issue-4-csr-2 | button | Generate a new key |  |  |  |
| E-issue-4-csr-3 | textarea | CSR PEM |  |  |  |
| E-issue-4-csr-4 | button | Back |  |  |  |
| E-issue-4-csr-5 | button | Next |  |  |  |
| E-issue-4-csr-6 | button | Cancel |  |  |  |

### S-issue-4-gen: Issue wizard step 4-gen: Key or CSR (generate locally; shows openssl command)

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-issue-4-gen-1 | button | I already have a CSR |  |  |  |
| E-issue-4-gen-2 | button | Generate a new key |  |  |  |
| E-issue-4-gen-3 | textarea | CSR PEM |  |  |  |
| E-issue-4-gen-4 | button | Back |  |  |  |
| E-issue-4-gen-5 | button | Next |  |  |  |
| E-issue-4-gen-6 | button | Cancel |  |  |  |

### S-issue-5: Issue wizard step 5: Review

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-issue-5-1 | button | Back |  |  |  |
| E-issue-5-2 | button | Finish |  |  |  |
| E-issue-5-3 | button | Cancel |  |  |  |

### S-policies-dryrun: Issuance policies: dry-run form

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-policies-dryrun-1 | select | Algorithm |  |  |  |
| E-policies-dryrun-2 | textbox | Min RSA bits / SAN / name fields (3) | text |  |  |
| E-policies-dryrun-3 | textbox | CA certificate | checkbox |  |  |
| E-policies-dryrun-4 | button | Run dry run |  |  | disabled until preconditions met |

### S-nhi-dlg-propose: Propose machine identity dialog

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-nhi-dlg-propose-1 | button | Close dialog |  |  |  |
| E-nhi-dlg-propose-2 | textbox | Name | text |  |  |
| E-nhi-dlg-propose-3 | select | Kind (ai_agent/service_account/workflow) |  |  |  |
| E-nhi-dlg-propose-4 | textbox | Scope: certificate.read | checkbox |  |  |
| E-nhi-dlg-propose-5 | textbox | Scope: certificate.issue | checkbox |  |  |
| E-nhi-dlg-propose-6 | textbox | Scope: certificate.renew | checkbox |  |  |
| E-nhi-dlg-propose-7 | textbox | Scope: certificate.revoke | checkbox |  |  |
| E-nhi-dlg-propose-8 | textbox | Scope: ca.manage | checkbox |  |  |
| E-nhi-dlg-propose-9 | textbox | Scope: key.manage | checkbox |  |  |
| E-nhi-dlg-propose-10 | textbox | Scope: action.propose | checkbox |  |  |
| E-nhi-dlg-propose-11 | textbox | Scope: action.approve | checkbox |  |  |
| E-nhi-dlg-propose-12 | textbox | Scope: report.read | checkbox |  |  |
| E-nhi-dlg-propose-13 | textbox | Scope: audit.read | checkbox |  |  |
| E-nhi-dlg-propose-14 | textbox | Scope: discovery.manage | checkbox |  |  |
| E-nhi-dlg-propose-15 | textbox | Scope: notification.manage | checkbox |  |  |
| E-nhi-dlg-propose-16 | textbox | Scope: protocol.manage | checkbox |  |  |
| E-nhi-dlg-propose-17 | textbox | Scope: dashboard.manage | checkbox |  |  |
| E-nhi-dlg-propose-18 | textbox | Scope: tenant.manage | checkbox |  |  |
| E-nhi-dlg-propose-19 | textbox | Scope: user.manage | checkbox |  |  |
| E-nhi-dlg-propose-20 | button | Cancel |  |  |  |
| E-nhi-dlg-propose-21 | button | Propose |  |  | disabled until preconditions met |

### S-keys-dlg-escrow: Escrow key dialog

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-keys-dlg-escrow-1 | button | Close dialog |  |  |  |
| E-keys-dlg-escrow-2 | select | Key to escrow |  |  |  |
| E-keys-dlg-escrow-3 | textbox | Custodian A passphrase | password | req |  |
| E-keys-dlg-escrow-4 | textbox | Custodian B passphrase | password | req |  |
| E-keys-dlg-escrow-5 | button | Cancel |  |  |  |
| E-keys-dlg-escrow-6 | button | Submit for approval |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |

### S-keys-dlg-recover: Recover escrowed key dialog

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-keys-dlg-recover-1 | button | Close dialog |  |  |  |
| E-keys-dlg-recover-2 | textarea | Escrow bundle (JSON) |  | req |  |
| E-keys-dlg-recover-3 | textbox | Custodian A passphrase | password | req |  |
| E-keys-dlg-recover-4 | textbox | Custodian B passphrase | password | req |  |
| E-keys-dlg-recover-5 | button | Cancel |  |  |  |
| E-keys-dlg-recover-6 | button | Submit for approval |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |

### S-keys-dlg-byok: BYOK export dialog

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-keys-dlg-byok-1 | button | Close dialog |  |  |  |
| E-keys-dlg-byok-2 | textarea | Escrow bundle (JSON) |  | req |  |
| E-keys-dlg-byok-3 | select | Provider |  |  |  |
| E-keys-dlg-byok-4 | textbox | Region | text |  |  |
| E-keys-dlg-byok-5 | textbox | Destination KMS key ID | text | req |  |
| E-keys-dlg-byok-6 | textbox | Custodian A passphrase | password | req |  |
| E-keys-dlg-byok-7 | textbox | Custodian B passphrase | password | req |  |
| E-keys-dlg-byok-8 | button | Cancel |  |  |  |
| E-keys-dlg-byok-9 | button | Submit for approval |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |

### S-templates-dlg-draft: Draft policy from text dialog

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-templates-dlg-draft-1 | button | Close dialog |  |  |  |
| E-templates-dlg-draft-2 | textbox | Policy name | text |  |  |
| E-templates-dlg-draft-3 | textarea | Rules in plain English |  |  |  |
| E-templates-dlg-draft-4 | button | Cancel |  |  |  |
| E-templates-dlg-draft-5 | button | Parse |  |  | disabled until preconditions met |

### S-users-dlg-role: Change role dialog

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-users-dlg-role-1 | button | Close dialog |  |  |  |
| E-users-dlg-role-2 | select | Role |  |  |  |
| E-users-dlg-role-3 | button | Save |  |  |  |
| E-users-dlg-role-4 | button | Cancel |  |  |  |

### S-alerts-tab-rules: Alerts: Alert rules tab

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-alerts-tab-rules-1 | button | New rule |  |  |  |
| E-alerts-tab-rules-2 | button | Delivery queue |  |  |  |
| E-alerts-tab-rules-3 | button | Alert rules |  |  |  |
| E-alerts-tab-rules-4 | button | Edit <item> |  |  |  |
| E-alerts-tab-rules-5 | button | Delete <item> |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |

### S-alerts-dlg-newrule: New alert rule dialog

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-alerts-dlg-newrule-1 | button | Close dialog |  |  |  |
| E-alerts-dlg-newrule-2 | textbox | Name | text | req |  |
| E-alerts-dlg-newrule-3 | select | Threshold unit |  |  |  |
| E-alerts-dlg-newrule-4 | textbox | Threshold | number |  |  |
| E-alerts-dlg-newrule-5 | select | Channel (Email/Slack/PagerDuty/Webhook/ITSM ticket) |  |  |  |
| E-alerts-dlg-newrule-6 | textbox | Route to owner team | checkbox |  |  |
| E-alerts-dlg-newrule-7 | textbox | Target | text | req |  |
| E-alerts-dlg-newrule-8 | button | Create rule |  |  |  |
| E-alerts-dlg-newrule-9 | button | Cancel |  |  |  |

### S-history-detail: Action history detail

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-history-detail-1 | button | Back to list |  |  |  |
| E-history-detail-2 | button | <action row> |  |  |  |

### S-acme-dlg-prov: New ACME provisioner dialog

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-acme-dlg-prov-1 | button | Close dialog |  |  |  |
| E-acme-dlg-prov-2 | textbox | Name | text |  |  |
| E-acme-dlg-prov-3 | select | CA |  |  |  |
| E-acme-dlg-prov-4 | select | Template (optional) |  |  |  |
| E-acme-dlg-prov-5 | textarea | Allowed names (one per line) |  |  |  |
| E-acme-dlg-prov-6 | textbox | Challenge method: http-01 | checkbox |  |  |
| E-acme-dlg-prov-7 | textbox | Challenge method: dns-01 | checkbox |  |  |
| E-acme-dlg-prov-8 | button | Cancel |  |  |  |
| E-acme-dlg-prov-9 | button | Save |  |  | disabled until preconditions met |

### S-enroll-dlg-estuser: New EST user dialog

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-enroll-dlg-estuser-1 | button | Close dialog |  |  |  |
| E-enroll-dlg-estuser-2 | textbox | Username | text |  |  |
| E-enroll-dlg-estuser-3 | textarea | Allowed DNS suffixes |  |  |  |
| E-enroll-dlg-estuser-4 | button | Cancel |  |  |  |
| E-enroll-dlg-estuser-5 | button | Create user |  |  | disabled until preconditions met |

### S-enroll-dlg-cmpanchor: Register CMP trust anchor dialog

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-enroll-dlg-cmpanchor-1 | button | Close dialog |  |  |  |
| E-enroll-dlg-cmpanchor-2 | textbox | Label | text |  |  |
| E-enroll-dlg-cmpanchor-3 | textarea | Certificate (PEM) |  |  |  |
| E-enroll-dlg-cmpanchor-4 | button | Cancel |  |  |  |
| E-enroll-dlg-cmpanchor-5 | button | Register anchor |  |  | disabled until preconditions met |

### S-enroll-dlg-pbm: New CMP PBM secret dialog

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-enroll-dlg-pbm-1 | button | Close dialog |  |  |  |
| E-enroll-dlg-pbm-2 | textbox | Label | text |  |  |
| E-enroll-dlg-pbm-3 | textarea | Allowed DNS suffixes (optional) |  |  |  |
| E-enroll-dlg-pbm-4 | button | Cancel |  |  |  |
| E-enroll-dlg-pbm-5 | button | Create secret |  |  | disabled until preconditions met |

### S-discovery-endpoint: Discovery endpoint detail

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-discovery-endpoint-1 | button | Back to list |  |  |  |
| E-discovery-endpoint-2 | button | Accept risk for <item> |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-discovery-endpoint-3 | button | View <item> |  |  |  |
| E-discovery-endpoint-4 | button | Queue scan |  |  |  |
| E-discovery-endpoint-5 | button | Search certs |  |  |  |

### S-posture-dlg-notify: Notify owner dialog

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-posture-dlg-notify-1 | button | Close dialog |  |  |  |
| E-posture-dlg-notify-2 | textbox | Owner team | text |  |  |
| E-posture-dlg-notify-3 | select | Channel |  |  |  |
| E-posture-dlg-notify-4 | textbox | Delivery target | text |  |  |
| E-posture-dlg-notify-5 | button | Confirm send |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |
| E-posture-dlg-notify-6 | button | Cancel |  |  |  |

### S-plugins-dlg-install: Install delivery plugin dialog

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-plugins-dlg-install-1 | button | Close dialog |  |  |  |
| E-plugins-dlg-install-2 | textbox | manifest.json | file |  |  |
| E-plugins-dlg-install-3 | textbox | Plugin module (.wasm) | file |  |  |
| E-plugins-dlg-install-4 | textbox | Signature (optional) | file |  |  |
| E-plugins-dlg-install-5 | button | Install |  |  | disabled until preconditions met |
| E-plugins-dlg-install-6 | button | Cancel |  |  |  |

### S-targets-agent: Target Setup: agent enrollment

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-targets-agent-1 | button | Agent |  |  |  |
| E-targets-agent-2 | button | Agentless |  |  |  |
| E-targets-agent-3 | textbox | Agent name | text |  |  |
| E-targets-agent-4 | select | Host type |  |  |  |
| E-targets-agent-5 | button | Generate token |  |  | disabled until preconditions met |
| E-targets-agent-6 | button | Revoke <item> |  |  | SKIPPED: destructive (firewalled; never executed by cartographer) |

### S-targets-agentless-1: Target Setup agentless step 1: Host

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-targets-agentless-1-1 | textbox | Target name | text |  |  |
| E-targets-agentless-1-2 | textbox | Host | text |  |  |
| E-targets-agentless-1-3 | textbox | Operating system: Linux / Unix | radio |  |  |
| E-targets-agentless-1-4 | textbox | Operating system: Windows | radio |  |  |
| E-targets-agentless-1-5 | textbox | Operating system: macOS | radio |  |  |
| E-targets-agentless-1-6 | button | Back |  |  | disabled until preconditions met |
| E-targets-agentless-1-7 | button | Next |  |  |  |

### S-targets-agentless-2: Target Setup agentless step 2: Discovery

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-targets-agentless-2-1 | select | Discovery mode (Network scan / Cloud provider / None) |  |  |  |
| E-targets-agentless-2-2 | button | Back |  |  |  |
| E-targets-agentless-2-3 | button | Next |  |  |  |

### S-targets-agentless-3: Target Setup agentless step 3: Install

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-targets-agentless-3-1 | select | Install mode (SSH push / F5 BIG-IP / Citrix ADC / Kubernetes secret / Cloud API / ACME / Delivery plugin) |  |  |  |
| E-targets-agentless-3-2 | button | Back |  |  |  |
| E-targets-agentless-3-3 | button | Next |  |  |  |

### S-targets-agentless-4: Target Setup agentless step 4: Credential

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-targets-agentless-4-1 | select | Credential (list + "+ Create a new credential") |  |  |  |
| E-targets-agentless-4-2 | textbox | Renewal schedule cron (optional) | text |  |  |
| E-targets-agentless-4-3 | select | Renewal method (Manual/ACME/EST/SCEP) |  |  |  |
| E-targets-agentless-4-4 | textbox | Auto-renew | checkbox |  |  |
| E-targets-agentless-4-5 | button | Back |  |  |  |
| E-targets-agentless-4-6 | button | Next |  |  |  |

### S-targets-agentless-5: Target Setup agentless step 5: Host key

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-targets-agentless-5-1 | button | Back |  |  |  |
| E-targets-agentless-5-2 | button | Next |  |  |  |
| E-targets-agentless-5-3 | textbox | (host-key pin fields: opens only after a valid SSH credential is chosen; not enumerated, needs SSH credential) | text |  | SKIPPED: auth-gated (needs SSH credential; guide-scribe expands) |

### S-targets-agentless-6: Target Setup agentless step 6: Review

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-targets-agentless-6-1 | button | Back |  |  |  |
| E-targets-agentless-6-2 | button | (review actions: not enumerated, needs SSH credential) |  |  | SKIPPED: auth-gated (needs SSH credential; guide-scribe expands) |

### S-audit-detail: Audit evidence detail card

| ID | Role | Accessible name | Type | Req | Notes |
|---|---|---|---|---|---|
| E-audit-detail-1 | button | <audit row> |  |  |  |


## 3. Edges (traversal graph)

Global edges: `S-login` --(button "Sign in")--> `S-dash`; every authenticated state --(Ctrl/Cmd+K)--> `S-palette` --(Esc)--> origin; `S-shell` link "Nav: X" --> default state of X (48 sidebar links, listed in `E-shell-*`); unauthenticated request to any route --> `S-login`; unknown path --> `S-notfound`; `/approvals` and `/pending-actions` --redirect--> `S-inbox`.

| From | Action | To |
|---|---|---|
| S-rollout | modal-open (button "New group") | S-rollout-dlg-new-group |
| S-acme | tab-click | S-acme-tab-eab-keys |
| S-acme | tab-click | S-acme-tab-provisioners |
| S-acme | modal-open (button "New key") | S-acme-dlg-new-key |
| S-enroll | tab-click | S-enroll-tab-scep |
| S-enroll | tab-click | S-enroll-tab-est |
| S-enroll | tab-click | S-enroll-tab-cmp |
| S-enroll | modal-open (button "New challenge") | S-enroll-dlg-new-challenge |
| S-certs | button "Edit" | S-certs-pane-edit |
| S-certs | modal-open (button "Import") | S-certs-dlg-import |
| S-cas | modal-open (button "Import external root") | S-cas-dlg-import-external-root |
| S-cas | modal-open (button "New CA") | S-cas-dlg-new-ca |
| S-ceremonies | modal-open (button "Start ceremony") | S-ceremonies-dlg-start-ceremony |
| S-keys | modal-open (button "Import") | S-keys-dlg-import |
| S-keys | modal-open (button "Generate Key") | S-keys-dlg-generate-key |
| S-keys | modal-open (button "Export backup") | S-keys-dlg-export-backup |
| S-templates | modal-open (button "New template") | S-templates-dlg-new-template |
| S-templates | modal-open (button "Edit") | S-templates-dlg-edit |
| S-discovery | modal-open (button "New scan") | S-discovery-dlg-new-scan |
| S-posture | modal-open (button "Open PQC wave") | S-posture-dlg-open-pqc-wave |
| S-pqc | button "Start migration wave" | S-pqc-pane-start-migration-wave |
| S-expiry | modal-open (button "Open PQC wave") | S-expiry-dlg-open-pqc-wave |
| S-users | modal-open (button "Invite user") | S-users-dlg-invite-user |
| S-accessreview | modal-open (button "Open campaign") | S-accessreview-dlg-open-campaign |
| S-policies | button "New policy" | S-policies-pane-new-policy |
| S-policies | button "Edit Baseline" | S-policies-pane-edit-policy |
| S-roles | button "New role" | S-roles-pane-new-role |
| S-roles | button "Edit cert-owner-readonly" | S-roles-pane-edit-role |
| S-settings | button "Add cluster" | S-settings-pane-add-cluster |
| S-settings | button "Add endpoint" | S-settings-pane-add-endpoint |
| S-settings | button "Add domain" | S-settings-pane-add-domain |
| S-settings | button "Add cloud source" | S-settings-pane-add-cloud-source |
| S-cas | modal-open (button "Update") | S-cas-dlg-update |
| S-cas | modal-open (button "Re-key") | S-cas-dlg-rekey |
| S-nhi | modal-open (button "Propose identity") | S-nhi-dlg-propose |
| S-keys | modal-open (button "Escrow") | S-keys-dlg-escrow |
| S-keys | modal-open (button "Recover") | S-keys-dlg-recover |
| S-keys | modal-open (button "BYOK export") | S-keys-dlg-byok |
| S-templates | modal-open (button "Draft policy from text") | S-templates-dlg-draft |
| S-users | modal-open (button "Change role") | S-users-dlg-role |
| S-alerts | tab-click | S-alerts-tab-rules |
| S-alerts | modal-open (button "New rule") | S-alerts-dlg-newrule |
| S-acme | modal-open (button "New provisioner") | S-acme-dlg-prov |
| S-enroll | modal-open (button "New user") | S-enroll-dlg-estuser |
| S-enroll | modal-open | S-enroll-dlg-cmpanchor |
| S-enroll | modal-open | S-enroll-dlg-pbm |
| S-posture | modal-open (button "Notify owner") | S-posture-dlg-notify |
| S-plugins | modal-open (button "Install plugin") | S-plugins-dlg-install |
| S-certs | row click | S-certs-detail |
| S-certs | row checkbox | S-certs-selected |
| S-certs | button "Issue certificate" | S-issue |
| S-issue | button "Next" | S-issue-2 |
| S-issue-2 | button "Next" | S-issue-3 |
| S-issue-3 | button "Next" | S-issue-4 |
| S-issue-4 | button "I already have a CSR" | S-issue-4-csr |
| S-issue-4 | button "Generate a new key" | S-issue-4-gen |
| S-issue-4-csr | button "Next" | S-issue-5 |
| S-issue-5 | button "Finish" | S-certs (new row) / myreq (approval templates) |
| S-cas | row click | S-cas-detail |
| S-cas | button "Hierarchy" | S-cas-hierarchy |
| S-cas-detail | button "Update" | S-cas-dlg-update |
| S-cas-detail | button "Re-key" | S-cas-dlg-rekey |
| S-policies | scroll | S-policies-dryrun |
| S-nhi | button "Propose identity" | S-nhi-dlg-propose |
| S-keys | button "Escrow" | S-keys-dlg-escrow |
| S-keys | button "Recover" | S-keys-dlg-recover |
| S-keys | button "BYOK export" | S-keys-dlg-byok |
| S-templates | button "Draft policy from text" | S-templates-dlg-draft |
| S-users | button "Change role" | S-users-dlg-role |
| S-alerts | tab "Alert rules" | S-alerts-tab-rules |
| S-alerts-tab-rules | button "New rule" | S-alerts-dlg-newrule |
| S-history | row click | S-history-detail |
| S-acme-tab-provisioners | button "New provisioner" | S-acme-dlg-prov |
| S-enroll-tab-est | button "New user" | S-enroll-dlg-estuser |
| S-enroll-tab-cmp | button "Register trust anchor" | S-enroll-dlg-cmpanchor |
| S-enroll-tab-cmp | button "New PBM secret" | S-enroll-dlg-pbm |
| S-discovery | row click (endpoint) | S-discovery-endpoint |
| S-posture | button "Notify owner" | S-posture-dlg-notify |
| S-plugins | button "Install plugin" | S-plugins-dlg-install |
| S-targets | card "Agent" | S-targets-agent |
| S-targets | card "Agentless" | S-targets-agentless-1 |
| S-audit | row click | S-audit-detail |
| S-dash | button "Open Inventory" | S-certs |
| S-dash | CA row | S-cas |
| S-discovery-endpoint | button "View →" | S-certs-detail |
| S-automation | link "Open SLO dashboard" | S-slo |
| S-slo | link "Back to Automation" | S-automation |
| S-cahealth | link <CA name> | S-cas-detail |
| S-inbox | button "Approve"/"Reject" | S-inbox (decision recorded; GUARDED) |
| S-targets-agentless-1 | button "Next" | S-targets-agentless-2 |
| S-targets-agentless-2 | button "Next" | S-targets-agentless-3 |
| S-targets-agentless-3 | button "Next" | S-targets-agentless-4 |
| S-targets-agentless-4 | button "Next" | S-targets-agentless-5 |
| S-targets-agentless-5 | button "Next" | S-targets-agentless-6 |

## 4. Destructive / skipped edges (firewall, default-deny)

Never executed during mapping. The crawler also blocked every non-GET `/api` request at the network layer (0 attempted writes recorded). Rows below are every control matching a mutation verb (delete, remove, revoke, reject, disable, deactivate, abort, suspend, re-key, rotate, approve, accept risk, send, submit for approval, close campaign, bulk renew/revoke/delete/rotate, renew, log out). Guide capture may open the confirm dialog only on a throwaway hub.

| Element | Source state | Action | Reason |
|---|---|---|---|
| E-shell-53 | S-shell | button "Log out" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-palette-4 | S-palette | button "Action: Revoke certificate…" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-dash-11 | S-dash | button "#Active Certs# revoked not counted" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-inbox-4 | S-inbox | button "Approve" x6 | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-inbox-5 | S-inbox | button "Reject" x6 | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-alerts-6 | S-alerts | button "Send test delivery" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-nhi-2 | S-nhi | button "Approve <item>" x3 | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-nhi-3 | S-nhi | button "Reject ci-deployer" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-nhi-4 | S-nhi | button "Revoke <item>" x3 | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-nhi-5 | S-nhi | button "Reject payments-svc" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-nhi-6 | S-nhi | button "Reject triage-copilot" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-targets-6 | S-targets | button "Revoke <item>" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-acme-4 | S-acme | button "Revoke <item>" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-acme-tab-eab-keys-4 | S-acme-tab-eab-keys | button "Revoke <item>" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-acme-tab-provisioners-6 | S-acme-tab-provisioners | button "Delete <item>" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-enroll-tab-est-5 | S-enroll-tab-est | button "Rotate password for <item>" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-enroll-tab-est-6 | S-enroll-tab-est | button "Disable <item>" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-enroll-tab-est-7 | S-enroll-tab-est | button "Delete <item>" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-enroll-tab-cmp-6 | S-enroll-tab-cmp | button "Rotate <item>" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-enroll-tab-cmp-7 | S-enroll-tab-cmp | button "Revoke <item>" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-integ-24 | S-integ | button "Send test" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-certs-17 | S-certs | button "Bulk renew" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-certs-19 | S-certs | button "Bulk revoke" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-certs-28 | S-certs | button "Renew" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-certs-29 | S-certs | button "Revoke" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-certs-pane-edit-17 | S-certs-pane-edit | button "Bulk renew" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-certs-pane-edit-19 | S-certs-pane-edit | button "Bulk revoke" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-certs-pane-edit-33 | S-certs-pane-edit | button "Renew" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-certs-pane-edit-34 | S-certs-pane-edit | button "Revoke" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-cas-12 | S-cas | button "Suspend" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-cas-13 | S-cas | button "Revoke <item>" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-ceremonies-2 | S-ceremonies | button "Approve <item>" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-ceremonies-3 | S-ceremonies | button "Abort <item>" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-keys-7 | S-keys | button "Bulk rotate" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-keys-8 | S-keys | button "Bulk delete" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-keys-10 | S-keys | button "Rotate <item>" x6 | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-keys-14 | S-keys | button "Delete <item>" x6 | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-codesign-4 | S-codesign | button "Revoked0" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-templates-4 | S-templates | button "Delete" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-templates-dlg-new-template-12 | S-templates-dlg-new-template | button "approver" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-templates-dlg-edit-11 | S-templates-dlg-edit | button "approver" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-discovery-7 | S-discovery | button "Accept risk for <item>" x4 | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-posture-10 | S-posture | button "Renew" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-posture-12 | S-posture | button "Accept risk…" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-pqc-12 | S-pqc | button "Expire before 203036still to migrate; rotate at renewal" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-pqc-pane-start-migration-wave-12 | S-pqc-pane-start-migration-wave | button "Expire before 203036still to migrate; rotate at renewal" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-expiry-2 | S-expiry | button "Renew" x2 | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-expiry-3 | S-expiry | button "Renew" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-users-3 | S-users | button "Deactivate" x4 | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-users-dlg-invite-user-4 | S-users-dlg-invite-user | button "Send invitation" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-accessreview-8 | S-accessreview | button "Close campaign" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-policies-4 | S-policies | button "Delete <item>" x2 | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-policies-pane-new-policy-13 | S-policies-pane-new-policy | button "Delete <item>" x2 | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-policies-pane-edit-policy-13 | S-policies-pane-edit-policy | button "Delete <item>" x2 | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-roles-4 | S-roles | button "Delete <item>" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-roles-pane-new-role-24 | S-roles-pane-new-role | button "Delete <item>" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-roles-pane-edit-role-24 | S-roles-pane-edit-role | button "Delete <item>" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-invsrc-2 | S-invsrc | button "Delete <item>" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-migration-9 | S-migration | button "Submit for approval" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-settings-2 | S-settings | button "Send test event" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-settings-7 | S-settings | button "Send now" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-settings-pane-add-cluster-2 | S-settings-pane-add-cluster | button "Send test event" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-settings-pane-add-cluster-7 | S-settings-pane-add-cluster | button "Send now" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-settings-pane-add-cluster-11 | S-settings-pane-add-cluster | button "Remove cluster <item>" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-settings-pane-add-endpoint-2 | S-settings-pane-add-endpoint | button "Send test event" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-settings-pane-add-endpoint-7 | S-settings-pane-add-endpoint | button "Send now" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-settings-pane-add-endpoint-11 | S-settings-pane-add-endpoint | button "Remove endpoint 1" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-settings-pane-add-domain-2 | S-settings-pane-add-domain | button "Send test event" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-settings-pane-add-domain-7 | S-settings-pane-add-domain | button "Send now" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-settings-pane-add-domain-13 | S-settings-pane-add-domain | button "Remove domain 1" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-settings-pane-add-cloud-source-2 | S-settings-pane-add-cloud-source | button "Send test event" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-settings-pane-add-cloud-source-7 | S-settings-pane-add-cloud-source | button "Send now" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-settings-pane-add-cloud-source-17 | S-settings-pane-add-cloud-source | button "Remove aws-acm" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-certs-detail-5 | S-certs-detail | button "Renew" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-certs-detail-6 | S-certs-detail | button "Revoke" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-certs-selected-2 | S-certs-selected | button "Bulk renew" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-certs-selected-4 | S-certs-selected | button "Bulk revoke" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-cas-detail-3 | S-cas-detail | button "Suspend" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-cas-detail-4 | S-cas-detail | button "Revoke <item>" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-keys-dlg-escrow-6 | S-keys-dlg-escrow | button "Submit for approval" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-keys-dlg-recover-6 | S-keys-dlg-recover | button "Submit for approval" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-keys-dlg-byok-9 | S-keys-dlg-byok | button "Submit for approval" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-alerts-tab-rules-5 | S-alerts-tab-rules | button "Delete <item>" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-discovery-endpoint-2 | S-discovery-endpoint | button "Accept risk for <item>" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-posture-dlg-notify-5 | S-posture-dlg-notify | button "Confirm send" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-targets-agent-6 | S-targets-agent | button "Revoke <item>" | mutation verb: opens confirm dialog or fires POST/PUT/DELETE |
| E-targets-agentless-5-3 | S-targets-agentless-5 | textbox "(host-key pin fields: opens only after a valid SSH credential is chosen; not enumerated, needs SSH credential)" | SKIPPED: auth-gated (needs SSH credential; guide-scribe expands) |
| E-targets-agentless-6-2 | S-targets-agentless-6 | button "(review actions: not enumerated, needs SSH credential)" | SKIPPED: auth-gated (needs SSH credential; guide-scribe expands) |

Also never executed: form submissions that create objects (Create CA, Generate token, Create key, etc.). They are mapped (the dialogs and fields are inventoried) but only clicked up to the final submit. The only login performed was the API/UI sign-in needed to browse.

## 5. Data and config readiness per state

| State key | Works on demo seed? | Needs |
|---|---|---|
| agents | Partly | a running agent heartbeat (seed registers one offline agent) |
| automation | Partly | agent heartbeat + one renewal run for non-zero tiles |
| rollout | Partly | targets (seeded) + agent/SSH to run |
| alerts | Partly | SMTP/webhook sink so deliveries reach Sent; test deliveries create rows |
| cloudkeys | No | AWS KMS/Azure Key Vault/GCP KMS credentials (LocalStack for AWS) |
| ct | No | CT monitor polling real logs for a domain you own |
| anomalies | No | scheduled anomaly scan after an issuance burst |
| slo | Partly | SLO sweeper to run (budgets empty on a fresh hub) |
| velocity | Partly | issuance spread over days (seed puts everything on one day) |
| posture | Partly | daily snapshots for the trend chart |
| spiffe | No | SPIFFE_SIGNING_CA_ID + attesting workload |
| tenants | No | MULTI_TENANCY=on + restart |
| plugins | No | signed WASM plugin bundle |
| migration | No | export file from AD CS / Venafi / etc. |
| enroll | Partly | SCEP needs KRYPTKEEPER_SCEP_ENABLED=true (shows "Not enabled") |
| settings | Partly | env/SMTP for evidence delivery; SIEM_* for SIEM |
| ceremonies | Partly | named approver principals (alice, bob, carol) to complete a ceremony |
| inbox | Yes | second named approver to clear items |
| codesign | No | approve the seeded code-signing requests as a named admin |
| targets-agentless-5 | No | SSH credential via API/CLI |
| targets-agentless-6 | No | SSH credential via API/CLI |
| keys-dlg-byok | No | external KMS |
| integ | Partly | SMTP/Slack/Jira targets; ITSM credential created via API |

All other states work on the standard seed from `docs/guides/screenshot-tour.md` (Recipe).

