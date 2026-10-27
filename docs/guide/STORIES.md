# Kryptkeeper UI: STORIES

Task-oriented flows for the guide and screenshot tour. Each step: route, element (accessible name from `APP_MAP.md`), action, expected visible result. "Capture" lists the screenshot states to take. Element ids are in `APP_MAP.md`; the claim table at the end maps every element id to the story or stories that exercise it (or a SKIPPED reason).

Conventions: **Persona** is the role to sign in as. **Flags**: `MULTI-USER` needs a second named principal, `LAB` needs hardware/host/agent, `EXTERNAL` needs a third-party service or artifact, `CONFIG` needs a hub env change + restart, `LOCAL SINK` needs a local SMTP/webhook receiver, `DESTRUCTIVE` capture only on a throwaway hub up to the confirm dialog, `TIME` needs scheduled jobs to run. Steps that create data say so; the dev hub resets from a fresh data dir.

Sign-in note: password login per `scripts/dev/local-review-env.sh` (the bootstrap token cannot approve and shows requester `bootstrap`). The login rate limit is about 9 per minute: reuse one session.

## 1. Stories

| ID | Title | Persona | Flags |
|---|---|---|---|
| U-01 | Sign in and find your way around | Any user | - |
| U-02 | See what needs attention on the dashboard | PKI admin | - |
| U-03 | Find anything with global search and the command palette | Any user | - |
| U-04 | Create a root CA | PKI admin | - |
| U-05 | Create an intermediate (issuing) CA under a root | PKI admin | - |
| U-06 | Import an external root CA (trust anchor) | PKI admin | - |
| U-07 | Inspect a CA and read the hierarchy | PKI admin / Auditor | - |
| U-08 | Suspend, update, re-key or revoke a CA (guarded) | PKI admin | DESTRUCTIVE |
| U-09 | Run a root key ceremony (M-of-N) | PKI admin + 2 designated approvers | MULTI-USER |
| U-10 | Create a certificate template | PKI admin | - |
| U-11 | Edit a template and read its revisions | PKI admin | - |
| U-12 | Draft an issuance policy from plain English | PKI admin | - |
| U-13 | Issue a certificate with the guided wizard (own CSR) | PKI operator | - |
| U-14 | Issue a certificate with a generated key (local openssl) | Developer | - |
| U-15 | Request a certificate that needs approval, then track it | Requester (developer) | - |
| U-16 | Browse, filter and inspect certificates | PKI operator / Auditor | - |
| U-17 | Approve a pending request (second person) | Approver (not the requester) | MULTI-USER |
| U-18 | Reject a request | Approver | DESTRUCTIVE (irreversible decision) |
| U-19 | Approve a proposed policy or exception (pending action) | Approver | MULTI-USER |
| U-20 | Take ownership of an unmanaged certificate and edit ownership | PKI operator | - |
| U-21 | Bulk import existing certificates | PKI operator | - |
| U-22 | Renew certificates (single and bulk) | PKI operator | - |
| U-23 | Revoke a certificate (single and bulk) | PKI admin | DESTRUCTIVE |
| U-24 | Export the certificate inventory as CSV | Auditor | - |
| U-25 | Run a discovery scan and read the results | Security engineer | - |
| U-26 | Inspect an endpoint and accept a finding as risk | Security engineer | MULTI-USER (accept risk becomes a pending action) |
| U-27 | Set up ACME for a server (provisioner, EAB key, client) | PKI admin then Platform engineer | LAB (ACME client host) |
| U-28 | Enroll devices with SCEP, EST or CMP | PKI admin / Network engineer | CONFIG + LAB DEVICE |
| U-29 | Enroll a satellite agent | Platform engineer | LAB (host running the agent) |
| U-30 | Bring an agentless target under management | Platform engineer | CONFIG + LAB HOST |
| U-31 | Set renewal policy per target | Platform engineer | - |
| U-32 | Roll a certificate out to a cluster (rollout group, canary first) | Platform engineer | LAB (to execute rollout) |
| U-33 | Watch automation and the failed-renewal queue | Platform engineer / SRE | LAB |
| U-34 | Install a delivery plugin (WASM) | Platform engineer | EXTERNAL ARTIFACT (build) |
| U-35 | Configure notifications (email, Slack, webhook, PagerDuty) | PKI admin | LOCAL SINK |
| U-36 | Send test deliveries, build alert rules, retry failures | PKI operator | LOCAL SINK |
| U-37 | Connect Jira or ServiceNow (ITSM) for ticket-based alerts | PKI admin | EXTERNAL SERVICE |
| U-38 | Invite a user and assign a role | PKI admin | - |
| U-39 | Create a custom role with least privilege | PKI admin | - |
| U-40 | Run a periodic access review | Auditor / PKI admin | - |
| U-41 | Turn on multi-tenancy and manage tenants | PKI admin (super-admin) | CONFIG |
| U-42 | Create issuance policies and dry-run a request | PKI admin | - |
| U-43 | Propose a machine identity and approve it (NHI) | Platform engineer + Approver | MULTI-USER |
| U-44 | Issue SPIFFE SVIDs for workloads | Platform engineer | CONFIG + LAB WORKLOAD |
| U-45 | Check the blast radius before a destructive change | PKI admin | - |
| U-46 | Issue an SSH user or host certificate | Platform engineer | - |
| U-47 | Use the Code Signing inventory | Release engineer | MULTI-USER |
| U-48 | Generate, back up, import and rotate keys | PKI admin | DESTRUCTIVE for rotate/delete |
| U-49 | Escrow, recover and BYOK-export a root key (dual control) | PKI admin + second approver | MULTI-USER + EXTERNAL KMS |
| U-50 | Review cloud KMS key inventory | Security engineer | EXTERNAL CLOUD |
| U-51 | Sync certificates from another CA (inventory sources) | PKI admin | EXTERNAL CA (live sources) |
| U-52 | Migrate templates from another CA product | PKI admin + Approver | EXTERNAL EXPORT FILE |
| U-53 | Monitor Certificate Transparency findings | Security engineer | EXTERNAL (public CT logs) |
| U-54 | Review issuance anomalies | Security engineer | TIME |
| U-55 | Read the PKI risk reports | PKI admin / CISO | - |
| U-56 | Produce compliance evidence (packs, CBOM, scheduled delivery) | Auditor | LOCAL SINK (for email) |
| U-57 | Investigate with Audit Evidence, Change Audit and History | Auditor | - |
| U-58 | Forward security events and manage discovery sources (Settings) | PKI admin | CONFIG + EXTERNAL |
| U-59 | Use the app on a phone-sized screen | Any user | - |
| U-60 | See empty, error and not-found states | Any user | - |
| U-61 | Connect an existing CA (Vault PKI) as an issuer | PKI admin | EXTERNAL |
| U-62 | Push a CA bundle to host trust stores (second approver) | PKI admin | MULTI-USER |
| U-63 | Start a post-quantum migration wave with a target algorithm | PKI admin | - |
| U-64 | Install onto SQL Server, Remote Desktop or Exchange over WinRM | PKI admin | LAB |

### U-01: Sign in and find your way around

- **Persona / role:** Any user
- **Preconditions:** Hub running with password login; signed out. Demo seed (`scripts/dev/seed-demo.sh`) optional.
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/login` · input "Email" · fill `demo@example.com` -> field shows value
  2. `/login` · input "Password" · fill the configured test password -> field masks value
  3. `/login` · button "Sign in" · click -> redirect to `/` (Dashboard "What needs a human")
  4. `/` · sidebar group headings (Today, Automation, Connect, Estate, Evidence, Analysis, Administration) · read -> 7 groups visible
  5. `/` · button "Theme: Dark" then "Theme: System" · click -> page recolours
  6. `/` · button "Collapse sidebar" · click -> sidebar collapses to icons; click again to expand
- **Capture:** login (empty); login (filled); dash (first view); shell expanded; shell collapsed; dash dark theme
- **States exercised:** `S-login`, `S-shell`, `S-dash`

### U-02: See what needs attention on the dashboard

- **Persona / role:** PKI admin
- **Preconditions:** Seeded hub
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/` · KPI tiles (Active Certs, Expiring 30d, Expired, Endpoints discovered, Risky endpoints, Alerts pending) · hover/click -> each deep-links to a filtered page
  2. `/` · button "Open Inventory" · click -> `/certificates`
  3. `/` · CA list card rows (e.g. "Acme Issuing CA") · click -> CA page
  4. `/` · button "Download executive one-pager PDF" · click -> PDF download (capture the button, not the file)
- **Capture:** dash full page 1440; dash expiry strip + estate donut
- **States exercised:** `S-dash`

### U-03: Find anything with global search and the command palette

- **Persona / role:** Any user
- **Preconditions:** Seeded hub
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. Any page · press Ctrl/Cmd+K -> command palette opens (Actions: Issue/Renew/Revoke certificate; Pages)
  2. Palette · input "Search pages, certificates, CAs…" · type `acme` -> matching pages/results
  3. Palette · press Escape -> closes
  4. `/search?q=acme` (direct) · input "Search all inventory" · view -> Results (13) grouped certificate/CA/template/endpoint
  5. `/search` · button "Clear" -> empty "Start typing" state
  6. `/search` · result row (CA) · click -> navigates to that CA
- **Capture:** palette open; palette with query; search empty; search results acme
- **States exercised:** `S-palette`, `S-search`

### U-04: Create a root CA

- **Persona / role:** PKI admin
- **Preconditions:** Signed in as pki-admin; software key store
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/cas` · button "New CA" · click -> dialog "New CA"
  2. dialog · select "Type" · choose Root
  3. dialog · input "Subject CN" (required) · fill `Lab Root CA`
  4. dialog · input "Subject Org (optional)" · fill `Acme`
  5. dialog · select "Algorithm" · choose ECDSA P-384
  6. dialog · input "Validity (e.g. 10y, 365d)" · fill `10y`
  7. dialog · button "Create CA" · click -> dialog closes, new row "Lab Root CA, Root, Software, Active" appears (NOTE: creates a root; use a throwaway hub)
- **Capture:** cas list; new CA dialog empty; new CA dialog filled; cas list with new CA
- **States exercised:** `S-cas`, `S-cas-dlg-new-ca`

### U-05: Create an intermediate (issuing) CA under a root

- **Persona / role:** PKI admin
- **Preconditions:** Root CA exists
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/cas` · button "New CA" -> dialog
  2. dialog · select "Type" · choose Intermediate -> a parent-CA selector appears (verify: crawler did not choose Intermediate; capture and note extra fields)
  3. dialog · input "Subject CN" · fill `Lab Issuing CA`
  4. dialog · button "Create CA" -> new Intermediate row
- **Capture:** new CA dialog Intermediate selected; cas list
- **States exercised:** `S-cas-dlg-new-ca`

### U-06: Import an external root CA (trust anchor)

- **Persona / role:** PKI admin
- **Preconditions:** A root certificate PEM file (public cert only)
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/cas` · button "Import external root" · click -> dialog
  2. dialog · input "Name" (required) · fill `Partner Root`
  3. dialog · textarea "Certificate PEM" (required) · paste PEM
  4. dialog · button "Import root" -> row appears marked imported/external
- **Capture:** import dialog empty; import dialog filled
- **States exercised:** `S-cas-dlg-import-external-root`

### U-07: Inspect a CA and read the hierarchy

- **Persona / role:** PKI admin / Auditor
- **Preconditions:** Seeded hub
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/cas` · row "Acme Issuing CA" · click -> URL `/cas/<id>`; detail card shows Type, Storage, Status, Issued count
  2. `/cas/<id>` · button "Hierarchy" · click -> tree: Root -> Issuing -> Internal Services; "Root renewal 2026" shown "Pending ceremony"
  3. `/cas` · button "List" -> back to list
  4. `/cas` · selects "Filter by CA type"/"Filter by CA status" -> list narrows
  5. `/reports/ca-health` · read table (expiry, days left, algorithm strength)
- **Capture:** cas detail; cas hierarchy; ca health table
- **States exercised:** `S-cas`, `S-cas-detail`, `S-cas-hierarchy`, `S-cahealth`

### U-08: Suspend, update, re-key or revoke a CA (guarded)

- **Persona / role:** PKI admin
- **Preconditions:** Throwaway hub (destructive); approver for re-key
- **Flags:** DESTRUCTIVE
- **Steps:**
  1. `/cas/<id>` · button "Update" -> dialog; fill "Display name", "CRL distribution points", "OCSP service URL"; "Save changes"
  2. `/cas/<id>` · button "Re-key" -> 3-step dialog: step 1 Blast radius (button "Acknowledge impact", then "Next"); step 2 Options; step 3 Review -> "Submit for approval" (capture up to review; do not submit on shared hub)
  3. `/cas/<id>` · button "Suspend" -> confirm; status becomes Suspended; "Activate" enables
  4. `/cas/<id>` · button "Revoke CA" -> confirm (capture the confirm only)
- **Capture:** update dialog; rekey step 1 blast radius; rekey step 2; rekey step 3; suspend confirm
- **States exercised:** `S-cas-detail`, `S-cas-dlg-update`, `S-cas-dlg-rekey`

### U-09: Run a root key ceremony (M-of-N)

- **Persona / role:** PKI admin + 2 designated approvers
- **Preconditions:** Multi-user: ceremony approvers must be named principals (seed uses alice, bob, carol; quorum 2). Seed leaves "Root renewal 2026" pending.
- **Flags:** MULTI-USER
- **Steps:**
  1. `/ceremonies` · button "Start ceremony" -> dialog
  2. dialog · inputs "Name", "Common name", select "Algorithm", "Validity days", "Approvers" (comma list), "Quorum" · fill `Root R3`, `Acme Root R3`, ECDSA-P384, 3650, `alice,bob`, 2
  3. dialog · button "Start" -> new ceremony card, "0 of 2 approvals"
  4. Sign in as alice (needs a login for that principal) · `/ceremonies` · button "Approve <ceremony>" -> "1 of 2"
  5. Repeat as bob -> quorum met; CA `Acme Root R3` becomes Active in `/cas`
  6. As initiator · button "Abort <ceremony>" (guarded) -> ceremony aborted
- **Capture:** ceremony list pending; start dialog; approvals 1 of 2; completed ceremony; cas list with new root
- **States exercised:** `S-ceremonies`, `S-ceremonies-dlg-start-ceremony`

### U-10: Create a certificate template

- **Persona / role:** PKI admin
- **Preconditions:** Seeded hub
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/templates` · button "New template" -> dialog
  2. dialog · input "Name (identifier)" (required) · `web-server-30d`
  3. dialog · inputs "Display name", "Validity period" (`30d`), "Extended key usage" (`serverAuth`), "Allowed algorithms" (`ECDSA-P256`)
  4. dialog · select "Issued to"; select "Status" Active
  5. dialog · role chips (pki-admin, pki-operator, approver, viewer, auditor, service-account) · toggle pki-operator
  6. dialog · checkboxes "Require approval", "Allow SSH certificates", "Restrict the names this template can issue"
  7. dialog · button "Create" -> row appears in table (NAME / VALIDITY / EKU / STATUS)
- **Capture:** templates list; new template dialog; new template with advanced checkboxes
- **States exercised:** `S-templates`, `S-templates-dlg-new-template`

### U-11: Edit a template and read its revisions

- **Persona / role:** PKI admin
- **Preconditions:** Seeded hub
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/templates` · row "Web Server (90 day)" · click -> opens Edit dialog
  2. dialog · change "Validity period" -> `60d`
  3. dialog · button "Save changes" -> row updates
  4. (Known: template revisions panel returns 503 on this build: see report)
- **Capture:** edit dialog
- **States exercised:** `S-templates`, `S-templates-dlg-edit`

### U-12: Draft an issuance policy from plain English

- **Persona / role:** PKI admin
- **Preconditions:** Seeded hub
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/templates` · button "Draft policy from text" -> dialog
  2. dialog · input "Policy name" · `no-rsa-2048`
  3. dialog · textarea "Rules in plain English" · `RSA keys must be at least 3072 bits. Maximum validity 90 days.`
  4. dialog · button "Parse" -> understood-rules preview; "Submit for approval" then needs a second person (see U-19)
- **Capture:** draft dialog empty; parsed preview
- **States exercised:** `S-templates-dlg-draft`

### U-13: Issue a certificate with the guided wizard (own CSR)

- **Persona / role:** PKI operator
- **Preconditions:** Issuing CA + template exist; a CSR PEM (e.g. `openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout k.pem -subj /CN=web.acme.test -out csr.pem`)
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/certificates` · button "Issue certificate" -> `/certificates/issue` step 1 of 5
  2. Step 1 · select "Certificate authority" · choose Acme Issuing CA · button "Next"
  3. Step 2 · select "Issuance template" · Web Server (90 day) · "Next"
  4. Step 3 · inputs "Subject common name" `web.acme.test`, "Subject alternative names" `web.acme.test` · "Next"
  5. Step 4 · button "I already have a CSR" -> textarea "CSR PEM" · paste · "Next"
  6. Step 5 Review (CA, Template, CN, SANs, Key source: Existing CSR) · button "Finish" -> certificate issued; download link / detail appears
  7. `/certificates` · search `web.acme.test` -> new row Active
- **Capture:** wizard step1; step2; step3; step4 choice; step4 csr pasted; step5 review; success + download; certificate in list
- **States exercised:** `S-issue`, `S-issue-2`, `S-issue-3`, `S-issue-4`, `S-issue-4-csr`, `S-issue-5`, `S-certs`

### U-14: Issue a certificate with a generated key (local openssl)

- **Persona / role:** Developer
- **Preconditions:** As U-13
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. Steps 1-3 as U-13
  2. Step 4 · button "Generate a new key" -> shows `openssl req ... -keyout issuance.key -out issuance.csr`; textarea "CSR PEM" appears for the result
  3. paste CSR · "Next" · "Finish"
- **Capture:** wizard step4 generate
- **States exercised:** `S-issue-4-gen`

### U-15: Request a certificate that needs approval, then track it

- **Persona / role:** Requester (developer)
- **Preconditions:** Template with approval (e.g. "Production Wildcard (needs approval)", "Code Signing (1 year)")
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/certificates/issue` · choose Acme Issuing CA and template "Production Wildcard (needs approval)" · fill CN `*.acme.test` · provide CSR · "Finish" -> message "submitted for approval" (no certificate yet)
  2. `/my-requests` · read "Monthly quota" card and "Your certificate requests" table -> row Status Pending
  3. When approved (U-17) · `/my-requests` · Download column shows download action
- **Capture:** submit confirmation; my requests pending; my requests approved
- **States exercised:** `S-myreq`, `S-issue-5`

### U-16: Browse, filter and inspect certificates

- **Persona / role:** PKI operator / Auditor
- **Preconditions:** Seeded hub
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/certificates` · input "Search certificates" · type `acme` -> filtered
  2. selects "Filter by CA", "Filter by certificate status", "Filter by grade", "Filter by management state", "Filter by origin", "Filter by trust class", "Sort certificates" · choose values · button "Apply filters"
  3. button "Unowned only" -> only unowned
  4. button "Reset" -> filters cleared
  5. row `lab-switch.acme.test` · click -> `/certificates/<fingerprint>`; detail card: Issuer, Valid until, Serial, Key algorithm, Origin, Grade, Risk score, Fingerprint, SANs, Ownership
  6. detail · button "Back to list"
- **Capture:** certs filters; cert detail card; cert grade/risk detail
- **States exercised:** `S-certs`, `S-certs-detail`

### U-17: Approve a pending request (second person)

- **Persona / role:** Approver (not the requester)
- **Preconditions:** Pending requests exist (seed leaves 5 + pending actions; the bootstrap token cannot approve). Sign in as a named approver/admin distinct from requester.
- **Flags:** MULTI-USER
- **Steps:**
  1. `/inbox` · selects "Type" (All/Certificate approvals/Pending actions) and "Age" -> list filters
  2. `/inbox` · card "Certificate approval: issue from template Production Wildcard (needs approval)" · button "Approve" -> card disappears; toast; certificate issued
  3. `/inbox` · card "Pending action: Codesign OIDC trust rule ..." · button "Approve" -> action applied
  4. `/reports/change-audit` -> new rows with requester vs approver
- **Capture:** inbox full; approve confirm/toast; inbox after approve
- **States exercised:** `S-inbox`

### U-18: Reject a request

- **Persona / role:** Approver
- **Preconditions:** Pending request
- **Flags:** DESTRUCTIVE (irreversible decision)
- **Steps:**
  1. `/inbox` · card · button "Reject" -> reason prompt (verify) -> confirm; card removed; requester sees status Rejected in `/my-requests`
- **Capture:** reject prompt
- **States exercised:** `S-inbox`

### U-19: Approve a proposed policy or exception (pending action)

- **Persona / role:** Approver
- **Preconditions:** Draft policy or exception proposed (U-12, U-44)
- **Flags:** MULTI-USER
- **Steps:**
  1. `/inbox` · filter "Type" = Pending actions
  2. card "Exception create ..." · "Approve" -> exception active; Discovery accepted-risk list updates
- **Capture:** pending actions list
- **States exercised:** `S-inbox`

### U-20: Take ownership of an unmanaged certificate and edit ownership

- **Persona / role:** PKI operator
- **Preconditions:** Unowned certs exist
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/certificates/<fp>` · detail · text "Nobody manages this certificate yet." · button "Take over" -> Ownership shows you
  2. detail · button "Edit" -> inline Ownership form (Owner email, Owner team, Service, Labels) · "Save"
  3. `/certificates` · row checkboxes · button "Take over selected" -> bulk
- **Capture:** detail with Take over; ownership edit form
- **States exercised:** `S-certs-detail`, `S-certs-pane-edit`, `S-certs-selected`

### U-21: Bulk import existing certificates

- **Persona / role:** PKI operator
- **Preconditions:** PEM file
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/certificates` · button "Bulk import" -> dialog (reads: Certificate PEM, Team ID, Notes)
  2. textarea "Certificate PEM" · paste
  3. inputs "Team ID", "Notes" · fill
  4. button "Confirm import" -> rows appear with origin "imported"
- **Capture:** import dialog
- **States exercised:** `S-certs-dlg-import`

### U-22: Renew certificates (single and bulk)

- **Persona / role:** PKI operator
- **Preconditions:** Certificates near expiry (seed: 13 within 90 days)
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/certificates` · status filter -> Active; row · detail · button "Renew" -> new certificate issued, replacing prior
  2. Select several rows · button "Bulk renew" -> progress then result summary
  3. `/reports/expiry-timeline` · confirm distribution shifts
- **Capture:** renew in detail; bulk renew result
- **States exercised:** `S-certs-detail`, `S-certs-selected`, `S-expiry`

### U-23: Revoke a certificate (single and bulk)

- **Persona / role:** PKI admin
- **Preconditions:** Disposable certificate
- **Flags:** DESTRUCTIVE
- **Steps:**
  1. `/blast-radius` first (U-45) -> see impact
  2. `/certificates/<fp>` · button "Revoke" -> confirm dialog with reason select (capture the dialog; confirm only on throwaway hub)
  3. Bulk: select rows · "Bulk revoke" -> confirm
  4. `/reports/revocation-activity` -> new row by reason
- **Capture:** revoke confirm; revocation activity
- **States exercised:** `S-certs-detail`, `S-certs-selected`, `S-revocation`

### U-24: Export the certificate inventory as CSV

- **Persona / role:** Auditor
- **Preconditions:** Seeded hub
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/certificates` · select rows (or "Select all visible") · button "Export CSV" -> file download
- **Capture:** export enabled state
- **States exercised:** `S-certs-selected`

### U-25: Run a discovery scan and read the results

- **Persona / role:** Security engineer
- **Preconditions:** Hub scanning loopback; seed starts openssl listeners on 18490-18493
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/discovery` · button "New scan" -> dialog
  2. dialog · select "Scan type" (Fast...); input "Target" `127.0.0.1`; input "Custom ports (optional, comma)" `18490,18491,18492,18493`
  3. dialog · button "Queue scan" -> scan job row, status Queued -> Running -> Completed
  4. `/discovery` · filter selects "Filter by protocol", "Show risky endpoints only", "Filter by trust class", "Filter scan jobs by status"; button "Refresh"
  5. Findings cards (Raw/Deduped/In scope/Effective/Suppressed) and endpoint table
- **Capture:** new scan dialog; scan job running; findings + endpoints
- **States exercised:** `S-discovery`, `S-discovery-dlg-new-scan`

### U-26: Inspect an endpoint and accept a finding as risk

- **Persona / role:** Security engineer
- **Preconditions:** Discovery results
- **Flags:** MULTI-USER (accept risk becomes a pending action)
- **Steps:**
  1. `/discovery` · row "127.0.0.1" (port 18493) · click -> `/discovery/endpoints/<id>` card: Risk score, Crypto posture (TLSv1.3 X25519MLKEM768), Mapped certificates, Scan history
  2. card · button "Accept risk for SELF_SIGNED" -> exception proposed; appears in "Accepted-risk exceptions: Pending approval"
  3. card · button "View →" -> certificate detail
  4. card · buttons "Queue scan", "Search certs"
- **Capture:** endpoint detail; accept risk pending
- **States exercised:** `S-discovery`, `S-discovery-endpoint`

### U-27: Set up ACME for a server (provisioner, EAB key, client)

- **Persona / role:** PKI admin then Platform engineer
- **Preconditions:** Issuing CA + template; an ACME client (certbot/lego) on a host that can reach the hub
- **Flags:** LAB (ACME client host)
- **Steps:**
  1. `/acme` · tab "Provisioners" · button "New provisioner" -> dialog
  2. dialog · input "Name" `internal-acme`; select "CA" Acme Issuing CA; select "Template (optional)"; textarea "Allowed names" `*.acme.test`; checkboxes http-01 / dns-01 · "Save"
  3. provisioner row · button "Copy directory URL for <name>" -> directory URL copied
  4. `/acme` · tab "EAB keys" · button "New key" -> dialog: input "Label" `cert-manager`, select "Provisioner (optional)", input "Template id (optional)" · "Create key" -> key id + HMAC shown once (capture before dismissing; redact)
  5. On host: `certbot certonly --server <directory-url> --eab-kid <id> --eab-hmac-key <hmac> -d web.acme.test` -> certificate appears in `/certificates`
  6. `/acme` · EAB row shows Uses > 0 and Last used
- **Capture:** provisioner list; new provisioner dialog; new EAB key dialog; EAB key shown once; certbot output (terminal); EAB key used
- **States exercised:** `S-acme`, `S-acme-tab-eab-keys`, `S-acme-tab-provisioners`, `S-acme-dlg-new-key`, `S-acme-dlg-prov`

### U-28: Enroll devices with SCEP, EST or CMP

- **Persona / role:** PKI admin / Network engineer
- **Preconditions:** SCEP needs KRYPTKEEPER_SCEP_ENABLED=true (off in demo: shows "Not enabled"); EST/CMP seeded
- **Flags:** CONFIG + LAB DEVICE
- **Steps:**
  1. `/enrollment` · tab "SCEP" · (when enabled) button "New challenge" -> dialog: inputs "Common name", "DNS names (one per line)", select "Valid for" (30m/1h/4h/24h) · "Create challenge" -> one-time password
  2. tab "EST" · button "New user" -> dialog: "Username", "Allowed DNS suffixes" · "Create user"; row actions: Rotate password, Disable, Delete
  3. tab "CMP" · "Register trust anchor" -> dialog (Label, Certificate PEM); "New PBM secret" -> dialog (Label, suffixes)
  4. Device side: `curl --cacert ... --user est-devices:<pw> https://<hub>/.well-known/est/simpleenroll` (lab)
- **Capture:** scep not enabled; scep challenge dialog (config on); est tab; est new user; cmp tab; cmp anchor dialog
- **States exercised:** `S-enroll`, `S-enroll-tab-scep`, `S-enroll-tab-est`, `S-enroll-tab-cmp`, `S-enroll-dlg-new-challenge`, `S-enroll-dlg-estuser`, `S-enroll-dlg-cmpanchor`, `S-enroll-dlg-pbm`

### U-29: Enroll a satellite agent

- **Persona / role:** Platform engineer
- **Preconditions:** A Linux/macOS/Windows host or local container that can reach the hub (seed registers one offline agent `web-01.acme.test`)
- **Flags:** LAB (host running the agent)
- **Steps:**
  1. `/targets/setup` · card "Agent" (default) · input "Agent name" `web-02.acme.test`; select "Host type" Linux · button "Generate token" -> single-use token (24h) shown once (redact)
  2. list "Unused enrollment tokens" · button "Revoke token <name>" (guarded)
  3. On host: run `kryptkeeper-agent` with `KRYPTKEEPER_HUB_URL` and the token -> prints AGENT_ID/AGENT_TOKEN
  4. `/agents` · refresh -> agent row Active, "Last seen" updates, Total/Active counters change
  5. `/agents` · "Install an Agent" quick-start card shows curl/chmod commands
- **Capture:** target setup agent card; token generated; agents list active; agent install quick-start
- **States exercised:** `S-targets`, `S-targets-agent`, `S-agents`

### U-30: Bring an agentless target under management

- **Persona / role:** Platform engineer
- **Preconditions:** SSH credential created via API/CLI (seed has only an api_token credential), reachable host
- **Flags:** CONFIG + LAB HOST
- **Steps:**
  1. `/targets/setup` · card "Agentless" -> 6-step wizard
  2. Step 1 Host · inputs "Target name" `db-01`, "Host" `db-01.acme.test`; radio OS (Linux/Unix, Windows, macOS) · Next
  3. Step 2 Discovery · select Network scan / Cloud provider / None · Next
  4. Step 3 Install · select SSH push / F5 BIG-IP / Citrix ADC / Kubernetes secret / Cloud API / ACME / Delivery plugin · Next
  5. Step 4 Credential · select credential; input cron `0 3 * * *`; select "Renewal method"; checkbox Auto-renew · Next (blocked "A credential reference is required for ssh install mode" without credential)
  6. Step 5 Host key and Step 6 Review (not enumerated, needs SSH credential)
- **Capture:** wizard step 1..4; validation message; step 5; step 6
- **States exercised:** `S-targets-agentless-1`, `S-targets-agentless-2`, `S-targets-agentless-3`, `S-targets-agentless-4`, `S-targets-agentless-5`, `S-targets-agentless-6`

### U-31: Set renewal policy per target

- **Persona / role:** Platform engineer
- **Preconditions:** Seeded targets web-01, web-02, lb-edge
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/targets/renewal-policy` · target card "web-01" · select "web-01 renewal method" (ACME/EST/SCEP/Manual) · input "web-01 auto-renew threshold days" `21` · button "Save" -> card shows "Threshold: 21 days"
  2. button "Clear override" -> falls back to env default (30)
  3. Group section · input "Group name" `prod-web`, "Group threshold days", target checkboxes · "Save group"
- **Capture:** renewal policy list; after save
- **States exercised:** `S-renewal`

### U-32: Roll a certificate out to a cluster (rollout group, canary first)

- **Persona / role:** Platform engineer
- **Preconditions:** Targets seeded; agent or SSH reachable to actually run
- **Flags:** LAB (to execute rollout)
- **Steps:**
  1. `/renewal/rollout-groups` · button "New group" -> dialog: input "Group name" `web-cluster`; checkboxes web-01 (ssh), web-02 (ssh), lb-edge (f5); inputs "Window start (UTC)" `02:00`, "Window end (UTC)" `04:00` · "Save group" (stored in this browser only)
  2. Select the group -> run panel: first node canary, then the rest
  3. Result: per-node status list
- **Capture:** empty state; new group dialog; group selected
- **States exercised:** `S-rollout`, `S-rollout-dlg-new-group`

### U-33: Watch automation and the failed-renewal queue

- **Persona / role:** Platform engineer / SRE
- **Preconditions:** Agent heartbeat + one renewal run for non-zero values
- **Flags:** LAB
- **Steps:**
  1. `/automation` · read tiles (Success rate, Mean time to renew, Endpoints managed, Agents 0/1, Queue depth, Drain ETA)
  2. link "Open SLO dashboard" -> `/reports/slo`
  3. Scheduler tiles: Renewal threshold 30d, Scan interval 24h, Candidates, Auto-renew triggers, Notifications sent, Expired (skipped)
  4. `/reports/slo` · inputs "Issuance latency p95 (seconds)", "Renewal success rate", "Issuance success rate" -> "Save objectives"
- **Capture:** automation overview; slo objectives
- **States exercised:** `S-automation`, `S-slo`

### U-34: Install a delivery plugin (WASM)

- **Persona / role:** Platform engineer
- **Preconditions:** A signed plugin bundle: manifest.json, .wasm, signature
- **Flags:** EXTERNAL ARTIFACT (build)
- **Steps:**
  1. `/delivery-plugins` · button "Install plugin" -> dialog (manifest.json, Plugin module, Signature optional)
  2. choose three files -> button "Install" enabled -> manifest capabilities shown for review
  3. Installed plugin card appears; Target Setup step 3 offers "Delivery plugin"
- **Capture:** empty state; install dialog; installed plugin
- **States exercised:** `S-plugins`, `S-plugins-dlg-install`

### U-35: Configure notifications (email, Slack, webhook, PagerDuty)

- **Persona / role:** PKI admin
- **Preconditions:** Local SMTP sink (e.g. MailHog/mailpit on :1025) or webhook receiver
- **Flags:** LOCAL SINK
- **Steps:**
  1. `/integrations` · Notifications panel · inputs "SMTP host" `127.0.0.1`, "SMTP port" `1025`, "SMTP from address" `kryptkeeper@acme.test` · each row button "Save" -> value stored, "env default" hint remains
  2. input "Slack webhook URL" (password-masked) · fill · "Save"
  3. input "Webhook URL", "Webhook signing secret" · "Save"; button "Reset to env default" undoes
  4. "Test a notification channel" · select "Channel" Email (SMTP) · input "Target" `ops@acme.test` · button "Send test" -> delivered; sink shows message
- **Capture:** integrations notifications; test channel result; sink inbox (external)
- **States exercised:** `S-integ`

### U-36: Send test deliveries, build alert rules, retry failures

- **Persona / role:** PKI operator
- **Preconditions:** Delivery provider = delivery; SMTP/webhook sink for Sent state
- **Flags:** LOCAL SINK
- **Steps:**
  1. `/alerts` · "Test delivery" form · select "Notification test channel" Email; input "Notification test target"; input "Notification test message" · button "Send test delivery" -> new row in queue
  2. Filters "Filter deliveries by status/channel"; buttons "← Previous"/"Next →"
  3. Row click -> `/alerts/deliveries/<id>` detail with attempts, Retry / Acknowledge
  4. tab "Alert rules" · button "New rule" -> dialog: "Name", "Threshold unit" (percent/days), "Threshold", "Channel", checkbox "Route to owner team", "Target" · "Create rule"
  5. Rule row actions Edit/Delete
- **Capture:** alerts queue; test delivery sent; delivery detail; alert rules tab; new rule dialog
- **States exercised:** `S-alerts`, `S-alerts-tab-rules`, `S-alerts-dlg-newrule`

### U-37: Connect Jira or ServiceNow (ITSM) for ticket-based alerts

- **Persona / role:** PKI admin
- **Preconditions:** ITSM credential (write-only) created via API
- **Flags:** EXTERNAL SERVICE
- **Steps:**
  1. `/integrations` · ITSM connections panel · select "Kind" (ServiceNow/Jira) · fill instance URL, project, credential reference · "Add connection"
  2. row button "Test connection <name>" -> success toast
  3. button "Preview" -> shows the ticket payload
- **Capture:** itsm panel; test connection result
- **States exercised:** `S-integ`

### U-38: Invite a user and assign a role

- **Persona / role:** PKI admin
- **Preconditions:** Signed in as pki-admin
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/users` · button "Invite user" -> dialog
  2. dialog · input "Email address" (required) `new.engineer@acme.test`
  3. dialog · select "Role" pki-operator
  4. dialog · button "Send invitation" -> row appears Status invited/active
  5. `/users` · row · button "Change role" -> dialog select (pki-admin, pki-operator, pki-auditor, discovery-operator, notification-operator, requester) · "Save"
  6. row · button "Deactivate" (guarded)
- **Capture:** users list; invite dialog; change role dialog
- **States exercised:** `S-users`, `S-users-dlg-invite-user`, `S-users-dlg-role`

### U-39: Create a custom role with least privilege

- **Persona / role:** PKI admin
- **Preconditions:** Seeded hub
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/roles` · button "New role" -> inline panel
  2. input "Role name" `cert-reader`; input "Description"
  3. checkbox group Read permissions (certificate.read, report.read, audit.read) and Write permissions (certificate.issue ... user.manage) -> tick read only
  4. SoD check message appears when a conflicting write pair is chosen (tick certificate.issue + action.approve to show)
  5. button "Create role" (enabled once name given) -> new Custom row
  6. row · "Edit <role>" / "Delete <role>"
- **Capture:** roles list; new role panel; sod warning
- **States exercised:** `S-roles`, `S-roles-pane-new-role`, `S-roles-pane-edit-role`

### U-40: Run a periodic access review

- **Persona / role:** Auditor / PKI admin
- **Preconditions:** Seeded campaign "Q4 access review" (4 users)
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/access-review` · button "Open campaign" -> dialog: input "Campaign name" `Q1 access review` · "Start review"
  2. campaign table · per row select Decision (keep/revoke/modify) · button "Save decision"
  3. button "Close campaign" -> seals report (guarded)
  4. Role changes (period) table lists recent role events
- **Capture:** access review list; open campaign dialog; decisions saved
- **States exercised:** `S-accessreview`, `S-accessreview-dlg-open-campaign`

### U-41: Turn on multi-tenancy and manage tenants

- **Persona / role:** PKI admin (super-admin)
- **Preconditions:** MULTI_TENANCY=on and hub restart
- **Flags:** CONFIG
- **Steps:**
  1. Default demo: `/tenants` · "Multi-tenancy is off" message (capture)
  2. With config on: `/tenants` · create tenant, tenant switcher appears in shell header; select tenant -> pages scope to it
- **Capture:** tenants off state; tenants on list; tenant switcher
- **States exercised:** `S-tenants`

### U-42: Create issuance policies and dry-run a request

- **Persona / role:** PKI admin
- **Preconditions:** Seeded policies (Baseline, Internal Services)
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/policies` · button "New policy" -> inline panel: "Name", "CA id (blank = all CAs)", "Allowed algorithms", "Min RSA bits", "Max validity days", checkboxes "Enabled", "Allow CA certificates" · "Create policy"
  2. policy row "Edit <name>" -> same panel
  3. Dry run card · select "Algorithm" RSA-2048; inputs; button "Run dry run" -> refusal naming policy and rule
- **Capture:** policies list; new policy panel; dry run refusal
- **States exercised:** `S-policies`, `S-policies-pane-new-policy`, `S-policies-pane-edit-policy`, `S-policies-dryrun`

### U-43: Propose a machine identity and approve it (NHI)

- **Persona / role:** Platform engineer + Approver
- **Preconditions:** SPIFFE_TRUST_DOMAIN set (seed uses acme.test)
- **Flags:** MULTI-USER
- **Steps:**
  1. `/nhi` · button "Propose identity" -> dialog: input "Name" `billing-bot`; select "Kind" ai_agent/service_account/workflow; scope checkboxes (certificate.read ...) · "Propose"
  2. row shows status pending, spiffe://acme.test/nhi/<kind>/<name>
  3. Second person: `/nhi` row · button "Approve" -> one-time join token issued (capture once, redact)
- **Capture:** nhi list; propose dialog; approved + join token
- **States exercised:** `S-nhi`, `S-nhi-dlg-propose`

### U-44: Issue SPIFFE SVIDs for workloads

- **Persona / role:** Platform engineer
- **Preconditions:** SPIFFE_SIGNING_CA_ID set + workload attesting
- **Flags:** CONFIG + LAB WORKLOAD
- **Steps:**
  1. Demo: `/spiffe` · "SPIFFE not configured" message (capture)
  2. Configured: trust domain card and bundle; mint SVID -> row in "Issued SVIDs"
- **Capture:** spiffe not configured; spiffe configured
- **States exercised:** `S-spiffe`

### U-45: Check the blast radius before a destructive change

- **Persona / role:** PKI admin
- **Preconditions:** A certificate fingerprint, CA id, or algorithm
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/blast-radius` · select "Action" Revoke certificate · input "Target" (SHA-256 fingerprint) · button "Simulate" -> impact list with Services and counts
  2. change "Action" to Retire CA -> Target placeholder "CA id"; Deprecate algorithm -> "Algorithm and size, e.g. RSA-2048"
- **Capture:** blast form; revoke result; retire CA result
- **States exercised:** `S-blast`

### U-46: Issue an SSH user or host certificate

- **Persona / role:** Platform engineer
- **Preconditions:** SSH template (seed: "SSH Access (user + host)"); authorized_keys public key
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/ssh-certificates` · panel "SSH CA" · button "Copy CA public key" -> toast; add to sshd TrustedUserCAKeys
  2. Form · select "Template"; radio "Certificate type" user/host; input "Key ID" (required) `alice@acme.test`; input "Principals" `deploy`; textarea "Public key" (authorized_keys line); input "TTL hours" `8` (max 24)
  3. button "Issue certificate" -> serial appears in "Issued certificates" table (Serial/Type/Key ID/Principals/Valid until/Status)
- **Capture:** ssh ca panel; issue form filled; issued table
- **States exercised:** `S-ssh`

### U-47: Use the Code Signing inventory

- **Persona / role:** Release engineer
- **Preconditions:** Code-signing certs issued (needs approval of seeded code-signing requests, U-17)
- **Flags:** MULTI-USER
- **Steps:**
  1. `/code-signing` · empty state before approval (capture)
  2. After U-17 approval · button "Refresh" -> cards Code-signing certs / Expired / Revoked and table fill
- **Capture:** empty; populated
- **States exercised:** `S-codesign`

### U-48: Generate, back up, import and rotate keys

- **Persona / role:** PKI admin
- **Preconditions:** Software key store; throwaway for rotate/delete
- **Flags:** DESTRUCTIVE for rotate/delete
- **Steps:**
  1. `/keys` · button "Generate Key" -> dialog: input key id; select algorithm (ECDSA-P256, ECDSA-P384, Ed25519, RSA...) · "Generate" -> row
  2. button "Export backup" -> dialog: input "Strong passphrase…" -> "Download Backup" (file)
  3. button "Import" -> dialog: key id, backup text, passphrase -> "Import Key"
  4. row checkboxes -> "Bulk rotate"/"Bulk delete" (guarded)
- **Capture:** keys list; generate dialog; export backup dialog; import dialog
- **States exercised:** `S-keys`, `S-keys-dlg-generate-key`, `S-keys-dlg-export-backup`, `S-keys-dlg-import`

### U-49: Escrow, recover and BYOK-export a root key (dual control)

- **Persona / role:** PKI admin + second approver
- **Preconditions:** Two custodian passphrases; BYOK needs an external KMS (LocalStack ok)
- **Flags:** MULTI-USER + EXTERNAL KMS
- **Steps:**
  1. `/keys` · button "Escrow" -> dialog: select "Key to escrow", two passphrases · "Submit for approval"
  2. button "Recover" -> dialog: escrow bundle JSON + two passphrases
  3. button "BYOK export" -> dialog: bundle, select Provider (AWS KMS...), "Region", "Destination KMS key ID", passphrases
  4. Approver completes in `/inbox` (U-17)
  5. `/reports/key-custody` · filter by key -> custody trail
- **Capture:** escrow dialog; recover dialog; byok dialog; key custody
- **States exercised:** `S-keys-dlg-escrow`, `S-keys-dlg-recover`, `S-keys-dlg-byok`, `S-custody`

### U-50: Review cloud KMS key inventory

- **Persona / role:** Security engineer
- **Preconditions:** AWS/Azure/GCP credentials in hub env (LocalStack for AWS)
- **Flags:** EXTERNAL CLOUD
- **Steps:**
  1. `/inventory/keys` · empty state explains required env (AWS_REGION ...)
  2. With credentials: table of keys (provider, id, algorithm, state); button "Refresh"
- **Capture:** empty state; populated
- **States exercised:** `S-cloudkeys`

### U-51: Sync certificates from another CA (inventory sources)

- **Persona / role:** PKI admin
- **Preconditions:** Source credential; seed has an AD CS export demo source
- **Flags:** EXTERNAL CA (live sources)
- **Steps:**
  1. `/inventory-sources` · row "ADCS enterprise CA export (demo)" · button "Sync now" -> Result "N new, M existing"
  2. Add a source · input "Name"; select "Type" (AD CS export/live, DigiCert, Sectigo, Entrust, AWS Private CA, GCP CA Service); select "Credential"; input "Sync every (minutes, 0 = manual)"; textarea "Configuration (JSON)" · "Add source"
  3. Imported certs show in `/certificates` with origin "Synced from CA"
- **Capture:** sources list; add source form; synced certs
- **States exercised:** `S-invsrc`

### U-52: Migrate templates from another CA product

- **Persona / role:** PKI admin + Approver
- **Preconditions:** Export file from AD CS / Venafi / Keyfactor / Vault / CertCentral
- **Flags:** EXTERNAL EXPORT FILE
- **Steps:**
  1. `/migration` · select "Source system" (Adcs, Certcentral, Keyfactor, Vault, Venafi)
  2. input file "Export file" or textarea "Paste export"; optional "Credential reference", "LDAP URL", "Base DN", "Bind DN"
  3. button "Dry run" -> report; "Submit for approval" -> second person approves in `/inbox`; "Batches" lists applied migrations with undo
- **Capture:** migration form; dry run report; batches
- **States exercised:** `S-migration`

### U-53: Monitor Certificate Transparency findings

- **Persona / role:** Security engineer
- **Preconditions:** CT domains configured (Settings) and external CT log access
- **Flags:** EXTERNAL (public CT logs)
- **Steps:**
  1. `/settings` · "CT monitor domains" · button "Add domain" -> input; "Save CT monitor domains"
  2. `/ct-findings` · toggles Open/Acknowledged; "Known issuer" filter; button "Refresh"
  3. Row actions: Acknowledge -> moves to Acknowledged
- **Capture:** ct empty; ct findings
- **States exercised:** `S-ct`, `S-settings-pane-add-domain`

### U-54: Review issuance anomalies

- **Persona / role:** Security engineer
- **Preconditions:** Scheduled anomaly scan has run after a burst of issuance
- **Flags:** TIME
- **Steps:**
  1. `/reports/anomalies` · "No scan has completed yet" (capture) -> after scan: Findings and Proposed remediations; remediation needs a second approver in `/inbox`
  2. `/reports/issuance-velocity` · cards and "Daily Issuance - Last 90 Days" bars; anomaly banner
- **Capture:** anomalies empty; anomalies populated; velocity
- **States exercised:** `S-anomalies`, `S-velocity`

### U-55: Read the PKI risk reports

- **Persona / role:** PKI admin / CISO
- **Preconditions:** Seeded hub
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/crypto-posture` · cards, trend ranges ("Last 30/90/365 days"), buttons "Refresh", "Export CSV", "Notify owner" -> dialog (Owner team, Channel, Delivery target -> "Confirm send")
  2. `/reports/pqc-migration` · tiles; button "Start migration wave" -> inline wave form (name, owner) -> Next/Back/Cancel; "Show all 39"; "Re-derive waves"; "Countdown PDF"
  3. `/reports/algorithm-sunset` · BANNED NOW / SUNSET 2030 groups
  4. `/reports/expiry-timeline` · distribution table; button "Open PQC wave" -> confirm dialog
  5. `/reports/ca-health` · table
  6. `/reports/revocation-activity` and `/reports/issuance-velocity` · range buttons
- **Capture:** posture; notify dialog; pqc wave panel; sunset; expiry; ca health; revocation; velocity
- **States exercised:** `S-posture`, `S-posture-dlg-notify`, `S-posture-dlg-open-pqc-wave`, `S-pqc`, `S-pqc-pane-start-migration-wave`, `S-sunset`, `S-expiry`, `S-expiry-dlg-open-pqc-wave`, `S-cahealth`, `S-revocation`, `S-velocity`

### U-56: Produce compliance evidence (packs, CBOM, scheduled delivery)

- **Persona / role:** Auditor
- **Preconditions:** Seeded hub; SMTP for scheduled delivery
- **Flags:** LOCAL SINK (for email)
- **Steps:**
  1. `/reports/compliance-evidence` · select "Compliance framework" (SOC 2, PCI DSS 4.0.1, NIST SP 800-57, DORA, NIS2, FedRAMP Moderate) -> control list and score
  2. button "Evidence pack (PDF)" -> download
  3. button "Download CBOM" -> CycloneDX download
  4. `/settings` · Evidence Delivery · selects "Framework", "Cadence"; input "Recipients (comma-separated)" · "Add schedule"; "Send now" (guarded)
- **Capture:** compliance report; evidence delivery form
- **States exercised:** `S-compliance`, `S-settings`

### U-57: Investigate with Audit Evidence, Change Audit and History

- **Persona / role:** Auditor
- **Preconditions:** Seeded hub (audit has 700+ events)
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/audit` · inputs "Filter audit action", "Filter actor type", "Filter resource type"; select "Filter audit outcome"; inputs "Filter after timestamp"/"Filter before timestamp"; checkbox "Hide read-only events" · "Apply filters"; "Reset"
  2. row click -> detail card (Timestamp, Action, Actor, Resource, Trace, Outcome)
  3. button "Export CSV"; paging "Previous"/"Next"
  4. `/reports/change-audit` · range buttons Last 7..365 days; mutation table
  5. `/history` · selects status/category; row -> `/history/<id>` detail; "Back to list"
- **Capture:** audit filters; audit detail; change audit; history detail
- **States exercised:** `S-audit`, `S-audit-detail`, `S-changeaudit`, `S-history`, `S-history-detail`

### U-58: Forward security events and manage discovery sources (Settings)

- **Persona / role:** PKI admin
- **Preconditions:** SIEM target via env; K8s/SaaS/cloud credentials by reference
- **Flags:** CONFIG + EXTERNAL
- **Steps:**
  1. `/settings` · SIEM Integration card -> state; button "Send test event" (enabled once configured)
  2. "Kubernetes clusters" · "Add cluster" -> row: "Cluster name", "Cluster credential", "Cluster namespace"; "Save Kubernetes clusters"
  3. "SaaS / API endpoints" · "Add endpoint" -> "Save SaaS / API endpoints"
  4. "Cloud sources" · "Add cloud source" -> "Save Cloud sources"
- **Capture:** settings full; add cluster row
- **States exercised:** `S-settings`, `S-settings-pane-add-cluster`, `S-settings-pane-add-endpoint`, `S-settings-pane-add-cloud-source`

### U-59: Use the app on a phone-sized screen

- **Persona / role:** Any user
- **Preconditions:** Viewport 375x812
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/` · button "Open navigation" -> drawer with the same sidebar links
  2. tap a link -> drawer closes, page loads
  3. Tables on `/certificates` scroll horizontally inside the card (WCAG reflow)
- **Capture:** mobile dashboard; mobile drawer; mobile certificates
- **States exercised:** `S-shell-mobile`

### U-60: See empty, error and not-found states

- **Persona / role:** Any user
- **Preconditions:** 
- **Flags:** none (works on the demo seed)
- **Steps:**
  1. `/login` · wrong password -> inline "invalid credentials"
  2. `/does-not-exist` (signed in) -> "404 This page doesn't exist. Back to the dashboard"
  3. Signed out, open any route -> redirect to `/login`
  4. `/history/abc` -> "Action not found"
  5. `/tenants`, `/spiffe`, `/inventory/keys`, `/ct-findings` -> explanatory empty/disabled states
- **Capture:** wrong password; 404; history not found; tenants off
- **States exercised:** `S-notfound`, `S-login`, `S-tenants`, `S-spiffe`, `S-cloudkeys`, `S-ct`

### U-61: Connect an existing CA (Vault PKI) as an issuer

- **Persona / role:** PKI admin
- **Preconditions:** A Vault PKI mount with a role, a Vault token (write-only), and Vault's TLS CA certificate. Captured against Vault 1.18 in dev-TLS mode.
- **Flags:** EXTERNAL
- **Steps:**
  1. `/issuers` · button "Add issuer" -> dialog "Add issuer" (5 steps)
  2. radio "HashiCorp Vault PKI" · "Next"
  3. inputs "Issuer name", "Vault address", "Role", "Vault server CA certificate (PEM)" · "Next"
  4. input "Vault token" (masked, write-only) · "Next"
  5. "Save and test" -> badge "healthy" · "Next"
  6. inputs "CA name", "Trust PEM" (the CA the issued certificates must chain to) · "Finish"
  7. `/inbox` -> the new external CA is a pending action requested by the proposer; the Approve button is disabled for the proposer (dual control)
- **Capture:** issuers list; add dialog; settings; credentials (token masked); healthy test; external CA step; pending approval
- **Not captured:** redeeming the approved external CA and issuing through it. The Add issuer wizard only proposes the CA (`POST /cas/external` answers 202); the repeat call with `approved_action_id` has no UI yet.
- **States exercised:** `S-issuers`, `S-issuers-dlg-add`, `S-inbox`

### U-62: Push a CA bundle to host trust stores (second approver)

- **Persona / role:** PKI admin (proposer); a second pki-admin approves
- **Preconditions:** At least one registered agent. The agent applies the bundle only if the host opted in (`KRYPTKEEPER_TRUST_STORE_PUSH=true`); the capture host is offline, so the per-host row shows "waiting for the agent".
- **Flags:** MULTI-USER
- **Steps:**
  1. `/agents` · Trust stores panel · inputs "Name", "CA certificates" (PEM, certificates only) · checkbox "Every Linux agent" · input "Why (shown to the approver)" · "Propose for approval"
  2. A second administrator approves the `trust_bundle.push` pending action (hidden setup step in the capture)
  3. `/agents` · the bundle row shows applied / not opted in / failed / waiting counts · click the row -> per-host table
- **Capture:** trust stores panel; filled proposal; proposed toast; approved bundle; per-host status
- **States exercised:** `S-agents`

### U-63: Start a post-quantum migration wave with a target algorithm

- **Persona / role:** PKI admin
- **Preconditions:** A template that allows an ML-DSA algorithm (created by a hidden setup step)
- **Flags:** none
- **Steps:**
  1. `/reports/pqc-migration` · button "Start migration wave" -> wizard
  2. inputs "Wave name", "Owner" · "Next"
  3. checkboxes for the certificates in the wave · "Next"
  4. selects "Issuance template" and "Target algorithm" (ML-DSA-65) · "Next" -> review · "Finish"
  5. Result: the wave is created and execution is proposed as a pending action a different administrator must approve
- **Capture:** report; wizard plan, select, schedule steps; proposed result
- **States exercised:** `S-pqc`

### U-64: Install onto SQL Server, Remote Desktop or Exchange over WinRM

- **Persona / role:** PKI admin
- **Preconditions:** None to set up the target; installing needs a Windows host reachable over WinRM, which is not part of the capture.
- **Flags:** LAB
- **Steps:**
  1. `/targets/setup` · radio "Agentless" · inputs "Target name", "Host" · radio "Windows" · "Next" (Discovery) · "Next" (Install)
  2. select "Install mode" -> "Microsoft SQL Server (WinRM)" (siblings: "Remote Desktop listener (WinRM)", "Microsoft Exchange (WinRM)") · "Next"
  3. select "Credential" -> "+ Create a new credential"; the options "Store it here" and "Fetch it from a secret manager" (Vault, OpenBao, CyberArk, Delinea)
  4. inputs "WinRM endpoint", "Username (local administrator)", "Password" (masked), "Instance name" · "Create & use"
  5. "Next" -> review · "Finish" -> "Target created"
- **Capture:** each wizard step; credential form; target created
- **States exercised:** `S-target-setup`

## 2. Element claim table

Every `E-*` id in `APP_MAP.md` appears exactly once. A claimed id lists the stories whose "States exercised" include its state. Destructive controls are SKIPPED here (never executed during mapping) with the guarded story that documents the capture.

| Element | State | Claimed by |
|---|---|---|
| E-login-1 | S-login | U-01, U-60 |
| E-login-2 | S-login | U-01, U-60 |
| E-login-3 | S-login | U-01, U-60 |
| E-shell-1 | S-shell | U-01 |
| E-shell-2 | S-shell | U-01 |
| E-shell-3 | S-shell | U-01 |
| E-shell-4 | S-shell | U-01 |
| E-shell-5 | S-shell | U-01 |
| E-shell-6 | S-shell | U-01 |
| E-shell-7 | S-shell | U-01 |
| E-shell-8 | S-shell | U-01 |
| E-shell-9 | S-shell | U-01 |
| E-shell-10 | S-shell | U-01 |
| E-shell-11 | S-shell | U-01 |
| E-shell-12 | S-shell | U-01 |
| E-shell-13 | S-shell | U-01 |
| E-shell-14 | S-shell | U-01 |
| E-shell-15 | S-shell | U-01 |
| E-shell-16 | S-shell | U-01 |
| E-shell-17 | S-shell | U-01 |
| E-shell-18 | S-shell | U-01 |
| E-shell-19 | S-shell | U-01 |
| E-shell-20 | S-shell | U-01 |
| E-shell-21 | S-shell | U-01 |
| E-shell-22 | S-shell | U-01 |
| E-shell-23 | S-shell | U-01 |
| E-shell-24 | S-shell | U-01 |
| E-shell-25 | S-shell | U-01 |
| E-shell-26 | S-shell | U-01 |
| E-shell-27 | S-shell | U-01 |
| E-shell-28 | S-shell | U-01 |
| E-shell-29 | S-shell | U-01 |
| E-shell-30 | S-shell | U-01 |
| E-shell-31 | S-shell | U-01 |
| E-shell-32 | S-shell | U-01 |
| E-shell-33 | S-shell | U-01 |
| E-shell-34 | S-shell | U-01 |
| E-shell-35 | S-shell | U-01 |
| E-shell-36 | S-shell | U-01 |
| E-shell-37 | S-shell | U-01 |
| E-shell-38 | S-shell | U-01 |
| E-shell-39 | S-shell | U-01 |
| E-shell-40 | S-shell | U-01 |
| E-shell-41 | S-shell | U-01 |
| E-shell-42 | S-shell | U-01 |
| E-shell-43 | S-shell | U-01 |
| E-shell-44 | S-shell | U-01 |
| E-shell-45 | S-shell | U-01 |
| E-shell-46 | S-shell | U-01 |
| E-shell-47 | S-shell | U-01 |
| E-shell-48 | S-shell | U-01 |
| E-shell-49 | S-shell | U-01 |
| E-shell-50 | S-shell | U-01 |
| E-shell-51 | S-shell | U-01 |
| E-shell-52 | S-shell | U-01 |
| E-shell-53 | S-shell | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-01) |
| E-shell-54 | S-shell | U-01 |
| E-shell-mobile-1 | S-shell-mobile | U-59 |
| E-palette-1 | S-palette | U-03 |
| E-palette-2 | S-palette | U-03 |
| E-palette-3 | S-palette | U-03 |
| E-palette-4 | S-palette | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-03) |
| E-palette-5 | S-palette | U-03 |
| E-palette-6 | S-palette | U-03 |
| E-notfound-1 | S-notfound | U-60 |
| E-dash-1 | S-dash | U-01, U-02 |
| E-dash-2 | S-dash | U-01, U-02 |
| E-dash-3 | S-dash | U-01, U-02 |
| E-dash-4 | S-dash | U-01, U-02 |
| E-dash-5 | S-dash | U-01, U-02 |
| E-dash-6 | S-dash | U-01, U-02 |
| E-dash-7 | S-dash | U-01, U-02 |
| E-dash-8 | S-dash | U-01, U-02 |
| E-dash-9 | S-dash | U-01, U-02 |
| E-dash-10 | S-dash | U-01, U-02 |
| E-dash-11 | S-dash | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-01, U-02) |
| E-dash-12 | S-dash | U-01, U-02 |
| E-dash-13 | S-dash | U-01, U-02 |
| E-dash-14 | S-dash | U-01, U-02 |
| E-dash-15 | S-dash | U-01, U-02 |
| E-dash-16 | S-dash | U-01, U-02 |
| E-dash-17 | S-dash | U-01, U-02 |
| E-dash-18 | S-dash | U-01, U-02 |
| E-dash-19 | S-dash | U-01, U-02 |
| E-dash-20 | S-dash | U-01, U-02 |
| E-dash-21 | S-dash | U-01, U-02 |
| E-dash-22 | S-dash | U-01, U-02 |
| E-dash-23 | S-dash | U-01, U-02 |
| E-dash-24 | S-dash | U-01, U-02 |
| E-dash-25 | S-dash | U-01, U-02 |
| E-dash-26 | S-dash | U-01, U-02 |
| E-dash-27 | S-dash | U-01, U-02 |
| E-dash-28 | S-dash | U-01, U-02 |
| E-inbox-1 | S-inbox | U-17, U-18, U-19 |
| E-inbox-2 | S-inbox | U-17, U-18, U-19 |
| E-inbox-3 | S-inbox | U-17, U-18, U-19 |
| E-inbox-4 | S-inbox | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-17, U-18, U-19) |
| E-inbox-5 | S-inbox | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-17, U-18, U-19) |
| E-alerts-1 | S-alerts | U-36 |
| E-alerts-2 | S-alerts | U-36 |
| E-alerts-3 | S-alerts | U-36 |
| E-alerts-4 | S-alerts | U-36 |
| E-alerts-5 | S-alerts | U-36 |
| E-alerts-6 | S-alerts | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-36) |
| E-alerts-7 | S-alerts | U-36 |
| E-alerts-8 | S-alerts | U-36 |
| E-alerts-9 | S-alerts | U-36 |
| E-alerts-10 | S-alerts | U-36 |
| E-search-1 | S-search | U-03 |
| E-search-2 | S-search | U-03 |
| E-ssh-1 | S-ssh | U-46 |
| E-ssh-2 | S-ssh | U-46 |
| E-ssh-3 | S-ssh | U-46 |
| E-ssh-4 | S-ssh | U-46 |
| E-ssh-5 | S-ssh | U-46 |
| E-ssh-6 | S-ssh | U-46 |
| E-ssh-7 | S-ssh | U-46 |
| E-ssh-8 | S-ssh | U-46 |
| E-ssh-9 | S-ssh | U-46 |
| E-nhi-1 | S-nhi | U-43 |
| E-nhi-2 | S-nhi | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-43) |
| E-nhi-3 | S-nhi | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-43) |
| E-nhi-4 | S-nhi | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-43) |
| E-nhi-5 | S-nhi | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-43) |
| E-nhi-6 | S-nhi | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-43) |
| E-ct-1 | S-ct | U-53, U-60 |
| E-ct-2 | S-ct | U-53, U-60 |
| E-automation-1 | S-automation | U-33 |
| E-automation-2 | S-automation | U-33 |
| E-automation-3 | S-automation | U-33 |
| E-automation-4 | S-automation | U-33 |
| E-automation-5 | S-automation | U-33 |
| E-automation-6 | S-automation | U-33 |
| E-automation-7 | S-automation | U-33 |
| E-automation-8 | S-automation | U-33 |
| E-automation-9 | S-automation | U-33 |
| E-automation-10 | S-automation | U-33 |
| E-automation-11 | S-automation | U-33 |
| E-automation-12 | S-automation | U-33 |
| E-automation-13 | S-automation | U-33 |
| E-automation-14 | S-automation | U-33 |
| E-automation-15 | S-automation | U-33 |
| E-automation-16 | S-automation | U-33 |
| E-targets-1 | S-targets | U-29 |
| E-targets-2 | S-targets | U-29 |
| E-targets-3 | S-targets | U-29 |
| E-targets-4 | S-targets | U-29 |
| E-targets-5 | S-targets | U-29 |
| E-targets-6 | S-targets | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-29) |
| E-renewal-1 | S-renewal | U-31 |
| E-renewal-2 | S-renewal | U-31 |
| E-renewal-3 | S-renewal | U-31 |
| E-renewal-4 | S-renewal | U-31 |
| E-renewal-5 | S-renewal | U-31 |
| E-renewal-6 | S-renewal | U-31 |
| E-renewal-7 | S-renewal | U-31 |
| E-renewal-8 | S-renewal | U-31 |
| E-renewal-9 | S-renewal | U-31 |
| E-renewal-10 | S-renewal | U-31 |
| E-renewal-11 | S-renewal | U-31 |
| E-renewal-12 | S-renewal | U-31 |
| E-renewal-13 | S-renewal | U-31 |
| E-renewal-14 | S-renewal | U-31 |
| E-renewal-15 | S-renewal | U-31 |
| E-rollout-1 | S-rollout | U-32 |
| E-rollout-dlg-new-group-1 | S-rollout-dlg-new-group | U-32 |
| E-rollout-dlg-new-group-2 | S-rollout-dlg-new-group | U-32 |
| E-rollout-dlg-new-group-3 | S-rollout-dlg-new-group | U-32 |
| E-rollout-dlg-new-group-4 | S-rollout-dlg-new-group | U-32 |
| E-rollout-dlg-new-group-5 | S-rollout-dlg-new-group | U-32 |
| E-rollout-dlg-new-group-6 | S-rollout-dlg-new-group | U-32 |
| E-rollout-dlg-new-group-7 | S-rollout-dlg-new-group | U-32 |
| E-rollout-dlg-new-group-8 | S-rollout-dlg-new-group | U-32 |
| E-plugins-1 | S-plugins | U-34 |
| E-agents-1 | S-agents | U-29 |
| E-acme-1 | S-acme | U-27 |
| E-acme-2 | S-acme | U-27 |
| E-acme-3 | S-acme | U-27 |
| E-acme-4 | S-acme | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-27) |
| E-acme-tab-eab-keys-1 | S-acme-tab-eab-keys | U-27 |
| E-acme-tab-eab-keys-2 | S-acme-tab-eab-keys | U-27 |
| E-acme-tab-eab-keys-3 | S-acme-tab-eab-keys | U-27 |
| E-acme-tab-eab-keys-4 | S-acme-tab-eab-keys | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-27) |
| E-acme-tab-provisioners-1 | S-acme-tab-provisioners | U-27 |
| E-acme-tab-provisioners-2 | S-acme-tab-provisioners | U-27 |
| E-acme-tab-provisioners-3 | S-acme-tab-provisioners | U-27 |
| E-acme-tab-provisioners-4 | S-acme-tab-provisioners | U-27 |
| E-acme-tab-provisioners-5 | S-acme-tab-provisioners | U-27 |
| E-acme-tab-provisioners-6 | S-acme-tab-provisioners | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-27) |
| E-acme-dlg-new-key-1 | S-acme-dlg-new-key | U-27 |
| E-acme-dlg-new-key-2 | S-acme-dlg-new-key | U-27 |
| E-acme-dlg-new-key-3 | S-acme-dlg-new-key | U-27 |
| E-acme-dlg-new-key-4 | S-acme-dlg-new-key | U-27 |
| E-acme-dlg-new-key-5 | S-acme-dlg-new-key | U-27 |
| E-acme-dlg-new-key-6 | S-acme-dlg-new-key | U-27 |
| E-enroll-1 | S-enroll | U-28 |
| E-enroll-2 | S-enroll | U-28 |
| E-enroll-3 | S-enroll | U-28 |
| E-enroll-4 | S-enroll | U-28 |
| E-enroll-tab-scep-1 | S-enroll-tab-scep | U-28 |
| E-enroll-tab-scep-2 | S-enroll-tab-scep | U-28 |
| E-enroll-tab-scep-3 | S-enroll-tab-scep | U-28 |
| E-enroll-tab-scep-4 | S-enroll-tab-scep | U-28 |
| E-enroll-tab-est-1 | S-enroll-tab-est | U-28 |
| E-enroll-tab-est-2 | S-enroll-tab-est | U-28 |
| E-enroll-tab-est-3 | S-enroll-tab-est | U-28 |
| E-enroll-tab-est-4 | S-enroll-tab-est | U-28 |
| E-enroll-tab-est-5 | S-enroll-tab-est | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-28) |
| E-enroll-tab-est-6 | S-enroll-tab-est | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-28) |
| E-enroll-tab-est-7 | S-enroll-tab-est | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-28) |
| E-enroll-tab-cmp-1 | S-enroll-tab-cmp | U-28 |
| E-enroll-tab-cmp-2 | S-enroll-tab-cmp | U-28 |
| E-enroll-tab-cmp-3 | S-enroll-tab-cmp | U-28 |
| E-enroll-tab-cmp-4 | S-enroll-tab-cmp | U-28 |
| E-enroll-tab-cmp-5 | S-enroll-tab-cmp | U-28 |
| E-enroll-tab-cmp-6 | S-enroll-tab-cmp | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-28) |
| E-enroll-tab-cmp-7 | S-enroll-tab-cmp | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-28) |
| E-enroll-dlg-new-challenge-1 | S-enroll-dlg-new-challenge | U-28 |
| E-enroll-dlg-new-challenge-2 | S-enroll-dlg-new-challenge | U-28 |
| E-enroll-dlg-new-challenge-3 | S-enroll-dlg-new-challenge | U-28 |
| E-enroll-dlg-new-challenge-4 | S-enroll-dlg-new-challenge | U-28 |
| E-enroll-dlg-new-challenge-5 | S-enroll-dlg-new-challenge | U-28 |
| E-enroll-dlg-new-challenge-6 | S-enroll-dlg-new-challenge | U-28 |
| E-integ-1 | S-integ | U-35, U-37 |
| E-integ-2 | S-integ | U-35, U-37 |
| E-integ-3 | S-integ | U-35, U-37 |
| E-integ-4 | S-integ | U-35, U-37 |
| E-integ-5 | S-integ | U-35, U-37 |
| E-integ-6 | S-integ | U-35, U-37 |
| E-integ-7 | S-integ | U-35, U-37 |
| E-integ-8 | S-integ | U-35, U-37 |
| E-integ-9 | S-integ | U-35, U-37 |
| E-integ-10 | S-integ | U-35, U-37 |
| E-integ-11 | S-integ | U-35, U-37 |
| E-integ-12 | S-integ | U-35, U-37 |
| E-integ-13 | S-integ | U-35, U-37 |
| E-integ-14 | S-integ | U-35, U-37 |
| E-integ-15 | S-integ | U-35, U-37 |
| E-integ-16 | S-integ | U-35, U-37 |
| E-integ-17 | S-integ | U-35, U-37 |
| E-integ-18 | S-integ | U-35, U-37 |
| E-integ-19 | S-integ | U-35, U-37 |
| E-integ-20 | S-integ | U-35, U-37 |
| E-integ-21 | S-integ | U-35, U-37 |
| E-integ-22 | S-integ | U-35, U-37 |
| E-integ-23 | S-integ | U-35, U-37 |
| E-integ-24 | S-integ | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-35, U-37) |
| E-integ-25 | S-integ | U-35, U-37 |
| E-integ-26 | S-integ | U-35, U-37 |
| E-integ-27 | S-integ | U-35, U-37 |
| E-integ-28 | S-integ | U-35, U-37 |
| E-integ-29 | S-integ | U-35, U-37 |
| E-integ-30 | S-integ | U-35, U-37 |
| E-integ-31 | S-integ | U-35, U-37 |
| E-integ-32 | S-integ | U-35, U-37 |
| E-integ-33 | S-integ | U-35, U-37 |
| E-integ-34 | S-integ | U-35, U-37 |
| E-integ-35 | S-integ | U-35, U-37 |
| E-integ-36 | S-integ | U-35, U-37 |
| E-integ-37 | S-integ | U-35, U-37 |
| E-integ-38 | S-integ | U-35, U-37 |
| E-integ-39 | S-integ | U-35, U-37 |
| E-integ-40 | S-integ | U-35, U-37 |
| E-integ-41 | S-integ | U-35, U-37 |
| E-integ-42 | S-integ | U-35, U-37 |
| E-integ-43 | S-integ | U-35, U-37 |
| E-integ-44 | S-integ | U-35, U-37 |
| E-integ-45 | S-integ | U-35, U-37 |
| E-integ-46 | S-integ | U-35, U-37 |
| E-integ-47 | S-integ | U-35, U-37 |
| E-integ-48 | S-integ | U-35, U-37 |
| E-integ-49 | S-integ | U-35, U-37 |
| E-certs-1 | S-certs | U-13, U-16 |
| E-certs-2 | S-certs | U-13, U-16 |
| E-certs-3 | S-certs | U-13, U-16 |
| E-certs-4 | S-certs | U-13, U-16 |
| E-certs-5 | S-certs | U-13, U-16 |
| E-certs-6 | S-certs | U-13, U-16 |
| E-certs-7 | S-certs | U-13, U-16 |
| E-certs-8 | S-certs | U-13, U-16 |
| E-certs-9 | S-certs | U-13, U-16 |
| E-certs-10 | S-certs | U-13, U-16 |
| E-certs-11 | S-certs | U-13, U-16 |
| E-certs-12 | S-certs | U-13, U-16 |
| E-certs-13 | S-certs | U-13, U-16 |
| E-certs-14 | S-certs | U-13, U-16 |
| E-certs-15 | S-certs | U-13, U-16 |
| E-certs-16 | S-certs | U-13, U-16 |
| E-certs-17 | S-certs | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-13, U-16) |
| E-certs-18 | S-certs | U-13, U-16 |
| E-certs-19 | S-certs | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-13, U-16) |
| E-certs-20 | S-certs | U-13, U-16 |
| E-certs-21 | S-certs | U-13, U-16 |
| E-certs-22 | S-certs | U-13, U-16 |
| E-certs-23 | S-certs | U-13, U-16 |
| E-certs-24 | S-certs | U-13, U-16 |
| E-certs-25 | S-certs | U-13, U-16 |
| E-certs-26 | S-certs | U-13, U-16 |
| E-certs-27 | S-certs | U-13, U-16 |
| E-certs-28 | S-certs | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-13, U-16) |
| E-certs-29 | S-certs | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-13, U-16) |
| E-certs-30 | S-certs | U-13, U-16 |
| E-certs-pane-edit-1 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-2 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-3 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-4 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-5 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-6 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-7 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-8 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-9 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-10 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-11 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-12 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-13 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-14 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-15 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-16 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-17 | S-certs-pane-edit | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-20) |
| E-certs-pane-edit-18 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-19 | S-certs-pane-edit | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-20) |
| E-certs-pane-edit-20 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-21 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-22 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-23 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-24 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-25 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-26 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-27 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-28 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-29 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-30 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-31 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-32 | S-certs-pane-edit | U-20 |
| E-certs-pane-edit-33 | S-certs-pane-edit | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-20) |
| E-certs-pane-edit-34 | S-certs-pane-edit | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-20) |
| E-certs-pane-edit-35 | S-certs-pane-edit | U-20 |
| E-certs-dlg-import-1 | S-certs-dlg-import | U-21 |
| E-certs-dlg-import-2 | S-certs-dlg-import | U-21 |
| E-certs-dlg-import-3 | S-certs-dlg-import | U-21 |
| E-certs-dlg-import-4 | S-certs-dlg-import | U-21 |
| E-certs-dlg-import-5 | S-certs-dlg-import | U-21 |
| E-certs-dlg-import-6 | S-certs-dlg-import | U-21 |
| E-cas-1 | S-cas | U-04, U-07 |
| E-cas-2 | S-cas | U-04, U-07 |
| E-cas-3 | S-cas | U-04, U-07 |
| E-cas-4 | S-cas | U-04, U-07 |
| E-cas-5 | S-cas | U-04, U-07 |
| E-cas-6 | S-cas | U-04, U-07 |
| E-cas-7 | S-cas | U-04, U-07 |
| E-cas-8 | S-cas | U-04, U-07 |
| E-cas-9 | S-cas | U-04, U-07 |
| E-cas-10 | S-cas | U-04, U-07 |
| E-cas-11 | S-cas | U-04, U-07 |
| E-cas-12 | S-cas | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-04, U-07) |
| E-cas-13 | S-cas | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-04, U-07) |
| E-cas-14 | S-cas | U-04, U-07 |
| E-cas-15 | S-cas | U-04, U-07 |
| E-cas-dlg-import-external-root-1 | S-cas-dlg-import-external-root | U-06 |
| E-cas-dlg-import-external-root-2 | S-cas-dlg-import-external-root | U-06 |
| E-cas-dlg-import-external-root-3 | S-cas-dlg-import-external-root | U-06 |
| E-cas-dlg-import-external-root-4 | S-cas-dlg-import-external-root | U-06 |
| E-cas-dlg-import-external-root-5 | S-cas-dlg-import-external-root | U-06 |
| E-cas-dlg-new-ca-1 | S-cas-dlg-new-ca | U-04, U-05 |
| E-cas-dlg-new-ca-2 | S-cas-dlg-new-ca | U-04, U-05 |
| E-cas-dlg-new-ca-3 | S-cas-dlg-new-ca | U-04, U-05 |
| E-cas-dlg-new-ca-4 | S-cas-dlg-new-ca | U-04, U-05 |
| E-cas-dlg-new-ca-5 | S-cas-dlg-new-ca | U-04, U-05 |
| E-cas-dlg-new-ca-6 | S-cas-dlg-new-ca | U-04, U-05 |
| E-cas-dlg-new-ca-7 | S-cas-dlg-new-ca | U-04, U-05 |
| E-cas-dlg-new-ca-8 | S-cas-dlg-new-ca | U-04, U-05 |
| E-ceremonies-1 | S-ceremonies | U-09 |
| E-ceremonies-2 | S-ceremonies | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-09) |
| E-ceremonies-3 | S-ceremonies | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-09) |
| E-ceremonies-4 | S-ceremonies | U-09 |
| E-ceremonies-dlg-start-ceremony-1 | S-ceremonies-dlg-start-ceremony | U-09 |
| E-ceremonies-dlg-start-ceremony-2 | S-ceremonies-dlg-start-ceremony | U-09 |
| E-ceremonies-dlg-start-ceremony-3 | S-ceremonies-dlg-start-ceremony | U-09 |
| E-ceremonies-dlg-start-ceremony-4 | S-ceremonies-dlg-start-ceremony | U-09 |
| E-ceremonies-dlg-start-ceremony-5 | S-ceremonies-dlg-start-ceremony | U-09 |
| E-ceremonies-dlg-start-ceremony-6 | S-ceremonies-dlg-start-ceremony | U-09 |
| E-ceremonies-dlg-start-ceremony-7 | S-ceremonies-dlg-start-ceremony | U-09 |
| E-ceremonies-dlg-start-ceremony-8 | S-ceremonies-dlg-start-ceremony | U-09 |
| E-ceremonies-dlg-start-ceremony-9 | S-ceremonies-dlg-start-ceremony | U-09 |
| E-keys-1 | S-keys | U-48 |
| E-keys-2 | S-keys | U-48 |
| E-keys-3 | S-keys | U-48 |
| E-keys-4 | S-keys | U-48 |
| E-keys-5 | S-keys | U-48 |
| E-keys-6 | S-keys | U-48 |
| E-keys-7 | S-keys | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-48) |
| E-keys-8 | S-keys | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-48) |
| E-keys-9 | S-keys | U-48 |
| E-keys-10 | S-keys | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-48) |
| E-keys-11 | S-keys | U-48 |
| E-keys-12 | S-keys | U-48 |
| E-keys-13 | S-keys | U-48 |
| E-keys-14 | S-keys | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-48) |
| E-keys-15 | S-keys | U-48 |
| E-keys-16 | S-keys | U-48 |
| E-keys-17 | S-keys | U-48 |
| E-keys-18 | S-keys | U-48 |
| E-keys-19 | S-keys | U-48 |
| E-keys-20 | S-keys | U-48 |
| E-keys-21 | S-keys | U-48 |
| E-keys-22 | S-keys | U-48 |
| E-keys-23 | S-keys | U-48 |
| E-keys-24 | S-keys | U-48 |
| E-keys-dlg-import-1 | S-keys-dlg-import | U-48 |
| E-keys-dlg-import-2 | S-keys-dlg-import | U-48 |
| E-keys-dlg-import-3 | S-keys-dlg-import | U-48 |
| E-keys-dlg-import-4 | S-keys-dlg-import | U-48 |
| E-keys-dlg-import-5 | S-keys-dlg-import | U-48 |
| E-keys-dlg-import-6 | S-keys-dlg-import | U-48 |
| E-keys-dlg-generate-key-1 | S-keys-dlg-generate-key | U-48 |
| E-keys-dlg-generate-key-2 | S-keys-dlg-generate-key | U-48 |
| E-keys-dlg-generate-key-3 | S-keys-dlg-generate-key | U-48 |
| E-keys-dlg-generate-key-4 | S-keys-dlg-generate-key | U-48 |
| E-keys-dlg-generate-key-5 | S-keys-dlg-generate-key | U-48 |
| E-keys-dlg-export-backup-1 | S-keys-dlg-export-backup | U-48 |
| E-keys-dlg-export-backup-2 | S-keys-dlg-export-backup | U-48 |
| E-keys-dlg-export-backup-3 | S-keys-dlg-export-backup | U-48 |
| E-keys-dlg-export-backup-4 | S-keys-dlg-export-backup | U-48 |
| E-codesign-1 | S-codesign | U-47 |
| E-codesign-2 | S-codesign | U-47 |
| E-codesign-3 | S-codesign | U-47 |
| E-codesign-4 | S-codesign | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-47) |
| E-templates-1 | S-templates | U-10, U-11 |
| E-templates-2 | S-templates | U-10, U-11 |
| E-templates-3 | S-templates | U-10, U-11 |
| E-templates-4 | S-templates | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-10, U-11) |
| E-templates-dlg-new-template-1 | S-templates-dlg-new-template | U-10 |
| E-templates-dlg-new-template-2 | S-templates-dlg-new-template | U-10 |
| E-templates-dlg-new-template-3 | S-templates-dlg-new-template | U-10 |
| E-templates-dlg-new-template-4 | S-templates-dlg-new-template | U-10 |
| E-templates-dlg-new-template-5 | S-templates-dlg-new-template | U-10 |
| E-templates-dlg-new-template-6 | S-templates-dlg-new-template | U-10 |
| E-templates-dlg-new-template-7 | S-templates-dlg-new-template | U-10 |
| E-templates-dlg-new-template-8 | S-templates-dlg-new-template | U-10 |
| E-templates-dlg-new-template-9 | S-templates-dlg-new-template | U-10 |
| E-templates-dlg-new-template-10 | S-templates-dlg-new-template | U-10 |
| E-templates-dlg-new-template-11 | S-templates-dlg-new-template | U-10 |
| E-templates-dlg-new-template-12 | S-templates-dlg-new-template | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-10) |
| E-templates-dlg-new-template-13 | S-templates-dlg-new-template | U-10 |
| E-templates-dlg-new-template-14 | S-templates-dlg-new-template | U-10 |
| E-templates-dlg-new-template-15 | S-templates-dlg-new-template | U-10 |
| E-templates-dlg-new-template-16 | S-templates-dlg-new-template | U-10 |
| E-templates-dlg-new-template-17 | S-templates-dlg-new-template | U-10 |
| E-templates-dlg-new-template-18 | S-templates-dlg-new-template | U-10 |
| E-templates-dlg-new-template-19 | S-templates-dlg-new-template | U-10 |
| E-templates-dlg-new-template-20 | S-templates-dlg-new-template | U-10 |
| E-templates-dlg-edit-1 | S-templates-dlg-edit | U-11 |
| E-templates-dlg-edit-2 | S-templates-dlg-edit | U-11 |
| E-templates-dlg-edit-3 | S-templates-dlg-edit | U-11 |
| E-templates-dlg-edit-4 | S-templates-dlg-edit | U-11 |
| E-templates-dlg-edit-5 | S-templates-dlg-edit | U-11 |
| E-templates-dlg-edit-6 | S-templates-dlg-edit | U-11 |
| E-templates-dlg-edit-7 | S-templates-dlg-edit | U-11 |
| E-templates-dlg-edit-8 | S-templates-dlg-edit | U-11 |
| E-templates-dlg-edit-9 | S-templates-dlg-edit | U-11 |
| E-templates-dlg-edit-10 | S-templates-dlg-edit | U-11 |
| E-templates-dlg-edit-11 | S-templates-dlg-edit | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-11) |
| E-templates-dlg-edit-12 | S-templates-dlg-edit | U-11 |
| E-templates-dlg-edit-13 | S-templates-dlg-edit | U-11 |
| E-templates-dlg-edit-14 | S-templates-dlg-edit | U-11 |
| E-templates-dlg-edit-15 | S-templates-dlg-edit | U-11 |
| E-templates-dlg-edit-16 | S-templates-dlg-edit | U-11 |
| E-templates-dlg-edit-17 | S-templates-dlg-edit | U-11 |
| E-templates-dlg-edit-18 | S-templates-dlg-edit | U-11 |
| E-templates-dlg-edit-19 | S-templates-dlg-edit | U-11 |
| E-discovery-1 | S-discovery | U-25, U-26 |
| E-discovery-2 | S-discovery | U-25, U-26 |
| E-discovery-3 | S-discovery | U-25, U-26 |
| E-discovery-4 | S-discovery | U-25, U-26 |
| E-discovery-5 | S-discovery | U-25, U-26 |
| E-discovery-6 | S-discovery | U-25, U-26 |
| E-discovery-7 | S-discovery | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-25, U-26) |
| E-discovery-8 | S-discovery | U-25, U-26 |
| E-discovery-9 | S-discovery | U-25, U-26 |
| E-discovery-10 | S-discovery | U-25, U-26 |
| E-discovery-11 | S-discovery | U-25, U-26 |
| E-discovery-12 | S-discovery | U-25, U-26 |
| E-discovery-13 | S-discovery | U-25, U-26 |
| E-discovery-14 | S-discovery | U-25, U-26 |
| E-discovery-15 | S-discovery | U-25, U-26 |
| E-discovery-16 | S-discovery | U-25, U-26 |
| E-discovery-17 | S-discovery | U-25, U-26 |
| E-discovery-18 | S-discovery | U-25, U-26 |
| E-discovery-19 | S-discovery | U-25, U-26 |
| E-discovery-dlg-new-scan-1 | S-discovery-dlg-new-scan | U-25 |
| E-discovery-dlg-new-scan-2 | S-discovery-dlg-new-scan | U-25 |
| E-discovery-dlg-new-scan-3 | S-discovery-dlg-new-scan | U-25 |
| E-discovery-dlg-new-scan-4 | S-discovery-dlg-new-scan | U-25 |
| E-discovery-dlg-new-scan-5 | S-discovery-dlg-new-scan | U-25 |
| E-discovery-dlg-new-scan-6 | S-discovery-dlg-new-scan | U-25 |
| E-slo-1 | S-slo | U-33 |
| E-slo-2 | S-slo | U-33 |
| E-slo-3 | S-slo | U-33 |
| E-slo-4 | S-slo | U-33 |
| E-slo-5 | S-slo | U-33 |
| E-compliance-1 | S-compliance | U-56 |
| E-compliance-2 | S-compliance | U-56 |
| E-compliance-3 | S-compliance | U-56 |
| E-custody-1 | S-custody | U-49 |
| E-audit-1 | S-audit | U-57 |
| E-audit-2 | S-audit | U-57 |
| E-audit-3 | S-audit | U-57 |
| E-audit-4 | S-audit | U-57 |
| E-audit-5 | S-audit | U-57 |
| E-audit-6 | S-audit | U-57 |
| E-audit-7 | S-audit | U-57 |
| E-audit-8 | S-audit | U-57 |
| E-audit-9 | S-audit | U-57 |
| E-audit-10 | S-audit | U-57 |
| E-audit-11 | S-audit | U-57 |
| E-audit-12 | S-audit | U-57 |
| E-audit-13 | S-audit | U-57 |
| E-changeaudit-1 | S-changeaudit | U-57 |
| E-changeaudit-2 | S-changeaudit | U-57 |
| E-changeaudit-3 | S-changeaudit | U-57 |
| E-changeaudit-4 | S-changeaudit | U-57 |
| E-changeaudit-5 | S-changeaudit | U-57 |
| E-changeaudit-6 | S-changeaudit | U-57 |
| E-history-1 | S-history | U-57 |
| E-history-2 | S-history | U-57 |
| E-history-3 | S-history | U-57 |
| E-history-4 | S-history | U-57 |
| E-history-5 | S-history | U-57 |
| E-history-6 | S-history | U-57 |
| E-blast-1 | S-blast | U-45 |
| E-blast-2 | S-blast | U-45 |
| E-blast-3 | S-blast | U-45 |
| E-posture-1 | S-posture | U-55 |
| E-posture-2 | S-posture | U-55 |
| E-posture-3 | S-posture | U-55 |
| E-posture-4 | S-posture | U-55 |
| E-posture-5 | S-posture | U-55 |
| E-posture-6 | S-posture | U-55 |
| E-posture-7 | S-posture | U-55 |
| E-posture-8 | S-posture | U-55 |
| E-posture-9 | S-posture | U-55 |
| E-posture-10 | S-posture | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-55) |
| E-posture-11 | S-posture | U-55 |
| E-posture-12 | S-posture | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-55) |
| E-posture-dlg-open-pqc-wave-1 | S-posture-dlg-open-pqc-wave | U-55 |
| E-posture-dlg-open-pqc-wave-2 | S-posture-dlg-open-pqc-wave | U-55 |
| E-posture-dlg-open-pqc-wave-3 | S-posture-dlg-open-pqc-wave | U-55 |
| E-pqc-1 | S-pqc | U-55 |
| E-pqc-2 | S-pqc | U-55 |
| E-pqc-3 | S-pqc | U-55 |
| E-pqc-4 | S-pqc | U-55 |
| E-pqc-5 | S-pqc | U-55 |
| E-pqc-6 | S-pqc | U-55 |
| E-pqc-7 | S-pqc | U-55 |
| E-pqc-8 | S-pqc | U-55 |
| E-pqc-9 | S-pqc | U-55 |
| E-pqc-10 | S-pqc | U-55 |
| E-pqc-11 | S-pqc | U-55 |
| E-pqc-12 | S-pqc | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-55) |
| E-pqc-13 | S-pqc | U-55 |
| E-pqc-14 | S-pqc | U-55 |
| E-pqc-15 | S-pqc | U-55 |
| E-pqc-16 | S-pqc | U-55 |
| E-pqc-17 | S-pqc | U-55 |
| E-pqc-18 | S-pqc | U-55 |
| E-pqc-pane-start-migration-wave-1 | S-pqc-pane-start-migration-wave | U-55 |
| E-pqc-pane-start-migration-wave-2 | S-pqc-pane-start-migration-wave | U-55 |
| E-pqc-pane-start-migration-wave-3 | S-pqc-pane-start-migration-wave | U-55 |
| E-pqc-pane-start-migration-wave-4 | S-pqc-pane-start-migration-wave | U-55 |
| E-pqc-pane-start-migration-wave-5 | S-pqc-pane-start-migration-wave | U-55 |
| E-pqc-pane-start-migration-wave-6 | S-pqc-pane-start-migration-wave | U-55 |
| E-pqc-pane-start-migration-wave-7 | S-pqc-pane-start-migration-wave | U-55 |
| E-pqc-pane-start-migration-wave-8 | S-pqc-pane-start-migration-wave | U-55 |
| E-pqc-pane-start-migration-wave-9 | S-pqc-pane-start-migration-wave | U-55 |
| E-pqc-pane-start-migration-wave-10 | S-pqc-pane-start-migration-wave | U-55 |
| E-pqc-pane-start-migration-wave-11 | S-pqc-pane-start-migration-wave | U-55 |
| E-pqc-pane-start-migration-wave-12 | S-pqc-pane-start-migration-wave | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-55) |
| E-pqc-pane-start-migration-wave-13 | S-pqc-pane-start-migration-wave | U-55 |
| E-pqc-pane-start-migration-wave-14 | S-pqc-pane-start-migration-wave | U-55 |
| E-pqc-pane-start-migration-wave-15 | S-pqc-pane-start-migration-wave | U-55 |
| E-pqc-pane-start-migration-wave-16 | S-pqc-pane-start-migration-wave | U-55 |
| E-pqc-pane-start-migration-wave-17 | S-pqc-pane-start-migration-wave | U-55 |
| E-pqc-pane-start-migration-wave-18 | S-pqc-pane-start-migration-wave | U-55 |
| E-pqc-pane-start-migration-wave-19 | S-pqc-pane-start-migration-wave | U-55 |
| E-pqc-pane-start-migration-wave-20 | S-pqc-pane-start-migration-wave | U-55 |
| E-pqc-pane-start-migration-wave-21 | S-pqc-pane-start-migration-wave | U-55 |
| E-pqc-pane-start-migration-wave-22 | S-pqc-pane-start-migration-wave | U-55 |
| E-sunset-1 | S-sunset | U-55 |
| E-sunset-2 | S-sunset | U-55 |
| E-sunset-3 | S-sunset | U-55 |
| E-sunset-4 | S-sunset | U-55 |
| E-sunset-5 | S-sunset | U-55 |
| E-sunset-6 | S-sunset | U-55 |
| E-sunset-7 | S-sunset | U-55 |
| E-sunset-8 | S-sunset | U-55 |
| E-expiry-1 | S-expiry | U-22, U-55 |
| E-expiry-2 | S-expiry | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-22, U-55) |
| E-expiry-3 | S-expiry | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-22, U-55) |
| E-expiry-4 | S-expiry | U-22, U-55 |
| E-expiry-5 | S-expiry | U-22, U-55 |
| E-expiry-dlg-open-pqc-wave-1 | S-expiry-dlg-open-pqc-wave | U-55 |
| E-expiry-dlg-open-pqc-wave-2 | S-expiry-dlg-open-pqc-wave | U-55 |
| E-expiry-dlg-open-pqc-wave-3 | S-expiry-dlg-open-pqc-wave | U-55 |
| E-cloudkeys-1 | S-cloudkeys | U-50, U-60 |
| E-cahealth-1 | S-cahealth | U-07, U-55 |
| E-cahealth-2 | S-cahealth | U-07, U-55 |
| E-cahealth-3 | S-cahealth | U-07, U-55 |
| E-cahealth-4 | S-cahealth | U-07, U-55 |
| E-velocity-1 | S-velocity | U-54, U-55 |
| E-velocity-2 | S-velocity | U-54, U-55 |
| E-revocation-1 | S-revocation | U-23, U-55 |
| E-revocation-2 | S-revocation | U-23, U-55 |
| E-revocation-3 | S-revocation | U-23, U-55 |
| E-users-1 | S-users | U-38 |
| E-users-2 | S-users | U-38 |
| E-users-3 | S-users | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-38) |
| E-users-dlg-invite-user-1 | S-users-dlg-invite-user | U-38 |
| E-users-dlg-invite-user-2 | S-users-dlg-invite-user | U-38 |
| E-users-dlg-invite-user-3 | S-users-dlg-invite-user | U-38 |
| E-users-dlg-invite-user-4 | S-users-dlg-invite-user | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-38) |
| E-users-dlg-invite-user-5 | S-users-dlg-invite-user | U-38 |
| E-accessreview-1 | S-accessreview | U-40 |
| E-accessreview-2 | S-accessreview | U-40 |
| E-accessreview-3 | S-accessreview | U-40 |
| E-accessreview-4 | S-accessreview | U-40 |
| E-accessreview-5 | S-accessreview | U-40 |
| E-accessreview-6 | S-accessreview | U-40 |
| E-accessreview-7 | S-accessreview | U-40 |
| E-accessreview-8 | S-accessreview | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-40) |
| E-accessreview-dlg-open-campaign-1 | S-accessreview-dlg-open-campaign | U-40 |
| E-accessreview-dlg-open-campaign-2 | S-accessreview-dlg-open-campaign | U-40 |
| E-accessreview-dlg-open-campaign-3 | S-accessreview-dlg-open-campaign | U-40 |
| E-policies-1 | S-policies | U-42 |
| E-policies-2 | S-policies | U-42 |
| E-policies-3 | S-policies | U-42 |
| E-policies-4 | S-policies | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-42) |
| E-policies-5 | S-policies | U-42 |
| E-policies-6 | S-policies | U-42 |
| E-policies-7 | S-policies | U-42 |
| E-policies-8 | S-policies | U-42 |
| E-policies-9 | S-policies | U-42 |
| E-policies-10 | S-policies | U-42 |
| E-policies-pane-new-policy-1 | S-policies-pane-new-policy | U-42 |
| E-policies-pane-new-policy-2 | S-policies-pane-new-policy | U-42 |
| E-policies-pane-new-policy-3 | S-policies-pane-new-policy | U-42 |
| E-policies-pane-new-policy-4 | S-policies-pane-new-policy | U-42 |
| E-policies-pane-new-policy-5 | S-policies-pane-new-policy | U-42 |
| E-policies-pane-new-policy-6 | S-policies-pane-new-policy | U-42 |
| E-policies-pane-new-policy-7 | S-policies-pane-new-policy | U-42 |
| E-policies-pane-new-policy-8 | S-policies-pane-new-policy | U-42 |
| E-policies-pane-new-policy-9 | S-policies-pane-new-policy | U-42 |
| E-policies-pane-new-policy-10 | S-policies-pane-new-policy | U-42 |
| E-policies-pane-new-policy-11 | S-policies-pane-new-policy | U-42 |
| E-policies-pane-new-policy-12 | S-policies-pane-new-policy | U-42 |
| E-policies-pane-new-policy-13 | S-policies-pane-new-policy | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-42) |
| E-policies-pane-new-policy-14 | S-policies-pane-new-policy | U-42 |
| E-policies-pane-new-policy-15 | S-policies-pane-new-policy | U-42 |
| E-policies-pane-new-policy-16 | S-policies-pane-new-policy | U-42 |
| E-policies-pane-new-policy-17 | S-policies-pane-new-policy | U-42 |
| E-policies-pane-new-policy-18 | S-policies-pane-new-policy | U-42 |
| E-policies-pane-new-policy-19 | S-policies-pane-new-policy | U-42 |
| E-policies-pane-edit-policy-1 | S-policies-pane-edit-policy | U-42 |
| E-policies-pane-edit-policy-2 | S-policies-pane-edit-policy | U-42 |
| E-policies-pane-edit-policy-3 | S-policies-pane-edit-policy | U-42 |
| E-policies-pane-edit-policy-4 | S-policies-pane-edit-policy | U-42 |
| E-policies-pane-edit-policy-5 | S-policies-pane-edit-policy | U-42 |
| E-policies-pane-edit-policy-6 | S-policies-pane-edit-policy | U-42 |
| E-policies-pane-edit-policy-7 | S-policies-pane-edit-policy | U-42 |
| E-policies-pane-edit-policy-8 | S-policies-pane-edit-policy | U-42 |
| E-policies-pane-edit-policy-9 | S-policies-pane-edit-policy | U-42 |
| E-policies-pane-edit-policy-10 | S-policies-pane-edit-policy | U-42 |
| E-policies-pane-edit-policy-11 | S-policies-pane-edit-policy | U-42 |
| E-policies-pane-edit-policy-12 | S-policies-pane-edit-policy | U-42 |
| E-policies-pane-edit-policy-13 | S-policies-pane-edit-policy | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-42) |
| E-policies-pane-edit-policy-14 | S-policies-pane-edit-policy | U-42 |
| E-policies-pane-edit-policy-15 | S-policies-pane-edit-policy | U-42 |
| E-policies-pane-edit-policy-16 | S-policies-pane-edit-policy | U-42 |
| E-policies-pane-edit-policy-17 | S-policies-pane-edit-policy | U-42 |
| E-policies-pane-edit-policy-18 | S-policies-pane-edit-policy | U-42 |
| E-policies-pane-edit-policy-19 | S-policies-pane-edit-policy | U-42 |
| E-roles-1 | S-roles | U-39 |
| E-roles-2 | S-roles | U-39 |
| E-roles-3 | S-roles | U-39 |
| E-roles-4 | S-roles | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-39) |
| E-roles-pane-new-role-1 | S-roles-pane-new-role | U-39 |
| E-roles-pane-new-role-2 | S-roles-pane-new-role | U-39 |
| E-roles-pane-new-role-3 | S-roles-pane-new-role | U-39 |
| E-roles-pane-new-role-4 | S-roles-pane-new-role | U-39 |
| E-roles-pane-new-role-5 | S-roles-pane-new-role | U-39 |
| E-roles-pane-new-role-6 | S-roles-pane-new-role | U-39 |
| E-roles-pane-new-role-7 | S-roles-pane-new-role | U-39 |
| E-roles-pane-new-role-8 | S-roles-pane-new-role | U-39 |
| E-roles-pane-new-role-9 | S-roles-pane-new-role | U-39 |
| E-roles-pane-new-role-10 | S-roles-pane-new-role | U-39 |
| E-roles-pane-new-role-11 | S-roles-pane-new-role | U-39 |
| E-roles-pane-new-role-12 | S-roles-pane-new-role | U-39 |
| E-roles-pane-new-role-13 | S-roles-pane-new-role | U-39 |
| E-roles-pane-new-role-14 | S-roles-pane-new-role | U-39 |
| E-roles-pane-new-role-15 | S-roles-pane-new-role | U-39 |
| E-roles-pane-new-role-16 | S-roles-pane-new-role | U-39 |
| E-roles-pane-new-role-17 | S-roles-pane-new-role | U-39 |
| E-roles-pane-new-role-18 | S-roles-pane-new-role | U-39 |
| E-roles-pane-new-role-19 | S-roles-pane-new-role | U-39 |
| E-roles-pane-new-role-20 | S-roles-pane-new-role | U-39 |
| E-roles-pane-new-role-21 | S-roles-pane-new-role | U-39 |
| E-roles-pane-new-role-22 | S-roles-pane-new-role | U-39 |
| E-roles-pane-new-role-23 | S-roles-pane-new-role | U-39 |
| E-roles-pane-new-role-24 | S-roles-pane-new-role | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-39) |
| E-roles-pane-edit-role-1 | S-roles-pane-edit-role | U-39 |
| E-roles-pane-edit-role-2 | S-roles-pane-edit-role | U-39 |
| E-roles-pane-edit-role-3 | S-roles-pane-edit-role | U-39 |
| E-roles-pane-edit-role-4 | S-roles-pane-edit-role | U-39 |
| E-roles-pane-edit-role-5 | S-roles-pane-edit-role | U-39 |
| E-roles-pane-edit-role-6 | S-roles-pane-edit-role | U-39 |
| E-roles-pane-edit-role-7 | S-roles-pane-edit-role | U-39 |
| E-roles-pane-edit-role-8 | S-roles-pane-edit-role | U-39 |
| E-roles-pane-edit-role-9 | S-roles-pane-edit-role | U-39 |
| E-roles-pane-edit-role-10 | S-roles-pane-edit-role | U-39 |
| E-roles-pane-edit-role-11 | S-roles-pane-edit-role | U-39 |
| E-roles-pane-edit-role-12 | S-roles-pane-edit-role | U-39 |
| E-roles-pane-edit-role-13 | S-roles-pane-edit-role | U-39 |
| E-roles-pane-edit-role-14 | S-roles-pane-edit-role | U-39 |
| E-roles-pane-edit-role-15 | S-roles-pane-edit-role | U-39 |
| E-roles-pane-edit-role-16 | S-roles-pane-edit-role | U-39 |
| E-roles-pane-edit-role-17 | S-roles-pane-edit-role | U-39 |
| E-roles-pane-edit-role-18 | S-roles-pane-edit-role | U-39 |
| E-roles-pane-edit-role-19 | S-roles-pane-edit-role | U-39 |
| E-roles-pane-edit-role-20 | S-roles-pane-edit-role | U-39 |
| E-roles-pane-edit-role-21 | S-roles-pane-edit-role | U-39 |
| E-roles-pane-edit-role-22 | S-roles-pane-edit-role | U-39 |
| E-roles-pane-edit-role-23 | S-roles-pane-edit-role | U-39 |
| E-roles-pane-edit-role-24 | S-roles-pane-edit-role | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-39) |
| E-invsrc-1 | S-invsrc | U-51 |
| E-invsrc-2 | S-invsrc | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-51) |
| E-invsrc-3 | S-invsrc | U-51 |
| E-invsrc-4 | S-invsrc | U-51 |
| E-invsrc-5 | S-invsrc | U-51 |
| E-invsrc-6 | S-invsrc | U-51 |
| E-invsrc-7 | S-invsrc | U-51 |
| E-invsrc-8 | S-invsrc | U-51 |
| E-migration-1 | S-migration | U-52 |
| E-migration-2 | S-migration | U-52 |
| E-migration-3 | S-migration | U-52 |
| E-migration-4 | S-migration | U-52 |
| E-migration-5 | S-migration | U-52 |
| E-migration-6 | S-migration | U-52 |
| E-migration-7 | S-migration | U-52 |
| E-migration-8 | S-migration | U-52 |
| E-migration-9 | S-migration | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-52) |
| E-settings-1 | S-settings | U-56, U-58 |
| E-settings-2 | S-settings | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-56, U-58) |
| E-settings-3 | S-settings | U-56, U-58 |
| E-settings-4 | S-settings | U-56, U-58 |
| E-settings-5 | S-settings | U-56, U-58 |
| E-settings-6 | S-settings | U-56, U-58 |
| E-settings-7 | S-settings | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-56, U-58) |
| E-settings-8 | S-settings | U-56, U-58 |
| E-settings-9 | S-settings | U-56, U-58 |
| E-settings-10 | S-settings | U-56, U-58 |
| E-settings-11 | S-settings | U-56, U-58 |
| E-settings-12 | S-settings | U-56, U-58 |
| E-settings-13 | S-settings | U-56, U-58 |
| E-settings-14 | S-settings | U-56, U-58 |
| E-settings-15 | S-settings | U-56, U-58 |
| E-settings-pane-add-cluster-1 | S-settings-pane-add-cluster | U-58 |
| E-settings-pane-add-cluster-2 | S-settings-pane-add-cluster | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-58) |
| E-settings-pane-add-cluster-3 | S-settings-pane-add-cluster | U-58 |
| E-settings-pane-add-cluster-4 | S-settings-pane-add-cluster | U-58 |
| E-settings-pane-add-cluster-5 | S-settings-pane-add-cluster | U-58 |
| E-settings-pane-add-cluster-6 | S-settings-pane-add-cluster | U-58 |
| E-settings-pane-add-cluster-7 | S-settings-pane-add-cluster | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-58) |
| E-settings-pane-add-cluster-8 | S-settings-pane-add-cluster | U-58 |
| E-settings-pane-add-cluster-9 | S-settings-pane-add-cluster | U-58 |
| E-settings-pane-add-cluster-10 | S-settings-pane-add-cluster | U-58 |
| E-settings-pane-add-cluster-11 | S-settings-pane-add-cluster | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-58) |
| E-settings-pane-add-cluster-12 | S-settings-pane-add-cluster | U-58 |
| E-settings-pane-add-cluster-13 | S-settings-pane-add-cluster | U-58 |
| E-settings-pane-add-cluster-14 | S-settings-pane-add-cluster | U-58 |
| E-settings-pane-add-cluster-15 | S-settings-pane-add-cluster | U-58 |
| E-settings-pane-add-cluster-16 | S-settings-pane-add-cluster | U-58 |
| E-settings-pane-add-cluster-17 | S-settings-pane-add-cluster | U-58 |
| E-settings-pane-add-cluster-18 | S-settings-pane-add-cluster | U-58 |
| E-settings-pane-add-cluster-19 | S-settings-pane-add-cluster | U-58 |
| E-settings-pane-add-endpoint-1 | S-settings-pane-add-endpoint | U-58 |
| E-settings-pane-add-endpoint-2 | S-settings-pane-add-endpoint | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-58) |
| E-settings-pane-add-endpoint-3 | S-settings-pane-add-endpoint | U-58 |
| E-settings-pane-add-endpoint-4 | S-settings-pane-add-endpoint | U-58 |
| E-settings-pane-add-endpoint-5 | S-settings-pane-add-endpoint | U-58 |
| E-settings-pane-add-endpoint-6 | S-settings-pane-add-endpoint | U-58 |
| E-settings-pane-add-endpoint-7 | S-settings-pane-add-endpoint | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-58) |
| E-settings-pane-add-endpoint-8 | S-settings-pane-add-endpoint | U-58 |
| E-settings-pane-add-endpoint-9 | S-settings-pane-add-endpoint | U-58 |
| E-settings-pane-add-endpoint-10 | S-settings-pane-add-endpoint | U-58 |
| E-settings-pane-add-endpoint-11 | S-settings-pane-add-endpoint | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-58) |
| E-settings-pane-add-endpoint-12 | S-settings-pane-add-endpoint | U-58 |
| E-settings-pane-add-endpoint-13 | S-settings-pane-add-endpoint | U-58 |
| E-settings-pane-add-endpoint-14 | S-settings-pane-add-endpoint | U-58 |
| E-settings-pane-add-endpoint-15 | S-settings-pane-add-endpoint | U-58 |
| E-settings-pane-add-endpoint-16 | S-settings-pane-add-endpoint | U-58 |
| E-settings-pane-add-endpoint-17 | S-settings-pane-add-endpoint | U-58 |
| E-settings-pane-add-domain-1 | S-settings-pane-add-domain | U-53 |
| E-settings-pane-add-domain-2 | S-settings-pane-add-domain | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-53) |
| E-settings-pane-add-domain-3 | S-settings-pane-add-domain | U-53 |
| E-settings-pane-add-domain-4 | S-settings-pane-add-domain | U-53 |
| E-settings-pane-add-domain-5 | S-settings-pane-add-domain | U-53 |
| E-settings-pane-add-domain-6 | S-settings-pane-add-domain | U-53 |
| E-settings-pane-add-domain-7 | S-settings-pane-add-domain | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-53) |
| E-settings-pane-add-domain-8 | S-settings-pane-add-domain | U-53 |
| E-settings-pane-add-domain-9 | S-settings-pane-add-domain | U-53 |
| E-settings-pane-add-domain-10 | S-settings-pane-add-domain | U-53 |
| E-settings-pane-add-domain-11 | S-settings-pane-add-domain | U-53 |
| E-settings-pane-add-domain-12 | S-settings-pane-add-domain | U-53 |
| E-settings-pane-add-domain-13 | S-settings-pane-add-domain | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-53) |
| E-settings-pane-add-domain-14 | S-settings-pane-add-domain | U-53 |
| E-settings-pane-add-domain-15 | S-settings-pane-add-domain | U-53 |
| E-settings-pane-add-domain-16 | S-settings-pane-add-domain | U-53 |
| E-settings-pane-add-domain-17 | S-settings-pane-add-domain | U-53 |
| E-settings-pane-add-cloud-source-1 | S-settings-pane-add-cloud-source | U-58 |
| E-settings-pane-add-cloud-source-2 | S-settings-pane-add-cloud-source | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-58) |
| E-settings-pane-add-cloud-source-3 | S-settings-pane-add-cloud-source | U-58 |
| E-settings-pane-add-cloud-source-4 | S-settings-pane-add-cloud-source | U-58 |
| E-settings-pane-add-cloud-source-5 | S-settings-pane-add-cloud-source | U-58 |
| E-settings-pane-add-cloud-source-6 | S-settings-pane-add-cloud-source | U-58 |
| E-settings-pane-add-cloud-source-7 | S-settings-pane-add-cloud-source | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-58) |
| E-settings-pane-add-cloud-source-8 | S-settings-pane-add-cloud-source | U-58 |
| E-settings-pane-add-cloud-source-9 | S-settings-pane-add-cloud-source | U-58 |
| E-settings-pane-add-cloud-source-10 | S-settings-pane-add-cloud-source | U-58 |
| E-settings-pane-add-cloud-source-11 | S-settings-pane-add-cloud-source | U-58 |
| E-settings-pane-add-cloud-source-12 | S-settings-pane-add-cloud-source | U-58 |
| E-settings-pane-add-cloud-source-13 | S-settings-pane-add-cloud-source | U-58 |
| E-settings-pane-add-cloud-source-14 | S-settings-pane-add-cloud-source | U-58 |
| E-settings-pane-add-cloud-source-15 | S-settings-pane-add-cloud-source | U-58 |
| E-settings-pane-add-cloud-source-16 | S-settings-pane-add-cloud-source | U-58 |
| E-settings-pane-add-cloud-source-17 | S-settings-pane-add-cloud-source | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-58) |
| E-settings-pane-add-cloud-source-18 | S-settings-pane-add-cloud-source | U-58 |
| E-settings-pane-add-cloud-source-19 | S-settings-pane-add-cloud-source | U-58 |
| E-tenants-1 | S-tenants | U-41, U-60 |
| E-issue-1 | S-issue | U-13 |
| E-issue-2 | S-issue | U-13 |
| E-issue-3 | S-issue | U-13 |
| E-issue-4 | S-issue | U-13 |
| E-certs-detail-1 | S-certs-detail | U-16, U-20, U-22, U-23 |
| E-certs-detail-2 | S-certs-detail | U-16, U-20, U-22, U-23 |
| E-certs-detail-3 | S-certs-detail | U-16, U-20, U-22, U-23 |
| E-certs-detail-4 | S-certs-detail | U-16, U-20, U-22, U-23 |
| E-certs-detail-5 | S-certs-detail | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-16, U-20, U-22, U-23) |
| E-certs-detail-6 | S-certs-detail | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-16, U-20, U-22, U-23) |
| E-certs-detail-7 | S-certs-detail | U-16, U-20, U-22, U-23 |
| E-certs-selected-1 | S-certs-selected | U-20, U-22, U-23, U-24 |
| E-certs-selected-2 | S-certs-selected | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-20, U-22, U-23, U-24) |
| E-certs-selected-3 | S-certs-selected | U-20, U-22, U-23, U-24 |
| E-certs-selected-4 | S-certs-selected | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-20, U-22, U-23, U-24) |
| E-cas-detail-1 | S-cas-detail | U-07, U-08 |
| E-cas-detail-2 | S-cas-detail | U-07, U-08 |
| E-cas-detail-3 | S-cas-detail | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-07, U-08) |
| E-cas-detail-4 | S-cas-detail | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-07, U-08) |
| E-cas-detail-5 | S-cas-detail | U-07, U-08 |
| E-cas-detail-6 | S-cas-detail | U-07, U-08 |
| E-cas-hierarchy-1 | S-cas-hierarchy | U-07 |
| E-cas-hierarchy-2 | S-cas-hierarchy | U-07 |
| E-cas-dlg-update-1 | S-cas-dlg-update | U-08 |
| E-cas-dlg-update-2 | S-cas-dlg-update | U-08 |
| E-cas-dlg-update-3 | S-cas-dlg-update | U-08 |
| E-cas-dlg-update-4 | S-cas-dlg-update | U-08 |
| E-cas-dlg-update-5 | S-cas-dlg-update | U-08 |
| E-cas-dlg-update-6 | S-cas-dlg-update | U-08 |
| E-cas-dlg-rekey-1 | S-cas-dlg-rekey | U-08 |
| E-cas-dlg-rekey-2 | S-cas-dlg-rekey | U-08 |
| E-cas-dlg-rekey-3 | S-cas-dlg-rekey | U-08 |
| E-cas-dlg-rekey-4 | S-cas-dlg-rekey | U-08 |
| E-cas-dlg-rekey-5 | S-cas-dlg-rekey | U-08 |
| E-issue-2-1 | S-issue-2 | U-13 |
| E-issue-2-2 | S-issue-2 | U-13 |
| E-issue-2-3 | S-issue-2 | U-13 |
| E-issue-2-4 | S-issue-2 | U-13 |
| E-issue-3-1 | S-issue-3 | U-13 |
| E-issue-3-2 | S-issue-3 | U-13 |
| E-issue-3-3 | S-issue-3 | U-13 |
| E-issue-3-4 | S-issue-3 | U-13 |
| E-issue-3-5 | S-issue-3 | U-13 |
| E-issue-4-1 | S-issue-4 | U-13 |
| E-issue-4-2 | S-issue-4 | U-13 |
| E-issue-4-3 | S-issue-4 | U-13 |
| E-issue-4-4 | S-issue-4 | U-13 |
| E-issue-4-5 | S-issue-4 | U-13 |
| E-issue-4-csr-1 | S-issue-4-csr | U-13 |
| E-issue-4-csr-2 | S-issue-4-csr | U-13 |
| E-issue-4-csr-3 | S-issue-4-csr | U-13 |
| E-issue-4-csr-4 | S-issue-4-csr | U-13 |
| E-issue-4-csr-5 | S-issue-4-csr | U-13 |
| E-issue-4-csr-6 | S-issue-4-csr | U-13 |
| E-issue-4-gen-1 | S-issue-4-gen | U-14 |
| E-issue-4-gen-2 | S-issue-4-gen | U-14 |
| E-issue-4-gen-3 | S-issue-4-gen | U-14 |
| E-issue-4-gen-4 | S-issue-4-gen | U-14 |
| E-issue-4-gen-5 | S-issue-4-gen | U-14 |
| E-issue-4-gen-6 | S-issue-4-gen | U-14 |
| E-issue-5-1 | S-issue-5 | U-13, U-15 |
| E-issue-5-2 | S-issue-5 | U-13, U-15 |
| E-issue-5-3 | S-issue-5 | U-13, U-15 |
| E-policies-dryrun-1 | S-policies-dryrun | U-42 |
| E-policies-dryrun-2 | S-policies-dryrun | U-42 |
| E-policies-dryrun-3 | S-policies-dryrun | U-42 |
| E-policies-dryrun-4 | S-policies-dryrun | U-42 |
| E-nhi-dlg-propose-1 | S-nhi-dlg-propose | U-43 |
| E-nhi-dlg-propose-2 | S-nhi-dlg-propose | U-43 |
| E-nhi-dlg-propose-3 | S-nhi-dlg-propose | U-43 |
| E-nhi-dlg-propose-4 | S-nhi-dlg-propose | U-43 |
| E-nhi-dlg-propose-5 | S-nhi-dlg-propose | U-43 |
| E-nhi-dlg-propose-6 | S-nhi-dlg-propose | U-43 |
| E-nhi-dlg-propose-7 | S-nhi-dlg-propose | U-43 |
| E-nhi-dlg-propose-8 | S-nhi-dlg-propose | U-43 |
| E-nhi-dlg-propose-9 | S-nhi-dlg-propose | U-43 |
| E-nhi-dlg-propose-10 | S-nhi-dlg-propose | U-43 |
| E-nhi-dlg-propose-11 | S-nhi-dlg-propose | U-43 |
| E-nhi-dlg-propose-12 | S-nhi-dlg-propose | U-43 |
| E-nhi-dlg-propose-13 | S-nhi-dlg-propose | U-43 |
| E-nhi-dlg-propose-14 | S-nhi-dlg-propose | U-43 |
| E-nhi-dlg-propose-15 | S-nhi-dlg-propose | U-43 |
| E-nhi-dlg-propose-16 | S-nhi-dlg-propose | U-43 |
| E-nhi-dlg-propose-17 | S-nhi-dlg-propose | U-43 |
| E-nhi-dlg-propose-18 | S-nhi-dlg-propose | U-43 |
| E-nhi-dlg-propose-19 | S-nhi-dlg-propose | U-43 |
| E-nhi-dlg-propose-20 | S-nhi-dlg-propose | U-43 |
| E-nhi-dlg-propose-21 | S-nhi-dlg-propose | U-43 |
| E-keys-dlg-escrow-1 | S-keys-dlg-escrow | U-49 |
| E-keys-dlg-escrow-2 | S-keys-dlg-escrow | U-49 |
| E-keys-dlg-escrow-3 | S-keys-dlg-escrow | U-49 |
| E-keys-dlg-escrow-4 | S-keys-dlg-escrow | U-49 |
| E-keys-dlg-escrow-5 | S-keys-dlg-escrow | U-49 |
| E-keys-dlg-escrow-6 | S-keys-dlg-escrow | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-49) |
| E-keys-dlg-recover-1 | S-keys-dlg-recover | U-49 |
| E-keys-dlg-recover-2 | S-keys-dlg-recover | U-49 |
| E-keys-dlg-recover-3 | S-keys-dlg-recover | U-49 |
| E-keys-dlg-recover-4 | S-keys-dlg-recover | U-49 |
| E-keys-dlg-recover-5 | S-keys-dlg-recover | U-49 |
| E-keys-dlg-recover-6 | S-keys-dlg-recover | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-49) |
| E-keys-dlg-byok-1 | S-keys-dlg-byok | U-49 |
| E-keys-dlg-byok-2 | S-keys-dlg-byok | U-49 |
| E-keys-dlg-byok-3 | S-keys-dlg-byok | U-49 |
| E-keys-dlg-byok-4 | S-keys-dlg-byok | U-49 |
| E-keys-dlg-byok-5 | S-keys-dlg-byok | U-49 |
| E-keys-dlg-byok-6 | S-keys-dlg-byok | U-49 |
| E-keys-dlg-byok-7 | S-keys-dlg-byok | U-49 |
| E-keys-dlg-byok-8 | S-keys-dlg-byok | U-49 |
| E-keys-dlg-byok-9 | S-keys-dlg-byok | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-49) |
| E-templates-dlg-draft-1 | S-templates-dlg-draft | U-12 |
| E-templates-dlg-draft-2 | S-templates-dlg-draft | U-12 |
| E-templates-dlg-draft-3 | S-templates-dlg-draft | U-12 |
| E-templates-dlg-draft-4 | S-templates-dlg-draft | U-12 |
| E-templates-dlg-draft-5 | S-templates-dlg-draft | U-12 |
| E-users-dlg-role-1 | S-users-dlg-role | U-38 |
| E-users-dlg-role-2 | S-users-dlg-role | U-38 |
| E-users-dlg-role-3 | S-users-dlg-role | U-38 |
| E-users-dlg-role-4 | S-users-dlg-role | U-38 |
| E-alerts-tab-rules-1 | S-alerts-tab-rules | U-36 |
| E-alerts-tab-rules-2 | S-alerts-tab-rules | U-36 |
| E-alerts-tab-rules-3 | S-alerts-tab-rules | U-36 |
| E-alerts-tab-rules-4 | S-alerts-tab-rules | U-36 |
| E-alerts-tab-rules-5 | S-alerts-tab-rules | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-36) |
| E-alerts-dlg-newrule-1 | S-alerts-dlg-newrule | U-36 |
| E-alerts-dlg-newrule-2 | S-alerts-dlg-newrule | U-36 |
| E-alerts-dlg-newrule-3 | S-alerts-dlg-newrule | U-36 |
| E-alerts-dlg-newrule-4 | S-alerts-dlg-newrule | U-36 |
| E-alerts-dlg-newrule-5 | S-alerts-dlg-newrule | U-36 |
| E-alerts-dlg-newrule-6 | S-alerts-dlg-newrule | U-36 |
| E-alerts-dlg-newrule-7 | S-alerts-dlg-newrule | U-36 |
| E-alerts-dlg-newrule-8 | S-alerts-dlg-newrule | U-36 |
| E-alerts-dlg-newrule-9 | S-alerts-dlg-newrule | U-36 |
| E-history-detail-1 | S-history-detail | U-57 |
| E-history-detail-2 | S-history-detail | U-57 |
| E-acme-dlg-prov-1 | S-acme-dlg-prov | U-27 |
| E-acme-dlg-prov-2 | S-acme-dlg-prov | U-27 |
| E-acme-dlg-prov-3 | S-acme-dlg-prov | U-27 |
| E-acme-dlg-prov-4 | S-acme-dlg-prov | U-27 |
| E-acme-dlg-prov-5 | S-acme-dlg-prov | U-27 |
| E-acme-dlg-prov-6 | S-acme-dlg-prov | U-27 |
| E-acme-dlg-prov-7 | S-acme-dlg-prov | U-27 |
| E-acme-dlg-prov-8 | S-acme-dlg-prov | U-27 |
| E-acme-dlg-prov-9 | S-acme-dlg-prov | U-27 |
| E-enroll-dlg-estuser-1 | S-enroll-dlg-estuser | U-28 |
| E-enroll-dlg-estuser-2 | S-enroll-dlg-estuser | U-28 |
| E-enroll-dlg-estuser-3 | S-enroll-dlg-estuser | U-28 |
| E-enroll-dlg-estuser-4 | S-enroll-dlg-estuser | U-28 |
| E-enroll-dlg-estuser-5 | S-enroll-dlg-estuser | U-28 |
| E-enroll-dlg-cmpanchor-1 | S-enroll-dlg-cmpanchor | U-28 |
| E-enroll-dlg-cmpanchor-2 | S-enroll-dlg-cmpanchor | U-28 |
| E-enroll-dlg-cmpanchor-3 | S-enroll-dlg-cmpanchor | U-28 |
| E-enroll-dlg-cmpanchor-4 | S-enroll-dlg-cmpanchor | U-28 |
| E-enroll-dlg-cmpanchor-5 | S-enroll-dlg-cmpanchor | U-28 |
| E-enroll-dlg-pbm-1 | S-enroll-dlg-pbm | U-28 |
| E-enroll-dlg-pbm-2 | S-enroll-dlg-pbm | U-28 |
| E-enroll-dlg-pbm-3 | S-enroll-dlg-pbm | U-28 |
| E-enroll-dlg-pbm-4 | S-enroll-dlg-pbm | U-28 |
| E-enroll-dlg-pbm-5 | S-enroll-dlg-pbm | U-28 |
| E-discovery-endpoint-1 | S-discovery-endpoint | U-26 |
| E-discovery-endpoint-2 | S-discovery-endpoint | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-26) |
| E-discovery-endpoint-3 | S-discovery-endpoint | U-26 |
| E-discovery-endpoint-4 | S-discovery-endpoint | U-26 |
| E-discovery-endpoint-5 | S-discovery-endpoint | U-26 |
| E-posture-dlg-notify-1 | S-posture-dlg-notify | U-55 |
| E-posture-dlg-notify-2 | S-posture-dlg-notify | U-55 |
| E-posture-dlg-notify-3 | S-posture-dlg-notify | U-55 |
| E-posture-dlg-notify-4 | S-posture-dlg-notify | U-55 |
| E-posture-dlg-notify-5 | S-posture-dlg-notify | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-55) |
| E-posture-dlg-notify-6 | S-posture-dlg-notify | U-55 |
| E-plugins-dlg-install-1 | S-plugins-dlg-install | U-34 |
| E-plugins-dlg-install-2 | S-plugins-dlg-install | U-34 |
| E-plugins-dlg-install-3 | S-plugins-dlg-install | U-34 |
| E-plugins-dlg-install-4 | S-plugins-dlg-install | U-34 |
| E-plugins-dlg-install-5 | S-plugins-dlg-install | U-34 |
| E-plugins-dlg-install-6 | S-plugins-dlg-install | U-34 |
| E-targets-agent-1 | S-targets-agent | U-29 |
| E-targets-agent-2 | S-targets-agent | U-29 |
| E-targets-agent-3 | S-targets-agent | U-29 |
| E-targets-agent-4 | S-targets-agent | U-29 |
| E-targets-agent-5 | S-targets-agent | U-29 |
| E-targets-agent-6 | S-targets-agent | SKIPPED: destructive (firewalled; never executed by cartographer) (guarded capture in U-29) |
| E-targets-agentless-1-1 | S-targets-agentless-1 | U-30 |
| E-targets-agentless-1-2 | S-targets-agentless-1 | U-30 |
| E-targets-agentless-1-3 | S-targets-agentless-1 | U-30 |
| E-targets-agentless-1-4 | S-targets-agentless-1 | U-30 |
| E-targets-agentless-1-5 | S-targets-agentless-1 | U-30 |
| E-targets-agentless-1-6 | S-targets-agentless-1 | U-30 |
| E-targets-agentless-1-7 | S-targets-agentless-1 | U-30 |
| E-targets-agentless-2-1 | S-targets-agentless-2 | U-30 |
| E-targets-agentless-2-2 | S-targets-agentless-2 | U-30 |
| E-targets-agentless-2-3 | S-targets-agentless-2 | U-30 |
| E-targets-agentless-3-1 | S-targets-agentless-3 | U-30 |
| E-targets-agentless-3-2 | S-targets-agentless-3 | U-30 |
| E-targets-agentless-3-3 | S-targets-agentless-3 | U-30 |
| E-targets-agentless-4-1 | S-targets-agentless-4 | U-30 |
| E-targets-agentless-4-2 | S-targets-agentless-4 | U-30 |
| E-targets-agentless-4-3 | S-targets-agentless-4 | U-30 |
| E-targets-agentless-4-4 | S-targets-agentless-4 | U-30 |
| E-targets-agentless-4-5 | S-targets-agentless-4 | U-30 |
| E-targets-agentless-4-6 | S-targets-agentless-4 | U-30 |
| E-targets-agentless-5-1 | S-targets-agentless-5 | U-30 |
| E-targets-agentless-5-2 | S-targets-agentless-5 | U-30 |
| E-targets-agentless-5-3 | S-targets-agentless-5 | SKIPPED: auth-gated (needs SSH credential; guide-scribe expands) |
| E-targets-agentless-6-1 | S-targets-agentless-6 | U-30 |
| E-targets-agentless-6-2 | S-targets-agentless-6 | SKIPPED: auth-gated (needs SSH credential; guide-scribe expands) |
| E-audit-detail-1 | S-audit-detail | U-57 |

Totals: 60 stories, 955 element rows claimed, 88 SKIPPED.