# v1 UI findings (phase 2 work list)

Found while mapping the app for the user-guide tour (APP_MAP.md, 2026-10-18).
Status: open unless marked.

| # | Where | Finding |
|---|---|---|
| 1 | /templates, Edit | `GET /api/v1/templates/<id>/revisions` returns 503; audit logs `template.revisions` Failure **Status: fixed (3732c014)** |
| 2 | /enrollment SCEP tab | `GET /api/v1/scep/challenges` 404 console error when SCEP is off (UI shows "Not enabled"); seed `POST /scep/challenges` 405 **Status: fixed (dc920bd7) (seed `POST /scep/challenges` 405 left as is: it is the seed skip, unrelated to the UI call)** |
| 3 | scripts/dev/seed-demo.sh | `api-keys ci-deploy-bot` fails 400 "invalid request body" **Status: fixed (bec4a0a5); seed payload was already correct, 400 was hub without APP_API_KEY_PEPPER, now a clear 503 and the seed skips with the reason** |
| 4 | Forms | Unlabelled controls: /policies new policy inputs+checkboxes; /roles permission checkboxes; /nhi scope checkboxes; /acme new provisioner fields + challenge checkboxes; /enrollment EST user, CMP trust anchor, PBM secret dialogs; /targets/renewal-policy group checkboxes; /targets/setup step 4 auto-renew; /reports/pqc-migration one unnamed button **Status: fixed (89d7686b); only the icon-only wave delete button was truly unnamed, the other controls sit inside wrapping <label>s and compute names (checked with dom-accessibility-api and existing getByLabelText tests)** |
| 5 | KPI tiles | Accessible names run together ("39Active Certs3 revoked not counted"): Dashboard, Automation, Target Setup cards **Status: fixed (c0989e85)** |
| 6 | /history | Three canned Apr 7 2026 rows on a fresh hub with the delivery provider **Status: fixed (21ca653c); the rows came from the file dashboard-action provider's built-in seed (the default provider). It now serves an empty history unless APP_DASHBOARD_ACTION_DEMO=true (smoke harness sets it)** |
| 7 | Detail routes | /alerts/deliveries/<unknown> and /audit/<unknown> silently fall back to the list; /history/<unknown> says "Action not found" **Status: fixed (3cee8af1)** |
| 8 | /search | Raw ISO timestamps in result rows **Status: fixed (f254502b)** |
| 9 | Dates | Dashboard (browser local) vs Issuance Velocity (UTC) disagree on the day **Status: fixed (fb0359a5); buckets are server UTC days so they are labelled UTC rather than shifted** |
| 10 | /integrations | Raw config keys as labels (notifications.slack_bot_token, notifications.teams_app_id) **Status: fixed (24b3cdf1)** |
| 11 | /renewal/rollout-groups | Groups stored in browser only, not shared between users **Status: not changed; needs a design decision (server-side store, tenant scoping, who may edit a group) before it is built** |
| 12 | /targets/setup agentless step 4 | Credential list offers a Jira api_token for SSH install mode; Next then blocked **Status: fixed (ad51abf9)** |
| 13 | Targets / auto-renew | A cert that matches an auto-renew target by host but has no binding is never renewed; the only signal is one hub log line. Check the UI warns about unbound host matches (W27-02) **Status: fixed (c12b205c); Renewal Policy rows for auto-renew targets warn when a live certificate matches the target host but is not bound to it, using the existing certificates and bindings APIs (no API change)** |
