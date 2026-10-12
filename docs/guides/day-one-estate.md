# Day One: a complete estate picture before you go home

Venafi-class rollouts budget 3–6 months of professional services
before value. This guide gets a fresh Kryptkeeper install to a
risk-scored, PQC-split estate report — covering certificates you
issued, certificates other CAs issued, and certificates nobody was
tracking — in one sitting. The companion script
`scripts/day-one-estate.sh` runs the same path non-interactively.

Every stage names the UI page and the API call it fronts, plus the
failure modes you might hit and where they surface.

## Stage 1 — Install and first login

Follow `docs/guides/getting-started.md` (single binary or compose).
Sign in on the **Login** page with your bootstrap credentials, then
create your admin user on the **Users** page.

- API: authentication endpoints per the getting-started guide.
- Failure modes: no core DB configured → CA features degrade visibly
  at startup (the log names the missing env); wrong bootstrap token →
  401 on every call, nothing silent.

## Stage 2 — Bulk-import what you already have

Export what you hold today (a PEM bundle from your old tracking
spreadsheet's folder, or a CSV) and import it on the
**Certificates** page → *Bulk import* dialog.

- API: `POST /api/v1/certificates/bulk-import` with
  `{"format":"pem"|"csv","bundle":"..."}`.
- Imported rows enter the estate as `origin=imported /
  management_state=unmanaged` — visible immediately, deduped by
  fingerprint, safe to re-run.
- Failure modes: unparsable rows are reported per-row in the
  response, never silently dropped; a re-import of the same bundle
  changes nothing (dedupe).

## Stage 3 — Scan the network

On the **Discovery** page start a scan of your server ranges.

- API: `POST /api/v1/discovery/scans` with a CIDR or host:port
  target; progress and results on the same page
  (`GET /api/v1/discovery/scans`, endpoints list).
- Failure modes: unreachable hosts land as per-endpoint errors on the
  scan result — visible, not fatal to the sweep; a huge CIDR is
  bounded by the scanner's concurrency and timeout settings.

## Stage 4 — Pull inventory from the CAs that issued it

Register your external CA sources so their issued certs join the
estate as `origin=synced / management_state=external`.

- API: `POST /api/v1/inventory-sources` (types: `adcs_export` — a
  certutil/ldifde PEM export directory; `digicert` — CertCentral API
  with a `credential_ref` from the outbound credential store), then
  `POST /api/v1/inventory-sources/{id}/sync` to pull now rather than
  waiting for the schedule.
- Failure modes: a bad export path or dead credential lands on the
  source's `last_sync_result` — the **Settings**/estate surfaces show
  it; sync never partially deletes (read-only pull).

## Stage 5 — Optional breadth (agents, cloud, mesh)

If you have time left in the sitting:

- Register an agent on a busy server (**Agents** page) for
  host-level cert stores.
- Set cloud inventory env (AWS ACM / Azure Key Vault / GCP) and mesh
  discovery (`KRYPTKEEPER_MESH_K8S_URL`,
  `KRYPTKEEPER_SAAS_ENDPOINTS`) — both sweep on their own schedulers.
- CT-log monitoring: set `KRYPTKEEPER_CT_DOMAINS` and certificates
  you never issued for your own domains become findings.

## Stage 6 — The payoff: one estate, one number

- **Dashboard**: the estate split (managed / external / unmanaged)
  is now live.
- **PQC Migration** report (`/reports/pqc-migration`): the
  PQC-readiness split across every origin — including the certs you
  imported and synced today.
- Export for the meeting: `GET /api/v1/reports/export/inventory`
  (CSV or XLSX, documented column set) from the Reports surfaces.

From here, the **takeover flow** (`POST /api/v1/estate/takeover`)
turns any unmanaged row into a managed one with a renewal path — but
that's day two's story.
