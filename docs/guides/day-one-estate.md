# Day One: a complete estate picture before you go home

Venafi-class rollouts budget 3–6 months of professional services
before value. This guide gets a fresh Kryptkeeper install to a
risk-scored, PQC-split estate report — covering certificates you
issued, certificates other CAs issued, and certificates nobody was
tracking — in one sitting. The companion script
`scripts/day-one-estate.sh` runs the same path non-interactively. Against a Compose
hub, pass `CACERT=ca.pem` (the hub serves TLS with its own root).

## Stage names and failure codes

The script names each stage and exits with a distinct code so a CI
wrapper can assert which stage failed without parsing text. On failure
it prints `FAILED stage=<name> exit=<code>` to stderr. Set
`KK_DAYONE_INJECT_FAIL=<name>` to force a stage to fail (fires before
any network call, so it needs no running hub).

| Guide stage | Name | Exit code | Fails when |
|---|---|---|---|
| 1 | `hub` | 10 | hub unreachable or token rejected (a wrong bootstrap token is a 401) |
| 2 | `import` | 20 | bundle unreadable or bulk-import rejected |
| 3 | `scan` | 30 | scan request rejected |
| 4 | `sync` | 40 | source create or sync rejected |
| 6 | `report` | 50 | any report or export download fails |
| 6 | `verify` | 60 | estate report and dashboard disagree, or `EXPECT_*` not met |

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

- API: `POST /api/v1/discovery/scans` with `scan_type` (`fast`,
  `targeted`, `full` or `deep`) and a CIDR or host `target`; follow the job
  with `GET /api/v1/discovery/scan-jobs` and the results with
  `GET /api/v1/discovery/endpoints`. The script starts a `full` scan and waits
  for its job to finish (`SCAN_WAIT_SECONDS`, default 600) before it reports.
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
- Estate report: `GET /api/v1/reports/estate` (JSON) and
  `GET /api/v1/reports/estate?format=pdf` (PDF) — origin x
  management-state matrix, PQC and risk summary. The script saves both
  as `kryptkeeper-estate-<date>.json` / `.pdf`.

### Verify the numbers

The final script stage (`verify`) compares `managed`, `external` and
`unmanaged` from the saved estate JSON (`by_state`) with
`GET /api/v1/dashboard/summary` (`data.certificates`); any difference
exits 60. To check against what you seeded, set `EXPECT_TOTAL`,
`EXPECT_MANAGED`, `EXPECT_EXTERNAL` and `EXPECT_UNMANAGED`; each that is
set must equal the estate report. The token needs dashboard read access
(the admin token the script already requires is enough).

From here, the **takeover flow** (`POST /api/v1/estate/takeover`)
turns any unmanaged row into a managed one with a renewal path — but
that's day two's story.

## Reading the inventory: what each row is, and how sure we are

Discovery gives every certificate an **inventory class**, one of five buckets
derived from who manages it and who issued it:

| Class | Meaning |
|---|---|
| `managed` | A Kryptkeeper renewal path owns it (an agent task, or a target with auto-renew). |
| `ours_unmanaged` | Issued by this hub's CAs, but nothing renews it. |
| `authorized_external` | Issued by an issuer you declared as authorized (Discovery, **Authorize this issuer**). Public roots are not authorized by default. |
| `unknown_issuer` | A public, unknown private, or unclassifiable issuer: a CA group you do not have. |
| `self_signed` | Always a finding, never a CA group. |

Next to the class, each endpoint shows what technology answers on it (for
example nginx, Tomcat, MSSQL, an F5). **That is a guess with evidence**, not a
fact: the evidence hover lists each signal (a Server header, a banner, a
certificate field, a handshake detail), where it came from and how much it
counted, so you can judge it. Fast and targeted scans only use signals from
connections they already make; the active probes run only in full and deep scans.
A low-confidence guess never produces an install recommendation.

<!-- screenshot to add: the evidence hover on a Discovery row (capture from the W34-20 corpus hub). -->

