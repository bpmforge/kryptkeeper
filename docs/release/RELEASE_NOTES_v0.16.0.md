# Kryptkeeper v0.16.0

This release is compliance reporting for auditors and GRC teams: a published
risk-score formula, crypto posture history with a compare-two-dates view,
scheduled report delivery, FedRAMP Moderate control mappings, a control-to-artifact
index and key-custody section in every evidence pack, manual attestations, a
validated CBOM, and key-custody entries. It is feature group W28 of the v1.0
release train. Boards, specs and decisions: `docs/board/plan.json` (W28-01..21),
D-140 and D-141.

## Upgrade notes (read first)

- **Migrations 000220 and 000221 run on upgrade** (postgres and sqlite):
  `report_schedules` and `compliance_attestations`.
- **Evidence-pack mail now retries.** A failing mailer is tried 3 times per due
  schedule, `EVIDENCE_RETRY_DELAY_SECONDS` apart (default 30). After the third
  failure the hub raises `evidence.delivery_failed` (audit row plus log line) and
  leaves the schedule due, so the next poll retries (D-140). The event detail
  carries schedule id, framework, attempts and error, never recipients or SMTP
  credentials.
- **Posture snapshot retention has a hard floor of 400 days.** The
  `POSTURE_RETENTION_DAYS` setting cannot be lowered below it, and pruning is
  audited. A missed snapshot raises an event.
- **CSV exports escape formula-injection prefixes.** The 12-column US-015 set is
  unchanged and numeric columns are not altered.
- No new required environment variables.
- Posture trend remains super-admin only (D-102).

## New

- **Risk score formula published** (`docs/guides/RISK_SCORING.md`), with a test
  that fails if the doc table and the code weights differ (W28-01). A seeded
  corpus test covers weak-crypto flags (W28-02).
- **Crypto posture page:** score tooltip, 30/90/365 day range picker and a
  compare-two-dates view (W28-03). Trend section in the executive summary JSON and
  board PDF (W28-05).
- **Posture snapshots:** retention floor, audited prune, missed-snapshot event and
  a two-replica lease test (W28-04).
- **Scheduled report delivery:** any report as CSV, XLSX or PDF on a schedule, with
  retry and a failure event; routes `/reports/schedules` (migration 000220,
  W28-06). The board still shows W28-06 as `todo`, but the code is merged
  (`d82cb10e`, merge `15c57bb0`); treat the board status as stale.
- **Export hardening:** CSV formula-injection escaping and a 50,000-row export
  performance test (W28-07); XLSX opened in headless LibreOffice in the nightly
  gate (W28-08).
- **Evidence packs:** FedRAMP Moderate certificate and key control mappings,
  labelled as mapping only, not an assessor claim (W28-09); a control-to-artifact
  index in every pack, including key-custody and CBOM sections, with
  tenant-scoped packs listing no foreign artifacts (W28-10); manual-attestation
  controls with a named attester and date (W28-11, migration 000221).
- **CBOM:** CycloneDX 1.6 schema validation, count reconciliation and a 10,000
  certificate streaming test (W28-14); download from the compliance evidence page
  (W28-15).
- **Key custody:** entries show requester, approver and redeemer, scoped to the
  tenant, with tombstones for deleted keys (W28-16); the page filters by key
  (W28-17).
- **Drill-through links** from CA health, issuance velocity, revocation activity
  and change audit to the matching filtered lists; the audit page seeds its
  filters from the URL (W28-21, D-141).
- **Verification:** smoke asserts for `/reports/*`, `/cbom` and per-framework
  evidence PDFs (W28-12); a Playwright journey over the six posture and operations
  pages (W28-18); search p95 under 1 s on 10,000 certificates with sampled
  `search.query` audit (W28-19).

## Decisions

D-140 (evidence mail retry and `evidence.delivery_failed`), D-141 (drill-through
and URL-seeded audit filters). Rows D-142 to D-149 do not exist in
`docs/DECISIONS.md`.

## Pending human runs

- **W28-13 is `in_progress`: the auditor dry run has not happened.**
  `docs/release/EVIDENCE_PACK_DRYRUN_v0.16.md` is `PENDING-RUN`. Only section 6
  (the automated mail run on 2026-10-16: delivery with PDF attached, no duplicate,
  3 failed attempts, `evidence.delivery_failed` row, recovery delivery) was filled
  in. The reviewer, organisation, the pci, nist, dora, nis2 and fedramp packs, the
  checklist and the verdict need a named external auditor or internal GRC lead.
  No auditor acceptance is claimed.

## Known gaps

- FedRAMP and other framework mappings are mappings, not an attestation or
  assessment.
- Imported keys have no creation event in key-custody history.
