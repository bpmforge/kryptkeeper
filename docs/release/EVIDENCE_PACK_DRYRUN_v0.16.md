# Evidence pack dry run — v0.16

Status: **PENDING-RUN**. Acceptance (W28-13 item 2) is met only when a named external auditor or internal GRC lead replaces every `PENDING-RUN` field below. Section 6 was produced by the automated run; nothing else here is filled in on anyone's behalf.

## 1. Header

| Field | Value |
|---|---|
| Version / commit | PENDING-RUN |
| Date | PENDING-RUN |
| Reviewer name | PENDING-RUN |
| Role (`external auditor` or `internal GRC lead`) | PENDING-RUN |
| Organisation | PENDING-RUN |

## 2. Packs reviewed

Generate each pack from a hub with a realistic estate (`POST /api/v1/reports/evidence/schedules`, or the on-demand evidence-pack download). The SOC 2 row is the pack produced by the automated mail run in section 6.

| Framework | Generated date | File name | Reviewed |
|---|---|---|---|
| pci | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| soc2 | 2026-10-16 | compliance-soc2-2026-10-16.pdf | PENDING-RUN |
| nist | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| dora | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| nis2 | PENDING-RUN | PENDING-RUN | PENDING-RUN |
| fedramp | PENDING-RUN | PENDING-RUN | PENDING-RUN |

## 3. Reviewer checklist

| Check | Result |
|---|---|
| Every control row cites an artifact and its pass/fail rule | PENDING-RUN |
| Key custody section is present | PENDING-RUN |
| CBOM is referenced | PENDING-RUN |
| Manual-attestation controls show attester and date | PENDING-RUN |
| Generated date and organisation name appear on every page | PENDING-RUN |

## 4. Verdict

Verdict (`ACCEPTED` | `ACCEPTED WITH FINDINGS` | `REJECTED`): PENDING-RUN

Findings:

- PENDING-RUN

## 5. Sign-off

| Name | Role | Date | Verdict |
|---|---|---|---|
| PENDING-RUN | PENDING-RUN | PENDING-RUN | PENDING-RUN |

## 6. Automated evidence

Command: `KK_UAT_PACK_OUT=<path> bash tests/live/evidence-mail/run.sh` (all steps passed on 2026-10-16: delivery with PDF attached, no duplicate, 3 failed attempts, `evidence.delivery_failed` audit row, recovery delivery).

| Field | Value |
|---|---|
| Pack file | `compliance-soc2-2026-10-16.pdf` (2469 bytes) |
| Framework | soc2 |
| Generated | 2026-10-16 |
| sha256 | `07612cfe4b324057e438e4cfb859f198b5775a1490c13989e796df6b9c282b08` |
| Path (local run artifact, not committed) | `<scratch>` |

The pack comes from a 5-certificate fixture estate, so it demonstrates structure, not a real estate; regenerate from a real hub before review.
