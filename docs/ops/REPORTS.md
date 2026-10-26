# Scheduled reports

A schedule emails one report, in one format, to up to 20 recipients on a
cadence. Requires SMTP (the same mail settings as evidence packs).

## What can be scheduled

`GET /api/v1/reports/schedules/catalog` is the source of truth; the Settings
page reads it too.

| Report | Formats |
|---|---|
| `executive-summary` | pdf |
| `estate` | csv, xlsx, pdf |
| `inventory`, `findings`, `crypto-posture`, `expiry-timeline`, `ca-health`, `algorithm-sunset` | csv, xlsx |

Each sheet is built by the same compute function as the report's HTTP
endpoint, so an emailed file and the on-screen report agree. XLSX is written
by the hub itself (no spreadsheet library). Other API reports are not
schedulable yet (see ROADMAP, "Schedule the remaining reports").

## Managing schedules

- UI: Settings, Report Delivery (add, list, delete).
- API: `POST/GET /api/v1/reports/schedules`, `DELETE /api/v1/reports/schedules/{id}`.
  Cadence is `daily`, `weekly` or `monthly` (30 days). Audited as
  `report.schedule_create` and `report.schedule_delete`.
- Schedules render fleet-wide data, so tenant-scoped principals get 403 and
  never see another tenant's schedule.

## Delivery and failure

The scheduler polls every `REPORT_POLL_HOURS` (default 6) and, on one replica
at a time (HA lease), sends what is due. A failed send is retried 3 times
(30 s apart); after the third failure the `report.delivery_failed` alert
event and an audit row are raised (recipient addresses are masked) and the
schedule stays unsent so the next poll tries again. A render failure raises
the same event without retries.

## Executive summary key readiness

The PDF prints `Keys ready / not ready / unknown for PQC migration` using the
key inventory counts the PQC posture page shows (`key_pqc` in the JSON). It
is omitted for tenant-scoped callers because keys are hub-wide.
