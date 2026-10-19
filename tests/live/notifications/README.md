# W19-07: notifications and SIEM UAT against real receivers

Proves notification/SIEM delivery reaches real external systems, not
httptest doubles: a Mailpit container (real SMTP inbox), a local Python
HTTP receiver standing in for a generic webhook / Slack incoming webhook /
SIEM ingest endpoint, and the hub's own real delivery worker
(`internal/notifications/delivery`) and SIEM router (`internal/bootstrap/siem_integration.go`).

## Run

```
bash tests/live/notifications/run.sh
```

No env switch is required (unlike some other `tests/live/*` fixtures) — it
builds and runs its own hub instance on an isolated port (8099) and its own
temp data dir, and cleans everything up on exit via a trap. Idempotent:
re-running removes any previous Mailpit container and hub process first.

Set `KK_UAT_KEEP=1` to keep the hub log, echo receiver's JSONL log, and temp
data dir after a run for debugging (containers/processes are still stopped).

## What it proves, and how

1. **SMTP** — `POST /api/v1/notifications/test-delivery` (channel `email`)
   and the real renewal-scheduler expiry sweep (see step 4) both deliver a
   real RFC 5322 message via `net/smtp` to a Mailpit container; asserted via
   Mailpit's own HTTP API (`GET /api/v1/messages`, `GET /api/v1/message/{id}`).
2. **Webhook** — same endpoint, channel `webhook`, POSTs JSON to a local
   Python HTTP receiver (`echo_receiver.py`); asserted by reading that
   receiver's append-only JSONL log directly (see "Why a Python receiver"
   below).
3. **Slack** — same endpoint, channel `slack`; asserted Slack-shaped (a
   `text` key) against the local receiver. Real-workspace delivery is the
   opt-in W30-19 section below (see "Live results (real endpoints)").
4. **SIEM** — `POST /api/v1/integrations/siem/test` delivers a JSON
   `SIEMEvent` to the same receiver with a Splunk-style `Authorization:
   Splunk <token>` header; asserted for `event_type`, `resource_type`,
   `resource_id`, and the auth header.
5. **The real trigger, not just the manual button** — the fixture also
   issues a certificate with a 48h validity template, sets ownership to a
   throwaway address, and restarts the hub so `RenewalScheduler.Start()`'s
   immediate on-startup scan (`runScan`) finds it and calls
   `notifProvider.TestDelivery` through the exact same delivery engine — the
   daily expiry sweep a pilot partner actually depends on, not only the
   `/notifications/test-delivery` button.
6. **PagerDuty** — W19-27 added `KRYPTKEEPER_PAGERDUTY_EVENTS_URL`, which
   this fixture points at the local receiver to assert the Events API v2
   payload shape. With it unset the hub dials the real
   `https://events.pagerduty.com/v2/enqueue`; that is what the W30-19
   real-endpoint section does.

## Known hub defect found here — filed as W19-18, not fixed on this branch

`cmd/kryptkeeper/main.go`'s `deliveryChannelsFromEnv` hardcodes the SMTP
port to `587` and never reads `notifications.smtp_port` /
`notifications.smtp_username` / `notifications.smtp_password`, even though
`config_store.go` has registered all three as configurable settings since
W8-13. In delivery mode the hub can therefore never reach an SMTP host on a
non-587 port, or one that requires auth. `cmd/kryptkeeper/main.go` is no
longer in this ticket's `write_scope` (see `docs/board/plan.json` W19-07,
after `docs(board) 6a46886`), so the fix is filed as ticket **W19-18**
instead of landing here. This fixture works around the defect by publishing
Mailpit's SMTP listener on the host's port 587 in addition to 1025.
**Update (W32-09):** the hub now honours `SMTP_PORT`, so the fixture
publishes Mailpit on high host ports only (SMTP `11025`, HTTP `18025`,
overridable via `KKW32_MAILPIT_SMTP_PORT` / `KKW32_MAILPIT_HTTP_PORT`);
rootless podman cannot bind 587. The container is named `kkw32-notif-mailpit`.

## Why a Python receiver instead of a container for webhook/Slack/SIEM

The fixture originally used `docker.io/mendhak/http-https-echo`. Its Node
process block-buffers stdout when not attached to a TTY, so `podman logs`
(used to verify delivery) lagged the real HTTP response by several
requests — caught live: a webhook POST that got a 200 immediately had its
logged body surface only once *later* Slack/SIEM requests pushed enough
output to flush the buffer, which read as "never delivered" when it had
been. `echo_receiver.py` (a small stdlib-only `http.server` script,
explicitly one of the two receiver options this ticket's notes allow) fsyncs
one JSON line per request, so the fixture's poll loops never race a buffer.
It is still a real, separate HTTP server process the hub dials over the
network — not an in-process httptest double — so it satisfies the same
"real receiver" bar Mailpit does.

## Environment-specific flake observed and mitigated

During development, the very first request to the just-started Python
receiver occasionally stalled for up to ~20s (a plain `curl` reproduced it
with no hub involved) before the receiver started responding instantly and
reliably for the rest of the run. `wait_echo_warm()` polls with a short
per-request timeout until one probe returns in under 0.5s before the
webhook/Slack/SIEM checks fire, absorbing this without weakening any
assertion.

## Real endpoints (W30-19, opt-in, operator-run)

Proves one message reaches a real Slack workspace and one incident is
created in a real PagerDuty sandbox service. Without `KK_LIVE_REAL=1` the
section prints `SKIP [real] ...` and has no effect on the exit code.

The operator exports the credentials in their own shell. The script only
tests them with `[ -n ... ]`, never echoes or logs them, never writes them to
a file, and hands them to a second hub instance (port 8100, own data dir) as
environment (not argv). `KRYPTKEEPER_PAGERDUTY_EVENTS_URL` is unset for that
hub so it dials the real Events API.

```
export KK_LIVE_REAL=1
export KK_LIVE_SLACK_WEBHOOK_URL='<Slack incoming-webhook URL for a sandbox channel>'
export KK_LIVE_PD_ROUTING_KEY='<Events API v2 integration key of a sandbox PagerDuty service>'
bash tests/live/notifications/run.sh
```

The script POSTs `/api/v1/notifications/test-delivery` once for `slack` and
once for `pagerduty` (message `kk-live-<epoch>`), requires `status":"queued"`,
then polls `GET /api/v1/notifications/deliveries` for up to 60 s until that
delivery id reports `sent` (the engine's success status; the original spec
text said "delivered"). PASS lines print channel and delivery id only.

Operator steps afterwards: confirm the Slack message and the PagerDuty
incident are visible, then **resolve the PagerDuty incident yourself** (the
script never sends `resolve`), and add a row below.

### Live results (real endpoints)

Status: **PENDING-RUN** (no real Slack/PagerDuty credentials were available
to the implementing agent; nothing below has been run against real services).

| Date | Channel | Delivery id | Result | Operator confirmed |
|---|---|---|---|---|
| _pending_ | slack | | | |
| _pending_ | pagerduty | | | |

## W32-09 additions

The hub's webhook/Slack/PagerDuty egress guard refuses loopback (and
production never reopens it), so `echo_receiver.py` now binds a private
(RFC1918) address of the host (`ECHO_HOST`, auto-detected; override with
`ECHO_HOST=<ip>`). Without a private interface the HTTP legs FAIL, loudly.

New receiver flags (backward compatible): `--bind <ip>`, `--fail-path <path>`
(answers 500, still records).

| Section | What it proves | Result |
|---|---|---|
| `[webhook-signed]` | `verify_webhook.py` (same algorithm as `docs/ops/WEBHOOK_VERIFY.md`) accepts the real signed delivery, carries `x-kryptkeeper-event-id`, and rejects BOTH tamper cases: signature removed, and a validly-signed timestamp of now-360s (2 of 2) | PASS |
| `[webhook-failing]` | `webhook_url` -> always-500 receiver (set via `PUT /api/v1/config/notifications.webhook_url`); delivery log shows `failed` in <60 s; receiver saw exactly 3 attempts | PASS (current contract) |
| `[cef]` | hub restarted with `SIEM_FORMAT=cef`; `POST /integrations/siem/test`; delivered lines pass the strict `cef_parse.py` with 0 errors | PASS |
| `[teams]` | no Teams channel exists | SKIP (needs prerequisite ticket) |
| `[owner_team]` | no `owner_team` routing / ownerless internal queue exists | SKIP (needs prerequisite ticket) |

Known contract gap, reported not faked: the board acceptance says delivery
"stops after 8 retries"; the product today makes 3 attempts with a linear
`5s * n` delay (`delivery.Worker`, `cmd/kryptkeeper/main.go`). The test asserts
the current contract and prints the discrepancy; 8 attempts / exponential
backoff needs a product ticket.

Slack and PagerDuty remain payload-shape checks against the stand-in receiver;
no real Slack workspace or PagerDuty account was used.
