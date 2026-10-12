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
   `text` key) since no real Slack workspace is available in this
   environment. Documented explicitly, not implied.
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
6. **PagerDuty** — NOT exercised. `delivery.PagerDutyChannel.Endpoint` is
   only settable in-process (its own doc comment: tests point it at an
   `httptest.Server`); `cmd/kryptkeeper/main.go`'s production wiring never
   sets it, so delivery-mode PagerDuty is permanently pinned to the real
   PagerDuty Events API (`https://events.pagerduty.com/v2/enqueue`) and
   cannot be redirected at this fixture's receiver without a real PagerDuty
   account.

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
Mailpit's SMTP listener on the host's port 587 (`MAILPIT_SMTP_HUB_PORT`, what
the hub actually dials) in addition to 1025, rather than silently
loosening its own expectations to hide the bug.

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
