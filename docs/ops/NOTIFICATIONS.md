# Notifications: routing, retries and failed-renewal tickets

Operator notes for the delivery engine (`APP_NOTIFICATION_PROVIDER=delivery`).
Decision: D-322.

## Who gets an expiry alert

A rule whose target is `@owner_team` ("Owner team routing" in the Alerts page)
sends each certificate's alert to routes chosen by the certificate's owner
team. Manage routes under Alerts, "Alert rules" tab, or
`/api/v1/notifications/team-routes`.

| Certificate | Routes tried, first match wins |
|---|---|
| Has an owner team | that team's routes on the rule's channel, then the global inbox (`owner_team` `*`) |
| No owner team | the ownerless queue (`owner_team` `!ownerless`), then the global inbox |
| Nothing matches | queued on the dashboard (delivery log channel `dashboard`); nothing is sent |

Levels never combine: a team match suppresses the global inbox, and the
ownerless queue never receives an owned certificate. Routes are tenant-scoped.

Alerts, "Alert rules" tab, shows "Ownerless expiring certificates": active
certificates with no owner team expiring within 30 days (expired ones
included). The same list is `GET /api/v1/notifications/ownerless?within_days=&limit=`.
Give those certificates an owner, or point the ownerless queue at the team
that triages them.

## Retries

Every send, on any channel (email, Slack, PagerDuty, webhook, ITSM and plugin
channels), goes through one retrier:

- Up to 8 attempts. The delay before attempt n+1 is 1 min x 2^(n-1), capped at
  1 h, with +/-20% jitter (about 2 h in total).
- If the receiver answers 429 or 503 with `Retry-After`, the next attempt waits
  at least that long, never more than the 1 h cap.
- The next attempt time is stored in `notification_delivery_queue`
  (migration 000381). After a restart the hub continues from there; an attempt
  that was in flight when the process died is retried after a 2 minute lease.
  Without a core database the state is in memory only.
- After the last attempt the delivery is marked `failed`, one
  `notification.delivery.settled` audit row is written (outcome failure, no
  target in the detail), and one alert goes to the escalation channel
  (`notifications.escalation_*` config) if it differs from the failing channel.
  A delivery that succeeds on a later attempt also writes one settled row
  (outcome success).
- The delivery log shows `retrying` between attempts. Receivers see the same
  `X-Kryptkeeper-Event-Id` on every attempt: dedupe on it.

Tuning (rarely needed): `KRYPTKEEPER_NOTIFY_RETRY_ATTEMPTS` (1-50),
`KRYPTKEEPER_NOTIFY_RETRY_BASE`, `KRYPTKEEPER_NOTIFY_RETRY_CAP` (Go durations,
for example `30s`). A malformed value is ignored with a warning.

The queue row holds the event, including its target, so that it can be
resent; a webhook URL that carries a token is stored in clear in that row for
as long as the delivery is pending, and settled rows are deleted after 14 days.
The same URL already sits in the notification rule or configuration that
produced the event.

## Failed renewals and tickets

When a renewal fails for good, one `renewal_failed` ITSM ticket is opened per
certificate:

- the scheduler, after its install attempts are exhausted;
- `POST /api/v1/renewal/execute`, when the executor fails (a 503
  "renewal execution failed"). Caller errors (bad request, unknown certificate,
  approval pending, rate limited) do not open a ticket. Repeated manual
  failures of one certificate share one ticket.

A later verified renewal, scheduled or manual, closes the ticket by
fingerprint. Both need an enabled ITSM notification rule.
