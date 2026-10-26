# Notification plugins: operator runbook (W38-02, D-321)

A notify plugin sends Kryptkeeper alerts to a service the hub has no built-in
channel for. Three first-party plugins ship in the tree:

| Plugin id | Sends to | Credential fields (`*` = secret) |
|---|---|---|
| `kryptkeeper.microsoft-teams` | a Teams channel, through a Workflows webhook | `webhook_url`* |
| `kryptkeeper.pagerduty` | PagerDuty, Events API v2 | `routing_key`*, `api_base` (default `https://events.pagerduty.com`) |
| `kryptkeeper.opsgenie` | Opsgenie, Alerts API | `api_key`*, `api_base` (default `https://api.opsgenie.com`; EU: `https://api.eu.opsgenie.com`) |

Slack, email, the generic webhook and the built-in PagerDuty channel are
unchanged. A plugin is for a service you want that the built-ins do not cover,
or for Teams, which is plugin-only.

## 1. Install and enable

Build, install and enable like any delivery plugin
([DELIVERY_PLUGINS.md](DELIVERY_PLUGINS.md) sections 1 and 2):

```bash
make plugins          # dist/plugins/<name>/plugin.wasm + pinned manifest.json
curl -X POST "$HUB/api/v1/delivery-plugins" -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/json' \
  -d "{\"manifest\": $(cat dist/plugins/pagerduty/manifest.json), \"wasm_base64\": \"$(base64 < dist/plugins/pagerduty/plugin.wasm)\"}"
```

The plugin list shows each plugin's **kind** ("Notification plugin"). A notify
plugin declares no key access; its only capability is network access to the host
named by its credential, which is **High**, so enabling it waits in Approvals for
a second pki-admin. The capability sentence the approver sees is "This plugin
connects to the device address you configure, so it has network access."

## 2. Create the credential

An `api_token` credential whose payload is a JSON object of the plugin's
credential fields:

```bash
curl -X POST "$HUB/api/v1/credentials" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"name": "oncall-pagerduty", "credential_type": "api_token",
       "payload": {"routing_key": "<32-character integration key>"}}'
```

Only the fields the plugin's schema names reach it, and secret fields are never
returned by the API.

## 3. Route alerts with a rule

A notification rule picks the plugin with channel `plugin` and target
`<plugin_id>/<credential_id>`:

```bash
curl -X POST "$HUB/api/v1/notifications/rules" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"name": "Expiring: page on-call", "threshold_days": 7, "channel": "plugin",
       "target": "kryptkeeper.pagerduty/<credential id>"}'
```

The hub checks the target when the rule is created or edited: the plugin must
exist, be enabled and be a notify plugin, and the credential must be visible to
you and be an `api_token`. Test it first with
`POST /api/v1/notifications/test-delivery` using the same channel and target.
The Alerts page form for plugin channels is not built yet (ROADMAP); use the API.

Needs `APP_NOTIFICATION_PROVIDER=delivery`, like every sending channel.

## What each plugin sends

- **Teams** posts an Adaptive Card (version 1.2) in the Workflows envelope
  `{"type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive","contentUrl":null,"content":{...}}]}`
  to the flow's URL. Office 365 Connector webhooks are retired; this is the
  format for the Power Automate trigger "When a Teams webhook request is
  received". Create the flow from a Teams channel's Workflows, copy its URL
  into `webhook_url`, and set who may trigger it to **Anyone** (the hub sends no
  token) or a tenant policy you handle outside the hub. The card has the title
  (red for critical and high, amber for medium), the body, the fields as a fact
  list and an "Open in Kryptkeeper" button. Teams has no alert identity, so a
  `.resolved` event is posted as one more card. Source:
  https://learn.microsoft.com/en-us/connectors/teams/ (TeamsIncomingWebhookTrigger).
- **PagerDuty** posts to `/v2/enqueue`: `event_action` `trigger` with
  `payload{summary, source: kryptkeeper, severity, custom_details}` and the
  event id as `dedup_key`; a `.resolved` event sends `resolve` with the same
  key. Severity maps critical to critical, high to error, medium to warning, low
  to info. `summary` is cut to 1024 characters and a `dedup_key` over 255 is
  replaced by a stable hash. A 202 is delivered; 400 is a failure PagerDuty
  does not want retried; 429 and 5xx are failures. Source:
  https://docs.pagerduty.com/developer/send-alert-event and
  https://docs.pagerduty.com/developer/events-api-v2-overview.
- **Opsgenie** posts to `/v2/alerts` with `Authorization: GenieKey <key>`:
  `message` (130 characters), `alias` (the event id), `description`,
  `priority` (critical P1, high P2, medium P3, low P4) and `details`; a
  `.resolved` event posts to `/v2/alerts/{alias}/close?identifierType=alias`.
  Opsgenie accepts with 202 and processes asynchronously, so a 202 means
  "accepted", not "created". Source: https://docs.opsgenie.com/docs/alert-api.
  Atlassian has announced the retirement of Opsgenie; confirm its current dates
  before building an on-call process on it.

## When a send fails

A plugin failure is an ordinary channel failure: the delivery worker's existing
attempts apply, the delivery shows `failed` with the plugin's reason (status and
a short cause, never the response body, the credential or the webhook URL), and
the escalation channel, if set, is alerted. The service's `Retry-After` is
passed back by the plugin as `retry_after_seconds` and is not acted on yet:
backoff and owner-team routing are W38-03.

## Audit

Every send writes `delivery_plugin.notify` naming the plugin, its version and
SHA-256, the event id, whether it was delivered and how many host calls the
sandbox refused. A refused host call writes `delivery_plugin.refused`.
Installing, enabling, approving, disabling and removing a plugin are audited as
for delivery plugins, with the plugin's kind in the detail.

## Limits and honesty

- The only network a plugin has is the host in its credential, over https, with
  the hub's TLS trust and egress policy. A redirect off that host is refused.
- Proven against local stand-in receivers only
  ([LIVE_RESULTS_NOTIFY_PLUGINS_v1.1.md](../release/LIVE_RESULTS_NOTIFY_PLUGINS_v1.1.md));
  a real Teams flow, PagerDuty service and Opsgenie team are on the ROADMAP's
  partner-hardware list.
- The hub kill switch `KRYPTKEEPER_DELIVERY_PLUGINS=off` also stops notify
  plugins; a `plugin` rule then fails closed.
