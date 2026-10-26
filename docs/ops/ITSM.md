# ITSM connections: operator runbook (W32-10, W38-09)

An ITSM connection turns hub events (`renewal_failed`, `approval_pending`,
`expiry_no_owner`) into tickets in your ticket system, exactly once per event,
and closes the ticket when the certificate is replaced and verified. Three kinds
of connection exist:

| Kind | Ticket system | Built as | Approval sync |
|---|---|---|---|
| `servicenow` | ServiceNow | native | yes |
| `jira` | Jira Cloud | native | yes |
| `plugin` | Zendesk, Freshservice, or any signed ticket plugin | WASM plugin (D-320, D-326) | **no** |

ServiceNow and Jira stay native in 1.1. A `plugin` connection names a ticket
plugin and a credential; everything else is the same code as the native kinds.

## What is shared, whatever the kind

All of this is native hub code in `internal/notifications/itsm` and does not
change for plugin connections:

- **Dedupe.** One event id leaves one row; submitting it again changes nothing.
- **Durable queue and retries.** Events are stored, then drained every minute; a
  temporary failure (5xx, 429, timeout) backs off 5 minutes doubling to 6 hours
  and an `itsm_unreachable` alert is raised once per outage; a permanent
  failure (a refused credential, a rejected payload) marks the event `failed`.
- **Reconcile.** Hourly, each created ticket is checked. A ticket deleted behind
  the hub's back is recreated once and flagged; deleted again, it is reported
  (audit and alert) and left alone.
- **Resolve.** A verified renewal closes the tickets of the replaced
  certificate with a comment.
- **Audit.** `itsm.ticket.create` and `itsm.ticket.resolve` rows for every
  outcome, written by the hub, never by a plugin.

## Plugin connections

### 1. Install and enable a ticket plugin

```bash
make plugins          # dist/plugins/<name>/plugin.wasm + pinned manifest.json
curl -X POST "$HUB/api/v1/delivery-plugins" -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/json' \
  -d "{\"manifest\": $(cat dist/plugins/zendesk/manifest.json), \"wasm_base64\": \"$(base64 < dist/plugins/zendesk/plugin.wasm)\"}"
```

First-party ticket plugins:

| Plugin id | Ticket system | Credential fields (`*` = secret) |
|---|---|---|
| `kryptkeeper.zendesk` | Zendesk Support | `base_url` (`https://<subdomain>.zendesk.com`), `email`, `api_token`* |
| `kryptkeeper.freshservice` | Freshservice | `base_url` (`https://<domain>.freshservice.com`), `api_key`*, `requester_email`, `workspace_id` (optional) |

A ticket plugin declares no key access. Its only capability is network access to
the host in its credential's `base_url`, which is **High**, so enabling it waits
in Approvals for a second pki-admin ("This plugin connects to the device address
you configure, so it has network access."). Nothing else is granted: no other
host, no private keys, no files.

### 2. Create the credential

An `api_token` credential whose payload is a JSON object of the plugin's
credential fields. The service address lives here, not on the connection:

```bash
curl -X POST "$HUB/api/v1/credentials" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"name": "zendesk-prod", "credential_type": "api_token",
       "payload": {"base_url": "https://acme.zendesk.com", "email": "ops@acme.example", "api_token": "<token>"}}'
```

Secret fields are never returned by the API and are redacted from anything the
plugin says.

### 3. Create the connection

```bash
curl -X POST "$HUB/api/v1/itsm/connections" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"kind": "plugin", "name": "Zendesk", "plugin_id": "kryptkeeper.zendesk",
       "credential_ref": "<credential id>",
       "event_classes": [{"class": "renewal_failed", "ticket_type": "incident"}]}'
```

The ITSM page offers the same through **Ticket plugin** in the kind list: it lists
the enabled ticket plugins and shows the credential fields each one asks for.

The hub checks at create time that the plugin exists, is enabled and is a ticket
plugin, and that the credential is visible to you and is an `api_token`. `base_url`
must be left empty. `ticket_type` is free text the plugin interprets
(Zendesk: `problem`, `incident`, `question` or `task`; Freshservice: `Incident` or
`Service Request`; anything else, or empty, means the plugin default).

**Test connection** (`POST /api/v1/itsm/connections/{id}/test`) runs a read-only
`ticket.exists` for a ticket id no ticket has. "No such ticket" proves the
service is reachable and the credential works; nothing is created.

### What the plugins send

- **Zendesk.** Create: `POST /api/v2/tickets.json` with `subject`, `comment.body`,
  `priority` (critical urgent, high high, low low, otherwise normal), `external_id`
  (the event id), `type` when valid and the tag `kryptkeeper`; a 201 returns the
  ticket id. Exists: `GET /api/v2/tickets/{id}.json`; a 404 or a status of
  `deleted` means gone. Resolve: `PUT` with `status: solved` and an **internal**
  (non-public) comment, so the requester is not emailed by the hub. Auth is
  API-token basic auth, username `{email}/token`. Sources:
  https://developer.zendesk.com/api-reference/ticketing/tickets/tickets/ and
  https://developer.zendesk.com/api-reference/introduction/security-and-auth/ .
  Zendesk marks API-token auth as deprecated in favour of OAuth; OAuth is not
  supported by this plugin.
- **Freshservice.** Create: `POST /api/v2/tickets` with `subject`, an HTML
  `description` (every value escaped), the credential's `requester_email`,
  `priority` (1 low to 4 urgent), `status` 2 (open), the tag `kryptkeeper`, and
  `workspace_id` when set; a 201 returns the ticket id. Exists: `GET
  /api/v2/tickets/{id}`; a 404 or `deleted: true` means gone. Resolve: `PUT` with
  `status: 4` (Resolved), then a **private** note. Auth is basic auth with the API
  key as username and the password `X`. Source: https://api.freshservice.com/#tickets .
- A 429 `Retry-After` is read by the plugin and reported; the ITSM queue's own
  backoff decides the next attempt.

## Limits, said plainly

- **Approvals are native-only in 1.1 (D-326).** A plugin connection cannot carry
  the `approval_pending` class (the API refuses it) and the approval bridge never
  polls it. Approve through ServiceNow or Jira connections, or in the hub.
- **No find before create.** Native connectors look a ticket up by event id
  before creating it, so a ticket made just before a hub crash that lost the row
  update is adopted instead of duplicated. The ticket ABI has no find op in 1.1,
  so that rare crash window can leave one duplicate ticket. Zendesk keeps the
  event id in `external_id` so a person can find it.
- A plugin that errors, traps or times out is retried like an outage; it never
  drops a ticket. A permanent refusal reported by the plugin marks the event
  failed.
- Only the host in the credential's `base_url` is reachable, over https, under
  the hub's egress policy. A redirect off that host is refused.
- Proven against local stand-in services only
  ([LIVE_RESULTS_TICKET_PLUGINS_v1.1.md](../release/LIVE_RESULTS_TICKET_PLUGINS_v1.1.md));
  a real Zendesk or Freshservice account is on the ROADMAP's partner-hardware
  list.
- `KRYPTKEEPER_DELIVERY_PLUGINS=off` also stops ticket plugins; their events stay
  queued and retried.

## Audit

Beyond the native `itsm.ticket.*` rows, each plugin create, resolve and probe
writes `delivery_plugin.ticket` naming the plugin, its version and SHA-256, the
operation and how many host calls the sandbox refused; a refused host call
writes `delivery_plugin.refused`. The hourly exists check is audited only when it
fails. Creating a connection writes `itsm.connection.create` with the plugin id.
