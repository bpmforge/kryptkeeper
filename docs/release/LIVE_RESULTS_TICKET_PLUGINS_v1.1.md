# Live results v1.1: ticket plugins (Zendesk, Freshservice), W38-09

Date: 2026-10-25. Base: `04cd67d7` (feat/v1.1-integrations) plus the W38-09 change on branch
`worktree-agent-a0dda3fb9c615cfeb`. Evidence is repeatable with the commands below.

## Verdict: PASS against local stand-in services; no real Zendesk account or Freshservice domain was used

## What ran

The real wasm of each first-party plugin (Zendesk 4.9 MB, Freshservice 5.1 MB,
built with `GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared`) was installed
into a hub plugin manager on a freshly migrated SQLite database (migration 000387
applied), enabled, and driven through the hub's own ITSM path: an ITSM connection of
kind `plugin`, `itsm.Service` (Submit, Drain, Reconcile, ResolveByFingerprint,
TestConnection) over the real `itsm.Store`, the plugin connector built by
`itsm.NewConnectorSource`, the wazero sandbox with its host-call enforcement,
the credential resolved per call from the credential store, and the audit sinks.
Each plugin spoke https, with TLS verified against the stand-in's certificate, to a
local service that keeps tickets in memory, answers the vendor's documented status
codes, and lets the test delete a ticket behind the hub's back. This is the hub's
code in one process, not a hub container.

```bash
go test ./internal/bootstrap/ -run 'TicketPluginsRunThroughTheITSMService|ITSMPluginConnectionRefusals|ITSMHandlers_PluginKind' -count=1 -v
go test ./tests/plugins/conformance/ -run 'Zendesk|Freshservice|TicketKind' -count=1 -v
```

## Results

| Step | Zendesk | Freshservice |
|---|---|---|
| Test connection: read-only `ticket.exists` for key `0`, "no such ticket" is OK | PASS | PASS |
| Create: event submitted, drained, row `created` with a key and an https link; the stand-in holds one open ticket | PASS | PASS |
| Exists: reconcile of a live ticket changes nothing (not recreated) | PASS | PASS |
| Externally deleted: reconcile recreates the ticket once, row flagged `recreated`, new key at the service | PASS | PASS |
| Resolve: `ResolveByFingerprint` closes the recreated ticket (Zendesk `solved`, Freshservice status 4), row `resolved` | PASS | PASS |
| Outage (stand-in answers 500): row stays `pending`, attempts 1, error classed temporary | PASS | PASS |
| Refused credential (401): row `failed`, error classed permanent; test connection returns a permanent error | PASS | PASS |
| Audit: native `itsm.ticket.create` success x2 and `itsm.ticket.resolve` x1; `delivery_plugin.ticket` rows carry kind, version and sha256 | PASS | PASS |
| No credential value (API token, API key) in any row error, alert or audit summary | PASS | PASS |

Conformance (`TicketSuite`, mock services that validate vendor request shape and
auth header): create returns a key and an https link and the service holds the
certificate name; exists is true, then a clean false after an external delete; the
probe key is a clean "no"; a non-numeric key never reaches the service as a path;
resolve closes the ticket and leaves the comment; 500 and 429 (`Retry-After: 7`
arrives as `retry_after_seconds=7`) are temporary, 401 is permanent; an outage in
`exists` is an error, never `false` (the hub would recreate a live ticket);
recovery; no credential or PEM in events, results or errors. All pass for both
plugins (22 subtests).

Hub refusals proven with the real modules: a delivery op on a ticket plugin and a
ticket op on a notify plugin are refused before any instance starts; a notify plugin
is refused as a ticket plugin by the API check and by the connector factory; a
missing credential field fails before the plugin runs, naming the field and no
value; a disabled plugin and a plugins-off hub fail closed; a wrong-typed credential
is refused. The connection API refuses a plugin connection with no plugin id, with a
`base_url`, with an unknown plugin, or carrying `approval_pending`, and refuses
`plugin_id` on a native kind. The plugin connector does not implement the approval
interface, so the approval bridge skips it. Both plugins' capability tier is High, so
enabling needs a second person.

## Vendor behaviour taken from documentation, not observed

Endpoints, bodies and auth were checked against the vendors' documentation (cited in
`plugins/zendesk/main.go`, `plugins/freshservice/main.go` and
[ITSM.md](../ops/ITSM.md)): Zendesk create, show and update with `status: solved`
and API-token basic auth `{email}/token`; Freshservice create (201), view, update
with status 4 (Resolved) and API-key basic auth. Where the documentation left a gap
the plugin handles both readings and says so: Zendesk's page does not state what a
deleted ticket returns, so a 404 and a status of `deleted` both read as gone;
Freshservice documents a `deleted` flag and a 404 for an invalid id, and both read as
gone. The Freshservice "Create a note" page was read for `body` and `private`; the
create-ticket page is inconsistent about `requester_id` versus `email`, so the plugin
sends `email` as the page's examples do.

## Not proven here (ROADMAP, Needs partner hardware)

- A real Zendesk account: API-token auth (Zendesk marks it deprecated), the soft-delete
  response of a deleted ticket, whether every plan accepts the fields sent (priority and type may
  depend on the plan), `external_id`, rate limits.
- A real Freshservice domain: required fields per workspace (some instances require
  more than `requester_email`), `workspace_id` handling, the resolve-then-note
  sequence against a workflow that blocks status changes, rate limits.
- A ticket created just before a hub crash is not adopted on retry (no `ticket.find`
  op); this is a design limit (D-326), not something a run can show.

Tracked on the ROADMAP row "ServiceNow, Jira Cloud, Zendesk and Freshservice
connectors" (W32-18, W38-09).
