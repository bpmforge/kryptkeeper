# Live results v1.1: notify plugins (Teams, PagerDuty, Opsgenie), W38-02

Date: 2026-10-25. Base: `e882ae74` plus the W38-01/W38-02 change on branch
`worktree-agent-aa9239c1a3c43198d`. Evidence is repeatable with the commands below.

## Verdict: PASS against local stand-in receivers; no real Teams, PagerDuty or Opsgenie tenant was used

## What ran

The real wasm of each first-party plugin (`bash scripts/build-plugins.sh`: Teams
5.2 MB, Opsgenie 5.3 MB, PagerDuty 5.4 MB) was installed into a hub plugin manager
on a freshly migrated SQLite database, enabled, and driven through the hub's own
path: `PluginNotifyChannel` (the `plugin` delivery channel), the delivery worker
(2 attempts), the wazero sandbox with its host-call enforcement, and the audit
provider. Each plugin talked https, with TLS verified against the stand-in's
certificate, to a local receiver that records the request and answers with a
status the test sets. This is the hub's code in one process, not a hub container;
`tests/live/plugins/run.sh` is the container recipe for delivery plugins and was
not extended for this ticket.

```bash
go test ./internal/bootstrap/ -run 'NotifyPluginsRunInTheHub|PluginChannel|PluginKinds' -count=1 -v
go test ./tests/plugins/conformance/ -run 'Teams|PagerDuty|Opsgenie|Kinds' -count=1 -v
```

## Results

| Check | Teams | PagerDuty | Opsgenie |
|---|---|---|---|
| Delivery worker result `sent`, 1 attempt, stand-in saw exactly one request | PASS | PASS | PASS |
| Request shape: Teams `type:message` + one adaptive-card attachment at the webhook path; PagerDuty `POST /v2/enqueue` `trigger` with `dedup_key` = event id and severity critical; Opsgenie `POST /v2/alerts` with `GenieKey` auth, alias = event id, priority P1 | PASS | PASS | PASS |
| Stand-in answers 500: result `failed`, 2 attempts, error names the plugin | PASS | PASS | PASS |
| Stand-in answers 429: result `failed` | PASS | PASS | PASS |
| Audit: `delivery_plugin.notify` rows with `kind=notify`, version, sha256, both outcomes | PASS | PASS | PASS |
| No credential value (routing key, API key, webhook URL signature) in the failure error or any audit row | PASS | PASS | PASS |

Conformance (`NotifySuite`, mock receivers that validate vendor request shape):
delivers; repeat keeps the same dedupe key (PagerDuty, Opsgenie); `.resolved`
clears the alert (PagerDuty `resolve`, Opsgenie close by alias; Teams posts a
card); 500 is a `NotifyError`; 429 `Retry-After: 7` arrives as
`retry_after_seconds=7`; recovery after failure; no credential or PEM in events,
results or errors. All pass for the three plugins.

Hub refusals proven with the real modules: a delivery op on a notify plugin and a
notify op on a delivery plugin are refused before any instance starts; a delivery
plugin as a rule target is refused ("not a notify plugin"); a notify plugin as a
renewal target is refused; a plugin id cannot change kind between versions; a
`dns01` manifest is refused at install; a disabled plugin and a plugins-off hub
fail closed; a wrong-typed credential is refused.

## Defect found by this run

The first conformance run failed the Teams plugin: the hub's `http` event detail
(which reaches logs) carried the full request URL, and a Teams Workflows webhook
URL holds its signature in the query. The detail is now scheme and host only
(`internal/plugins/delivery/host.go`), for every plugin. The same fix covers the
redirect-refusal message. Delivery plugins lose the request path in that event
detail; nothing consumed it.

## Not proven here (ROADMAP, Needs partner hardware)

- A real Teams Workflows flow: the card renders in a channel, the "Anyone" trigger
  setting, tenant-restricted triggers (the hub sends no bearer token).
- A real PagerDuty service (routing key, de-duplication into one incident, resolve
  closing it) and a real Opsgenie team (alias folding, close by alias, EU instance).
  Opsgenie answers 202 and processes asynchronously; the plugin reports "accepted".
- The vendors' live rate-limit behaviour; PagerDuty does not document a
  `Retry-After` header, so the plugin passes one on only if it is sent.

Tracked on the ROADMAP row "Slack, PagerDuty, Microsoft Teams and Opsgenie alerts"
(W30-19, W38-02).
