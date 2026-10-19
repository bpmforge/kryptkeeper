# Kryptkeeper v0.18.0

This release is SRE and operations: percent-of-lifetime expiry thresholds,
owner-team notification routing, reloadable channels, SLO error budgets and burn
rates, anomaly findings with propose-only remediation, natural-language policy
drafting, structured JSON logging, health and metrics endpoints for every
process, live operation events over SSE, and 100k-certificate performance fixes.
It is feature group W30 of the v1.0 release train. 22 of 27 tickets are `done`;
5 are `in_progress` waiting on runs described below. Decisions: D-160 to D-171.

## Upgrade notes (read first)

- **Migrations 000260 and 000261 run on upgrade:** `notification_rule_options`
  (per-rule percent threshold and template override) and
  `notification_team_routes` (owner-team routing).
- **Logs are now structured JSON (slog).** All 893 `log.Printf` call lines across
  194 files were migrated; the std `log` package is banned outside tests by a
  lint rule. Secrets are redacted in the handler (covers nested attributes and
  message text); probes log at Debug and 5xx at Error (D-162). Update any log
  parser that expects the old plain-text lines.
- **Expiry thresholds default to percent of lifetime**, because fixed
  7/14/30/60/90 days breaks 47-day certificates; absolute days remain an option.
  A threshold fires once per crossing per fingerprint, and a template-scoped rule
  overrides all global rules for that certificate (D-167). Requests return 503
  when the options store is down rather than silently dropping the setting.
- **`/metrics` can require a bearer token:** set the Secret config key
  `metrics.bearer_token`. It is compared in constant time and never logged.
  `/healthz` and `/readyz` stay unauthenticated. Satellite processes expose an
  ops listener via `KRYPTKEEPER_OPS_ADDR` (D-161).
- **Notification fan-out reports undelivered.** `FanOutChannel.Send` returns
  `ErrNoConfiguredChannel` when no member is configured, so CT findings are no
  longer marked notified when nothing was delivered (D-169). SLO, anomaly and CT
  alerts now go to all configured channels, not only the first.
- **`notifications.escalation_target` is a Secret config key** (D-168); GET
  /config shows only `configured`.
- **SLO samples are in memory.** After a restart, pre-existing failures do not
  page until new ones arrive; the first tick is the baseline (D-166).
- **SSE:** a principal may hold 5 streams; the 6th gets 429 and
  `events.stream.reject` is audited (D-163).
- Scale tests are nightly-only (`KRYPTKEEPER_SCALE_TESTS=1`, D-180) rather than
  on PR CI.

## New

- **Alerting:** configurable thresholds (percent or days, EXPIRED, template
  override) (W30-01); routing by `owner_team` with a global inbox and an
  in-dashboard queue fallback (W30-02); channel config that reloads at runtime
  with a persisted webhook target (W30-03); Alerts and Integrations UI for all of
  this (W30-18).
- **SLO:** error budgets and 1 h / 6 h burn rates with Grafana panels (W30-05);
  operator-tunable objectives in the config store, keys `slo.*` (W30-06); an SLO
  dashboard page covering issuance latency, renewal success, expiry distribution,
  budget and burn (W30-15).
- **Anomalies:** requester persisted on issuance events plus a precision/recall
  harness (W30-07); findings create propose-only remediations in the approval
  queue, five actions, proposer never approver, `mcp-agent` never approver
  (W30-08, D-165); an Anomaly findings page linking to the proposed approvals
  (W30-16).
- **Policy drafting:** `POST /policies/draft`, `POST /policies/draft/submit` and
  an MCP `draft_policy` tool, validated on a 20-phrase corpus; drafts land
  disabled behind a `policy.activate` approval, and the server re-parses on submit
  (W30-09, W30-17, D-164). There is no LLM front end in v1.0.
- **Observability:** slog JSON logging with request-id and tenant fields
  (W30-10, W30-11); health and metrics endpoints for agent, MCP and certmanager
  with a metric catalogue (W30-12).
- **Live operations:** SSE producers for renew, install and migrate with a replay
  ring (256 entries, `Last-Event-ID`) and tenant filtering (W30-13); a UI
  `useOperationEvents` hook replacing scan polling (falls back to polling after 3
  errors) (W30-14).
- **HA:** `ha.failover` audit and a deduped `scheduler.failover` alert plus a
  `backup.stale` sweep; every scheduler in a process shares one replica ID
  (W30-27, D-171).
- **Performance:** the 2 s inventory refresh fetches only changed rows (W30-25,
  W30-26, D-170). At 100k certificates on Postgres: search p99 975 to 115 ms and
  peak RSS 2.49 to 1.70 GiB.
- **Docs:** reference architectures, a data-residency table and the telemetry
  egress list (CT, ACME) (W30-24).

## Decisions

D-160 (human/nightly runs ship as PENDING-RUN), D-161 to D-171 as listed above.

## Pending human runs (board status `in_progress`; not done)

- **W30-19 (UAT):** SSE through nginx, 600 s soak, passed locally; the SLO hub
  half passed (1 page, latched). Real Slack and PagerDuty (`KK_LIVE_REAL=1`) and
  the Prometheus/Grafana half are PENDING-RUN; they need operator-supplied
  webhook and routing key.
- **W30-20 (egress):** zero-default-egress is not proven. The first real capture
  is PENDING-RUN (`bash tests/live/egress/run.sh --short`, then `--ct`); the 25 h
  soak is manual. CT egress needs a 65-minute window (D-160).
- **W30-21 (100k Postgres benchmark):** measured twice after the fixes: search
  p99 112 and 120 ms, list p95 38 and 8 ms, RSS about 1.7 GiB, all passing.
  Issuance rate was 287 and 1206 rps against a bar of 500; the bar is not
  established (high variance). The 1M run is PENDING-RUN and 1M is not claimed.
- **W30-22 (renewal storm):** a 5k scaled storm drained in 1.37 min with 0
  failures (bar 6 min). The full 50k run and the rate-20 run are PENDING-RUN.
- **W30-23 (DR and rolling upgrade):** DR failover was measured live once: RPO 1 s,
  RTO 2 s, pass (targets RPO <= 5 min, RTO <= 15 min). The zero-5xx rolling
  upgrade at 50 rps is PENDING-RUN (no vegeta or kind offline). The drill
  assertion for the failover event is not yet wired live.

## Known gaps

- Resident inventory is about 17 KiB per certificate, which is the 1M scaling
  limit; a lazy-parse redesign is deferred.
