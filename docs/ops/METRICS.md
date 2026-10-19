# Metrics, probes and scrape auth

Kryptkeeper exposes Prometheus text-format metrics (v0.0.4) on the hub at
`/metrics` and probes at `/healthz` (liveness) and `/readyz` (readiness). The
agent, MCP server and cert-manager issuer each serve the same three paths on a
small ops listener. The metric names below are checked against the registry by
`TestMetricsDocMatchesRegistry` (`internal/metrics/metrics_doc_test.go`); add a
row here whenever you register a family.

## Metric catalogue

The stdlib registry has no label support except on the SLO gauges. Counters
and histograms carry no labels.

| Name | Type | Help | Source |
|---|---|---|---|
| `kryptkeeper_acme_orders_created_total` | counter | ACME orders created | `internal/metrics/vars.go` |
| `kryptkeeper_acme_orders_finalized_total` | counter | ACME orders successfully finalized | `internal/metrics/vars.go` |
| `kryptkeeper_acme_orders_invalid_total` | counter | ACME orders that transitioned to invalid | `internal/metrics/vars.go` |
| `kryptkeeper_audit_append_failures_total` | counter | Audit entries that could not be appended to the audit store | `internal/metrics/vars.go` |
| `kryptkeeper_ca_sign_duration_seconds` | histogram | Latency of CA signing operations | `internal/metrics/vars.go` |
| `kryptkeeper_cert_expiry_days` | histogram | Distribution of certificate time-to-expiry in days | `internal/metrics/slo.go` |
| `kryptkeeper_cert_issue_duration_seconds` | histogram | Latency of certificate issuance end-to-end | `internal/metrics/vars.go` |
| `kryptkeeper_cert_issue_errors_total` | counter | Certificate issuance failures | `internal/metrics/vars.go` |
| `kryptkeeper_cert_issue_total` | counter | Certificates successfully issued | `internal/metrics/vars.go` |
| `kryptkeeper_cert_renewal_failure_total` | counter | Certificate renewals that failed | `internal/metrics/slo.go` |
| `kryptkeeper_cert_renewal_success_total` | counter | Certificate renewals that completed successfully | `internal/metrics/slo.go` |
| `kryptkeeper_cert_revoke_errors_total` | counter | Certificate revocation failures | `internal/metrics/vars.go` |
| `kryptkeeper_cert_revoke_total` | counter | Certificates successfully revoked | `internal/metrics/vars.go` |
| `kryptkeeper_crl_requests_total` | counter | CRL fetch requests served | `internal/metrics/vars.go` |
| `kryptkeeper_http_request_duration_seconds` | histogram | Latency of HTTP requests served by the hub | `internal/metrics/vars.go` |
| `kryptkeeper_http_requests_total` | counter | HTTP requests served by the hub | `internal/metrics/vars.go` |
| `kryptkeeper_http_responses_4xx_total` | counter | HTTP responses with a 4xx status | `internal/metrics/vars.go` |
| `kryptkeeper_http_responses_5xx_total` | counter | HTTP responses with a 5xx status | `internal/metrics/vars.go` |
| `kryptkeeper_ocsp_requests_error_total` | counter | OCSP requests that returned an error | `internal/metrics/vars.go` |
| `kryptkeeper_ocsp_requests_good_total` | counter | OCSP requests answered: certificate good | `internal/metrics/vars.go` |
| `kryptkeeper_ocsp_requests_revoked_total` | counter | OCSP requests answered: certificate revoked | `internal/metrics/vars.go` |
| `kryptkeeper_ocsp_requests_unknown_total` | counter | OCSP requests answered: certificate unknown | `internal/metrics/vars.go` |
| `kryptkeeper_readyz_failures_total` | counter | Readiness probes that returned 503 | `internal/metrics/vars.go` |
| `kryptkeeper_siem_events_dropped_total` | counter | Audit-derived events dropped because the SIEM forward queue was full | `internal/metrics/vars.go` |
| `kryptkeeper_siem_events_forwarded_total` | counter | Audit-derived events delivered to a SIEM target | `internal/metrics/vars.go` |
| `kryptkeeper_siem_send_failures_total` | counter | SIEM deliveries that failed (per target attempt) | `internal/metrics/vars.go` |
| `kryptkeeper_slo_breaches_total` | counter | SLO breach transitions detected | `internal/metrics/slo.go` |
| `kryptkeeper_slo_burn_rate` | gauge | Error budget burn rate (1.0 = exactly on budget) per window | `internal/metrics/slo.go` |
| `kryptkeeper_slo_error_budget_remaining_ratio` | gauge | Fraction of the 30-day error budget remaining (0..1) | `internal/metrics/slo.go` |
| `kryptkeeper_slo_objective` | gauge | SLO objective as a ratio | `internal/metrics/slo.go` |

## Scrape auth

`/metrics` is open by default. To require a bearer token set the Secret config
key `metrics.bearer_token` (`PUT /api/v1/config/metrics.bearer_token`, admin
only) or, as a bootstrap fallback, the env var
`KRYPTKEEPER_METRICS_BEARER_TOKEN`. The config-store value wins over the env
var.

- With a token set, an unauthenticated or wrong-token `GET /metrics` returns
  `401` with `WWW-Authenticate: Bearer`. The comparison is constant time.
- `/healthz` and `/readyz` are never authenticated, so kubelet probes keep
  working.
- The key is write-only: `GET /api/v1/config` reports it as configured but
  never returns the value, and it never appears in logs or audit rows.
- Changing or resetting it writes `config.set` / `config.reset` and
  `config.metrics_auth.update` audit events.
- The hub caches the resolved token for 10 s, so a change takes effect within
  that window.

Prometheus:

```yaml
scrape_configs:
  - job_name: kryptkeeper
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/secrets/kryptkeeper-metrics-token
    static_configs:
      - targets: ["kryptkeeper.example.com:8080"]
```

Prometheus Operator `ServiceMonitor`: reference a Secret holding the token with
`endpoints[].authorization.credentials` (`name`/`key`). Helm values are out of
scope for this change (follow-up).

## Satellite probes

Each satellite listens on `KRYPTKEEPER_OPS_ADDR`. The default is loopback so
nothing is exposed unasked; set `0.0.0.0:<port>` in containers so the kubelet
can reach it, or `off` to disable. The satellite `/metrics` endpoint is
unauthenticated, so do not bind it to an untrusted network.

| Binary | Default address | Ready when |
|---|---|---|
| `kryptkeeper-agent` | `127.0.0.1:9101` | a hub heartbeat succeeded within 3 x poll interval + 60 s |
| `kryptkeeper-mcp` | `127.0.0.1:9102` | the hub answers `whoami` and the token role cannot approve actions (cached 5 s) |
| `kryptkeeper-certmanager` | `127.0.0.1:9103` | the controller loop is running |

The MCP HTTP transport keeps its own `/healthz` on the MCP port. The MCP stdio
transport never writes to stdout from the ops listener.

```yaml
env:
  - {name: KRYPTKEEPER_OPS_ADDR, value: "0.0.0.0:9103"}
livenessProbe:  {httpGet: {path: /healthz, port: 9103}, periodSeconds: 10}
readinessProbe: {httpGet: {path: /readyz,  port: 9103}, periodSeconds: 10}
```

## Readiness drill

Pass line: hub `/readyz` turns non-200 within one 10 s probe period of losing
Postgres and returns to 200 within 10 s of recovery. Each probe is bounded by
`readinessTimeout` (2 s) and the HA probe (1.5 s).

```bash
# terminal 1: one sample per second
while true; do printf '%s %s\n' "$(date +%s)" \
  "$(curl -s -o /dev/null -w '%{http_code}' -m 3 http://HUB/readyz)"; sleep 1; done | tee readyz.log
# terminal 2
docker stop <postgres>     # note T0; first non-200 line minus T0 must be <= 10
docker start <postgres>    # note T1; first 200 line minus T1 must be <= 10
```

Use `tests/live/ha/docker-compose.ha.yml` (`run.sh`) or any Postgres-backed hub.

| Run | Date | Stop to first non-200 | Start to first 200 |
|---|---|---|---|
| (not yet executed) | | | |

Status: the drill was not executed when this change was written (no
Postgres-backed hub available in the build environment). Record the numbers
here when it is run.
