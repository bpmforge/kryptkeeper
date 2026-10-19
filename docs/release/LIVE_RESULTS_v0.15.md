# Live results index - v0.15

Verdicts are copied from each record; none is upgraded here. All dates 2026-10-16.

## Summary

| Record | Overall verdict |
|---|---|
| [SSH install (W27-08)](docs/release/LIVE_RESULTS_SSH_INSTALL_v0.15.md) | PASS |
| [Rollout groups (W27-16)](tests/live/rollout/last-run.json) | PASS |
| [Push modes / autopilot (W27-06)](docs/release/LIVE_RESULTS_PUSH_MODES_v0.15.md) | PARTIAL |
| [Upstream renewal (W27-10)](docs/release/LIVE_RESULTS_UPSTREAM_RENEW_v0.15.md) | PARTIAL |
| [ACME dns-01 providers (W27-26)](docs/release/LIVE_RESULTS_ACME_DNS_PROVIDERS_v0.15.md) | PARTIAL (local legs PASS; cloud and staging legs PENDING-RUN) |
| [Delivery plugins, cloud (W27-32)](docs/release/LIVE_RESULTS_DELIVERY_CLOUD_v0.15.md) | PARTIAL (Vault PASS; every other leg PENDING-RUN) |
| [Renewal storm (W27-34)](tests/live/storm/results/2026-10-16T181220Z.json) | PARTIAL (strict zero-violation check fails; follow-up W27-39) |

## Per-leg verdicts

### SSH agentless install (W27-08)
Record: `docs/release/LIVE_RESULTS_SSH_INSTALL_v0.15.md`. Result ALL PASS, 43 checks.

| Leg | Verdict |
|---|---|
| nginx install, 60 s serve check, verify-mismatch rollback | PASS |
| apache install, serve check, rollback | PASS |
| haproxy install, serve check, rollback | PASS |
| haproxy forced config-test failure (file restored byte for byte) | PASS |
| tomcat install, serve check, rollback | PASS |
| tomcat forced config-test failure (file restored byte for byte) | PASS |
| keystore password in hub log and audit | PASS (0 occurrences) |

Observation recorded: Tomcat `configtest` failure detail is a roughly 4 KB stack trace.

### Rollout groups (W27-16)
Record: `tests/live/rollout/last-run.json` (hub 8ffc5d86, 252 s, Apple M4 Max, podman 6.1.3). Result PASS.

| Case | Verdict |
|---|---|
| A happy path | PASS |
| B node 3 flip failure | PASS |
| C canary flip failure | PASS |

### Push modes and policy tick (W27-06)
Record: `docs/release/LIVE_RESULTS_PUSH_MODES_v0.15.md`. Record verdict: PARTIAL.

| Leg | Verdict |
|---|---|
| plugin (healthy and `-fail-bind` device) | PASS (15/15) |
| k8s on kind (healthy namespace and RBAC-refused namespace) | PASS (16/16) |
| policy tick 30 to 45 days | PASS (14/14) |
| IIS | NOT RUN (no Windows lab host; the harness does not implement the scripted IIS flow) |

Board acceptance 4 (IIS and WinRM runs on the current build) is recorded as not met.

### Upstream renewal (W27-10)
Record: `docs/release/LIVE_RESULTS_UPSTREAM_RENEW_v0.15.md`. Record verdict: PARTIAL.

| Leg | Connector level | Hub level | Verdict |
|---|---|---|---|
| SCEP (micromdm scepserver v2.3.0) | PASS | PASS | PASS |
| EST (Cisco libest r3.2.0) | PASS | PASS | PASS (after the EST client fix) |
| WSTEP (AD CS CES) | NOT RUN | NOT RUN | NOT RUN (no AD CS lab) |
| DigiCert (CertCentral) | NOT RUN | NOT RUN | NOT RUN (no sandbox) |
| DigiCert 429 (local stub) | PASS | not exercised | PASS (connector and registry level); no real CertCentral 429 observed |

### ACME dns-01 per provider (W27-26)
Record: `docs/release/LIVE_RESULTS_ACME_DNS_PROVIDERS_v0.15.md`. Local stand-ins use a local BIND and Pebble, not Let's Encrypt.

| Leg | Verdict |
|---|---|
| rfc2136 (local BIND + Pebble) | PASS |
| wildcard (local BIND + Pebble) | PASS |
| rfc2136-long-wait, 170 s (local BIND + Pebble) | PASS (171 s) |
| route53 | PENDING-RUN |
| azure | PENDING-RUN |
| gcp | PENDING-RUN |
| rfc2136 vs Let's Encrypt staging | PENDING-RUN |
| cname (acme-dns delegation) | PENDING-RUN |
| wildcard vs Let's Encrypt staging | PENDING-RUN |
| route53-long-wait (170 s) | PENDING-RUN |
| Cloudflare | not in this ticket (W20-29) |

### Delivery plugins, cloud (W27-32)
Record: `docs/release/LIVE_RESULTS_DELIVERY_CLOUD_v0.15.md`.

| Leg | Verdict |
|---|---|
| vault (local Vault dev server; forced failure rolled back) | PASS |
| akv | PENDING-RUN |
| gcpsm | PENDING-RUN |
| aws-sm | PENDING-RUN |
| aws-alb | PENDING-RUN |
| aws-cloudfront | PENDING-RUN |
| azure-appgw | PENDING-RUN |
| azure-frontdoor | PENDING-RUN |
| cloudflare | PENDING-RUN |

### Renewal storm (W27-34)
Records: `tests/live/storm/results/2026-10-16T171749Z.json` (commit 4060d9c0, before fixes) and
`tests/live/storm/results/2026-10-16T181220Z.json` (commit 208fc35d, after fixes). N=2000, SCALE=60, goal 360 s.
Board verdict for the ticket: PARTIAL (the script exits 1 because `zero_ca_limit_violations` is false).

| Run | 17:17Z (before) | 18:12Z (after) |
|---|---|---|
| A uninterrupted | completion 324 s; strict violations 202; late 8; duplicates 0. FAIL on zero_ca_limit_violations and zero_late_violations; other checks true | completion 339 s; strict violations 22; late 0; duplicates 0. PARTIAL: FAIL on zero_ca_limit_violations only; other checks true |
| B graceful restart | completion 362 s; violations 371; late 8; peak in flight 11; duplicates 10. FAIL on completion_within_goal, zero_ca_limit_violations, zero_late_violations, peak_in_flight_within_cap, zero_duplicate_issuance | completion 350 s; violations 105; late 0; duplicates 0. PARTIAL: FAIL on zero_ca_limit_violations only; other checks true |
| B2 kill -9 (informational) | completion 372 s; violations 635; late 21; duplicates 5 | completion 362 s (misses the goal); violations 154; late 3; duplicates 0 |

All legs finalized 2,000 unique certificates before the earliest expiry. Strict violations are up to 10 sibling
orders already on the wire when one draws a 429. Follow-up: W27-39 (todo, not part of v0.15.0).
