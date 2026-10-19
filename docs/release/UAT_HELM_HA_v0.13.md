# UAT: Helm HA on kind (W25-05)

Harness: `tests/live/helm-ha/run.sh` (kind 1 control-plane + 1 worker on podman, chart `charts/kryptkeeper` at this commit, hub image built from this tree, kube-prometheus-stack 92.8.0, Postgres 16). Run date 2026-10-15, re-run after the two HA fixes (no workarounds) `ALL PASS`. The run uses Postgres at its default `max_connections=100`, never restarts a replica after seeding, and uses a fresh cluster.

## Verdict against the board acceptance

| # | Acceptance | Result |
|---|---|---|
| 1a | install on kind, 2 replicas serve traffic | PASS: 2/2 Ready, 20/20 requests 200 over TLS verified against the hub CA |
| 1b | failover within the 30 s lease TTL | NOT MET. No 30 s lease exists: `TryAcquire` floors every lease at 60 s and the scheduler asks for 2x poll (120 s at poll=1 min). Realistic bounds were asserted instead (below). |
| 1c | 0 duplicate renewals, 0 duplicate pages | PASS for pages (5 certificates, 5 audit rows, 5 sink pages from the renewal leader, none repeated across both failovers). Renewals: none ran (no auto-renew target in kind), `kryptkeeper_cert_renewal_success_total` = 0, so renewal de-duplication is UNPROVEN here. |
| 2a | drain keeps >= 1 pod available | PASS: min Ready = 1, `/readyz` stayed 200 for the 60 s window |
| 2b | ServiceMonitor target UP | PASS: 2 targets `up` (chart default `insecureSkipVerify`, acceptable for this UAT only) |

## Measured failover (renewal-scheduler lease, poll = 1 min)

| Mode | Measured | Asserted bound | Notes |
|---|---|---|---|
| graceful (`kubectl delete pod`, SIGTERM, `Release`) | 9 s (re-run); earlier runs 3 s and 17 s | <= 75 s (poll + 15 s) | resolution about 2 s |
| hard (SIGKILL of the hub process from the node) | 124 s (re-run); earlier run 121 s | <= 195 s (2*poll + poll + 15 s) | lease lapsed naturally |

A forced pod delete (`--grace-period=0 --force`) is not a crash: the kubelet still delivers SIGTERM and the hub released its lease in 6 s, so the harness SIGKILLs the process instead.

## Variant run
Single worker (RWO keystore PVC shared by both replicas on one node). Drain evicts one hub pod, the PDB (`minAvailable: 1`) then blocks the second, so `kubectl drain` times out by design (exit 1). Node-spanning drain needs RWX storage: not run.

## Measured replica visibility and Postgres connections (re-run)
- **Per-replica certificate lists, no restart.** 5 certificates were issued through the load-balanced Service. Each pod was then queried directly (port-forward to the pod, TLS verified against the hub CA): both pods listed 6 certificates (the 5 seeded plus the hub's own listener certificate) with 0 seeded fingerprints missing.
- **Renewal leader pages all N.** The sink received 5 pages for 5 distinct certificates, and the audit log has 5 `renewal_notification_sent` success rows, across a graceful and a hard failover: no duplicates.
- **Postgres connections** (`max_connections=100`, default; `SELECT count(*) FROM pg_stat_activity` sampled about every 3 s via `kubectl exec`, so the sampler's own session is included). Observed over 40 samples (sampling gaps of up to about 60 s occurred while pods were being killed, so a short peak could have been missed): 2-replica steady state 63 total / 58 client backends at seeding; idle readings later in the run 9 to 18 total; peak 93 total / 88 client backends; 45 total / 40 client backends at the end after the drain recovery. The peak stayed under 100 but leaves little headroom while a replacement pod overlaps its predecessor. No `db mode unavailable` fallback was logged by the live replicas.

## Product findings from this run
1. **Certificate provider was per-process: FIXED and re-verified.** Replicas now merge peer rows and lookups read through (`internal/bootstrap/certificate_discovery_refresh.go`). Re-verified without any replica restart: both pods listed all 5 seeded certificates (6 rows each) and the leader paged for all 5 (measured values above).
2. **Postgres connections: FIXED and re-verified.** Per-store pools default to 3 open / 1 idle with a 60 s idle timeout (`internal/bootstrap/db_pool_config.go`), 33 pools per replica. With Postgres at the default `max_connections=100` the run peaked at 93 total / 88 client backends, with 63 total / 58 client at 2-replica steady state, and no store fell back off Postgres.
3. **Template store is file-backed** and defaults to `./var`, which the chart's read-only root filesystem rejects; fixed in this PR: the chart now sets `APP_TEMPLATE_FILE` under the keystore PVC (the measured run used the same path via the harness).
4. **Fresh install needs `KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true`**, and two replicas would race creating the root; the harness installs one replica, then upgrades to the chart default of 2.
5. The dashboard (W25-03) was also verified on this cluster: Deployment Ready, `/` 200, `/readyz` proxied to the hub with `proxy_ssl_verify on` returned 200.
