# W30-19: SLO breach drill (real Prometheus + Grafana)

```
bash tests/live/slo/run.sh
```

Needs podman, go, curl, python3, openssl, ssh-keygen and the two images
already pulled (pinned tags, override with `KK_SLO_PROM_IMAGE` /
`KK_SLO_GRAFANA_IMAGE`):

```
podman pull docker.io/prom/prometheus:v2.55.1 docker.io/grafana/grafana-oss:11.3.0
```

No operator credentials are involved. The Grafana admin password is generated
per run (`openssl rand`) and never printed. Runtime is about 8 minutes (it
waits on real sweep intervals: `KRYPTKEEPER_SLO_SWEEP_MINUTES=1`).

## What it does

1. Starts the hub with the webhook as the **only** channel
   (`WEBHOOK_URL` -> echo receiver `/slo`, `KRYPTKEEPER_SLO_NOTIFY_TARGET=slo-drill`),
   Prometheus scraping `host.containers.internal:<hub>/metrics` every 5 s, and
   Grafana with the Prometheus datasource as default; imports
   `docs/ops/pki-slo-dashboard.json`.
2. Idle check: 2 sweeps, 0 records at `/slo`.
3. Forces the breach (details below), then asserts exactly 1 record at `/slo`
   mentioning `renewal-success-rate` within 150 s and still exactly 1 after 3
   more sweeps (a steady breach does not re-page).
4. Series check: the renewal panel expression returns a series from
   Prometheus and a frame from Grafana's `POST /api/ds/query`, and
   `GET /api/dashboards/uid/kryptkeeper-pki-slo` finds the dashboard.

## Deviations from the ticket text (verified against code)

- The hub egress guard (`internal/egress`) always refuses loopback, so the
  echo receiver binds a private LAN address of this host (auto-detected;
  override `KK_SLO_ECHO_HOST`), not `127.0.0.1`.
- The breach is not "5 failures, success stays 0": the first
  `renewal/execute` renews the certificate and then fails to install over SSH
  (`connect_failed`), which the executor counts as a renewal **success**. Calls
  2..6 return 409 "certificate already has a successor" and each increments
  `kryptkeeper_cert_renewal_failure_total`. Net: 1 success, 5 failures, rate
  0.17 < 0.99.
- Single-channel setup is kept deliberately (W30-04 fans out to every
  configured channel), so "exactly once" is unambiguous.

## Dry run without the images

`KK_SLO_NO_OBS=1 bash tests/live/slo/run.sh` runs only the hub half (idle
check, forced breach, exactly-once, no re-page). It does **not** satisfy
acceptance 2 (dashboard series).

## Results

See "Live results" below; fill it in after a real run.

| Part | Status | Date | Notes |
|---|---|---|---|
| Hub half (`KK_SLO_NO_OBS=1`): idle, breach, exactly-once, no re-page | ALL PASS (agent, local) | 2026-10-16 | 0 pages idle; failure_total=5 success_total=1; exactly 1 `/slo` record, still 1 after 3 sweeps |
| Prometheus + Grafana + dashboard series | **PENDING-RUN** (images not available offline) | | |
