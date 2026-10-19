# HA soak v0.11 (W23-28, W23-29)

Two hub replicas on one Postgres and one shared keystore, 10,000 issuances in
31 minutes with one node kill, one Postgres restart and one network partition.
Every number below was measured in the run named here; it is copied from
`tests/live/ha/soak-result.json` (soak) or the chaos run log (chaos).
Harness: `tests/live/ha/` (`run.sh --soak`).

**Verdict: PASS on all criteria, with the limits listed below.** The
availability pass is narrow (99.919% against 99.9%) and depends on how the
balancer treats `/readyz`; read "Results" and "Known limits" before quoting it.

## Setup

| Item | Value |
|---|---|
| Machine | Apple M4 Max, 16 cores, 64 GB, macOS 27.0.1 (Darwin 27.0.0 arm64) |
| Container runtime | podman 6.1.3, one VM (`podman-machine-default`, 12 CPUs, 32 GiB) |
| Host load | shared with other work: 16 containers running; load average 1/5/15 min at start `29.48 40.34 52.23`, at end `21.42 31.85 36.69`, peak 1-min sample `70.40` (samples every 60 s are in the JSON) |
| Hub image | `localhost/kryptkeeper:kkha-w23`, id `213f95a04cfaf31ae85d34ba7aad05ed148eb12d86889a5883278decfb755e16`, built from the product tree at `79a2bb75` (`VERSION=w23-ha`); harness commit `53fc414e` |
| Postgres | PostgreSQL 16.15 (`postgres:16-alpine`), `max_connections=300` |
| Replicas | A (`kkha_kk-a_1`, port 18081, created the root CA) and B (`kkha_kk-b_1`, port 18082); plain HTTP, ECDSA P-256 software CA |
| Config | `RENEWAL_POLL_MINUTES=1`, `KRYPTKEEPER_REVOCATION_SYNC_INTERVAL=2s`, shared keystore volume, shared `templates.json` volume |
| Run | 2026-10-16 02:06:08Z to 02:37:08Z UTC, 1859.5 s of timed phase |

## Timeline (injector log from the JSON, offsets from t0)

| t+ (s) | UTC | Event | Note |
|---|---|---|---|
| 1.1 | 02:06:09 | soak start | 50 serials already issued and primed on both replicas |
| 302 | 02:11:10 | revocation probe 1 | visible on B in 2.01 s |
| 480 | 02:14:08 | SIGKILL replica A | `podman kill` took 115 ms |
| 540 | 02:15:08 | start replica A | A `/readyz` 200 at t+540.7 |
| 602 | 02:16:10 | revocation probe 2 | 2.01 s |
| 900 | 02:21:08 | Postgres restart (`podman restart -t 0`) | abrupt, took 1.269 s; both replicas `/readyz` 503 from t+900.7 to t+902.2 |
| 902.2 | 02:21:10 | revocation probe 3 | 2.11 s (issued and revoked immediately after the restart) |
| 1202 | 02:26:10 | revocation probe 4 | 2.01 s |
| 1320 | 02:28:08 | partition: disconnect B from the database network | the `podman network disconnect` call took 40.6 s on the loaded host, so B first reported 503 at t+1362.2 |
| 1410 | 02:29:38 | reconnect B | the call took 12.6 s; B `/readyz` 200 at t+1422.7 |
| 1502 | 02:31:10 | revocation probe 5 | 2.01 s |
| 1802 | 02:36:10 | revocation probe 6 | 2.01 s |
| 1859.5 | 02:37:08 | 10,000th issuance, end | both replicas ready |

The effective partition (B reporting 503) lasted about 60 s, not the planned 90 s,
because of the slow `podman network` calls.

## Results

| Criterion | Measured | Pass |
|---|---|---|
| Issuance successes | 10,001 of 10,000 target (201 responses) | yes |
| Duplicate `(ca_id, serial)` groups | 0 (`GROUP BY ca_id, serial_number HAVING COUNT(*) > 1`) | yes |
| Partial rows (`raw_cert_b64 IS NULL`) | 0 | yes |
| certificates rows for the CA | 10,057 = 10,001 + 50 primed + 6 revocation-probe certificates; every failed request left no row | n/a |
| Issuance failures | 9 total: 6 HTTP 5xx (1 from A, 5 from B, body `certificate unavailable`), 2 connection refused (A, t+480 to 540 window), 1 client timeout (B, 20 s) | n/a |
| Failures per minute | m08: 2, m15: 2, m22: 4, m23: 1 (kill, Postgres restart, partition) | n/a |
| Ticks with no ready replica / dropped (workers busy) | 5 / 308 | n/a |
| Successful issuance latency | p50 5.0 ms, p95 151.8 ms, p99 2425.3 ms, max 8633.2 ms | n/a |
| CRL + OCSP availability via the readiness-gated balancer, 50 primed serials | 7,426 of 7,432 = **99.919%** (CRL 3,712/3,716 = 99.892%, OCSP 3,714/3,716 = 99.946%) | yes (>= 99.9%) |
| Same, directly to either replica with one failover (no `/readyz` gate) | 7,432 of 7,432 = 100% | informational |
| OCSP for never-queried serials (database path), via the balancer | 1,852 of 1,856 = 99.784% | informational (known limit) |
| Revocation visible on B (6 probes) | max 2.11 s, p50 2.01 s, all visible | yes (< 60 s) |
| B `/readyz` during the partition | 503 (not a dead socket) from t+1362.2 | yes |
| Duplicate renewals / alert deliveries | 0 duplicates, but the queries examined 0 renewal rows and 0 alert rows (vacuous here, see limits) | yes |
| Both replicas ready at the end | yes | yes |

The 6 failed availability probes: 2 CRL fetches at t+480 (balancer still sent
them to A for up to 1 s after the SIGKILL), 2 CRL and 2 OCSP at t+901 to 902
(both replicas 503 for about 1.5 s during the Postgres restart). 4 unprimed
OCSP failures at t+79, t+480, t+901 and t+1364.

## Chaos run (W23-28, `run.sh` without `--soak`, 2026-10-16, load average not captured)

| Check | Measured |
|---|---|
| Concurrent issuance through both replicas | 400 of 400 returned 201, 400 rows, 0 duplicate `(ca_id, serial)`, `idx_cert_serial_ca` present |
| `renewal-scheduler` lease after SIGKILL of the holder (A) | taken over by B after 2 m 0 s (poll 1 min, lease 2 min, test bound 190 s); B issued 5 of 5 certificates during the takeover |
| Duplicate renewals / alerts | 0 duplicates; 0 and 0 rows examined |
| After restarting A | `/readyz` 200 on both |

## Product findings

1. **Two replicas do not fit Postgres' default `max_connections=100`.** One hub
   holds about 60 idle connections (66 rows in `pg_stat_activity` with one hub
   running; each provider opens its own pool via `openConfiguredDB`, 5 open
   connections each, `internal/bootstrap/db_provider_helpers.go`). With the
   stock image the second hub started but logged `... db mode unavailable:
   ... sorry, too many clients already (SQLSTATE 53300)` for most of its
   providers, i.e. it came up degraded. The harness
   sets `max_connections=300`. `docs/` has no `max_connections` guidance.
2. **Templates are file-only.** `APP_TEMPLATE_PROVIDER` has no database mode;
   the `certificate_templates` table stays empty. A template created through A
   is invisible to B. The harness shares one `templates.json` volume. A real HA
   deployment needs the same, or issuance by template id fails on the replica
   that never saw it.
3. **A hub refuses to start while Postgres is down** (`refusing to start with
   APP_CERTIFICATE_PROVIDER=ca: core database unavailable`). Fail-closed and
   consistent with W23-27, but a replica restarted during a database outage
   stays down until an orchestrator restarts it.
4. **Every revocation drops the whole OCSP response cache on both replicas**
   (`SyncVersion` on the stamp change). The "primed" serials are therefore only
   primed until the next revoke; the prober re-primes them within seconds.
5. **`/readyz` goes 503 on database loss, so a `/readyz`-gated balancer drains
   every replica during a database outage** even though a cache hit could
   answer. That is the 99.919% above; an L4 balancer that ignores `/readyz`
   measured 100%. Which one a deployment has decides whether CRL/OCSP ride out
   a Postgres blip.

## Known limits

- **The Postgres "failover" is an abrupt restart** of one instance (connections
  dropped, transactions aborted, back in 1.3 s). There is no standby and no
  promotion; Postgres HA is bring-your-own. Do not read this as a promotion test.
- **Availability is defined on 50 primed serials** (spec default). The
  never-queried-serial figure (99.784%) is the database path and is reported
  separately; it was good here only because the Postgres outage was short.
- The 99.9% budget over 31 minutes is about 1.9 s of unavailability. The
  readiness-gated path had 6 failed 500 ms probes, so it passed narrowly; a
  longer Postgres outage than the 1.3 s restart here would fail the criterion
  on that path.
- **Duplicate renewals / alerts is not exercised:** certificates are 30-day,
  renewal needs a managed target, and no notification channel is configured, so
  both queries examined 0 rows. The queries themselves were checked against
  seeded duplicates in a scratch Postgres (each returned the seeded group, and
  `rule_id=` rows were excluded). The serial-uniqueness check is the substantive one.
- Plain HTTP, loopback, one machine, one CA, software ECDSA P-256 signer.
  `APP_TRUSTED_PROXY_CIDRS` trusts the podman gateway and every probe carries a
  distinct `X-Forwarded-For`, so the hub's per-IP limits (CRL 30/min, OCSP
  200/min) were not exercised.
- Revocation latency is bounded by `KRYPTKEEPER_REVOCATION_SYNC_INTERVAL=2s`
  here; the default is 5 s (see `REVOCATION_BENCH_v0.11.md`: max 7.9 s).
- The host was heavily shared (load average 21 to 70 during the run). The
  slow `podman network` calls and the 8.6 s maximum issuance latency come with
  that; rerun on the target hardware before quoting numbers elsewhere.

## Run history

- Short dry runs (200 issuances, about 80 s) were used to debug the harness
  and are not results (their windows are too small for the availability ratio).
- A first full run was discarded: the harness gave issuance requests a 1 s
  client timeout (a bug in the harness's balancer client, fixed), which
  produced 2,645 false timeouts. Nothing from that run is quoted here.
- This document's run is the second full run, with the harness as committed.
