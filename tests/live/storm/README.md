# W27-34 — renewal storm against a rate-limited stub CA

`bash tests/live/storm/run.sh [full|smoke]` seeds N due certificates into a real hub container and lets the
hub's own scheduler renew them through an ACME connector pointed at a stub CA that enforces a new-order
limit. Needs `podman`, `go`, `python3`, `curl`; without podman it prints `SKIP` and exits 2.

## Topology (one podman network per leg)

| container | role |
|---|---|
| `hub` | the product binary, file/sqlite stores on a volume, `RENEWAL_POLL_MINUTES=1`, `KRYPTKEEPER_CONNECTOR_MAX_CONCURRENT=10`, `KRYPTKEEPER_RENEWAL_WORKERS=16`, `RENEWAL_TICK_JITTER_PERCENT=10`, `SSL_CERT_FILE` = the fixture root |
| `fixture` (alias `fixture`) | `:9443` stub ACME CA, `:9444` fake Kubernetes Secrets API, `N` TLS verify listeners on `21000..21000+N-1` |

Per certificate `i` the seeder (`fixture seed`, run from the host through the hub's published port) creates:
a self-signed certificate `storm-%04d.storm.test`, a takeover onto the shared ACME connector, an `api_token`
credential (`base_url` = the fake API, `secret_name` = `s<i>`, `ca_cert` = the fixture root), an armed
`install_mode: k8s` target with `verify_host_port = fixture:<21000+i>`, and an explicit certificate–target
binding (the scheduler never guesses targets).

The install leg is real: the hub's K8s pusher GETs/POSTs/PUTs the Secret on the fake API, the fake API makes
listener `i` serve that Secret's certificate, and the hub's verify-after-install TLS dial compares the served
fingerprint with the renewed leaf.

## Scale maths

`SCALE` divides every wall-clock quantity (default 60 for `full`):

| quantity | simulated | real at SCALE=60 |
|---|---|---|
| stub CA limit | 100 new orders / 15 min (sliding) | 100 / 15 s |
| issuance time per order | 3 s | 50 ms |
| certificate lifetime after seeding | 7 h | 7 min |
| goal (all N renewed) | 6 h | 6 min |
| floor from the limit alone (N=2000) | 5 h | 5 min |

The scheduler cadence is **not** scaled (`RENEWAL_POLL_MINUTES=1` is the smallest the knob allows). The connector
throttle's 30 s minimum 429 backoff is scaled through `KRYPTKEEPER_CONNECTOR_MIN_BACKOFF` (`run.sh` sets
`30 s / SCALE`; the product default stays 30 s). W26-28's 0-60 s jitter on a CA Retry-After is scaled the same way
through `KRYPTKEEPER_ACME_RATELIMIT_JITTER_MAX` (`60 s / SCALE`; product default stays 60 s). The cadence is a fixed real-time cost, so a scaled run is pessimistic against the hub at high `SCALE` (hence `smoke` uses
`SCALE=120` and `LIMIT=20`; 7 h / 600 would be shorter than one tick and every certificate would expire
unrenewed).

## Legs

* **A** uninterrupted.
* **B** the same seed with a graceful `podman stop` + `start` of the hub once half the certificates are finalized.
* **B2** (full only) `podman kill` instead; informational.

## Reading `results/<UTC stamp>.json`

Stamped files are git-ignored; each run also copies itself to `results/last-run.json`, the only tracked result.

`stats_*` are the stub CA's counters: `orders`, `limit_hits` (429s served), `violations` (a `newOrder`
arriving while a previous 429's Retry-After was still running, the spec definition), `late_violations` (the
same, but more than 1 s after that 429 went out; requests already on the wire when the first 429 left are
concurrency, not disobedience), `peak_in_flight` (orders accepted and not yet downloaded), `duplicates` (names
finalized more than once).

`completion_s_*` is seconds from the end of seeding to the last finalize; the before-expiry check adds the
seed time because certificate lifetime runs from the start of seeding. `pass.*` values are booleans, `null`
for a leg that did not run. The script exits 1 if any value in `run_a` or `run_b` is `false`.

A restart can lose an order after the stub finalized it; the hub then renews again and the stub counts a
duplicate. That is reported as FAIL with the count, never masked.

## Measured (2026-10-16, commit 4060d9c0 + merge, Apple M4 Max, podman machine 12 cpu; another podman job shared the host)

`results/2026-10-16T171749Z.json`, full, N=2000, SCALE=60, goal 360 s, time left at storm start 565 s (the
import allowance was generous; the check uses the measured value).

| run | completion s | 429s | strict violations | late (>1 s) | peak in flight | duplicates |
|---|---|---|---|---|---|---|
| A uninterrupted | 324 | 239 | 202 | 8 | 10 | 0 |
| B graceful restart | 362 | 477 | 371 | 8 | 11 | 10 |
| B2 kill (info) | 372 | 838 | 635 | 21 | 10 | 5 |

* A meets the 6 h-scaled goal and finishes before expiry, but the strict "0 violations" criterion fails: with 10
  issuances in flight, the siblings of the request that draws a 429 are already on the wire (late violations,
  i.e. a client that really ignored Retry-After, are 8).
* B and B2 renew some certificates twice across a restart (duplicate issuance: 10 and 5). B also misses the 360 s
  goal (362 s) and shows peak 11 because the stub still counts the killed process's orders as in flight until its
  60 s idle reap.
* The connector throttle's 30 s minimum 429 backoff is not scaled, so at SCALE=60 it exceeds the stub's 15 s window.

## Measured after the fixes (2026-10-16, commit 208fc35d, same host)

`results/2026-10-16T181220Z.json`, full, N=2000, SCALE=60, goal 360 s, time left at storm start 558 s.

| run | completion s | 429s | strict violations | late (>1 s) | peak in flight | duplicates |
|---|---|---|---|---|---|---|
| A uninterrupted | 339 | 58 | 22 | 0 | 10 | 0 |
| B graceful restart | 350 | 159 | 105 | 0 | 10 | 0 |
| B2 kill (info) | 362 | 243 | 154 | 3 | 10 | 0 |

Before -> after: late violations A 8 -> 0, B 8 -> 0; duplicates B 10 -> 0; B completion 362 s -> 350 s (now inside
the 360 s goal). Still failing: `zero_ca_limit_violations` (strict) in A and B (22 and 105). These are the up to
10 sibling orders already on the wire when one draws a 429, which no client-side gate can recall; the script
exits 1 because of it. B2 (`kill -9`, informational) misses the goal by 2 s and has 3 late violations; a hard
kill cannot be drained.

What changed: `Stop` now drains running renewals (no new ones start; `KRYPTKEEPER_SHUTDOWN_DRAIN`, default 8 s,
under a container runtime's 10 s SIGKILL grace), and the ACME client's internal 429 retries are reported to a
connector-wide hold that parks sibling `newOrder` requests until Retry-After has elapsed.

## After the v0.14.0 merge regression and its fix (2026-10-16, same host)

The merge of W26-28's connector gate with the W27 throttle regressed run A: `results/2026-10-16T203528Z.json`
finalized only 1865/2000 before expiry with 250 CA limit hits and 171 strict violations. Verified causes (hub
logs of a smoke run and a full run, plus a failing unit test written first):

1. **A sibling's success reopened the gate (the main cause).** `acmeIssuerConnector.Issue` called
   `acmeBackoff.Clear(connector)` on every success, so any order that was in flight when a sibling drew a 429
   erased that sibling's Retry-After gate and the next orders went straight back to the CA (many more 429s and
   violations). The gate is now left to lapse on its own.
2. **Unscaled W26 jitter (0-60 s = up to 60 simulated minutes at SCALE=60) and a gated sweep waiting for the next
   1 min poll.** Jitter is now `KRYPTKEEPER_ACME_RATELIMIT_JITTER_MAX` (default unchanged), scaled by `run.sh`;
   and the scheduler re-scans when the soonest gate it deferred work for lapses (when sooner than the next poll),
   instead of idling until the next tick.

Not the cause: gate-key mismatch (gate key and `RenewalConnectorID` are the same connector id in the logs).
The harness now also counts W26's `acme.upstream.ratelimited` audit rows (`acme_ratelimited_rows`).

`results/2026-10-16T214738Z.json`, full, N=2000, SCALE=60, goal 360 s:

| run | completion s | 429s | strict violations | late (>1 s) | peak in flight | duplicates | acme.upstream.ratelimited rows |
|---|---|---|---|---|---|---|---|
| A uninterrupted | 362 | 59 | 16 | 0 | 10 | 0 | 284 |
| B graceful restart | 341 | 63 | 18 | 0 | 10 | 0 | 271 |
| B2 kill (info) | 467 | 46 | 18 | 0 | 10 | 0 | 224 |

A: 2000/2000 (was 1865), 429s 250 -> 59, strict 171 -> 16 (pre-merge baseline 58 / 22). A completes in 362 s, 2 s
over the 360 s goal (pre-merge 339 s); `zero_ca_limit_violations` still fails in A and B for the same reason as
before the merge (sibling orders already on the wire), so the script still exits 1.

## Linux lab runner (2026-10-18, Ryzen 9 6900HX, 8 cores, podman 4.9 rootless)

Three findings from the first runs on the lab VM. Two were product bugs and are fixed; two remaining effects are
properties of the scaled clock and of the process model, not defects.

"Late violation" in this harness means a `newOrder` reaching the stub CA more than 1 s after a 429 while that
429's Retry-After was still running (a client ignoring Retry-After). It is not "renewed after the certificate's
deadline".

1. **Seeding hung (fixed, 943d9419).** `queryChangedCerts` waited for the provider lock while its open cursor held
   the only connection of a `MaxOpenConns=1` sqlite pool; `UpdateEstate`/`UpdateOwnership` hold that lock across their
   `db.Exec`. A goroutine dump showed the pair and ~60 goroutines queued behind it. Seeding 100 certs went from 72
   client timeouts to 14-17 s.
2. **A takeover could be reverted in memory (fixed, b6b8ad38).** `UpdateOwnership` and `UpdateEstate` stamped
   second-resolution `updated_at`; the row trigger rewrites a same-value stamp to milliseconds, and `refreshFromTable`
   fetches full rows before taking the lock, so a row read between the two writes and merged after them outranked the
   live copy. The certificate lost `management_state=managed` and `renewal_connector_id` in memory only (the database
   row was right), so the scheduler renewed it through the hub CA and failed with `ca not found`, on every attempt
   until a restart. Seen as 1/100 in one smoke leg and 4/2000 in a full leg A (1996/2000 finalized,
   `results/2026-10-18T075838Z.json`); after the fix the full leg A finalizes 2000/2000 in 323 s
   (`results/2026-10-18T084926Z.json`). Regression test `TestStaleRefreshRowDoesNotRevertTakeover` fails on the old code.
3. **Late violations in leg B are a restart effect (not fixed, documented).** The hub drains running renewals on a
   graceful stop, but the Retry-After gate (the connector backoff and the upstream gate) is in process memory. A hub
   that restarts while the CA's Retry-After is running forgets it and orders again early. Evidence
   (`fixture-B.log`/`hub-B.log`, smoke run `results/2026-10-18T072306Z.json`): the stub issued a 429 at 07:27:03.72 with
   Retry-After to 07:27:10, the hub stopped at 07:27:05.68 and restarted at 07:27:06.4, and three orders arrived at
   07:27:07.4, 3.7 s after the 429 and 2.1 s early. The full profile shows the same (3 late, 2.8 s before the end of
   Retry-After). Persisting the gate (a table or the audit rows' `retry_at`) would close it; not done here because it needs a
   migration and a design decision on multi-replica sharing. Leg A has 0 late violations in every run.
4. **B2 (`kill -9`, informational) always ends at 1700/2000 on this runner (scale artifact).** After a hard kill the
   dead replica's scheduler lease (`ha_coordinator.go`, `minHALeaseDuration` = 1 min, renewal scheduler lease ~2.4 min)
   is still held; the new process logs `ha failover: lease taken over ... lease_age_seconds=142..145` and renews
   nothing for that long. At SCALE=60 that dead time is 40% of the 360 s goal; at real scale it is under 1% of a 6 h
   window. The lease is a split-brain guard and is deliberately not scaled. The 2026-10-16 Mac B2 legs did finish (467 s); why this runner takes the full lease is not investigated. Treat B2 as informational only, as before.

Smoke profile on this runner (N=100, SCALE=120): 5 runs, all legs finalize 100/100 in 87-98 s except one run whose leg A
finalized 99/100 (cause 2 above); strict violations 0-6 per leg. Seeding no longer limits it.

## Retry-After across restarts (W35-01)

The Retry-After gate is persisted (`connector_retry_gate`), so a hub restarted inside a CA 429 window orders
nothing before `retry_at`. The v1 late violations in leg B (3 orders up to 2.8 s early) came from the gate living
in process memory; a live leg B run should now report 0 late violations. See `docs/ops/ACME_UPSTREAM.md`.
