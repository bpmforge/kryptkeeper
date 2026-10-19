# Revocation benchmark (W23-52)

Measured with `tests/live/revocation-bench/run.sh` (see its README for method
and env). Every number below comes from the committed JSON files under
`tests/live/revocation-bench/results/`; a leg that was not run is marked "not
measured".

## Targets

| Criterion | Target | Source |
|---|---|---|
| CRL generation at 100k revocations | under 2 s | UC-M09 |
| OCSP p99 at 500 rps (cold: every request signs) | under 50 ms, zero errors | board acceptance |
| Revoke visible on a second replica (CRL and OCSP) | under 60 s | board acceptance |
| CRL at 10k and 1M revocations | reported, no target | |

## Reference hardware

The machine the runs were made on (expected reference class: the owner's Apple
Silicon dev Mac). No Linux CI-runner row: not measured.

| | |
|---|---|
| Machine | Apple M4 Max, 16 cores, 64 GB, macOS 27.0.1 (Darwin arm64), go1.27.1 |
| Load | Shared with other work: load average about 46-51 (1/5/15 min) on 16 cores at the end of both runs. Treat every number as measured under contention, not on a quiet machine. |
| Code | Runs made on top of commit `de1adcf6` plus the uncommitted benchmark code that this ticket's commit contains |

## Results

### In-process legs, no hub or database running
File `results/2026-10-16T002950Z.json`, 2026-10-16T00:29Z.

| Revocations | CRL DER bytes | Generation, median of 3 | Retained heap | Allocated per generation |
|---|---|---|---|---|
| 10,000 | 495,259 | 18.25 ms | 1.48 MB | 14.05 MB |
| 100,000 | 4,949,905 | 222.83 ms | 12.77 MB | 136.13 MB |
| 1,000,000 | 49,498,743 | 1307.5 ms | 111.22 MB | 1329.03 MB |

| OCSP, 500 rps for 30 s, open loop, loopback | n | errors | p50 | p95 | p99 | max |
|---|---|---|---|---|---|---|
| cold (each request signed) | 15,000 | 0 | 0.57 ms | 5.38 ms | 14.21 ms | 94.93 ms |
| warm (responses cached) | 15,000 | 0 | 0.48 ms | 3.34 ms | 6.56 ms | 14.44 ms |

### Replica run: two hub processes on one Postgres 16 and one keystore
File `results/2026-10-16T002708Z.json`, 2026-10-16T00:27Z. The same in-process
legs ran in this file while two hubs and Postgres were also running on the
machine, so its CRL numbers are noisier (100k: 241.67 ms, 1M: 3620.53 ms; OCSP
cold p99 5.48 ms, warm p99 7.42 ms). Spread between the two files, with
identical code, shows how much the shared machine matters.

| OCSP attached (hub B plain-HTTP `/ocsp`, 500 rps, 30 s) | n | errors | p50 | p95 | p99 | max |
|---|---|---|---|---|---|---|
| single leaf, hub response cache | 15,000 | 0 | 0.48 ms | 2.76 ms | 6.62 ms | 36.65 ms |

| Cert | Visible on B via CRL | Visible on B via OCSP |
|---|---|---|
| 1 | 4.76 s | 4.77 s |
| 2 | 4.74 s | 4.74 s |
| 3 | 5.66 s | 5.68 s |
| 4 | 2.85 s | 2.85 s |
| 5 | 7.79 s | 7.90 s |

Median over all ten observations 4.77 s, max 7.90 s.

Time for the first `GET /crl/<ca>.crl` on A after each revoke (regeneration at
this tiny volume): 3, 4.89, 443.9, 30.62 and 65.18 ms.

## Verdict against the targets

| Criterion | Result | Pass |
|---|---|---|
| CRL, 100k | 222.83 ms (idle-hub file), 241.67 ms (replica file) | yes |
| OCSP p99 cold, in-process | 14.21 ms, 0 errors | yes |
| OCSP p99, attached hub | 6.62 ms, 0 errors | yes |
| Replica visibility | max 7.90 s | yes |
| CRL 1M | 1.31 s to 3.62 s, 49.5 MB | no target |

## Method

1. CRL: P-256 CA, synthetic revoked list of random 128-bit serials, reason 1,
   built outside the timer; `Generator.Generate` three times per size, median
   reported; heap measured after a forced GC.
2. OCSP in process: `ocsp.Responder` behind `httptest`, 10% of serials revoked,
   cache size 200,000, bodies prebuilt, one shared HTTP client. Open loop:
   request i is due at start + i/500 s and fired then, latency measured from
   the due time. Cold uses a distinct serial per request, warm repeats them.
   Two responses are checked to verify against the CA before timing.
3. Attached OCSP: same driver against hub B's plain-HTTP listener.
4. Replica visibility: five certificates issued through A's API; B's CRL and
   OCSP caches warmed; revoke through A; B polled every 100 ms until the serial
   is revoked in its CRL and in an OCSP response.
5. Environment captured in the JSON (CPU, cores, RAM, OS, Go, commit, UTC time,
   load average, DB engine, note).

## What this does not prove

- Loopback, not a network; no TLS on the revocation path.
- The in-process OCSP status lookup is in memory. The attached leg uses one
  leaf, so it exercises the hub's response cache, not a DB lookup per request.
  No DB-bound OCSP or CRL-at-volume measurement through a hub was made.
- Hub rate limits: CRL 30/min and OCSP 200/min per client IP. The attached and
  replica legs ran with `APP_TRUSTED_PROXY_CIDRS=127.0.0.1/32` and a distinct
  synthetic `X-Forwarded-For` per request, so the limiter did not apply. A
  single real client at 500 rps would be throttled by it.
- Replica visibility is dominated by the revocation-stamp poll interval
  (`KRYPTKEEPER_REVOCATION_SYNC_INTERVAL`, default 5 s) and was measured with
  the default.
- One CA; ECDSA P-256 software signer only. An HSM or KMS signer will be slower.
- CRL numbers now come from the DB (migration 000124), so they are monotonic
  across replicas; the benchmark's generator uses the in-memory fallback.
- A shared, loaded machine: see the load average above.

## Feeds M10

Reuse: CRL 100k = about 4.9 MB, generated in 0.22 to 0.24 s; 1M = about 49.5 MB in
1.3 to 3.6 s; OCSP p99 under 15 ms at 500 rps cold and 7 ms attached; cross-replica
revoke visibility 2.9 to 7.9 s with the 5 s sync default. All measured on the
machine above under load; re-run `run.sh` on the target hardware before quoting
them elsewhere.
