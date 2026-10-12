# Measurements

All against a local hub (`APP_CERTIFICATE_PROVIDER=ca`, SQLite, `APP_AUDIT_PROVIDER=db` unless noted,
TLS off, one `pki-admin` login). Load generator is `harness/loadtool.go.txt` (stdlib Go). Times are
client-observed over loopback. M4 Max, 16 threads.

## Seeding

- 10,000 certificates issued through `POST /api/v1/certificates` (ECDSA P-256 CSR, template with
  `validity 90d`), 4 concurrent: 93 s total, p50 36.4 ms, p95 47.7 ms, 0 failures.
- 52,600 certificates: the 10,520 issued ones plus 4 SQL clones of each row with new fingerprint and serial
  (`harness/clone-to-50k.sql.txt`), then hub restart (so the inventory hydrates from the DB). Cloned rows share
  the original certificate PEM; this affects only key-reuse flags, not the timings measured here.
- 5,100 revoked rows set directly in SQL for the CRL measurement.

## Inventory and write paths (ms)

| Case | 10.5k p50 | p95 | 52.6k p50 | p95 |
|------|----------:|----:|----------:|----:|
| GET /certificates?limit=25, c=1 | 4.90 | 7.16 | 30.08 | 38.57 |
| GET /certificates?limit=25, c=8 | 6.37 | 10.64 | 40.28 | 58.61 |
| GET /certificates?limit=100&offset=5000, c=1 | 5.04 | 7.40 | 30.32 | 38.98 |
| GET /certificates?limit=100&offset=5000, c=8 | 8.05 | 10.57 | 36.29 | 59.79 |
| GET /certificates?limit=25&q=host-4, c=1 | 1.35 | 3.47 | 10.88 | 17.32 |
| GET /certificates?limit=25&q=host-4, c=8 | 2.36 | 6.41 | 17.52 | 28.27 |
| GET /dashboard/summary, c=1 | 11.93 | 12.40 | 58.12 | 60.05 |
| GET /dashboard/summary, c=8 | 82.2 | 209.3 | 403.1 | 919.3 |
| POST issue, c=1 | 33.76 | 35.49 | 103.66 | 115.44 |
| POST issue, c=8 | 88.56 | 116.70 | 418.60 | 587.43 |
| Mixed: issue c=1 + list c=4 at 52.6k | | | list 38.5 | list 105.4 |

Issue at an empty inventory: 18.6 / 20.9 ms (c=1). Throughput at c=8: 88.7/s (10.5k), 18.7/s (52.6k).
List throughput at c=8: 1,128/s (10.5k), 193/s (52.6k). Response size for a 25-row page: 27 KB.

## Reports at 52.6k (single client; report limiter is 60 per minute per principal)

| Endpoint | 10.5k p50 | 52.6k p50 | 52.6k max |
|----------|----------:|----------:|----------:|
| reports/executive-summary (n=10) | 11.7 | 77.6 | 83.1 |
| reports/compliance-evidence (n=3) | 356.8 | 13,557 | 14,827 |
| reports/crypto-posture (n=3) | 325.8 | 2,496 | 2,528 |
| reports/expiry-timeline (n=3) | 325.1 | 2,494 | 2,501 |

The executive summary returns `total_certs: 100` on a 10,000-cert hub (H2): its timing is the cost of
building and discarding the full copy, not of summarizing the fleet.

## Protocol endpoints

Per-IP limiters (OCSP 200/min, CRL 30/min) were bypassed by setting `APP_TRUSTED_PROXY_CIDRS=127.0.0.0/8`
and varying `X-Forwarded-For`. Unauthenticated.

| Case | p50 | p95 | rps |
|------|----:|----:|----:|
| OCSP POST, c=1 (same serial, cache hit) | 74 us | 121 us | 10,120 |
| OCSP POST, c=16 | 394 us | 947 us | 27,537 |
| CRL GET, c=1 (5.1k revoked, 253 KB, cached) | 103 us | 206 us | 8,003 |
| CRL GET, c=16 | 1.5 ms | 2.8 ms | 9,095 |
| CRL first generation | 41 ms | | |

An empty-CRL fetch was 51 us. The OCSP uncached path (one SQLite point lookup + one ECDSA signature) showed
a worst case of 0.43 ms on the first request after restart.

## Go benchmarks (`harness/bootstrap_perf_test.go.txt`, `internal/bootstrap`, synthetic items)

| Benchmark | ns/op | Notes |
|-----------|------:|-------|
| ListPage25 10k | 3,975,556 | 6.2 MB/op, 4 allocs |
| ListPage25 50k | 22,870,778 | 31.2 MB/op |
| ListPage25 Q=host-4, 50k | 11,538,194 | |
| FullPaging 10k (100/page) | 382,038,889 | anomaly/SLO tick shape |
| FullPaging 50k | 11,111,138,305 | |
| RenewalSweep 50k (nil stores, sees 100) | 20,380,358 | logs `found 100 renewal candidates` |
| ScanKeyReuse 10k / 50k | 2,852,883 / 13,077,417 | |
| `clientip.FromEnv().ClientIP` | 333 | 9 allocs |

`TestPerfLimitClamp`: `Limit:50000` over 10,000 -> `items=100 total=10000`.
`TestPerfBucketGrowth` (ratelimit): 200,000 keys retained after expiry, 20.6 MB.

## Memory and threads (hub RSS)

| State | RSS |
|-------|----:|
| Fresh start, empty inventory | about 160 MB |
| 10.5k certs, idle after start | 176 MB |
| 10.5k, after report calls | 252 MB |
| 52.6k, idle after start | 484 MB (hydrate about 1 s) |
| 52.6k, after list/issue/dashboard suite | 1,511 MB |
| 52.6k, after reports | 1,022 MB |
| 30 concurrent bad logins, distinct IPs | 258 -> 583 MB |

OS thread count was 23 before and after every suite. The hub has no goroutine or heap gauge and
`/debug/pprof` is not served (it falls through to the UI), so goroutine counts could not be read. RSS after
bursts is not returned promptly, so it overstates the live heap.

## Audit file provider (H1)

Hub in default config, 3,000 concurrent issuances at c=4: audit file 2,458 bytes at the end, 27 resets logged.
Sequential `GET /certificates?limit=25` x1000 repeated four times (file 0.27 MB -> 1.08 MB): p50 1.91, 3.03,
4.24, 5.49 ms.

## Not measured

Postgres runtime; 1k managed targets and 100 agents under load (static review only); a real scheduler tick
with the H2 clamp removed; Dashboard UI timing in a browser; the discovery scan path.
