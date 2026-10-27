# RC4 measurements (W30-21)

Command: `PG_IMAGE=docker.io/library/postgres:16 bash tests/perf/bench.sh --certs 100000 --out <dir>`
(the local image is the 16.15 that `:16` currently resolves to; the script default pins `:16.15`,
which this lane could not pull offline). Host: Apple M4 Max, 64 GiB, macOS 27.0.1, Go 1.27.1,
PostgreSQL 16.15, client and server on one machine. Date: 2026-10-16, commit `5bd2ce33`.

## 100k certificates (pass-bar run)

| Metric | Run 1 | Run 2 | Bar |
|---|---:|---:|---|
| certs in table | 100000 | 100000 | |
| search p99 (ms) | 970.833 | 984.75 | < 500 FAIL |
| list p95 (ms) | 11.729 | 8.87 | < 300 pass |
| issue rps at c=16 | 595.3 | 1023.5 | >= 500 pass |
| issue failures | 0 | 0 | 0 pass |
| peak RSS (MiB) | 2489.4 | 2496.2 | < 2048 FAIL |

Raw bench lines, run 1:

```
GET /api/v1/search?q=host-7.perf.example.com n=3000 c=8 codes=map[200:3000] bytes=2671 p50=19.593ms p95=36.093ms p99=970.833ms max=1.062098s rps=194.1
GET /api/v1/certificates?limit=25 n=3000 c=8 codes=map[200:3000] bytes=28376 p50=3.167ms p95=11.729ms p99=17.236ms max=992.979ms rps=1124.0
POST /api/v1/certificates n=5000 c=16 codes=map[201:5000] bytes=1096 p50=14.162ms p95=79.578ms p99=306.827ms max=615.849ms rps=595.3
```

Observations (not diagnosed; follow-up for the ops lane): search p50 is 20 ms and p95 36-45 ms, so
the p99 miss is a tail of roughly 1 s stalls, and the list run shows a ~1 s max too; both runs
repeat it, so it is not noise. Issuance rps varied 595 to 1023 between runs. Peak RSS repeats at
about 2.49 GiB (the hub hydrates the inventory in memory), over the 2 GiB bar.

Acceptance status (this run, superseded below): search p99 and RSS missed; the W30-25 / W30-26 fix below
cleared search p99, and the 2026-10-26 section at the end of this file records the nightly evidence and
the remaining RSS and issue-rps work. No baselines recorded because no run passed every bar.

## W30-25 / W30-26 fix: before and after (100k certificates)

Cause (verified with timing logs in `refreshFromTable`, 20k run: every 2 s refresh returned all 20000
rows in ~185 ms, about 9 us a row, so ~1 s at 100k): the inventory's lazy `updated_at` refresh reads a
30 s window below the watermark, and after a bulk write that window covers nearly the whole table. Each
refresh re-read, PEM-decoded and x509-parsed every row only for `mergeLocked` to discard them, under
`refreshMu`, so every concurrent list/search caller stalled for the duration (the ~1 s tails on both
endpoints), and each pass allocated gigabytes of garbage (peak RSS). Fix: a narrow
`(fingerprint, updated_at, revoked)` scan decides which rows could win `rowSupersedes`, and only those
are fetched in full (`queryChangedCerts`).

| Metric | Before run 1 | Before run 2 | After run 1 | After run 2 | Bar |
|---|---:|---:|---:|---:|---|
| search p99 (ms) | 970.8 | 984.8 | 112.0 | 119.6 | < 500 |
| list p95 (ms) | 11.7 | 8.9 | 38.2 | 8.0 | < 300 |
| list max (ms) | 993 | n/a | 483 | 89 | |
| peak RSS (MiB) | 2489.4 | 2496.2 | 1704.1 | 1698.6 | < 2048 |
| issue rps at c=16 | 595.3 | 1023.5 | 287.2 | 1205.5 | >= 500 |

After-runs: same command and host as above, commit base `b4981ff0` plus this change. Issue rps varies
widely run to run (as it did before the fix); run 1 of the after pair fell below 500 and run 2 well
above, so that bar is not proven by this ticket. Residual RSS of ~1.7 GiB is the resident inventory
(~17 KiB per certificate: PEM, parsed x509 and item), which fits the bar at 100k but is the scaling limit
for larger estates (1M needs the lazy-parse redesign, not done here).

## Hosted nightly evidence and the RSS / issue-rps fix (2026-10-26)

Hosted `perf-regression` runs (GitHub `ubuntu-latest`, 4 vCPU, 100k certificates), nightly job log lines:

| Night | Code | Failing metric | Value | Other metrics |
|---|---|---|---:|---|
| 2026-10-21 | 1.0 | issue_rps_c16 | 481.8 (bar >= 500) | |
| 2026-10-23 | 1.0 | issue_rps_c16 | 313.9 | |
| 2026-10-25 | 1.0 | rss_mib_peak | 2099 (bar < 2048) | |
| 2026-10-26 | 1.1 | rss_mib_peak | 2121.7 | search p99 302.7, list p95 11.6, issue rps 797.1 |

So the job is not a 1.1 regression, and the stale "NOT MET" status above (search p99) no longer applies: search
p99 and list p95 pass on hosted runners. Two defects remained, both in the harness rather than the hub:

1. RSS. The bench started the hub without `GOMEMLIMIT`, but every supported deployment sets it to
   `1600MiB` against the 2Gi limit that the 2048 MiB bar represents (`docs/deployment.md` "Memory sizing",
   `docker-compose.yml`, `charts/kryptkeeper/values.yaml`). Unbounded, the Go GC lets startup hydration and
   refresh garbage lift RSS to ~2.1 GiB over a live heap that fits in 1.6 GiB. `bench.sh` now runs the hub
   with `GOMEMLIMIT=1600MiB` (`HUB_GOMEMLIMIT` overrides). This measures the hub as shipped; the bar is unchanged.
2. Issue throughput. One 5000-request pass (~6 s) on a runner shared by Postgres, the hub and the load tool is
   dominated by scheduling noise (287 to 1205 req/s across runs here, 314 to 797 on hosted nights). `bench.sh`
   now warms up (200 requests) and reports the median of three 3000-request passes, so one slow pass cannot
   decide the result; the bar is still >= 500 req/s.

Local check (Apple M4 Max, 64 GiB, shared with other sessions, so use relative RSS and not absolute rps;
hosted runners are slower), commit base `66b2f9c0`, `PG_IMAGE=docker.io/library/postgres:16`:

| Metric | Before (no GOMEMLIMIT, one pass) | GOMEMLIMIT only | After (both changes, run A) | After (run B) | Bar |
|---|---:|---:|---:|---:|---|
| peak RSS (MiB) | 2180.9 | 1646.2 | 1827.8 (+15k issued vs 5k) | 1810.0 | < 2048 |
| search p99 (ms) | 126.0 | 104.6 | 101.0 | 130.0 | < 500 |
| list p95 (ms) | 6.1 | 7.2 | 5.4 | 40.9 | < 300 |
| issue rps c=16 | 1386.5 | 1532.8 | 1610.3 (median of 1610, 1690, 1433) | 730.3 (median of 730, 815, 508) | >= 500 |

Run B shows the noise: the same code, minutes later under other sessions' load, ran at less than half the
rate, and one of its three passes (508) nearly touched the bar while the median stayed above it.
The `GOMEMLIMIT` cap did not cost latency. Not verified on a hosted runner; the next nightly is the check.
The RSS margin is ~200 MiB under the bar, so the lazy-parse inventory redesign above remains the real
scaling work.

## 1M certificates (no pass bar)

PENDING-RUN. Command: `bash tests/perf/bench.sh --certs 1000000 --no-bar --out perf-out-1m`
(or `workflow_dispatch` with `certs=1000000`). Expect about 25 GiB of hub RSS; run on a host sized
for it.
