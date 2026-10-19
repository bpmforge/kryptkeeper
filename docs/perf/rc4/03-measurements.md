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

Acceptance status: 1 NOT MET (search p99 and RSS miss), 2 met (gate and nightly job in place,
edge unit-tested), 3 PENDING-RUN. No baselines recorded because no run passed every bar.

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

## 1M certificates (no pass bar)

PENDING-RUN. Command: `bash tests/perf/bench.sh --certs 1000000 --no-bar --out perf-out-1m`
(or `workflow_dispatch` with `certs=1000000`). Expect about 25 GiB of hub RSS; run on a host sized
for it.
