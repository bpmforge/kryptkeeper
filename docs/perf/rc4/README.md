# RC4 perf: Postgres 100k-cert benchmark (W30-21)

One script reproduces everything here:

```bash
bash tests/perf/bench.sh --certs 100000 --out perf-out      # writes perf-out/results.json
KK_PERF_RESULTS=$PWD/perf-out/results.json go test ./tests/perf/... -count=1 -v
```

`bench.sh` starts `postgres:16.15` in podman (`shared_buffers=1GB`, named volume, random password,
free port), builds and starts the hub against it, seeds 500 real certificates through the API, clones
those rows inside Postgres up to N (`pgcrypto` fingerprints and serials, `created_at` spread over
730 days, every other column copied), asserts the row count is within 500 of N, restarts the hub for
cold caches, then measures. It always exits 0 after writing `results.json`; the Go test judges it.
Teardown (trap) removes the container, volume, hub and temp dirs. `PG_IMAGE` overrides the image.
The script is source-able (`perf_up`, `perf_measure`, `perf_down`) for `storm.sh` (W30-22).

## Method

| Metric | Measurement (after a 200-request warm-up) |
|---|---|
| `search_p99_ms` | `GET /api/v1/search?q=host-7.perf.example.com`, n=3000, c=8, p99 |
| `list_p95_ms` | `GET /api/v1/certificates?limit=25`, n=3000, c=8, p95 |
| `issue_rps_c16`, `issue_failures` | `POST /api/v1/certificates`, n=5000, c=16; rps and count of non-2xx or transport errors |
| `rss_mib_peak` | `ps -o rss=` of the hub every 2 s from the start of measurement, max in MiB |

The load tool is a patched copy of `docs/perf/rc1/harness/loadtool.go.txt` (p99 column, hub address
from `HUB_BASE`, keep-alive pool sized to c so ephemeral ports are not exhausted; each patch is
asserted). The `.txt` source is not edited. The search CN belongs to a seed row, so the cloned rows
make it match many certificates.

Caveats: client, hub and Postgres share one host, so numbers include load-generator contention. The
hub runs natively; only Postgres is in a container (on macOS that is inside the podman VM). RC1/RC3
numbers are SQLite and are not comparable.

## Gate

`tests/perf/budgets.json` holds the pass bars (acceptance 1) and, per metric, a `baseline` (the last
accepted measurement). `go test ./tests/perf/...` fails a 100k results file that misses a bar or
regresses more than 20% against a non-null baseline; a results file with `certs >= 1,000,000` is
published without a bar. Without `KK_PERF_RESULTS` the results-driven tests skip, so `go test ./...`
stays green. The 20% edge (19% passes, 21% fails) is unit-tested with synthetic data.

**Baselines are all `null` on purpose.** The values in `budgets.json` are the spec's pass bars, not
measurements. The first 100k run missed two bars (see `03-measurements.md`), so there is no accepted
measurement to record yet. Set `baseline` per metric after a run that passes every bar.

## Verdict (100k, first run, 2026-10-16)

| Metric | Bar | Run 1 | Run 2 | Verdict |
|---|---|---:|---:|---|
| search p99 | < 500 ms | 970.8 ms | 984.8 ms | FAIL |
| list p95 | < 300 ms | 11.7 ms | 8.9 ms | pass |
| issuance c=16 | >= 500/s, 0 failures | 595.3/s, 0 | 1023.5/s, 0 | pass |
| peak RSS | < 2048 MiB | 2489.4 MiB | 2496.2 MiB | FAIL |

Environment: Apple M4 Max, 64 GiB, macOS 27.0.1, Go 1.27.1, `postgres:16` image = PostgreSQL 16.15
(Debian) in podman; commit `5bd2ce33` plus this ticket's uncommitted files. Nightly (self-hosted
podman runner) will record its own environment in `results.json`.

## 1M certificates

Stretch run, manual: `workflow_dispatch` with `certs=1000000`, or `bash tests/perf/bench.sh --certs
1000000 --no-bar`. Published without a pass bar; PENDING-RUN (not executed here: at the measured
~25 MiB of hub RSS per 1k certificates it would need about 25 GiB). Do not claim 1M support from
this ticket.
