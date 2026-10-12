# Method and reproduction

## Rules followed

Measure before claiming. A finding is HIGH only with a measurement or a concrete complexity argument tied
to the hot path. Code was not modified; temporary test files used for benchmarks were removed from the
tree and kept as `harness/*.txt`. No push, PR or tag.

## Environment

- Worktree branch `kk/rc1-perf-scan` at `d74edf3`; `go build -o dist/kryptkeeper ./cmd/kryptkeeper`.
- Hub started by `harness/start-hub.sh.txt` (copy to a `.sh`, point it at a scratch data dir). It generates
  random pepper, keystore passphrase, signing secret and login password into an untracked `secrets.env`;
  none are printed or committed. `KRYPTKEEPER_TLS_DISABLE=true`, `APP_CERTIFICATE_PROVIDER=ca`,
  `RENEWAL_POLL_MINUTES=1`, `APP_AUDIT_PROVIDER=db` (the H1 run used the default `file`),
  `APP_TRUSTED_PROXY_CIDRS=127.0.0.0/8` (only to vary `X-Forwarded-For` past the per-IP limiters).
- The hub was stopped at the end of the scan.

## Existing harness

No Go benchmarks existed (`grep -rl "func Benchmark"` over the repo is empty). The nightly workflow
(`.github/workflows/nightly-scale-and-protocol.yml`) runs `scripts/test/run.sh` protocol, integration and
smoke suites plus `go test ./...`: functional, not scale. No seeder script exists. `scripts/dev/local-review-env.sh`
was the model for the start script (it hard-codes weak dev secrets, so it was not used directly).

## Tools

- `loadtool.go.txt`: login, `seed` (n certificates at concurrency c), `bench` (any path, method, body file,
  content type, optional `X-Forwarded-For` randomization), `revoke`. Prints p50/p95/max/rps/status codes.
- `bootstrap_perf_test.go.txt`: copy to `internal/bootstrap/zz_perf_scan_test.go`, then
  `go test ./internal/bootstrap -run '^$' -bench . -benchtime 3x`, and `-run TestPerfLimitClamp -v`.
- `ratelimit_perf_test.go.txt`, `clientip_perf_test.go.txt`: same pattern in their packages.
- `clone-to-50k.sql.txt`: `sqlite3 <data>/kryptkeeper.db < clone-to-50k.sql.txt` with the hub stopped, then restart.
- Profile sampling: macOS `sample <pid> 6 -file out.txt` while a sequential issue loop runs.
- OCSP request made with `openssl ocsp -issuer ca.pem -cert leaf.pem -reqout ocsp.req -no_nonce`.

## Caveats

- Client and server share one machine; absolute numbers are optimistic versus a container with 500m CPU
  (chart default). Ratios and growth curves are the signal.
- Cloned rows (52.6k case) share certificate bytes; SPKI-sharing affects only `KEY_REUSE` flags.
- The login limiter (10 per minute per IP) throttled the harness itself several times; restarting the hub
  clears it. Some runs were repeated for that reason.
- RSS overstates live heap because Go retains freed pages. There is no `runtime.MemStats` exposure to check.
- Postgres was reviewed statically (query shapes, indexes in `internal/db/migrations/postgres`) and not run.
