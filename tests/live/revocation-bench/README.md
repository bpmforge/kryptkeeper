# Revocation benchmark (W23-52)

Measures CRL generation at scale, OCSP latency under open-loop load, and
revoke-to-visible time on a second replica. Results and published targets:
`docs/release/REVOCATION_BENCH_v0.11.md`.

```bash
# in-process legs (no services): CRL at 10k/100k/1M revocations, OCSP cold+warm at 500 rps
bash tests/live/revocation-bench/run.sh

# with two running replicas on one DB (see below)
KK_A_URL=... KK_B_URL=... KK_B_REVOCATION_URL=... KK_TOKEN=... \
  [KK_BENCH_OCSP_URL=... KK_BENCH_LEAF_PEM=... KK_BENCH_ISSUER_PEM=...] \
  bash tests/live/revocation-bench/run.sh replica
```

`run.sh` writes `results/<UTC>.json`, prints markdown tables and exits 1 when a
measured criterion fails. A leg that did not run is `null` in `pass`, never
true. `go test` alone skips everything unless `KK_LIVE_REVBENCH=1`.

Env: `KK_BENCH_SIZES` (default `10000,100000,1000000`), `KK_BENCH_OCSP_RPS`
(500), `KK_BENCH_OCSP_SECONDS` (30), `KK_BENCH_REPLICA_CERTS` (5),
`KK_BENCH_OUT`, `KK_BENCH_NOTE` (free text stored in the JSON), `KK_DB_ENGINE`
(label), `KK_CACERT` (CA bundle for HTTPS API URLs), `KK_CA_ID`,
`KK_A_REVOCATION_URL` (A's plain-HTTP base; defaults to `KK_A_URL`),
`KK_BENCH_XFF=1` (see the rate limiter note). `KK_TOKEN` is only sent as a
bearer header and never printed.

## Rate limiter

The hub limits CRL fetches to 30/min and OCSP to 200/min per client IP
(`cmd/kryptkeeper/main.go`). One load generator at 500 rps would only measure
that limiter (429s). For the attached and replica legs, run the hubs with
`APP_TRUSTED_PROXY_CIDRS=127.0.0.1/32` and set `KK_BENCH_XFF=1`: the client then
puts a distinct synthetic `X-Forwarded-For` on every request. Results produced
this way say so in their `env.note`.

## What this does NOT prove

- Loopback, not a network: no latency, loss or TLS cost.
- The in-process OCSP status lookup is a map; DB cost appears only in the
  attached and replica legs. The attached leg uses one leaf, so after the first
  request it measures the hub's response cache, not a DB lookup per request.
- One CA, ECDSA P-256 signer. An HSM or cloud-KMS signer is slower per signature.
- The replica leg uses a shared Postgres and keystore directory on one machine;
  it shows the revocation-stamp poll (`KRYPTKEEPER_REVOCATION_SYNC_INTERVAL`,
  5s default) works, not cross-datacentre behaviour.
- Numbers depend on the machine and its load at the time; the JSON records both.
