# W23-02 — day-one CA hierarchy, timed

```
bash tests/live/ca-hierarchy/run.sh                       # compose mode, project kkw23ca
KK_BASE_URL=https://localhost:8080 KK_TOKEN=... KK_CACERT=ca.pem \
  bash tests/live/ca-hierarchy/run.sh                     # attach mode
```

Env: `OPENSSL_BIN`, `BUDGET_SECONDS` (900), `EXPECT_ALGS` (9), `REQUIRE_ALL=1`.

Discovers the algorithm set from the 400 body of `POST /api/v1/cas` with
`algorithm=DSA` (`supported_algorithms`), asserts the count is 9, then for each
algorithm creates root + issuing CA + a P-256 leaf and requires
`openssl verify -CAfile root -untrusted issuing leaf` to print OK. Writes
`last-run.json` (date, commit, openssl, per-algorithm result, elapsed, machine).

## Proves
- Every supported CA algorithm yields a chain a stock OpenSSL accepts.
- Wall-clock from `compose up` to the last verified leaf (image build excluded).

## Does NOT prove
- Pull/build time (done before the clock starts).
- Verification by non-OpenSSL clients (Windows/ADCS do not validate Ed25519; ML-DSA needs OpenSSL >= 3.5).
- Only the `kryptkeeper` service is started in compose mode (no dashboard, no Postgres).
- Compose mode sets `KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true`: the harness wants a
  root present before it builds the hierarchies (a hub with no CA now starts in first-run mode, `cmd/kryptkeeper/startup_ca.go`, but the protocol endpoints answer 503 until one exists).
