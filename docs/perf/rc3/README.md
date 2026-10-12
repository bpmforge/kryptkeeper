# Kryptkeeper RC3 performance re-scan

Candidate: `origin/main` at `26e17cac`. Scan date 2026-10-10. Read-only on code. M4 Max, SQLite, CA
provider, DB audit provider, own hub on :8090, keep-alive load client (RC1 harness, patched).

## Verdict: PASS

Owner gate: RC1 HIGHs H1-H4 verified fixed by measurement; no new HIGH at 10k-60k certs; no unbounded
growth. All three hold. Residual MEDIUM items are listed below.

## RC1 vs now (p50, ms unless noted)

| Case | RC1 10.5k | RC3 10.5k | RC1 52.6k | RC3 55-60k |
|------|----------:|----------:|----------:|-----------:|
| list limit=25 c=1 | 4.9 | 0.25 | 30.1 | 0.22-0.23 |
| list c=8 | 6.4 | 0.78 | 40.3 | 0.66-0.70 |
| dashboard summary c=1 | 11.9 | 0.15 | 58.1 | 0.14-0.15 |
| dashboard summary c=8 | 82 | 0.75 | 403 | 0.71-0.73 |
| issue c=1 | 33.8 | 0.64 | 103.7 | 0.56-0.60 |
| issue c=8 (rps) | 88.6 (89) | 2.8 (2,053) | 418.6 (19) | 2.6 (2,035-2,177) |
| executive-summary `total_certs` | 100 (wrong) | 11,001 (real) | 100 (wrong) | 55,505-61,005 (real) |
| compliance-evidence | 357 | 4.8 | 13,557 | 29-42 |
| crypto-posture | 326 | 7.6 | 2,496 | 35-47 |
| expiry-timeline | 325 | 3.9 | 2,494 | 18-19 |
| OCSP c=16 (rps) | 27.6k | 26.3k | same | 27.6k-38.4k |
| CRL GET, 5k revoked, 248 KB | | | 0.10 | 0.095-0.10 |
| RSS idle | 176 MB | 172 MB | 484 MB | 629-665 MB |
| RSS after reports | 252 MB | 261 MB | 1,022 MB | 964-1,066 MB |
| RSS peak, 8-way issue burst | | | 1.3 GB (3 GB after inventory fix) | 970 MB |
| Renewal tick candidates | 100 | | 100 | 56,005 |

## Findings against RC1 HIGHs

- H1 (audit): fixed. 2,000 concurrent audited writes (c=8): 2,000 rows present (total 22,986 to 25,287
  with 301 expected extras from my own audited reads and login), ids gap-free, issue p50 flat at
  2.51-2.56 ms across four 500-write windows. DB provider is the default with a core DB.
- H2 (clamp): fixed. Executive summary equals the real count; renewal sweep sees 56,005.
- H3 (O(n^2) reports): fixed. compliance-evidence 13.6 s to 29-42 ms at 55k; list/dashboard sub-ms.
- H4 (memory): fixed at the sizing level. Helm now requests 512Mi, limits 2Gi, `GOMEMLIMIT` 1600MiB. Worst
  measured RSS at 61k certs is 1,066 MB (after reports), 970 MB for an 8-way issue burst, versus
  the 3 GB seen before the keystore-KDF fix.

## Remaining items (none HIGH)

1. MEDIUM: 30-way bad-login spray still adds about 325 MB RSS (664 to 989 MB) from Argon2id
   verification buffers. Login KDF concurrency is capped at min(4, GOMAXPROCS) (`auth_login_state.go`); the
   +325 MB is the RSS high-water mark from buffers that were freed but not returned to the OS.
2. MEDIUM: idle RSS scales at about 11 KB per cert (484 MB at 52.6k in RC1, 629-665 MB at 55-60k now).
   Extrapolating, the 2Gi limit is reached somewhere above 100k certs; report calls add a 300-380 MB transient.
3. LOW: the four reports retain about 280-380 MB RSS after a call (Go does not return freed pages).
4. LOW: `GET /audit` p50 wobbles 0.4-1.0 ms within a run; not tied to row count. Cause not isolated.
5. INFO: the hub still has no goroutine/heap/limiter-size metric and no pprof, so limiter growth and goroutine
   leaks are inferred from RSS plateau (400k distinct IPs: +215 MB then +21 MB) and unit tests.
6. INFO: the UI is still one 803 kB (211 kB gzip) chunk. Acceptable.
7. INFO: scheduler tick duration is not logged; it is under the 1 s log resolution at 56k candidates.

## Harness caveat

The RC1 load tool uses Go's default transport (2 idle connections per host), so at c>2 it churns TCP
connections. This run exhausted the host's ephemeral ports (16k TIME_WAIT), invalidating one M5 attempt, and the
tool was fixed to keep-alive. Re-running the 60k suite showed the same latencies as the first pass, so the
RC3 table is not affected, but RC1's c=8 numbers probably include connection-setup overhead.

## Files

[03-measurements.md](03-measurements.md): per-step numbers and NOT MEASURED list. Method and harness are
unchanged from [../rc1/05-method.md](../rc1/05-method.md); the only tool change is the shared keep-alive
transport and an optional pre-minted token (login limiter is 10 per minute).
