# RC3 measurements

Hub: current main (`26e17cac`), `APP_CERTIFICATE_PROVIDER=ca`, SQLite, `APP_AUDIT_PROVIDER=db`, TLS off,
own data dir, strong random secrets, port 8090, `APP_TRUSTED_PROXY_CIDRS=127.0.0.1/32`. Load tool is the
RC1 `harness/loadtool.go.txt` (base URL/email patched, optional pre-minted token to dodge the 10/min login
limiter). Client and server share one M4 Max, so ratios matter more than absolutes. Times are client-observed
over loopback.

## Step 1: 10k certificates

Seeding: 10,000 certs through `POST /api/v1/certificates`, c=6, 0 failures, 4.4 s total (RC1: 93 s at c=4),
p50 2.1 ms / p95 5.7 ms. Hub restarted before measuring (inventory hydrated from DB). Cert count at start of
the run: 10,501 (10,000 seed + probes + the earlier 10k run's 500 issues), so "10k" is really 10.5k to 11k.

| Case | p50 | p95 | rps |
|------|----:|----:|----:|
| GET /certificates?limit=25 c=1 | 245 us | 375 us | 3,694 |
| same c=8 | 782 us | 2.27 ms | 8,101 |
| GET /dashboard/summary c=1 | 153 us | 241 us | 4,285 |
| same c=8 | 745 us | 2.15 ms | 8,462 |
| POST issue c=1 | 0.64 ms | 0.83 ms | 1,123 |
| POST issue c=8 | 2.84 ms | 8.67 ms | 2,053 |
| reports/executive-summary | 9.4 ms | | |
| reports/compliance-evidence | 4.8 ms | | |
| reports/crypto-posture | 7.6 ms | | |
| reports/expiry-timeline | 3.9 ms | | |
| OCSP POST c=16 (20k req) | 428 us | 1.1 ms | 26,313 |
| CRL GET c=1 (empty CRL, 233 B) | 49 us | 75 us | 15,649 |

Executive summary `total_certs` = 11,001 immediately after 500 more issues on top of a list-meta total of
10,501: equals the real count (H2 fixed; RC1 said 100).

RSS: 172 MB idle after restart, 203 MB after list/dashboard/issue, 261 MB after reports, 262 MB at end.
(RC1: 176 idle, 252 after reports.) The issue path is about 30x faster than RC1 at the same size.

Note: the CRL here is empty (no revoked rows). A 5k-revoked CRL is measured in step 2.

## Step 2: 55k certificates (10.5k cloned x4 in SQL, plus 5,000 revoked in SQL for the CRL)

`clone-to-50k.sql.txt` ran unchanged against the current schema: 55,005 rows. Hub restarted so the
inventory hydrates from the DB. Same measurement script as step 1.

| Case | p50 | p95 | rps |
|------|----:|----:|----:|
| GET /certificates?limit=25 c=1 | 231 us | 344 us | 3,799 |
| same c=8 | 704 us | 2.12 ms | 8,928 |
| GET /dashboard/summary c=1 | 150 us | 207 us | 2,162 (one 60 ms cache refresh) |
| same c=8 | 707 us | 2.00 ms | 9,082 |
| POST issue c=1 | 0.56 ms | 0.74 ms | 1,216 |
| POST issue c=8 | 2.58 ms | 8.93 ms | 2,124 |
| reports/executive-summary | 56.2 ms | | |
| reports/compliance-evidence | 28.9 ms (max 40.9) | | |
| reports/crypto-posture | 46.7 ms | | |
| reports/expiry-timeline | 17.6 ms | | |
| OCSP POST c=16 | 407 us | 1.0 ms | 27,584 |
| CRL GET c=1 (5,000 revoked, 248 KB, cached) | 101 us | 177 us | 6,984 |

Executive summary `total_certs` = 55,505 = 55,005 + 500 issued during the run (real count; RC1 said 100).

RSS: 629 MB idle after restart (RC1: 484 MB at 52.6k), 706 MB after list/dash/issue, 964 MB after reports.

### 8-way issue burst at 55k

3,000 issues, c=8, 0 failures, p50 2.6 ms / p95 8.3 ms, 2,177 rps (RC1 before fix: 19 rps; after the
inventory fix: 98 rps). RSS sampled every 200 ms: 966 MB before, **970 MB peak**, 971 MB after.
AFTER_FIX recorded about 880 MB live heap and RSS near 3 GB for the same burst, so the per-issue
keystore KDF allocation (about 65 MB per sign) is gone. Peak is under half of the Helm 2Gi limit with
the 55k inventory resident. (The sampler took 7 samples because the burst finished in about 1.4 s.)

## Step 3: H1 audit trail (db provider, 55k-cert hub)

2,000 audited issues as 4 windows of 500 at c=8, 0 failures. Audit rows via `GET /api/v1/audit`
(`meta.total` and max `id`):

| | total | max id |
|--|------:|-------:|
| before | 22,986 | 22,986 |
| after | 25,287 | 25,287 |

Delta 2,301 = 2,000 `certificate.issue` + 300 audited `GET /audit` reads in my own latency probe + 1 login.
Every write is present, ids are gap-free (total == max id). RC1 H1: the file provider reset itself 27 times
and held 2.4 KB after about 3.5k events.

Issue p50 per window (c=8): 2.556, 2.562, 2.512, 2.532 ms; p95 8.4, 9.8, 8.5, 8.4 ms. Flat from the first
500 to the last 500 (RC1 file provider: GET latency 1.9 to 5.5 ms after 4k events).

`GET /audit?limit=25` c=1 p50: 0.39 ms before, 1.06 ms right after, then across six more 500-request runs
(each read is itself audited, so the table grew from 25.8k to 31k rows): 0.47/0.57/0.70, 0.37/0.65/1.02,
0.47/0.83/1.04 ms. It climbs within each fresh process-token run and drops at the start of the next, so it
tracks the run, not the row count; bounded at about 1 ms. Cause not isolated (candidates: per-principal
limiter, audited-read write contention); not a finding at this scale.

## Step 4: M4 (login spray) and M5 (many client IPs)

Harness note: the first pass of steps 1 to 4 used a load client built on Go's default transport
(`MaxIdleConnsPerHost=2`), which opens a new TCP connection for most requests at c>2. That exhausted the
host's ephemeral ports (16k sockets in TIME_WAIT) and broke the first M5 run (148k of 300k requests failed with
"can't assign requested address"; discarded). The client was fixed to a shared keep-alive transport
(TIME_WAIT then stayed under 60). Steps 1 to 3 completed without errors, but their latencies include
connection setup; a keep-alive re-run is in the section below. RC1 used the same default-transport tool, so
its c=8 numbers probably carry the same overhead.

**M4**, 300 bad logins at c=30, distinct `X-Forwarded-For` (hub at 55k certs, fresh restart): RSS 664 MB idle,
**969 MB peak, 989 MB after** (+325 MB; RC1: +325 MB, 258 to 583). p50 0.47 ms, p95 109 ms (Argon2id verifies
queueing), all 401. RSS did not fall 3 s later. Unchanged from RC1: login Argon2id concurrency is capped at
min(4, GOMAXPROCS) (`auth_login_state.go`), so the +325 MB is the RSS high-water mark from freed buffers, a
transient against a 2Gi limit, so MEDIUM. Same-IP spray: 8 x 401,
92 x 429 (limiter works), no RSS change.

**M5**, 200,000 OCSP POSTs from 200,000 random distinct client IPs (`APP_TRUSTED_PROXY_CIDRS=127.0.0.1/32`),
c=16, 39k rps, all 200: RSS 680 MB before, 874 MB peak/after, 3 s later 874 MB. A second 200,000 distinct IPs
(400k total, 4x the limiter's 100,000-key cap): 895 MB, +21 MB. Growth plateaus, consistent with the
bounded map. The hub exposes no limiter-size metric, so map size is not read directly; `go test
./internal/ratelimit -run 'Evict|Cap|Bound'` passes (`TestLimiter_MapIsCapped`, `TestLimiter_EvictsIdleKeys`,
`TestLimiter_EvictionKeepsLiveKeysLimited`). RC1: 200,000 keys retained after expiry (20.6 MB).

## Step 2 re-run with the keep-alive client (60.5k certs at start, fresh restart)

Same script after the transport fix, to check the connection-churn effect. p50 / p95:
list c=1 222 / 362 us, c=8 660 us / 2.12 ms (9,337 rps); dashboard c=1 136 / 188 us, c=8 725 us / 1.82 ms;
issue c=1 0.60 / 0.79 ms, c=8 2.67 / 9.56 ms (2,035 rps); executive-summary 42.4 ms (`total_certs` 61,005 = real);
compliance-evidence 41.8 ms; crypto-posture 35.2 ms; expiry-timeline 19.0 ms; OCSP c=16 275 / 624 us
(38.4k rps); CRL 5,000 revoked, 248 KB, 95 / 175 us. RSS 665 MB idle, 690 MB after list/dash/issue,
**1,066 MB after the four reports** (a 380 MB transient, not returned). The numbers match the first pass
within noise, so connection churn did not distort the latencies at these (sub-ms) scales. TIME_WAIT stayed under 90.

## Step 5: scheduler tick at 56k candidates

`RENEWAL_POLL_MINUTES=1`, `RENEWAL_THRESHOLD_DAYS=120` (every non-revoked cert is a candidate), 61k-cert
inventory (5,000 revoked). Log: `renewal scheduler: found 56005 renewal candidates (expired/skipped: 0)`
at startup and again 60 s later. RC1 logged 100 (H2). The hub log has 1 s resolution and both lines carry
the same second as startup, so the tick, including hydrating and the first anomaly/SLO/posture work,
completes in under 1 s wall; total process CPU was 1.45 s after two minutes (startup included).
RSS 858 MB. Exact tick duration is NOT MEASURED (no duration in the logs). For reference, RC1's
AFTER_FIX in-process benchmark: renewal tick at 50k = 18.9 ms; full pass 4.9 ms (before: 10.6 s).

## Step 6: UI bundle (`cd ui && npm ci && npm run build`)

Build succeeded (1,903 modules). `index-*.js` 803.32 kB, gzip 210.88 kB (RC1: 803.16 kB / 208.4 kB);
`index-*.css` 111.12 kB / 17.94 kB; three Geist woff2 fonts 14.7 / 15.3 / 28.4 kB. Single JS chunk,
Vite's >500 kB warning persists, no code splitting. Unchanged from RC1: acceptable.

## Not measured

- Step 3 file-provider (JSONL) repeat: the default is now the DB trail whenever a core DB exists
  (`ResolveAuditProvider`), so the RC1 failing configuration is no longer the default; skipped for time.
- Exact scheduler tick duration (see step 5). Postgres runtime; 1k targets / 100 agents; browser timing.
- Limiter map size read directly (no metric); inferred from RSS plateau and unit tests.
- The 10k pass used a hub that already held 10.5k to 11k certs and the client was not keep-alive (see step 4).
