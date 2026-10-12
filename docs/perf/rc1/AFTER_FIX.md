# RC1 perf scan: after the inventory-iteration fix

Branch `kk/rc1-fix-inventory-iter`. Fixes H2, H3, M1, M2, M3, M6 from the scan
(`01-findings-high.md`, `02-findings-medium-low.md`). Same harness and method as
`03-measurements.md`: local hub, `APP_CERTIFICATE_PROVIDER=ca`, SQLite,
`APP_AUDIT_PROVIDER=db`, 10,000 issued certs, cloned in SQL to 50,000.
Client and server share one M4 Max, so ratios matter more than absolutes.

## What changed

- `ForEachCertificate(ctx, provider, query, fn)` is an unclamped iterator. The CA
  provider walks an ordered index in 1,024-row chunks and holds no lock while `fn`
  runs. Providers without it get a paging fallback. `ListCertificates` keeps the
  100-row HTTP cap.
- Every internal full-inventory caller uses it (renewal, posture, executive summary,
  evidence, PQC, agility, blast radius, code-signing, CBOM, CA key compromise, bulk
  revoke, anomaly, SLO, CT monitor, report helper, tenant-filtered list).
- The CA provider keeps its list order (created_at desc, fingerprint asc), an SPKI
  index and per-CA active counts up to date on every write, so a page is a slice
  window, key-reuse is O(holders), and the per-issue `GROUP BY ca_id` is gone.
- Renewal tick memoizes silence lookups per tick. Dashboard summary is cached 2 s.

## Live results (hub, ms unless noted)

| Case | 10k before | 10k after | 50k before | 50k after |
|------|-----------:|----------:|-----------:|----------:|
| reports/compliance-evidence p50 | 351 | 10.3 | 14,006 | 39.6 |
| reports/executive-summary p50 | 12.7 | 7.0 | 72.5 | 44.5 |
| executive-summary `total_certs` | 100 (wrong) | 10,000 | 100 (wrong) | 50,000 |
| GET /certificates?limit=25 c=1 p50 / p95 | 3.63 / 5.80 | 0.27 / 0.77 | 28.8 / 36.5 | 0.34 / 0.65 |
| GET /certificates?limit=25 c=8 p50 / p95 | 7.15 / 13.2 | 0.81 / 2.35 | 37.5 / 57.0 | 0.74 / 2.22 |
| GET /dashboard/summary c=1 p50 | 10.2 | 0.27 | 60.2 | 0.21 |
| GET /dashboard/summary c=8 p50 / p95 | 70.9 / 155.7 | 0.82 / 4.4 | 383.9 / 815.0 | 0.87 / 3.0 |
| POST issue c=1 p50 | 33.9 | 21.8 | 104.9 | 19.3 |
| POST issue c=8 p50 / rps | 86.7 / 89 | 65.3 / 116 | 418.7 / 18 | 78.5 / 98 |
| Renewal tick candidates seen (log) | 100 | 10,000 | 100 | 50,000 |

Reports were run with `RENEWAL_THRESHOLD_DAYS=120` so every cert is a renewal candidate.

## Go benchmarks (in-process, synthetic items, ms per op)

| Case | 10k before | 10k after | 50k before | 50k after |
|------|-----------:|----------:|-----------:|----------:|
| List page of 25 | 3.49 (6.2 MB) | 0.014 (16 KB) | 21.8 (31 MB) | 0.010 (16 KB) |
| List page of 25, `q` filter | | | 8.6 | 1.6 |
| Full pass (anomaly/SLO tick shape) | 330 | 1.0 | 10,573 | 4.9 |
| Report collect (`reportVisibleCertificates`) | 325 | 4.5 | 10,655 | 17.7 |
| Renewal tick, 100% candidates | 3.3 (sees 100) | 4.1 (sees 10k) | 21.1 (sees 100) | 18.9 (sees 50k) |

The renewal tick looks the same cost but now does the real work: it sees every
certificate rather than 100.

## Caveats

- Cloned rows share certificate bytes, as in the scan; only key-reuse flags are affected.
- RSS is noisy and not a regression signal here. Each issuance allocates about 65 MB
  inside the keystore/engine in both trees (measured per call in-process). With the
  global-lock O(n) work gone, 8 concurrent issues now really run in parallel, so more of
  that per-sign garbage is live at once: live heap after an 8-way issue burst at 50k was
  about 880 MB after versus about 365 MB before, and RSS peaked near 3 GB versus 1.3 GB.
  That per-issue allocation is the next thing to look at for H4 sizing.
  Superseded: commit 155acbac removed the per-issue keystore KDF (IssueCertificate bench
  67.2 MB/op to 28 KB/op per its message), and `docs/perf/rc3/03-measurements.md` records
  an 8-way issue burst at 55k certificates peaking at 970 MB RSS.
- Per-CA counts now come from the in-memory inventory. Rows written straight to the
  `certificates` table by other paths (discovery inserts, the revocation backfill) are not
  counted until restart, the same visibility the inventory itself has.
- The dashboard summary can be up to 2 s stale.
- Scheduler cooldown lookups (`LastAlertedAt`) are still one query per owned candidate;
  only silence lookups were batched.
