# Kryptkeeper v0.9.0-rc.1 performance scan

Candidate: `d74edf3`. Scan date 2026-10-10. Read-only on code: nothing was optimized.
Hardware: Apple M4 Max, SQLite default (Postgres checked statically only).

## Verdict: FAIL

PASS was defined as: no HIGH (user-visible slowdown/timeout or resource blow-up at
10k-50k certificates, 1k targets, 100 agents) on core paths; no unbounded
memory/goroutine growth; UI production bundle reasonable.

Four HIGH findings, so the gate fails. The UI bundle is acceptable. No thread or
goroutine leak was observed (OS thread count flat at 23 across all runs), but the
hub exposes no goroutine or heap metric and no pprof, so that is weak evidence.

### Blockers (HIGH)

| ID | Finding | Evidence |
|----|---------|----------|
| H1 | Default audit provider is a JSON file rewritten whole on every event, with no lock. It corrupts and resets under concurrency, and every request slows as it grows. | 27 "invalid JSON; resetting file" at 4 concurrent clients; audit file held 2.4 KB after about 3.5k events; GET latency 1.9 -> 5.5 ms after 4k events |
| H2 | `ListCertificates` silently clamps `Limit` to 100. Sixteen call sites ask for 10,000 to 50,000 and get 100. | Measured: executive summary on a 10,000-cert hub says `total_certs: 100`; renewal sweep over a 50k provider logs "found 100 renewal candidates". By inspection only (not run): CA-compromise response (`key_lifecycle.go:362`, no Limit) flags 25 certs; bulk revoke (`pending_action_exec.go:63`) gets 100 of 500 |
| H3 | Report and scheduler paths page 100 at a time, and every page copies and sorts the whole inventory (O(n^2/100)). | Compliance-evidence 0.36 s at 10.5k -> 13.6 s at 52.6k (server WriteTimeout is 15 s); anomaly/SLO tick = 11.1 s CPU at 50k |
| H4 | Default Helm memory limit is 256Mi. Measured idle RSS at 52.6k certs is 484 MB; at 10.5k it reaches 252 MB under report load, within a login spray of the limit. | 484 MB idle and 1.0-1.5 GB under load at 52.6k (vs 256Mi limit); 176 MB idle / 252 MB after reports at 10.5k; +325 MB from a 30-way login spray |

Fixing H2 without fixing H3 turns a silent truncation into a timeout, so they have to land together.

### Measured numbers (p50 / p95, ms; sequential unless noted)

| Operation | ~0 certs | 10.5k certs | 52.6k certs |
|-----------|---------:|------------:|------------:|
| GET /certificates?limit=25 | - | 4.9 / 7.2 | 30.1 / 38.6 |
| same, 8 concurrent | - | 6.4 / 10.6 (1128 rps) | 40.3 / 58.6 (193 rps) |
| GET /certificates?q=host-4 | - | 1.3 / 3.5 | 10.9 / 17.3 |
| GET /dashboard/summary | - | 11.9 / 12.4 | 58.1 / 60.0 |
| same, 8 concurrent | - | 82 / 209 (81 rps) | 403 / 919 (17 rps) |
| POST issue (CSR) | 18.6 / 20.9 | 33.8 / 35.5 | 103.7 / 115.4 |
| POST issue, 8 concurrent | - | 88.6 / 116.7 (89 rps) | 418.6 / 587.4 (19 rps) |
| GET reports/executive-summary (wrong: 100 certs) | - | 11.7 / 13.7 | 77.6 / 80.7 |
| GET reports/compliance-evidence | - | 357 | 13,557 (max 14,827) |
| GET reports/crypto-posture, expiry-timeline | - | 326 | 2,496 |
| OCSP POST (cache hit) | - | 0.07 / 0.12 | 0.07 / 0.12 |
| OCSP POST, 16 concurrent | - | 0.39 / 0.95 (27.6k rps) | same |
| CRL GET, 5.1k revoked (253 KB), cached | - | - | 0.10 / 0.21 |
| CRL first generation (5.1k revoked) | - | - | 41 |
| Renewal sweep CPU (as shipped, sees 100 certs) | - | - | 20 |

Details: [03-measurements.md](03-measurements.md).

### Top 5 improvements

1. Make the audit trail a real append-only store by default (DB when a DB is configured, or a locked JSONL append). Closes H1.
2. Replace the clamped list API for internal callers with a streaming or cursor iterator (`ForEachCertificate`), and migrate the sixteen call sites. Closes H2 and, with item 3, H3.
3. Stop copy-and-sorting the inventory per request: keep a created_at-ordered index in memory, or query the DB with `LIMIT/OFFSET` and an index on `(created_at DESC, fingerprint)`. Cuts list from 30 ms to well under 5 ms at 50k and removes 31 MB per request.
4. Raise chart defaults (memory request 512Mi, limit 1-2Gi), set `GOMEMLIMIT`, and cap concurrent Argon2id verifications (bounded semaphore). Closes H4.
5. Remove O(n) work from the issuance path: the per-issue `GROUP BY ca_id` count in `engineCAProvider.GetCA` and the full `scanKeyReuse` rebuild under the global write lock (issue 18.6 -> 104 ms from 0 to 52.6k certs).

### Index

- [01-findings-high.md](01-findings-high.md): H1-H4 with file:line, evidence, fix
- [02-findings-medium-low.md](02-findings-medium-low.md): M1-M9, L1-L5, and checked-and-fine items
- [03-measurements.md](03-measurements.md): raw numbers, benchmarks, RSS
- [04-ui-bundle.md](04-ui-bundle.md): production bundle report
- [05-method.md](05-method.md): how it was measured and how to reproduce
- `harness/`: load tool, benchmark tests and SQL used (`.txt` so they are not compiled into the module)
