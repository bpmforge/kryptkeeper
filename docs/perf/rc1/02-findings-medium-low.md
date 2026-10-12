# MEDIUM and LOW findings

## M1. Issuance cost grows linearly with inventory size

- Where: `caCertificateProvider.scanKeyReuse` (`certificate_ca_provider.go:272`, called after every issue,
  renew, ACME record and import) and `engineCAProvider.GetCA -> loadCertCounts ->
  NewDBActiveCertCountByCA` (`ca_engine_provider.go:28-53`, reached from `Engine.issueLeafCertificate`).
- Evidence: sequential `POST /certificates` p50 18.6 ms (0 certs), 33.8 ms (10.5k), 103.7 ms (52.6k);
  8 concurrent at 52.6k: p50 419 ms, 19 issues/s. A 6 s `sample` of the hub during sequential issuance at
  10.5k showed both `scanKeyReuse/spkiHash` and `loadCertCounts` repeatedly in the request-handler stacks
  (raw: `sample.txt` not kept; reproduce with `sample <pid> 6` while issuing). Benchmark of `scanKeyReuse` alone: 2.9 ms at 10k, 13.1 ms at 50k.
  The per-issue `SELECT ca_id, COUNT(*) ... GROUP BY ca_id` scans the table (no covering index on
  `(renewal_status, ca_id)`), which accounts for the rest of the slope. Attribution between the two is
  approximate; both are O(n) per issue.
- Impact: bulk onboarding of N certificates is O(N^2): 10 issues/s at 52k. `scanKeyReuse` holds the global
  write lock, so list p95 rose from 58 ms to 105 ms while issuing at 52.6k.
- Fix: maintain the SPKI -> fingerprints map incrementally; cache the per-CA counts and invalidate on write.
- Severity: MEDIUM (slow, not failing; sub-second at the stated scale).

## M2. Dashboard summary is a full-table scan on a single-connection store

- Where: `certs_summary_db_provider.go:111-130` (SQLite: `julianday(valid_until)` evaluated per row;
  `openConfiguredDB("sqlite", dsn, 1, 1)` so all callers serialize).
- Evidence: 11.9 ms at 10.5k, 58 ms at 52.6k sequential; 8 concurrent at 52.6k: 17 rps, p95 919 ms, max 1.9 s.
- Impact: the landing page calls it; a handful of open dashboards saturates it.
- Fix: compare `valid_until` as text against two precomputed bounds (uses `idx_cert_valid_until`), or
  cache the snapshot for a few seconds.

## M3. Every inventory list request copies and sorts the entire inventory

- Where: `certificate_ca_provider.go:688-740`. Page of 25: 4 ms / 6.2 MB at 10k, 22.9 ms / 31.2 MB at 50k.
- Evidence: live p50 30 ms at 52.6k; 193 rps at 8 concurrent versus 1128 rps at 10.5k. The Dashboard fetches
  up to 10 sequential pages (`ui/src/pages/Dashboard.tsx:286-307`) on every load: about 0.3 s and 310 MB of
  garbage per dashboard view at 50k, each page also writing an audit row.
- Fix: as H3. Also have the Dashboard use the summary endpoint plus a server-side expiry histogram.

## M4. Argon2id login verification has no global concurrency bound

- Where: `auth_password.go:72,145` (19 MiB, t=2, p=1 per verify). The only guard is a per-client-IP limit of
  10 per minute (`handlers_auth.go:63`), which does not bound parallelism across addresses.
- Evidence: 60 wrong-password logins, 30 concurrent, distinct `X-Forwarded-For` (trusted-proxy env set):
  RSS 258 MB -> 583 MB, p95 85 ms. A single address can still start 10 verifies at once (about 190 MB).
- Impact: unauthenticated memory amplification; with the 256Mi chart limit a small login spray is an OOM.
  Behind a proxy without `APP_TRUSTED_PROXY_CIDRS` all users share one 10/min bucket (functional, not perf).
- Fix: bounded semaphore around verification (for example 2 x GOMAXPROCS), returning 429/503 when full.

## M5. `ratelimit.Limiter` never evicts keys

- Where: `internal/ratelimit/ratelimit.go:47-70`. Keys are pruned only when the same key returns. Used by
  the public ACME, OCSP, CRL, EST, SCEP, CMP, WSTEP and XCEP endpoints (`cmd/kryptkeeper/main.go:518-525`).
- Evidence: 200,000 distinct keys stay resident after the window expires: 20.6 MB, 103 B/key
  (`TestPerfBucketGrowth`). One IPv6 /64 supplies unlimited keys.
- Impact: slow unbounded memory growth on internet-facing endpoints. The authenticated limiter
  (`auth_rate_limit.go:86-128`) does sweep a bounded 128 keys per call and is fine.
- Fix: periodic sweep or LRU cap, as the authenticated limiter does.

## M6. Renewal scheduler is N+1 per candidate (hidden today by H2)

- Where: `renewal_scheduler.go:456-515`. Per candidate with an owner: up to 3 `IsSilenced` queries (cert, CA,
  template) plus 1 `LastAlertedAt`, every tick. Auto-renew targets add `installState`, one audit query of up to
  100 rows per candidate (`:669`).
- Evidence: not measurable live because the sweep only sees 100 certs. CPU-only sweep (list, parse, filter) is
  20 ms at 50k as shipped; corrected to see all certs it would be about 23 ms list + 15 ms loop. At
  `RENEWAL_POLL_MINUTES=1` with 5k candidates inside the window that is about 20k point queries per minute
  on single-connection stores.
- Fix: load silences and cooldowns into maps once per tick; ask the DB for candidates by `valid_until`
  (`idx_cert_valid_until` exists) instead of listing everything.

## M7. Audit table grows without bound; list query scans

- Where: `audit_db_provider.go:303-330`. Every authenticated request, including reads, writes a row, and
  append-only triggers (`:68-74`) block deletion, so there is no retention path.
- Evidence (SQLite, 1M synthetic rows, same index set): `ORDER BY timestamp DESC, id DESC LIMIT 25` 89 ms;
  filtered by action 114 ms; `COUNT(*)` is cheap. The plan is `SCAN ... USING COVERING INDEX
  idx_audit_timestamp` plus a temp B-tree for the `id` term. Postgres not measured.
- Fix: an index on `(timestamp DESC, id DESC)`; do not audit successful list/summary reads (or sample them);
  document a partition/archive strategy compatible with the append-only rule.

## M8. CRL cache invalidation is O(revoked) per revoke

- Where: `crl/generator.go:150`. Each revoke re-queries the revoked set for every cached CA to decide which
  cache entry to drop. First CRL build at 5.1k revoked took 41 ms and is 253 KB; cached fetch 0.1 ms.
  Bulk revoke of N certificates is therefore O(N x revoked). Not measured under bulk revoke; complexity only.
- Fix: invalidate by CA id (the caller knows it) without re-querying.

## M9. OCSP cache flush-all when full

- Where: `ocsp/responder.go:211-213`. At 10,000 entries the whole map is replaced, so a large relying-party
  population causes periodic simultaneous misses. Cache hit 0.07 ms; a miss costs one SQLite point lookup on
  `idx_cert_serial_ca` plus one ECDSA signature (under 0.5 ms observed). Low practical impact; use LRU.

## LOW and informational

- L1. UI ships as one 803 KB (211 KB gzip) chunk with no route splitting. See `04-ui-bundle.md`.
- L2. No goroutine or heap metrics on `/metrics` and no pprof, so leaks cannot be diagnosed in the field.
- L3. Audit file default path `./var/bootstrap-audit.json` is relative to the working directory (H1).
- L4. `clientip.FromEnv()` is rebuilt per audit event (`audit_events.go:136`): 333 ns, 9 allocs. Negligible.
  `NewCustomRoleStoreFromEnv` is called once at server build (`server.go:100,129`), not per request.
- L5. `ListCertificates` ignores `TemplateID`, `Grades` and `Order` from `CertificateListQuery`
  (`certificate_ca_provider.go:688-720`). Correctness, noted in passing.

## Checked and fine

- Indexes: `certificates` has indexes on serial+ca (unique), valid_until, risk_score, grade, renewal_status,
  team, ca, common_name, revoked_at, subject_dn, and the validity window; `audit_log` has timestamp,
  resource, actor, outcome+timestamp, tenant. The scheduler's `installState` query uses `idx_audit_resource`.
  The `certificates` list is served from memory, so the missing `created_at` index only matters once M3 is fixed.
- SSE: 3 streams per principal, heartbeat 15 s, idle 300 s, max life 1800 s (`handlers_sse.go:17-24`).
- SIEM forwarder: bounded channel, drops and counts when full, never blocks (`siem_integration.go:205-221`).
- Replay and nonce state: ACME nonce service capped at 10,000 with ordered eviction (`acme/nonce.go`); CMP replay
  cache capped by `max` and `ttl` with oldest-first eviction (`cmp/replay.go:27-70`); SCEP challenges live in a
  store, hashed, one-time. EST and WSTEP hold no request-keyed maps. Code review only.
- Scanner concurrency: 50 default, deep scan probes capped at 100 (`discovery/scanner`).
- Authenticated rate limiter: bounded sweep (128 keys per call); report endpoints limited to 60 per minute per principal.
- Start-up: hydrate of 52.6k certificates took about 1 s.
- Targets (1k) and agents (100): the scheduler reads the managed-target list once per tick; no per-request
  scan of either was found. Not load-tested.
