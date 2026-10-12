# HIGH findings

## H1. Default audit provider loses events under concurrency and slows every request as it grows

- Where: `internal/bootstrap/audit_file_provider.go:113-145` (`AppendEntry`), `:34` (`ListEntries`);
  default chosen at `internal/bootstrap/audit_provider.go:81-83`. Neither `docker-compose.yml`
  nor `charts/kryptkeeper/templates/configmap.yaml` sets `APP_AUDIT_PROVIDER`, and `env.example:65`
  documents `file` as the default. Every handler calls `emitAuditEvent` (`audit_events.go:40-77`),
  including plain GETs, so every API call performs one append.
- What it does: read the whole JSON file, unmarshal, prepend, marshal, `os.WriteFile`. No mutex, no
  atomic rename. If unmarshal fails (a reader saw a half-written file) it logs and starts from an empty
  slice.
- Evidence (hub in default config, 4 concurrent issuers, 3,000 issuances):
  - 27 log lines `audit file append fallback: invalid JSON; resetting file`.
  - `var/bootstrap-audit.json` was 2,458 bytes at the end. Each event is about 270 bytes, so roughly
    3,500 events had been written and about 99.8 percent were gone.
  - Sequential `GET /certificates?limit=25`, 1,000 requests per step, audit file growing 270 KB per step:
    p50 1.9 ms, 3.0, 4.2, 5.5 ms (file 0.27, 0.54, 0.81, 1.08 MB). About 1.1 ms per 1,000 events per
    request; one full file read, parse and rewrite per request. At 100k events (27 MB): about 110 ms and
    tens of MB allocated per request. At 1M events: over a second per request.
  - Comparison, same load with `APP_AUDIT_PROVIDER=db`: 10,000 issuances at 4 concurrent, no loss,
    latency flat apart from the issue-path growth in M1.
- Impact: violates the "audit records are append-only" rule in `CLAUDE.md` on the out-of-the-box
  configuration; concurrency of 2 is enough. The renewal retry history (`installState`,
  `renewal_scheduler.go:669`) is also read from this log, so retry state is lost with it. In a container
  the default path `./var/` is also ephemeral.
- Fix: default to the DB provider whenever a DB is configured (ca mode always has one), or make the file
  provider a locked JSONL append with a reader that tolerates a torn tail. Fail closed rather than reset.
  Add a startup warning for `file`.
- Severity: HIGH (data loss plus unbounded per-request cost on the default path).

## H2. `ListCertificates` clamps Limit to 100; internal callers believe they get everything

- Where: clamp at `internal/bootstrap/certificate_ca_provider.go:685` (and `certificate_provider.go:231`
  for the HTTP parser). Default when Limit is 0 is 25 (`:680`).
- Callers that ask for more and receive 100:
  `renewal_scheduler.go:302` (50000), `posture_scheduler.go:135` (10000), `handlers_executive_summary.go:112`,
  `handlers_evidence.go:20`, `handlers_agility.go:81`, `handlers_blast_radius.go:82`,
  `handlers_codesign.go:120,151`, `handlers_pqc_countdown.go:150`, `handlers_pqc_waves.go:41,169`,
  `handlers_pqc_migration.go:60`, `handlers_key_custody.go:88`.
  By inspection (not run), callers that pass no limit and receive 25: `key_lifecycle.go:362` (CA key compromise: affected
  certificates to flag `reissue_required` and re-issue), `cbom_export.go:156` (CBOM export).
  `pending_action_exec.go:63` asks for `maxBulkRevoke` (500) and gets 100.
  `handlers_reports.go:116` (`reportVisibleCertificates`) documents the clamp and pages around it, so
  the team knows; the others were not updated. `ui/src/pages/Dashboard.tsx:286` also works around it.
- Evidence:
  - Live, 10,000-cert hub: `GET /reports/executive-summary` returns `"total_certs":100`.
  - Unit probe: `Limit:50000` over 10,000 items returns `items=100 total=10000`
    (`harness/bootstrap_perf_test.go.txt`, `TestPerfLimitClamp`).
  - `RenewalScheduler.runScan` over a 50,000-cert provider logs `found 100 renewal candidates`.
    So at 10k+ certificates, renewal reminders and auto-renewal only ever see the newest 100.
- Impact: this is a correctness defect that is also masking performance. Reports, PQC readiness, posture
  snapshots, renewal reminders, bulk revoke and CA-compromise response all silently operate on a sliver
  of the fleet. It also means the schedulers look cheap today (20 ms at 50k) and will not be once fixed.
- Fix: add an iterator that does not clamp (`ForEachCertificate(ctx, query, fn)` or a cursor), move every
  internal caller to it, and make the HTTP clamp an explicit property of the HTTP layer only. Return an
  error, not a silent truncation, if a caller's limit exceeds the cap.
- Severity: HIGH (wrong results at scale, security-relevant for key compromise).

## H3. Report and scheduler paths are O(n^2/100) and approach the 15 s WriteTimeout

- Where: every `ListCertificates` call copies all matching items and sorts them before slicing
  (`certificate_ca_provider.go:688-740`). Callers that page 100 at a time therefore do n/100 full
  copy-and-sorts: `reportVisibleCertificates` (`handlers_reports.go:116`), `listCertificatesTenantFiltered`
  (`handlers_certificates.go:831`, tenancy on), `AnomalyScheduler.issuanceEvents` (`anomaly_wiring.go:93-98`,
  every 30 min), SLO scheduler (`slo_wiring.go:112`, every 15 min).
- Evidence (Go benchmark on the real provider type, and live hub):

  | Case | 10k certs | 50k certs |
  |------|----------:|----------:|
  | one list page (25) | 4.0 ms, 6.2 MB alloc | 22.9 ms, 31.2 MB alloc |
  | full paging pass (anomaly / SLO tick) | 0.38 s | 11.1 s |
  | live `reports/compliance-evidence` | 0.36 s | 13.6 s (max 14.8 s) |
  | live `reports/crypto-posture`, `expiry-timeline` | 0.33 s | 2.5 s |

  `http.Server.WriteTimeout` is 15 s (`server.go:104,133`), so compliance-evidence at 52.6k is one
  slow disk or one concurrent issuance away from a dropped connection. A 50k paging pass allocates
  about 15 GB (500 pages x 31 MB) in 11 s, under a read lock, which also stalls writers queued behind it.
- Impact: the compliance report, the most audit-facing endpoint, breaks at the top of the stated scale
  range, and the background ticks burn a core for 11 s every 15-30 minutes.
- Fix: same as H2 (single pass iterator), plus an ordered index so a page is O(limit). Cache report
  results for a short TTL. Both problems disappear together.
- Severity: HIGH at 50k (near-timeout), MEDIUM at 10k.

## H4. Default memory limit (256Mi) is below the measured working set

- Where: `charts/kryptkeeper/values.yaml:48-54` (limit 256Mi, request 128Mi, cpu 500m). No `GOMEMLIMIT`.
  The whole inventory is held in memory, each entry carrying the cert PEM and a parsed `x509.Certificate`
  (`certificate_ca_provider.go:51-55`).
- Evidence (RSS of the hub process):
  - 10.5k certs, idle after start: 176 MB. After report calls: 252 MB.
  - 52.6k certs, idle after start: 484 MB (start-up hydrate took about 1 s). After the list/issue/report
    suite: 1.0-1.5 GB.
  - 30 concurrent wrong-password logins from distinct addresses: 258 MB -> 583 MB (see M4).
  - About 6-9 KB resident per certificate.
- Impact: at 52.6k certificates a default Helm install exceeds its limit at idle (484 MB vs 268 MB). At 10.5k it
  sits at 176-252 MB, just under the limit, so ordinary report load plus a login burst (M4, +325 MB) crosses it. Go does not return memory
  to the OS quickly, so RSS stays high after bursts.
- Fix: raise chart defaults and document sizing (about 10 KB per cert plus 3x headroom for transient list
  copies), set `GOMEMLIMIT` from the container limit, and cut per-request garbage (H3 fix 31 MB -> KBs).
- Severity: HIGH (default deployment resource blow-up).
