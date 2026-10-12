# Security Audit: WS-05/06/07/08 Provider Abstraction Layer

**Date:** 2026-04-07
**Scope:** Provider interfaces, file adapters, handler rewrites, env helpers, DI wiring
**Auditor:** Automated security review agent

## Summary

| Severity | Count | Status |
|----------|-------|--------|
| CRITICAL | 0 | N/A |
| HIGH | 2 | RESOLVED |
| MEDIUM | 4 | RESOLVED (3), ACCEPTED (1) |
| LOW | 3 | RESOLVED (1), ACCEPTED (2) |
| INFO | 1 | ACCEPTED |

## Resolved Findings

### HIGH-1: scan_type/target fields lacked allowlist validation (RESOLVED)
- **Location:** `handlers_discovery.go` scan create endpoint
- **Fix:** Added `scan_type` allowlist (`full`, `targeted`, `fast`) and target length cap (253 chars)

### HIGH-2: test-delivery channel/target lacked allowlist validation (RESOLVED)
- **Location:** `handlers_notifications.go` test-delivery endpoint
- **Fix:** Added `channel` allowlist (`email`, `slack`, `pagerduty`, `webhook`), target cap (320 chars), message cap (500 chars)

### MEDIUM-1: reason/note fields had no per-field length cap (RESOLVED)
- **Location:** All POST handlers across protocols, discovery, notifications, dashboard
- **Fix:** Added `tooLong()` check (500 char cap) on all `reason`, `note`, and `message` fields

### MEDIUM-2: JWT/OIDC service-account role blocked from all endpoints (RESOLVED)
- **Location:** `authz_ops.go` canReadOperationalSummaries
- **Fix:** Added `service-account` to ops-read allowlist; write endpoints remain 403 for service-accounts

### LOW-1: Missing ReadTimeout/WriteTimeout/IdleTimeout on http.Server (RESOLVED)
- **Location:** `server.go`
- **Fix:** Added `ReadTimeout: 15s`, `WriteTimeout: 15s`, `IdleTimeout: 60s`

## Accepted Findings (no action needed)

### MEDIUM-3: note field echoed verbatim in state-mutation responses
- **Mitigation:** 500-char cap now limits reflection size; JSON encoding prevents XSS in API responses

### MEDIUM-4: reason field echoed into audit via provider chain
- **Mitigation:** 500-char cap limits audit log bloat; field values are sanitized by trim + length check

### LOW-2: Nil provider guard only in RegisterHandlers, not Run
- **Mitigation:** Panic at startup is correct fail-closed; stack trace points to RegisterHandlers call

### LOW-3: Bootstrap token absence warning goes to stdout only
- **Mitigation:** Application correctly fails closed (401 on all requests); operational concern only

### INFO-1: q search parameter unbounded length
- **Mitigation:** File provider does in-memory Contains; no DB query risk in current implementation

## Strengths Noted

- All providers nil-checked at startup with panic guards
- Every provider error path returns 503 (fail-closed)
- MaxBytesReader (8 KB) on every POST endpoint
- Auth + role check before every provider call
- Error responses never include internal error details
- Audit events emitted for all terminal states (denied/failure/success)
