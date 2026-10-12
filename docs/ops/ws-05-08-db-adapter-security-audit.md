# Security Audit: WS-05/06/07/08 DB Adapter Layer

**Date:** 2026-04-08
**Scope:** discovery_db_provider.go, notification_db_provider.go, dashboard_action_db_provider.go, W8 migration
**Auditor:** Automated security review agent

## Summary

| Severity | Count | Status |
|----------|-------|--------|
| CRITICAL | 0 | N/A |
| HIGH | 0 | N/A |
| MEDIUM | 2 | RESOLVED |
| LOW | 3 | RESOLVED (2), ACCEPTED (1) |

## Resolved Findings

### MEDIUM-1: Unvalidated filter enum values reach WHERE clauses (RESOLVED)
- **Fix:** Added allowlist validation for `status`, `channel`, `category` parameters in handlers_discovery.go, handlers_notifications.go, handlers_dashboard.go

### MEDIUM-2: Unescaped LIKE metacharacters + no length cap on q (RESOLVED)
- **Fix:** Added `escapeLIKE()` helper to escape `%`, `_`, `\` in LIKE patterns. Added 200-char cap on `q` parameter. Applied `ESCAPE '\'` clause to both SQLite and Postgres LIKE queries.

### LOW-4: AckDelivery UPDATE does not check RowsAffected (RESOLVED)
- **Fix:** Both SQLite and Postgres AckDelivery now check RowsAffected and return error for non-existent delivery IDs.

## Accepted Findings

### LOW-3: Predictable time-based IDs
- **Mitigation:** All mutation endpoints require authentication + write-role authorization. ID enumeration only visible to authorized users. Accepted for bootstrap phase; will migrate to crypto/rand UUIDs when production backend is wired.

### LOW-5: Seed migration uses example.com email addresses
- **Mitigation:** example.com is IANA-reserved; addresses cannot be delivered. CI-only seed data.

## Positive Observations
- Zero SQL injection: all user input uses bind parameters
- Fail-closed pattern consistent across all 3 DB adapters
- Ping-on-open verified for both drivers
- SQL errors never disclosed to HTTP callers
- Migration CHECK constraints provide defense-in-depth
