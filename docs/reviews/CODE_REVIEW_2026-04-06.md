# Code Review Summary

Scope: latest cert summary provider/db boundary changes.

## Summary
- DB mode is **clearly marked as unimplemented** (`source=db-store-unimplemented` + log), but it does **not** fail closed.
- The main risk is semantic drift: the env switch looks operational, yet it still returns a successful zero summary.
- Recommendation: **fix before merge**.

## Findings

### [HIGH] DB mode still behaves as an unimplemented backend seam
**Location:** `internal/bootstrap/certs_summary_provider.go:30-41`, `internal/bootstrap/certs_summary_db_provider.go:31-50`, `internal/bootstrap/handlers_protected_certs_summary.go:19-40`
**Category:** Behavior / Pattern
**Description:** `APP_CERTS_SUMMARY_PROVIDER=db` still does not query a real backend; it remains a placeholder seam. The response path is now distinguishable, but the env switch still does not represent a production DB provider.
**Suggested:** either wire the real DB store or disable the `db` mode until it can query real data.

### [MEDIUM] DB store seam is present but unused, which invites contract drift
**Location:** `internal/bootstrap/certs_summary_db_provider.go:10-28,39-41`
**Category:** Maintainability / Debt
**Description:** The provider advertises a `dbCertSummaryStore` boundary and stores it on the struct, but `LoadSummary` ignores it. That makes the seam look real in tests and construction while guaranteeing the behavior never changes, which will be easy to forget during the actual DB implementation.
**Suggested:** either remove the unused store seam for now, or route `LoadSummary` through the store and surface its error so the boundary is real.

## Verdict
**NEEDS FIX** — db mode is labeled, but not fail-closed; the current contract can still mislead consumers.
