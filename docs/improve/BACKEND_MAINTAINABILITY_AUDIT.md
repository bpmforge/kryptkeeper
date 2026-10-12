# Backend Maintainability Audit — Bootstrap DB providers
**Date:** 2026-04-13
**Reviewer:** code-reviewer
**Scope:** `internal/bootstrap/audit_db_provider.go`, `internal/bootstrap/discovery_db_provider.go`, `internal/bootstrap/notification_db_provider.go`, `internal/bootstrap/dashboard_action_db_provider.go`, `internal/bootstrap/db_provider_helpers.go`
**Method:** Static review only

## Summary
The backend provider layer works, but it is built from repeated copy/paste patterns. The highest-risk maintainability issue is that four provider modules all reimplement the same bootstrapping shape, so any change to DB mode handling, error propagation, or store construction has to be repeated in several places.

## Findings

### High-Priority
#### [High-Priority] Four providers repeat the same bootstrap pattern
**Where:** `internal/bootstrap/audit_db_provider.go:17-46,48-74,102-121`, `internal/bootstrap/discovery_db_provider.go:16-57,59-85,102-147`, `internal/bootstrap/notification_db_provider.go:16-53,55-81,98-135`, `internal/bootstrap/dashboard_action_db_provider.go:16-45,47-73,90-111`
**Current code:**
```go
type dbAuditStore interface {
	ListEntries(context.Context, AuditListQuery) (AuditListResult, error)
	AppendEntry(context.Context, AuditEntry) error
}

type dbAuditStoreError struct{ err error }

func newDBAuditProviderFromEnv() AuditProvider {
	store := newDBAuditStoreFromEnv()
	if errStore, ok := store.(dbAuditStoreError); ok {
		return &dbAuditProvider{openErr: errStore.err}
	}
	return &dbAuditProvider{store: store}
}

func newDBAuditStoreFromEnv() dbAuditStore {
	mode := currentDBMode()
	...
}
```
**Problem:** Each provider repeats the same sequence: define a store interface, define an error wrapper, construct a provider with `openErr`, switch on DB mode, resolve DSN, open the DB, and guard every method with `if p.openErr != nil`. The only things that change are the store methods and DSN environment names.
**Why it matters:** This is exactly the kind of repetition that quietly forks behavior over time. A future fix to logging, DSN fallback, pool settings, or error semantics will likely be made in one provider and forgotten in the others.
**Suggested direction:** Introduce one shared provider factory/helper that accepts per-service DSN resolution, logger prefix, and store constructor, then returns the standard `openErr` wrapper automatically. Keep the service-specific store methods, but remove the repeated constructor/control-flow boilerplate.

### Medium-Priority
#### [Medium-Priority] List/pagination logic is duplicated across store implementations
**Where:** `internal/bootstrap/audit_db_provider.go:124-214`, `internal/bootstrap/discovery_db_provider.go:170-260`, `internal/bootstrap/notification_db_provider.go:159-244`, `internal/bootstrap/dashboard_action_db_provider.go:118-200`
**Current code:**
```go
limit := query.Limit
if limit <= 0 {
	limit = 25
}
offset := query.Offset
if offset < 0 {
	offset = 0
}
...
if cursor > total {
	cursor = total
}
...
var nextCursor *int
if end < total {
	n := end
	nextCursor = &n
}
```
**Problem:** The same normalization and page-window math appears in each store, just with different query shapes and DB placeholders.
**Why it matters:** Pagination behavior is easy to drift. If one store changes the default limit, cursor math, or next/prev calculation, users will see inconsistent list navigation across audit, discovery, notifications, and dashboard history.
**Suggested direction:** Extract a small pagination helper that normalizes limit/cursor and calculates `nextCursor` / `prevCursor`, then have each store only supply its SQL query and row scan logic.

### Medium-Priority
#### [Medium-Priority] DSN lookup helpers are repeated service-by-service
**Where:** `internal/bootstrap/audit_db_provider.go:77-99`, `internal/bootstrap/discovery_db_provider.go:88-100`, `internal/bootstrap/notification_db_provider.go:84-96`, `internal/bootstrap/dashboard_action_db_provider.go:76-88`, `internal/bootstrap/db_provider_helpers.go:10-34`
**Current code:**
```go
func auditSQLiteDSNFromEnv() (string, error) {
	if dsn := strings.TrimSpace(os.Getenv("APP_AUDIT_DB_DSN")); dsn != "" {
		return dsn, nil
	}
	dataDir := strings.TrimSpace(os.Getenv("KRYPTKEEPER_DATA_DIR"))
	...
}

func auditPostgresDSNFromEnv() string {
	if dsn := strings.TrimSpace(os.Getenv("APP_AUDIT_DB_DSN")); dsn != "" {
		return dsn
	}
	if dsn := strings.TrimSpace(os.Getenv("KRYPTKEEPER_DB_DSN")); dsn != "" {
		return dsn
	}
	return strings.TrimSpace(os.Getenv("DATABASE_URL"))
}
```
**Problem:** `currentDBMode`, `unsupportedDBMode`, and `openConfiguredDB` are shared, but each provider still reimplements a near-identical env lookup function pair.
**Why it matters:** The provider layer now has two kinds of duplication: the DB bootstrap shape and the env fallback chains. That makes it harder to know which environment variables are actually authoritative and increases the chance of subtle mismatch between services.
**Suggested direction:** Centralize DSN resolution into a shared helper that takes the service-specific env variable name and SQLite fallback behavior as inputs. That keeps the fallback order consistent and shortens each provider module.

## Overall assessment
The backend is stable, but the provider layer is not yet “easy for a new hire.” The repeated bootstrap pattern is the biggest maintainability problem, followed by repeated pagination and env-resolution helpers.
