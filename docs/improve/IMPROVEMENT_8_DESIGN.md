# Improvement #8 Design — Backend maintainability

## Problem
The bootstrap DB provider layer repeats the same pattern four times: resolve mode, resolve DSN, open DB, wrap errors, and guard every provider method. That makes the code easy to drift and hard to update consistently.

## Proposed fix
Create a small shared provider factory in `internal/bootstrap/` that handles:
- mode resolution
- DSN resolution
- DB open + ping
- error wrapper conversion
- standard provider `openErr` guarding

Keep the actual store queries and result mapping inside each service file.

## Files affected
- `internal/bootstrap/db_provider_helpers.go`
- `internal/bootstrap/audit_db_provider.go`
- `internal/bootstrap/discovery_db_provider.go`
- `internal/bootstrap/notification_db_provider.go`
- `internal/bootstrap/dashboard_action_db_provider.go`

## Risks
- Over-abstracting could make service-specific DSN behavior harder to follow.
- A too-generic helper could hide important differences between SQLite and Postgres behavior.

## Rollback
If the helper becomes too opaque, split it back into smaller service-local constructors while keeping only the truly shared DB open/ping logic.

## Done criteria
- Provider modules are shorter and share one bootstrap path.
- Error handling and DSN fallback behavior remain unchanged.
- `go test ./...` still passes.

## Implementation sketch
1. Add a generic helper that accepts:
   - a service name for logs/errors
   - SQLite DSN resolver
   - Postgres DSN resolver
   - a store constructor that accepts `*sql.DB`
2. Let the helper return a small wrapper that forwards methods when the store opens successfully.
3. Keep `openConfiguredDB` and `currentDBMode` as shared primitives.
4. Preserve service-specific SQL and row-mapping code in each provider file.

## Refactor boundaries
- Do not merge service SQL queries into the helper.
- Do not change pagination behavior yet.
- Do not change query result shapes yet.

## Verification checklist
- Compare file sizes after refactor; each provider should lose repetitive constructor boilerplate.
- Run `go test ./...`.
- Spot-check that SQLite and Postgres still honor the same env precedence rules.

## Why this is the right next step
The audit showed the provider layer is maintainable today but fragile over time. A shared factory gives the highest leverage without touching query semantics, which keeps the change safe and reversible.
