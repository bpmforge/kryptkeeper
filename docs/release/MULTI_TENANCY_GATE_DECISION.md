# Multi-tenancy experimental gate: decision record (v0.10.0)

**Date:** 2026-10-16. **Ticket:** W22-03. **Decision:** **A — gate lifted.** Owner (the owner) approved the recommended option in the W22 project thread on 2026-10-16.

## Decision

`MULTI_TENANCY=on` no longer requires `KRYPTKEEPER_MULTI_TENANCY_EXPERIMENTAL=accept-risk` to start. The start-up WARNING is replaced by a neutral NOTICE that points at `docs/design/TENANCY_POSTURE.md`.

## Evidence

- Suite: `bash scripts/test/run.sh --suite tenant-idor` (W22-02), run on branch `kk/w22-governance` at commit `17c3e4ed` and its parent merges, 2026-10-16.
- SQLite: `[tenant-idor] engine=sqlite routes=227 requests=908 leaks=0`.
- PostgreSQL 16: `[tenant-idor] engine=postgres routes=227 requests=908 leaks=0` (`KK_IDOR_REQUIRE_POSTGRES=1`).
- Self-test: the harness exits non-zero against a seeded leaking hub (`self-test PASS ... leaks=4`).
- Before the fixes the same suite reported 55 leaks on SQLite; every leak L-01..L-21 from `docs/release/TENANT_ISOLATION_VALIDATION_v0.9.3.md` has a named `TestLeakL*` regression test in `internal/bootstrap`.
- Limits of the evidence: the suite cannot detect a write to instance-global state that names no other tenant's data (L-08 is proven by `TestLeakL08_*` unit tests instead); approval requests are not seeded as victim data (bootstrap-minted keys cannot act as named approvers).

## Behaviour change

- Hubs with multi-tenancy on start without the acknowledgement env var.
- Log line at start-up: `NOTICE: multi-tenancy is enabled; see docs/design/TENANCY_POSTURE.md for the enforced isolation boundary.`
- No schema or API change from this ticket.

## Rollback

Set `KRYPTKEEPER_MULTI_TENANCY_GATE=enforce` (exact, case-sensitive). The hub then behaves exactly as v0.9: it refuses to start with multi-tenancy on unless `KRYPTKEEPER_MULTI_TENANCY_EXPERIMENTAL=accept-risk` is set. No data migration is involved.

## Docs still to update (outside this ticket's scope)

`README.md`, `SECURITY.md`, `env.example`, `CHANGELOG.md`, `docs/STATUS.md`, and the UI "Experimental" label on the Tenants page and tenant switcher still describe the gate; update them in the v0.10.0 release change.
