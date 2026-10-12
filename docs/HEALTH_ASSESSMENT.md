# Health Assessment

> **STALE (recorded 2026-07-15, design review G-7):** describes the 2026-04-17 Waves 0–5 state, pre-v1.1. Current state: `docs/SESSION_STATUS.md`; current gaps: `docs/work/DESIGN_REVIEW.md`.

## Overall summary

Kryptkeeper has completed the full Waves 0–5 improvement cycle documented in
`docs/IMPROVEMENT_PLAN_V2.md` (now archived to `docs/reviews/`). The platform has
shifted from "status console with in-memory stubs" to an operable PKI product with
persistent storage, real OCSP/CRL enforcement, working enrollment protocols, a full
observability surface, rate-limited protocol endpoints, and a UI that supports every
core operator workflow.

**Last updated:** 2026-04-17 (post Waves 0–5, all waves complete)

## Signals checked

- `go test ./...` ✅ (14 packages, includes integration tests for issue→revoke→OCSP/CRL path,
  ACME full order flow + HTTP-01 validation + failure path, SQLite persistence,
  AWS KMS unit tests, CMP parser, XCEP golden-XML)
- `npm --prefix ui run build` ✅ (tsc + vite, zero errors)
- UI: CA create, cert issue, template CRUD, login, auth redirect, search,
  pagination (Certs/CAs/Alerts/Discovery), URL-persisted filters, cert detail panel ✅
- PKI persistence: certs survive restart, OCSP/CRL read from DB ✅
- Security: fail-fast startup, no default SCEP challenge, CSRF posture documented ✅
- A11y: `scope="col"` on all `<th>`, skip link correct ✅
- Observability: `/metrics` endpoint, 14 Prometheus counters/histogram, Grafana dashboard ✅
- Rate limits: per-IP sliding-window on ACME, OCSP, CRL, EST, SCEP (429 + Retry-After) ✅

## Scores

| Dimension | Before (Wave 0) | After (Wave 5) | Why |
|---|---:|---:|---|
| Code quality | 7 | 8 | Interfaces clean; persistence layer, metrics, rate limiter well-structured |
| Test coverage | 7 | 9 | Integration tests, ACME/CMP/XCEP/KMS unit tests, metric format tests |
| Operational robustness | 6 | 9 | Full persistence, real OCSP/CRL, fail-fasts, rate limits, metrics |
| UX readiness | 5 | 9 | All operator workflows, pagination, URL filters, revocation detail, error surfacing |
| Security posture | 6 | 8 | Fail-fasts enforced, CSRF documented, no default secrets, rate limits on all protocol endpoints |

## What is working well

- Full PKI lifecycle: create CA → issue cert → revoke → OCSP returns revoked → CRL contains serial
- Template policy enforcement (algorithm constraints, validity cap, EKU allow-list)
- Cert provider hydrates from DB on startup — no state loss across restarts
- ACME store backed by SQLite with `EnsureSchema` + in-memory fallback
- AWS KMS `GenerateKey` calls `CreateKey` + `GetPublicKey`; `Sign` calls `kms.Sign` with digest
- CMP ir/cr pipeline: `parsePKIMessage` → `handleCertRequest` → `buildCertResponse`
- XCEP GetPolicies SOAP response with template names, OIDs, SHA-256 hash algorithm reference
- Prometheus text-format metrics with no external dependency (`sync/atomic` only)
- Per-IP sliding-window rate limiter reused across all five protocol endpoints
- URL-persisted filter state on all four list pages (shareable, refresh-safe)
- Auth-gated endpoints, audit events pervasive throughout

## Remaining gaps

### 1. Cloud KMS — GCP and Azure (Wave 2.6 partial)
AWS KMS is fully wired. GCP (`AsymmetricSign`) and Azure (Key Vault `Sign`) stubs return errors.

**Fix:** Wire GCP and Azure SDK calls in `cloudkms.go` using the same pattern as AWS.
**Effort:** 2–3 days each.

### 2. Bootstrap package complexity (ongoing)
`internal/bootstrap` owns startup wiring, routing, auth, provider selection, and several domain
behaviors (~3000 LOC). Incremental extraction recommended as each area is touched next.

### 3. CMP: simplified parser (Wave 2.5 note)
`parsePKIMessage` is a heuristic parser, not a full RFC 4210 ASN.1 codec. It works for
PKCS#10-encapsulated requests but will reject some compliant clients.

**Fix:** Replace with a proper `encoding/asn1` struct tree for `PKIMessage`.
**Effort:** 3–5 days.

## Risk table

| Risk | Impact | Likelihood | Notes |
|---|---|---|---|
| GCP/Azure KMS stubs | Medium | Low | Only matters if customer selects those providers |
| Bootstrap sprawl | Medium | Medium | Harder to safely add features |
| CMP simplified parser | Low | Low | Only affects non-standard CMP clients |

## Recommended next priorities

1. **GCP KMS** — if AWS KMS adoption proves the pattern works, add GCP next
2. **Bootstrap decomposition** — tackle opportunistically when touching each area
3. **CMP full parser** — only if a non-certbot CMP client is needed

## Bottom line

The platform is operationally complete for an internal PKI team. CA/cert/revocation
correctness is solid, ACME HTTP-01 is fully implemented and tested end-to-end, all
protocol endpoints are rate-limited and instrumented, and every operator workflow is
reachable from the UI. The remaining gaps (GCP/Azure KMS, CMP parser, bootstrap
refactor) are completeness and maintainability items, not correctness failures.
