# Code Review Summary

Scope: WS-04 certificate/bootstrap wave review for:
- `internal/bootstrap/handlers_certificates.go`
- `internal/bootstrap/certificate_provider.go`
- `internal/bootstrap/certificate_file_provider.go`
- `internal/bootstrap/handlers.go`
- `internal/bootstrap/server.go`
- `cmd/kryptkeeper/main.go`

## Summary
- The certificate wave is functionally broad and follows existing bootstrap patterns, but the central certificate handler has grown into a high-complexity hotspot.
- Dependency wiring is consistent with current codebase style, yet the long positional constructor signatures are becoming brittle.
- Error payload shape is mostly consistent (`{"error","message"}`), but response handling is fragmented and partially inconsistent across branches.
- Test coverage exists for happy-path certificate flows, but critical wiring and error branches remain untested.

---

## Findings

### [HIGH] Certificate handler is a God-function with high branching cost
**Location:** `internal/bootstrap/handlers_certificates.go:14-468`
**Category:** Complexity
**Description:** A single function handles list/get/issue/import/chain/revoke/renew/download routing, auth handling, audit emissions, and response rendering. This exceeds maintainability thresholds and raises regression risk when adding endpoints (or changing error semantics).
**Current:**
```go
func registerCertificateHandlers(...) {
  mux.HandleFunc("/api/v1/certificates", func(...) { ... })
  mux.HandleFunc("/api/v1/certificates/", func(...) {
    if tail == "import" { ... }
    if strings.HasSuffix(tail, "/chain") { ... }
    if strings.HasSuffix(tail, "/revoke") { ... }
    if strings.HasSuffix(tail, "/renew") { ... }
    if strings.HasSuffix(tail, "/download") { ... }
    ...
  })
}
```
**Suggested:**
```go
func registerCertificateHandlers(...) {
  mux.HandleFunc("/api/v1/certificates", certificatesCollectionHandler(...))
  mux.HandleFunc("/api/v1/certificates/", certificatesItemRouter(...))
}

// each operation isolated (issue/import/get/chain/revoke/renew/download)
```
**Recommendation:** Split by route concern (collection vs item), then by operation. Keep behavior identical while reducing branching depth.

### [MEDIUM] Repeated error/audit response blocks create drift risk
**Location:** `internal/bootstrap/handlers_certificates.go:30-64, 159-195, 266-299, 326-367, 397-413`
**Category:** Debt
**Description:** The same patterns (emit audit, set JSON headers, write status + hardcoded payload) are repeated many times. This is already causing maintainability overhead and makes future envelope updates expensive.
**Current:**
```go
emitAuditEvent(..., "failure")
w.Header().Set("Content-Type", "application/json")
w.WriteHeader(http.StatusBadRequest)
_, _ = w.Write([]byte(`{"error":"bad_request","message":"invalid request body"}`))
```
**Suggested:**
```go
writeAPIError(w, http.StatusBadRequest, "bad_request", "invalid request body")
emitFailureAudit(r, auditProvider, principal, action, "certificate", id)
```
**Recommendation:** Introduce internal helper(s) for standardized JSON error writing and common audit failure/success paths.

### [MEDIUM] Dependency injection style is consistent but brittle (long positional wiring)
**Location:** `internal/bootstrap/server.go:14-17`, `internal/bootstrap/handlers.go:5-31`, `cmd/kryptkeeper/main.go:11-27`
**Category:** Pattern
**Description:** Current DI uses many positional args across `main -> Run -> RegisterHandlers`. This is consistent with current codebase, but ordering mistakes become easier as providers grow.
**Current:**
```go
Run(addr, auth, certSummaryProvider, auditProvider, caProvider, templateProvider, certificateProvider)
```
**Suggested:**
```go
type BootstrapDeps struct {
  Auth *Authenticator
  CertSummary CertSummaryProvider
  Audit AuditProvider
  CA CAProvider
  Template TemplateProvider
  Certificate CertificateProvider
}
```
**Recommendation:** Consider a dependency struct for `Run`/`RegisterHandlers` in a follow-up refactor (non-breaking if introduced incrementally).

### [MEDIUM] Error envelope handling is not fully uniform
**Location:** `internal/bootstrap/handlers_certificates.go:80,155,219,256,316,385,424` and helper `internal/bootstrap/response.go:18-21`
**Category:** Error Handling
**Description:** Most errors use JSON envelope (`{"error","message"}`), but method-not-allowed responses use `http.Error` plain text via `writeMethodNotAllowed`. This creates API inconsistency for clients expecting JSON error bodies.
**Current:**
```go
func writeMethodNotAllowed(w http.ResponseWriter, allow string) {
  w.Header().Set("Allow", allow)
  http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}
```
**Suggested:**
```go
func writeMethodNotAllowed(w http.ResponseWriter, allow string) {
  w.Header().Set("Allow", allow)
  writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
}
```
**Recommendation:** Align all error responses to one envelope writer.

### [LOW] Request parsing responsibilities are split across layers
**Location:** `internal/bootstrap/certificate_provider.go:201-232`, `internal/bootstrap/handlers_certificates.go:470-486`
**Category:** Pattern
**Description:** Certificate request parsing is split between provider file (`parseCertificateIssue/Renew/ImportRequest`) and handler file (`parseCertificateRevokeRequest`). This weakens module cohesion and makes parse logic harder to discover.
**Current:** parsing helpers live in both provider and handler modules.
**Suggested:** place all HTTP payload parsing helpers together in handler module (or a dedicated transport parser file), and keep provider focused on domain operations.
**Recommendation:** Consolidate parsing location without changing behavior.

### [MEDIUM] Coverage gaps on bootstrap wiring and negative paths
**Location:** `cmd/kryptkeeper/main.go:10-29`, `internal/bootstrap/server.go:14-64`, `internal/bootstrap/certificate_provider.go:163-232`
**Category:** Testability
**Description:** Existing test (`internal/bootstrap/certificate_store_test.go`) covers many certificate happy paths, but there are no direct tests for:
- bootstrap wiring behavior in `main`/`Run` (startup/shutdown/error path)
- env-based provider selection fallback (`NewCertificateProviderFromEnv`)
- parser boundary/negative cases for issue/import/renew/revoke helpers
- method-not-allowed and other non-happy-path handler branches
**Recommendation:** Add focused unit tests for provider/env selection and parser edge cases, plus a small server lifecycle test around `Run`.

---

## Notable Strengths

- **Clear provider abstractions:** `CertificateProvider` interface cleanly defines capabilities and supports swapping implementations.
- **Defensive handler registration:** `RegisterHandlers` nil-guards dependencies early (`panic` fail-fast), preventing partially wired servers.
- **Audit integration is pervasive:** certificate operations consistently emit success/failure/denied audit events.
- **Useful integration-style coverage exists:** `certificate_store_test.go` validates list/get/chain/revoke/issue/renew/download/import flows end-to-end through HTTP.

---

## Findings by Severity

| Severity | Count |
|---|---:|
| HIGH | 1 |
| MEDIUM | 4 |
| LOW | 1 |

## Overall Maintainability Assessment
**★★★☆☆ (3/5)** — Functional and mostly consistent, but concentrated complexity and repeated response logic will become expensive to change.

## Top 3 Most Impactful Improvements
1. Decompose `registerCertificateHandlers` into operation-specific handlers.
2. Introduce shared JSON error writer + audit helper to remove repeated blocks.
3. Replace long positional DI signatures with a dependency struct for safer evolution.

## WS-04 Wave Recommendation (Go/No-Go)
**NO-GO for final merge as-is** (requires revision).

Rationale: There is one HIGH-severity maintainability issue (God-function handler) and multiple MEDIUM issues that increase drift risk. If this wave must proceed, at minimum split handler structure and standardize error-writing before approval.

## Verdict
**NEEDS REVISION**

Applied rubric: function size/complexity threshold exceeded (`registerCertificateHandlers`), with additional medium pattern/debt/testability concerns.

---

## Subtask Tracking

1. `[DONE]` Establish baseline patterns in bootstrap module and API responses.
2. `[DONE]` Review target files for modularity/DI/maintainability/error handling.
3. `[DONE]` Assess duplication and safe refactor opportunities.
4. `[DONE]` Assess testability and coverage gaps.
5. `[DONE]` Produce WS-04 go/no-go recommendation.

## Confidence (Reasoning Loop)

| Subtask | Confidence (1-10) |
|---|---:|
| 1 | 9 |
| 2 | 9 |
| 3 | 8 |
| 4 | 8 |
| 5 | 9 |

All subtasks scored >= 7; no revision pass required.
