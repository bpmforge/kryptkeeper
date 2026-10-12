# Complexity Findings — Kryptkeeper — 2026-10-09

Scope: Go backend + React/TS UI at main 6062c62. Tool inputs: `docs/work/code-reviewer/health-2026-10-09/{gocyclo,gocognit,largest-files}.txt` (not re-run). 11 source files read. Module key = Go package path.

## Summary

| Severity | Count |
|---|---|
| CRITICAL | 0 |
| HIGH | 2 |
| MEDIUM | 5 |
| LOW | 2 |

Tool shape: 129 functions with cyclo>15, 121 with cognitive>20. About 45 of the cyclo entries and 49 of the cognitive entries are `register*Handlers` route tables (see "Acceptable"). The real risk sits in about 40 non-handler functions, and a handful of those are on startup, auth, issuance or revocation paths.

| ID | Sev | Conf | Module | Location | Metric | Title |
|---|---|---|---|---|---|---|
| CX-001 | HIGH | 90 | cmd/kryptkeeper | main.go:62 | cyclo 133, cog 304 | `main()` hides fail-open and double-root branches |
| CX-002 | HIGH | 85 | internal/bootstrap | handlers_reports.go:1108 | cyclo 45, cog 83 | Compliance evidence silently passes unparseable expiry |
| CX-003 | MEDIUM | 90 | internal/bootstrap | auth_config.go:119 | cyclo 74, cog 94 | `NewAuthenticatorFromEnv` is a 200-line env-parsing monolith |
| CX-004 | MEDIUM | 95 | internal/bootstrap | discovery_db_provider.go:836, :1444 | cog 63 x2 | sqlite/postgres `upsertScanResults` are 60-line near-clones |
| CX-005 | MEDIUM | 85 | internal/bootstrap | certificate_ca_provider.go:1317, :1411 | cyclo 33/35 | Risk score and risk flags duplicate the same rule ladder |
| CX-006 | MEDIUM | 85 | internal/bootstrap | pending_action_exec.go:37 | cyclo 31, cog 52 | Approval-queue executor: one switch, 7 inline decoders |
| CX-007 | MEDIUM | 80 | internal/acme | server.go:770, :980 | cyclo 23/24 | `handleRevokeCert`/`handleKeyChange` are 180/140-line inline pipelines |
| CX-008 | MEDIUM | 78 | internal/bootstrap | certificate_ca_provider.go (1736 lines), discovery_db_provider.go (1928), handlers_reports.go (1485) | file length | Three files over 1400 lines mix several concerns |
| CX-009 | LOW | 80 | internal/bootstrap | connector_acme.go:246 | cyclo 38, cog 58 | ACME issuer `Issue` (160 lines) mixes order, DNS-01 and finalize |
| CX-010 | LOW | 75 | ui/src/pages | Certificates.tsx (1957 lines) | file length | Five UI page files are 900-1950 lines |

## Top findings

### CX-001 HIGH — `main()` (cmd/kryptkeeper/main.go:62-~330)

Metric: cyclomatic 133, cognitive 304 (highest in the repo, ahead of every handler table).

`main()` is the whole composition root. Flag dispatch, keystore backend selection, CA store choice, policy engine wiring, root CA bootstrap, auth, providers, six schedulers, the CT monitor (with an inline paginated closure) and the server start are all in one function. Two hidden branches on the security path:

```go
// main.go:186
if pe, err := ca.NewPolicyEngine(coreDB, isPostgres); err == nil {
    engine.SetPolicyEngine(pe)
```
If the policy engine fails to construct, the error is dropped with no log, and the engine issues with no data-driven issuance policy gate. This is a fail-open on the issuance path, and the complexity of `main()` is what hides it. (Compare the adjacent `keystore.CheckRootKeyCustody`, which is correctly fatal.)

```go
// main.go:211
cas, _ := caEngine.ListCAs()
if len(cas) == 0 {
    if os.Getenv("KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT") == "true" { ... CreateRootCA ...
```
A transient `ListCAs` error is read as "no CAs", and with `BOOTSTRAP_CREATE_ROOT=true` left set (the log message itself asks the operator to remove it) a second root CA gets minted. Likelihood is low, but the impact is a spurious trust anchor.

Also: `os.MkdirAll(keystoreDir, 0o700)` error is unchecked (keystore dir creation), and `log.Fatal` calls inside make the function untestable.

Refactor: extract, in order, `parseSubcommands(args)`, `buildKeystore(env) (keystore.Store, backendName, error)`, `buildCAEngine(keys, coreDB) (ca.Service, ca.RevocationStore, error)`, `resolveDefaultCA(engine, env) (string, error)`, `startSchedulers(deps) (stop func())`, `startCTMonitor(deps)`. Each returns an error to a thin `main` that does the `log.Fatal`. Make the policy-engine error either fatal or a loud, explicit "issuance policy gate DISABLED" log at WARN level with a strict-mode env to refuse. Check `ListCAs` error before the empty test. This follows the house style (constructor injection, no new globals) and makes each step table-testable.

### CX-002 HIGH — `computeComplianceEvidence` (handlers_reports.go:1108-~1300)

Metric: cyclomatic 45, cognitive 83, ~190 lines. One function emits every control for SOC 2, PCI, NIST, DORA, etc., via `if framework == "all" || framework == "x"` blocks and inline `func() string {...}()` remediation closures.

```go
expiring30 := count(func(c CertificateItem) bool {
    if c.ValidUntil == "" { return false }
    t, err := time.Parse(time.RFC3339, c.ValidUntil)
    return err == nil && t.Before(now.Add(30*24*time.Hour)) && t.After(now)
```
A certificate with an empty or unparseable `ValidUntil` counts as neither expired nor expiring, so the SOC2-CC6.7 control can report `pass` over certificates whose expiry is unknown. For a compliance-evidence report that is a likely correctness bug, hidden by the repeated parse-inside-closure pattern (it is copy-pasted for `expired`). Related: `total/10` and `total/20` integer thresholds make "warn" unreachable when total < 10 (0 <= 0 only when count is 0).

Refactor: parse `ValidUntil` once into a `certView{item, notAfter time.Time, parsed bool}` slice; add an explicit "unknown expiry" bucket that downgrades status to `warn`/`fail`. Turn each framework into `func(ctx evidenceInput) []ComplianceControl` registered in `map[string]controlBuilder` (the file already has `doraNIS2Controls` as a precedent). Inject `now` for tests. Add table tests for empty and malformed `ValidUntil`.

### CX-003 MEDIUM — `NewAuthenticatorFromEnv` (auth_config.go:119-~320)

Metric: cyclomatic 74, cognitive 94. Straight-line env reads for bootstrap, JWT, OIDC, login, SCIM, SAML and API-key config, each with its own validation/log branch. The branches are individually trivial but the unit cannot be tested without `t.Setenv` of ~40 variables, and it is the function that decides what fails closed.

```go
loginEnabled = strings.EqualFold(raw, "true") || raw == "1"   // repeated 6x
```
`envFlagTrue` already exists (used at :123) but the "true or 1" idiom is hand-rolled 6 times in this one function, so a flag-parse change would miss sites. Note the SCIM and API-key JSON parse errors only `log.Printf` and continue (fail-closed by absence, which is intended per the messages, but untested per branch).

Refactor: replace the six idioms with `envFlagTrue`; split into `loadBootstrapCfg`, `loadJWTCfg`, `loadOIDCCfg`, `loadSAMLCfg`, `loadSCIMCfg`, `loadAPIKeyCfg(getenv func(string) string)` each returning a sub-struct of `authValidatorConfig`. Injecting `getenv` matches the existing `MultiTenancyExperimentalCheck(os.Getenv)` style.

### CX-004 MEDIUM — duplicated per-dialect upsert (discovery_db_provider.go:836 and :1444)

Metric: cognitive 63 each. A `diff` of the two 63-line bodies shows differences only in placeholders (`?` vs `$1..`) and in `now` being a string vs `time.Time`. Both carry the savepoint, touched-pair tracking and staleness sweep logic. Any fix to the sweep or the cert upsert must be made twice. `ListEndpoints` (:983/:1589, cog 27 each) has the same split.

Refactor: one `upsertScanResults(ctx, d dialect, results)` where `dialect` supplies `rebind(query)` and `ts(time.Time) any`; keep the SQL as a single string with `?` and rebind for postgres. That removes about 130 lines and one drift hazard.

### CX-005 MEDIUM — `computeRiskScore` / `computeRiskFlags` (certificate_ca_provider.go:1317, :1411)

Metric: cyclomatic 33 / 35. The same expiry ladder, RSA/EC key-size, NIST-sunset and 200-day rules appear in both functions (the `2027-03-15` date literal at :1373 and :1465), so score and flags can disagree. Both call `time.Now()` directly. NIST sunset is a package-level `var` (:1312) that tests can mutate.

Refactor: a single ordered `[]riskRule{flag string, points int, applies func(*x509.Certificate, time.Time) bool}` table; flags = applied rules, score = sum capped at 100. Pass `now` in. The compliance report (CX-002) filters on these flag strings, so a table also gives one source of truth for flag names.

### CX-006 MEDIUM — `executePendingAction` (pending_action_exec.go:37-~150)

Metric: cyclomatic 31, cognitive 52. This executes human-approved revoke/bulk_revoke/issue/renew/rotate/etc. Each case repeats unmarshal, required-field check, provider call and result marshalling. `bulk_revoke` has an inline loop with partial-failure accounting. Positive: the default is an error, not a silent drop, and the same-key rotation guard is explicit.

Refactor: `map[string]pendingHandler` with generic `decode[T any](raw) (T, error)` plus a per-type `validate`; move bulk revoke to `bulkRevoke(ctx, p) result`. Tests then cover each action type independently, which matters because this is the single place approvals turn into destructive operations.

### CX-007 MEDIUM — ACME `handleRevokeCert` (server.go:770-~950) and `handleKeyChange` (:980-~1115)

Metric: cyclomatic 23 / 24, cognitive 28 / 22. Both follow the same shape: method check, bounded read, JWS parse, verify, payload decode, authorization, state mutation. The revoke handler's authorization ordering is correct and well commented (issued-by-us check precedes both authorization modes, issuing CA resolved before recording). The risk is maintainability: nine early-return `writeACMEError` blocks with repeated URN literals, and mutation under `s.mu` mixed with response building.

Refactor: extract `parseAndVerifyJWS(w, r, mode)` (the opening 40 lines are common to several handlers), `authorizeRevocation(vjws, cert, issuerAccountID) *acmeError`, and a const set for the error URNs. Do not change ordering of checks; add a regression test that pins "unrecognised cert rejected before key comparison".

### CX-008 MEDIUM — oversized files

`discovery_db_provider.go` 1928, `certificate_ca_provider.go` 1736, `acme/server.go` 1540, `handlers_reports.go` 1485, `cmd/kryptkeeper/main.go` 1228. The first three bundle file/sqlite/postgres provider variants or several report computations. Split by concern within the package (e.g. `discovery_store_sqlite.go`, `discovery_store_postgres.go`, `cert_risk.go`, `reports_compliance.go`), no new strata. `acme/server.go` splits naturally into account, order, challenge and revocation files.

### CX-009 LOW — `acmeIssuerConnector.Issue` (connector_acme.go:246-~405)

Metric: cyclomatic 38, cognitive 58. Order creation, authorization loop with DNS-01 present/cleanup, finalize and chain fetch are inline; cleanup funcs are accumulated in a loop. Extract `solveAuthorizations`, `finalizeOrder`. LOW because it is an outbound client path with an established deferred-cleanup pattern.

### CX-010 LOW — UI page files (light pass)

- `ui/src/pages/Certificates.tsx` 1957 lines, 17 `useState`, 5 inline components: the largest; split list, detail drawer and issue/renew dialogs into `features/certificates/`.
- `Discovery.tsx` 1503 lines, 6 `useState`: scan config, results table, and endpoint detail in one file.
- `TargetSetup.tsx` 1036 lines, 4 `useState`: wizard steps could be one component per step.
- `Alerts.tsx` 963 lines, 7 `useState`: rules editor and channel config mixed.
- `CAs.tsx` 924 lines, 1 `useState`, 3 inline components: acceptable density, split only if touched.

## Acceptable as-is

- **`register*Handlers` functions** (`registerCertificateHandlers` cyclo 119/cog 351, `registerCAHandlers` 101/304, `registerTemplateHandlers`, `registerNotificationHandlers`, `registerKeyHandlers`, and ~40 more): these are flat route tables whose score comes from inline `HandleFunc` closures. They are long but each closure is independent, with no cross-closure state, so a change touches one route. Low risk; refactor only opportunistically (name the closures as methods when a route is next edited). Not listed individually.
- `computeAlgorithmSunset`, `computeIssuanceVelocity`, `computeCAHealth`, `doraNIS2Controls`: reporting/aggregation, no security decision.
- `ca.(*Engine).issueLeafCertificate` (cyclo 28), `(*NamePolicy).Check` (31 cog), `(*PolicyEngine).Check` (26 cog), `ParseCertificateRequestHybrid`, `acme.(*JSONWebKey).publicKey`: sequential validation ladders with early returns on crypto paths. Branchy by nature; keep as is and keep the tests, since flattening risks weakening a check.
- `wstep.serveRST`, agentdiscovery parsers (`ParseJKSCerts`, `WalkLinuxCerts`), `K8sPusher.Push`: protocol/parse code where linear complexity mirrors the format.
- `hasInline` (cyclo 27), `bootstrap.ListCertificates` file provider: file-backed demo providers.

## Score: Complexity 6 / 10

Justification: the overall complexity is concentrated rather than diffuse. The crypto and protocol packages (`ca`, `acme`, `keystore`) have moderate, well-commented ladders with explicit ordering, which is the right shape. Roughly 40% of the tool hits are benign route tables. What pulls the score down is (a) one 1,200-line composition root with a cyclo of 133 that hides a fail-open policy gate and a swallowed error before root CA creation, (b) three monolithic 90-190 line functions (`computeComplianceEvidence`, `NewAuthenticatorFromEnv`, `executePendingAction`) on report, auth and approval paths, (c) a duplicated dialect implementation that doubles the cost of every discovery fix, and (d) five files over 1,200 lines. No function is untestable-by-design, and none needs emergency work, so no CRITICAL. Fixing CX-001 and CX-002 and splitting `main()` would move this to 7-8.
