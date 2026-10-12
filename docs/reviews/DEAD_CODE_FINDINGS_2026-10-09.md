# Dead Code Findings — 2026-10-09

Scope: Go backend + ui/ at main 6062c62 (worktree code-review-2026-10-09). Read-only review.
Inputs: `docs/work/code-reviewer/health-2026-10-09/{deadcode,deadcode-with-tests,staticcheck}.txt`.
Method: every entry hand-verified with grep over `cmd internal sdk` (non-test callers). knip not run (ui/node_modules absent). Confidence <75 suppressed.

## Dead Code score: 5 / 10

Reasoning: the unreachable-even-with-tests list is small (43), mostly benign. The score is dragged down by
**4 HIGH disconnected pipelines** (SIEM push, upstream-connector renewal, accepted-risk exceptions, non-ACME CA connectors)
that have passing tests and look finished in review but do nothing in production.

## Utilization Summary

| Metric | Value |
|---|---|
| `deadcode ./...` (no tests) unreachable funcs | 155 |
| `deadcode -test ./...` unreachable funcs | 43 (36 non-test-file, 7 inside `_test.go`) |
| Reachable only from tests (155 - 43 = 112) | 112 (bootstrap 42, connectors 37, agentdiscovery 22, sshkeys 8, audittrust 7, keystore 7, conformance kit 6) |
| Of the 43: truly dead | 27 |
| Of the 43: build-tag stub / platform shim / test hook (keep) | 8 |
| Of the 43: public/verifier surface (keep) | 4 |
| Of the 43: disconnected pipeline entries | 4 (SIEM Emit/EmitFromAuditEntry/mapAuditActionToSIEM, newFindingExceptionID) |
| Test-only-in-practice features (tests, no prod wiring) | 7 (DEAD-001..009 excl. 005 partial) |
| Orphan UI files | 0 (all pages routed or rendered; Onboarding is rendered via Dashboard.tsx:347) |
| Unused UI primitives | 5 shadcn files + 1 tracked `.bak` |

Findings: 15 total. By class: (d) disconnected 9, (a) delete 6 (one grouped). By severity: HIGH 4, MEDIUM 5, LOW 6. Live-path stubs: 0 (no CRITICAL).

## Disconnected pipelines (class d) — the important ones

### DEAD-001 [HIGH] SIEM forwarding never receives events — only the "test" button works
- `internal/bootstrap/siem_integration.go:187` `func (s *SIEMRouter) Emit(`; `:453` `func (s *SIEMRouter) EmitFromAuditEntry(entry AuditEntry)`; `:475` `mapAuditActionToSIEM`.
- Evidence: `grep -rn 'EmitFromAuditEntry\|\.Emit(' internal cmd` -> only the definitions and the internal call between them. `NewSIEMRouterFromEnv` is called only in `handlers_integrations.go:90` (status) and `:112` (`router.Test`). No audit-write path references SIEM (`grep -ril siem` -> handlers_integrations, siem_integration, evidence_mailer only).
- Product today: operator sets SIEM_WEBHOOK_URL / SIEM_SYSLOG_ADDR, UI shows "configured", the Test button succeeds, and **no real audit/security event is ever forwarded**. Silent compliance gap.
- Should be called from: the audit emission path (`emitAuditEvent` / AuditProvider append) -> `EmitFromAuditEntry`.
- Action: wire into audit append (async, non-blocking, failures non-fatal) or remove the "enabled" claim from status. Confidence 92.

### DEAD-002 [HIGH] Upstream-CA renewal is disarmed: RenewalExecutor never gets its connector registry
- `internal/bootstrap/renewal_executor.go:127` `func (e *RenewalExecutor) WithConnectorRegistry(r *connectors.Registry)`; `handlers_connectors.go:45` `BuildConnectorRegistry` (both unreachable even with tests... callers are only `*_test.go`).
- Evidence: production builds the executor at `cmd/kryptkeeper/main.go:324`: `bootstrap.NewRenewalExecutorFromEnv(certificateProvider).WithPluginDeliverer(...)` — no `.WithConnectorRegistry`. `renewMaterial` (`renewal_executor.go:499`) gates on `e.registry != nil`, so it always falls to `e.certs.RenewCertificate` (line ~516). `connectors.NewRegistry` has zero non-test callers.
- Product today: a cert with `RenewalConnectorID` set (acme/internal connector) is renewed **by the hub's own CA** instead of the pinned upstream issuer — wrong issuer, no error, no audit hint. `renewalKeyAlgorithmFor` SCEP-RSA branch is likewise unreachable.
- Action: in main.go call `BuildConnectorRegistry(ctx, connectorStore, certificateProvider, creds)` and pass to `WithConnectorRegistry` (refresh on connector create/delete). Confidence 90.

### DEAD-003 [HIGH] Accepted-risk finding exceptions can never be created
- `internal/bootstrap/finding_exception_store.go:131` `func newFindingExceptionID()`; `Create` on `:148`/`:203`.
- Evidence: `grep -rn 'FindingException{' internal cmd` outside tests -> only the scan-row constructors in the store itself; `.Create(` on the store is called only from `*_test.go` (finding_exception_store_test, handlers_pqc_countdown_test). No `/api/v1/.../exceptions` handler registered (openapi.yaml mentions exceptions only as report text). Readers (`discovery_db_provider.go:592`, `handlers_reports.go:155`, executive summary, PQC countdown) all call `ListActive`.
- Product today: the exception-aware funnel (raw/effective/suppressed, W2-06/W2-11/W2-12) always sees an empty set, so "suppressed" is always 0 and risk acceptance is impossible via the product.
- Action: add create/list/revoke handler (proposer != approver applies) or drop the feature surface from reports/openapi. Confidence 88.

### DEAD-004 [HIGH] DigiCert / EST / SCEP / WSTEP issuer connectors exist but cannot be instantiated
- `internal/connectors/{digicert,est_client,scep_client,wstep_client}.go` (37 of the 112 test-only funcs). `NewDigiCertConnector`, `NewESTClient`, `NewSCEPClient`, `NewWSTEPClient` have only `_test.go` callers.
- Evidence: `handlers_connectors.go:26-39` `buildRuntimeConnector` switch handles only `"internal"` and `"acme"`; `default: return nil` -> listing reports health "unknown". The `ID/Type/Origin` methods in the deadcode-with-tests list are the interface impls of these never-built types.
- Product today: a stored connector row of type digicert/est/scep/wstep is inert; the SCEP renewal path in DEAD-002 can never trigger. Confidence 85 (could be intentional roadmap, but code + tests ship as if live).
- Action: add cases to `buildRuntimeConnector` (config decode + creds) or move packages behind a build tag/WIP note; fix with DEAD-002.

### DEAD-005 [MEDIUM] CT-monitor findings are write-only
- `internal/ctmonitor/store.go:83` `EnsureSchema`(called inside NewStore), `:117` `Store.List`, `:152` `Store.Acknowledge` unreachable. `cmd/kryptkeeper/main.go:348-373` builds Store+Monitor; `bootstrap` does not import ctmonitor (grep).
- Product today: unknown-certificate CT findings are persisted but no API/UI can list or acknowledge them (only the notifier path surfaces them). Add handler or document. Confidence 80.

### DEAD-006 [MEDIUM] Agent keystore/config/agentless-SSH discovery never invoked
- `internal/agentdiscovery/keystores.go:42,150,178,224` (`ParseJKSCerts`, `ParsePKCS12Certs`, `ParseKubeconfigCerts`, `ScanKeystoreFile`), `configparser.go:78 FindCertPathsInConfigs`, `agentless_ssh.go:82 NewAgentlessSSHScanner` (+Scan, scanHostKeys, parseCertsSkippingKeys, looksLikeKeyFile).
- Evidence: `cmd/kryptkeeper-agent/main.go:194,202` calls only `WalkCerts`/`WalkConfigCerts`; `bootstrap/winrm_discovery.go` uses only the WinRM scanner. Zero non-test callers of the above.
- Product today: JKS/PKCS12/kubeconfig and agentless SSH discovery silently do not run; ~22 funcs test-only. Confidence 88. Wire into agent walk / scan job or delete.

### DEAD-007 [MEDIUM] sshkeys.Inventory (stale-key + risk scoring) unused
- `internal/sshkeys/inventory.go:57 NewInventory`, `Add/List/StaleKeys/Stats`, `computeSSHRisk`, `FingerprintPublicKey`, `SSHKey.IsStale`. `bootstrap` imports sshkeys only for `Policy/IssueCert/AuthorityLine`. Product has no SSH key inventory/staleness report. Confidence 88.

### DEAD-008 [MEDIUM] Expiry ThresholdEvaluator not scheduled
- `internal/notifications/delivery/delivery.go:378 NewThresholdEvaluator`, `:390 Evaluate`: zero non-test callers. I did not find another certificate-expiry notification path (SLO/anomaly wiring use `delivery.Channel` only). Possible that renewal_scheduler covers it — owner to confirm. Confidence 75.

### DEAD-009 [MEDIUM] AD enrollment-service registration unused
- `internal/adsync/adsync.go:127 Service.RegisterEnrollmentService`; `bootstrap/handlers_adsync.go` uses templates sync only. Confidence 78.

## Truly dead code (class a)

### DEAD-010 [LOW] SA4010 dead slice in CRL generator — confirmed
- `internal/crl/generator.go:79-85`: `revokedEntries := make([]pkix.RevokedCertificate, 0, len(revokedCerts))` + append loop; template uses `RevokedCertificateEntries: toRevocationEntries(revokedCerts)` (line 101). `grep -n revokedEntries` shows only lines 79/81. Delete the block (and `pkix` import if now unused). Confidence 99.

### DEAD-011 [LOW] Duplicate `*StoreFromEnv` constructors (NOT disconnected)
- `bootstrap/dashboard_action_db_provider.go:41 newDBDashboardActionStoreFromEnv`, `discovery_db_provider.go:596 newDBDiscoveryStoreFromEnv`, `notification_db_provider.go:47 newDBNotificationStoreFromEnv`: zero callers (staticcheck U1000 agrees).
- I checked the hypothesis that production falls back to memory: it does not. The sibling `new...ProviderFromEnv` is the wired path (`dashboard_action_provider.go:73`, `notification_provider.go:98`, `discovery_provider.go:204`) and duplicates the same `newDBProviderState` call. Delete the three Store variants. Confidence 95.

### DEAD-012 [LOW] Individually dead funcs/methods (delete)
| file:line | symbol | evidence |
|---|---|---|
| internal/acme/server.go:86 | `NewServer` | main.go:560 uses `NewServerWithStore`; wrapper only ever referenced by its own doc |
| internal/bootstrap/user_provider.go:54 | `NewFileUserProvider` | 0 callers; `NewUserProviderFromEnv` builds `&fileUserProvider{}` directly |
| internal/bootstrap/handlers_agents.go:240 | `memAgentStore.authenticate` | U1000 + 0 callers |
| internal/ca/ceremony.go:89 | `CeremonyManager.SetClock` | 0 callers anywhere incl. tests |
| internal/ca/hybrid_cert.go:185 | `ParseHybridCertPEM` | 0 callers |
| internal/ca/revocation.go:147 | `DBRevocationStore.ph` | U1000 |
| internal/agentdiscovery/linux.go:158-181 | `KeySize, IsExpired, DaysUntilExpiry, FormatFingerprint` | 0 callers |
| internal/keystore/cloudkms_azure.go:98 | `azureKVGetPublicKey` | U1000 |
| internal/keystore/mldsa.go:171 | `mldsaPublicKeyFromSigner` | U1000 |
| internal/keystore/vault.go:445 | `hashForOpts` | U1000 |
| internal/keystore/leaf_escrow.go:41 | `LeafEscrowPolicy.OptOut` | 0 callers; tenant escrow opt-in has no revoke path (only `NewLeafEscrowPolicy` from env at handlers_key_custody_ops.go:41) — also a small feature gap |
| internal/cipheraudit/auditor.go:83 | `Auditor.AuditMultiple` | 0 callers |
| internal/cmp/pkimessage.go:48 | type `certOrEncCert` | U1000 |
| internal/cmp/replay.go:71 | `replayCache.size` | 0 callers |
| internal/cloudinventory/aws_acm.go:100 | `acmStatusToString` | 0 callers |
| internal/acme/server.go:1360, http01.go:76 | `SetTXTResolver`, `SetHTTP01DialContext` | 0 callers (test seams never used; keep only if a test is planned) |
| internal/agentinstall/iis.go:144 | `IISInstaller.WithTempDir` | 0 callers |
| internal/plugins/delivery/runtime.go:67,78,81; deliver.go:75 | `Runtime.Close`, `Plugin.Manifest/Granted/Validate` | 0 prod callers; `Runtime.Close` unreachable may mean wazero runtime never closed (check lifecycle) |
| internal/metrics/metrics.go:25,31 | `Counter.Add`, field `mu` | U1000 on `mu` |
Confidence 90 each (hand-grepped).

### DEAD-013 [LOW] Unused test helpers/types (staticcheck U1000, all `_test.go`)
`agentdiscovery/ntlm_server_test.go:15,21,27` (`testServerSealer`, `newTestServerSealer`, `seal1`), `winrm_sealed_test.go:37 authedConns`, `bootstrap/auth_oidc_login_test.go:27 newTestOIDCTokenEndpoint`, `certs_summary_store_test.go:28,32 stubCertSummaryStore(.LoadSummary)`, `handlers_ssh_certs_test.go:62 newSSHCertTestMux`, `dashboard_handlers_test.go:16,22 err`, `handlers_byok_test.go:23 priv`, `cmp/cmp_test.go:80 cmpTestMessage`. Delete. Confidence 95.

### DEAD-014 [LOW] Unused shadcn primitives (UI)
`ui/src/components/ui/{alert-dialog,dialog,select,sidebar,table}.tsx`: no importer (`grep -rF "ui/<name>" ui/src` excluding self and tests = 0; no sibling import). Generated library files; safe to delete or keep as palette — project choice. Confidence 80.

### DEAD-015 [LOW] Tracked backup file
`ui/src/index.css.bak` (145 lines) is git-tracked (`git ls-files` lists it); referenced by nothing. Delete. Confidence 97.

## Keep: classified, no action

| Entry | Class | Why |
|---|---|---|
| agentdiscovery/windows_stub.go:16 `WalkWindowsCerts` | (b) | default-build stub for `windows.go` (CLAUDE.md rule); real one called from walk_windows.go:13 |
| connectors `ID/Type/Origin` on DigiCert/EST/SCEP/WSTEP (digicert.go:76-78, est_client.go:56-58, scep_client.go:72-74, wstep_client.go:60) | (b) interface impls | dead only because DEAD-004; resolve there |
| keystore `newAWSKMSImportTargetWithAPI`, keyinventory `newAWSKeySourceWithAPI`, certmanagerissuer `NewK8sClient`, notifications `AllowLoopbackForTest`, `NewCloudKMSStore` (memory wrapper) | (b) test seams / constructors | documented test injection points |
| keystore/fips.go:47 `FIPSPosture` | (b/c) | posture API; confirm a caller exists in `fips`-tagged build before deleting |
| audittrust `VerifyInclusion, VerifyConsistency, VerifyCheckpoint, rootFromInclusion, isPowerOfTwo, AppendLeafHash, EqualRoots` | (c) | the handler (`handlers_audit_trust.go:94`) serves proofs; these are the verifier half for external auditors and tests. `AppendLeafHash`/`EqualRoots` have no tests either; fold into docs or delete (LOW) |
| db/migrate.go:112,317 `RollbackMigration`, `applyDown` | (c) ops API | no CLI exposes it; add a `kryptkeeper migrate down` command or accept as library-only |
| tests/plugins/conformance/kit.go (6 funcs) | (c) | third-party plugin conformance kit; used by plugin tests |
| plugins/delivery `Manifest/Granted` | (c) | plugin ABI accessors; keep |

## Priorities
1. DEAD-002 + DEAD-004 (wrong issuer on upstream renewals; connector types inert).
2. DEAD-001 (SIEM forwards nothing) and DEAD-003 (exceptions cannot be created).
3. DEAD-005..009 decide wire-or-delete per feature; each has green tests that mask the gap.
4. DEAD-010..015 one cleanup PR (~250 lines removed).
