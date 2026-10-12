# Kryptkeeper V4 — Implementation Plan
# Sprint 3 + Sprint 4 + OSS Launch

**Date:** 2026-04-24
**Total estimate:** ~14 weeks (Sprint 3 + Sprint 4 + Launch)
**Branch:** `feature/v4-pqc-platform` off `improve/crypto-inventory-vision`

---

## Workstream Map

```
WS-01: ML-DSA Keystore (unblocked)
WS-02: ML-DSA CA + Issuance (blocked by WS-01)
WS-03: Hybrid Certificates (blocked by WS-01, WS-02)
WS-04: PKCS#11 Backend (unblocked, parallel with WS-01)
WS-05: Intune BYOCA Integration (unblocked, parallel)
WS-06: Crypto Posture Dashboard (unblocked, parallel)
WS-07: Template Policy Enforcement (unblocked, parallel)
WS-08: Satellite Agent (Sprint 4, blocked by WS-01–07 stable)
WS-09: K8s + Terraform (Sprint 4, parallel with WS-08)
WS-10: OSS Launch Prep (parallel from week 6)
```

---

## Sprint 3 Workstreams (Weeks 1–8)

---

### WS-01 — ML-DSA Keystore Backend
**Owner:** Backend
**Estimate:** 3 days
**Blocks:** WS-02, WS-03
**Risk:** T-02 (Go x509 compatibility) — SPIKE FIRST

**Tasks:**
- [ ] WS-01-1: Spike — verify `x509.CreateCertificate` accepts CIRCL ML-DSA signer
  - If yes: proceed with CIRCL
  - If no: build custom `CreateCertificateWithMLDSA` using raw DER encoding
  - Output: decision documented in `docs/sdlc/v4-planning/ADR_MLDSA_GO_X509.md`
- [ ] WS-01-2: Add `MLDSA44`, `MLDSA65`, `MLDSA87` to `Algorithm` enum (`internal/keystore/keystore.go`)
- [ ] WS-01-3: Add `go get github.com/cloudflare/circl` to `go.mod`
- [ ] WS-01-4: Implement `generateMLDSAKey(algo)` in `internal/keystore/software.go`
- [ ] WS-01-5: Implement `mldsaSigner` type wrapping CIRCL key; implement `crypto.Signer` interface
- [ ] WS-01-6: Wire `GenerateKey` and `Signer` for ML-DSA algorithms in `SoftwareStore`
- [ ] WS-01-7: Tests: `TestGenerateAndSignMLDSA44`, `TestGenerateAndSignMLDSA65`, `TestGenerateAndSignMLDSA87`
- [ ] WS-01-8: Test: round-trip (generate → persist → reload → sign → verify)

**Done when:** `go test ./internal/keystore/...` passes with ML-DSA cases; CIRCL signer accepted by x509 pipeline (or spike result documented).

---

### WS-02 — ML-DSA CA + Certificate Issuance
**Owner:** Backend
**Estimate:** 4 days
**Blocked by:** WS-01 spike result

**Tasks:**
- [ ] WS-02-1: Verify `ca.Engine.CreateRootCA` works with ML-DSA keyID
- [ ] WS-02-2: Verify `ca.Engine.IssueCertificate` produces valid cert when CA key is ML-DSA
- [ ] WS-02-3: Update `internal/pqc/planner.go` — recognize ML-DSA algorithms as `quantum_safe`
- [ ] WS-02-4: Add `MLDSA44/65/87` options to CA create UI (`ui/src/pages/CAs.tsx` algorithm picker)
- [ ] WS-02-5: Add `MLDSA44/65/87` options to cert issue UI (`ui/src/pages/Certificates.tsx`)
- [ ] WS-02-6: Integration test: create ML-DSA-65 root CA → issue leaf → download PEM → verify with CIRCL
- [ ] WS-02-7: OCSP: verify OCSP responder handles ML-DSA-signed certs correctly
- [ ] WS-02-8: CRL: verify CRL generator handles ML-DSA CA signing correctly

**Done when:** End-to-end ML-DSA cert issuance works in UI and API; PQC planner marks certs quantum_safe; OCSP/CRL functional.

---

### WS-03 — Hybrid Certificates (ECDSA + ML-DSA)
**Owner:** Backend
**Estimate:** 5 days
**Blocked by:** WS-01, WS-02

**Spec reference:** IETF draft-lamps-pq-composite-sigs-07
**Composite extension OID:** 2.16.840.1.114027.80.6.1 (pre-RFC, may change)

**Tasks:**
- [ ] WS-03-1: Add `HybridP256MLDSA65`, `HybridP384MLDSA87` to `Algorithm` enum
- [ ] WS-03-2: Implement `CompositeSigner` struct: holds classical + ML-DSA signer; `Sign()` calls both; returns concatenated DER
- [ ] WS-03-3: Implement `HybridStore` wrapper: `GenerateKey` creates two keypairs; stores both IDs
- [ ] WS-03-4: `encodeCompositePublicKey(classical, mldsa)` — encode as composite SubjectPublicKeyInfo per draft spec
- [ ] WS-03-5: `addCompositeSignatureExtension(cert, mldsaSig)` — add secondary sig as non-critical extension
- [ ] WS-03-6: Wire into `ca.Engine.IssueCertificate` — detect hybrid algo, use composite path
- [ ] WS-03-7: Update PQC planner: hybrid certs → `hybrid_quantum_safe`
- [ ] WS-03-8: UI: "Hybrid (ECDSA P-256 + ML-DSA 65)" option in algorithm pickers
- [ ] WS-03-9: Test: issue hybrid cert; verify ECDSA path with standard Go x509; verify ML-DSA path with CIRCL
- [ ] WS-03-10: Test: hybrid cert in TLS handshake (use httptest.NewTLSServer)

**Done when:** Hybrid cert issues, classical verifier accepts it, ML-DSA verifier also accepts it; tests pass.

---

### WS-04 — PKCS#11 / HSM Backend
**Owner:** Backend
**Estimate:** 4 days
**Unblocked**

**Dependency:** `github.com/ThalesGroup/crypto11`

**Tasks:**
- [ ] WS-04-1: `go get github.com/ThalesGroup/crypto11`
- [ ] WS-04-2: Add `PKCS11Store` struct to `internal/keystore/pkcs11.go` implementing `Store` interface
- [ ] WS-04-3: Config: read `KRYPTKEEPER_PKCS11_LIB`, `KRYPTKEEPER_PKCS11_SLOT`, `KRYPTKEEPER_PKCS11_TOKEN_LABEL`, `KRYPTKEEPER_PKCS11_PIN`
- [ ] WS-04-4: `GenerateKey`: dispatch to crypto11 key generation for RSA/ECDSA algorithms
- [ ] WS-04-5: `Signer`: return crypto11-backed signer (private key never leaves HSM)
- [ ] WS-04-6: `NewFromEnv()` factory: reads env vars, returns `*PKCS11Store` or error
- [ ] WS-04-7: Wire into `cmd/kryptkeeper/main.go` keystore selector: `KRYPTKEEPER_KEY_BACKEND=pkcs11`
- [ ] WS-04-8: UI: "HSM (PKCS#11)" option in CA key storage type selector
- [ ] WS-04-9: Tests (using SoftHSM2): generate key, get signer, sign cert, verify
  - CI note: SoftHSM2 must be available in test environment; document setup

**Done when:** `KRYPTKEEPER_KEY_BACKEND=pkcs11` starts Kryptkeeper using SoftHSM2; can create CA and issue cert with HSM-backed key; private key bytes never appear in logs.

---

### WS-05 — Microsoft Intune BYOCA Integration
**Owner:** Backend
**Estimate:** 3 days
**Unblocked**

**Reference:** https://learn.microsoft.com/en-us/intune/cloud-pki/configure-byoca

**Tasks:**
- [ ] WS-05-1: Research: document exact SCEP challenge format Intune expects for BYOCA
  - Output: `docs/sdlc/v4-planning/INTUNE_BYOCA_SPEC.md` (request/response examples)
- [ ] WS-05-2: Add `GET /scep/mscep_admin` → returns SCEP challenge password (Intune-specific URL)
- [ ] WS-05-3: Verify Intune-style SCEP `GetCACert` response format compatibility
- [ ] WS-05-4: Verify Intune-style `PKIOperation` with device-generated CSR compatibility
- [ ] WS-05-5: Add `GET /api/v1/integrations/microsoft` — returns BYOCA status object
- [ ] WS-05-6: UI: "Microsoft Integration" section in Settings page
  - BYOCA status: SCEP URL, enrollment URL, cert count
  - XCEP/WSTEP status: endpoint URL, last enrolled device
  - Copy-to-clipboard for enrollment URLs
- [ ] WS-05-7: Integration test: simulate Intune BYOCA SCEP flow with httptest
- [ ] WS-05-8: Write `docs/guides/intune-byoca.md` — step-by-step setup guide

**Done when:** SCEP endpoint responds correctly to Intune BYOCA challenge format (per spec); UI shows Microsoft Integration section; setup guide written.

---

### WS-06 — Crypto Posture Dashboard + Reporting
**Owner:** Frontend + Backend
**Estimate:** 5 days
**Unblocked**

**New page:** `ui/src/pages/CryptoPosture.tsx`
**New route:** `/crypto-posture` in `ui/src/App.tsx`
**New API:** `GET /api/v1/reports/crypto-posture`

**Backend tasks:**
- [ ] WS-06-1: New handler `internal/bootstrap/handlers_reports.go`
- [ ] WS-06-2: `cryptoPostureQuery(ctx, db)` — aggregate queries:
  - Algorithm breakdown (COUNT GROUP BY algorithm)
  - Expiry buckets (certs expiring in 47d/90d/200d/1yr)
  - PQC readiness score (% quantum_safe + hybrid)
  - Risk grade distribution (COUNT GROUP BY grade)
  - Automation coverage (% with `renewal_method = 'acme'`)
  - Policy violations (certs with weak algo where template forbids it)
- [ ] WS-06-3: `GET /api/v1/reports/crypto-posture` — returns structured JSON
- [ ] WS-06-4: Snapshot table `crypto_posture_snapshots(captured_at, data JSONB)` — weekly cron stores snapshot for trend
- [ ] WS-06-5: PDF export: Go `html/template` → `wkhtmltopdf` or pure-Go `gofpdf`
  - Output: executive one-pager with all metrics, date, org name
- [ ] WS-06-6: CSV export: raw cert inventory rows

**Frontend tasks:**
- [ ] WS-06-7: `CryptoPosture.tsx` — page layout with 6 sections
- [ ] WS-06-8: Algorithm donut chart (recharts or similar)
- [ ] WS-06-9: PQC readiness percentage with trend sparkline
- [ ] WS-06-10: Expiry urgency table (47d/90d/200d/1yr counts with click-through to filtered cert list)
- [ ] WS-06-11: Risk grade bar chart
- [ ] WS-06-12: "Export PDF" and "Export CSV" buttons
- [ ] WS-06-13: Add "Crypto Posture" to sidebar nav

**Done when:** Page loads with real data from API; PDF generates a readable one-pager; CSV includes all cert fields; trend data visible after second snapshot.

---

### WS-07 — Template Policy Enforcement at Issuance
**Owner:** Backend
**Estimate:** 3 days
**Unblocked**

**Tasks:**
- [ ] WS-07-1: `ValidateAgainstTemplate(req IssuanceRequest, tmpl Template) error` in `internal/ca/engine.go`
- [ ] WS-07-2: Enforce AllowedAlgorithms: return error if req algo not in list
- [ ] WS-07-3: Enforce MaxValidity: return error if req validity > template max
- [ ] WS-07-4: Enforce AllowedEKUs: return error if req EKU not in template list
- [ ] WS-07-5: Enforce MinKeySize: return error if key bits < minimum
- [ ] WS-07-6: Wire into `IssueCertificate` — call ValidateAgainstTemplate when TemplateID set
- [ ] WS-07-7: HTTP: map `ErrPolicyViolation` → 422 with `policy_violation` type and field detail
- [ ] WS-07-8: Wire TemplateID through XCEP/WSTEP enrollment path
- [ ] WS-07-9: Tests: one test per violation type; one test for valid issuance passing all checks

**Done when:** Issuing against a restrictive template with forbidden algo returns 422 with clear message; existing tests still pass.

---

## Sprint 4 Workstreams (Weeks 9–14)

---

### WS-08 — Satellite Agent v1
**Owner:** Backend
**Estimate:** 10 days
**Branch:** `feature/satellite-agent`

**Design principles:**
- Single Go binary, < 15MB, no CGO dependencies
- Outbound-only (phones home to Hub; no inbound port required)
- Read-only for discovery; writes only via Hub API

**Capabilities v1:**
- Discovers certs in Windows certificate store (via Windows API)
- Discovers certs in Linux file system (/etc/ssl, /etc/pki, common app dirs)
- Discovers certs in IIS, Apache, nginx config files
- Reports inventory to Hub API (`POST /api/v1/agent/inventory`)
- Performs auto-renewal via ACME when cert approaches expiry threshold
- Self-updates via Hub (Hub serves agent binary)
- Runs as Windows service or systemd unit

**Protocol:**
- Agent registers with Hub: `POST /api/v1/agent/register` → receives agent token
- Agent reports heartbeat: `POST /api/v1/agent/heartbeat`
- Agent reports inventory: `POST /api/v1/agent/inventory`
- Hub pushes renewal tasks: `GET /api/v1/agent/tasks` (agent polls)

**Tasks:**
- [ ] WS-08-1: New module `cmd/kryptkeeper-agent/`
- [ ] WS-08-2: Windows cert store discovery (golang.org/x/sys/windows)
- [ ] WS-08-3: Linux file system cert discovery (walk common paths)
- [ ] WS-08-4: IIS/Apache/nginx config parser for cert file paths
- [ ] WS-08-5: Hub API client (register, heartbeat, report, fetch tasks)
- [ ] WS-08-6: ACME renewal executor (use existing ACME client against Hub)
- [ ] WS-08-7: Windows service installer / systemd unit generator
- [ ] WS-08-8: Hub: agent management endpoints and agent store
- [ ] WS-08-9: UI: Agents page — list agents, status, last seen, certs managed
- [ ] WS-08-10: Cross-compile CI: build agent for windows/amd64, linux/amd64, linux/arm64

---

### WS-09 — Ecosystem Integrations
**Owner:** Backend
**Estimate:** 8 days (parallelizable)

**WS-09A: cert-manager Issuer Plugin (~4 days)**
- `CertificateRequest` CRD → Kryptkeeper API → issue cert → patch status
- Helm chart for plugin deployment
- Published to cert-manager community plugins

**WS-09B: Terraform Provider (~4 days)**
- `kryptkeeper_ca` resource (create/read/delete root + intermediate CAs)
- `kryptkeeper_certificate` resource (issue/renew/revoke)
- `kryptkeeper_template` resource (manage certificate templates)
- Published to HashiCorp Registry

---

### WS-10 — OSS Launch Preparation (Weeks 6–14, parallel)

**Checklist:**

**Code:**
- [ ] All Sprint 3 features stable and tested
- [ ] `CHANGELOG.md` complete with v1.0.0 entry
- [ ] `SECURITY.md` with vulnerability disclosure process
- [ ] License headers on all source files
- [ ] CGO usage audited (prefer pure-Go where possible)
- [ ] No hardcoded secrets, test credentials, or internal URLs

**Release artifacts:**
- [ ] GitHub Actions release workflow producing signed binaries
- [ ] Docker multi-arch image (linux/amd64, linux/arm64)
- [ ] Helm chart published to Artifact Hub
- [ ] cosign signature on all images + binaries
- [ ] SBOM (CycloneDX) attached to release

**Documentation:**
- [ ] `docs/` site structure (MkDocs or Docusaurus)
- [ ] Getting Started guide (< 15 min to first cert)
- [ ] "Replace ADCS with Kryptkeeper" guide
- [ ] "Connect Kryptkeeper to Microsoft Intune" guide
- [ ] "Issue your first PQC certificate" guide
- [ ] API reference (generated from OpenAPI spec)
- [ ] Deployment guide: Docker Compose, Kubernetes/Helm, bare metal

**Community:**
- [ ] GitHub Discussions enabled
- [ ] Issue templates (bug report, feature request, question)
- [ ] CONTRIBUTING.md
- [ ] Code of conduct
- [ ] GitHub Actions badge in README

**Launch:**
- [ ] HackerNews "Show HN" post draft
- [ ] r/netsec and r/sysadmin posts
- [ ] "Kryptkeeper vs. EJBCA vs. step-ca" comparison blog post
- [ ] LinkedIn / X announcement posts
- [ ] Record demo video (< 5 min): create CA → issue cert → revoke → OCSP

---

## Dependency Graph

```
WS-01 (ML-DSA keystore)
  └── WS-02 (ML-DSA CA issuance)
        └── WS-03 (Hybrid certs)
WS-04 (PKCS#11) ──────────────────────── parallel
WS-05 (Intune BYOCA) ─────────────────── parallel
WS-06 (Crypto Posture) ───────────────── parallel
WS-07 (Template enforcement) ─────────── parallel

Sprint 3 stable
  └── WS-08 (Satellite Agent)
  └── WS-09 (Ecosystem integrations)
  └── WS-10 (OSS Launch) ── starts week 6
```

---

## Timeline

```
Week 1–2:  WS-01 spike + implementation | WS-04 + WS-05 start
Week 2–4:  WS-02 (ML-DSA CA) | WS-06 (Crypto Posture) | WS-07 (Template enforcement)
Week 3–5:  WS-03 (Hybrid certs) | WS-05 complete | WS-04 complete
Week 5–6:  Sprint 3 integration testing | Bug fixes | Performance check
Week 6–8:  Sprint 3 freeze | WS-10 doc site starts | WS-08 design
Week 8–10: WS-08 Satellite Agent | WS-09A cert-manager | WS-09B Terraform
Week 10–12: Integration testing Sprint 4 | WS-10 docs complete
Week 12–14: OSS Launch: release cut, binaries signed, launch posts
```

---

## Gate Criteria

### Sprint 3 Gate (Week 8)
- [ ] All WS-01 through WS-07 done criteria met
- [ ] `go test ./... -count=1` passes with 0 failures
- [ ] `docker compose up` starts clean; all endpoints respond
- [ ] ML-DSA cert issuable via UI
- [ ] Crypto Posture page loads with real data
- [ ] No CRITICAL or HIGH security issues (run gosec + nancy)

### Sprint 4 Gate (Week 12)
- [ ] Satellite agent installs on Windows and Linux, discovers certs, reports to Hub
- [ ] cert-manager issuer plugin issues a cert in a local kind cluster
- [ ] Terraform apply creates a CA and issues a cert
- [ ] All Sprint 3 functionality still passing

### OSS Launch Gate (Week 14)
- [ ] All Sprint 4 gate criteria met
- [ ] Documentation site live with all 5+ guides
- [ ] Release binaries signed and SBOM attached
- [ ] Demo video recorded
- [ ] CHANGELOG.md complete
