# Kryptkeeper Sprint 3 Plan
# PQC · Microsoft Integration · Crypto Agility · Hub+Satellite Architecture

**Created:** 2026-04-24
**Status:** Planning
**Prerequisite:** Improvement Plan V2 waves 0–4 complete (2026-04-24 ✅)

---

## Context: Why This Sprint Matters Now

Three market forces make Sprint 3 urgent:

1. **TLS cert lifetimes are collapsing.** CA/Browser Forum mandated:
   - 200-day max starting **March 15, 2026** (already in effect)
   - 100-day max: March 15, 2027
   - **47-day max: March 2029**
   Only 5% of organizations have fully automated cert management. The other 95% face a manual renewal crisis.

2. **PQC deadline is real.** NIST FIPS 203/204/205 finalized August 14, 2024.
   CNSA 2.0 mandates PQC for national security systems by 2030. Enterprise migrations take 5–15 years.
   Keyfactor and Venafi/CyberArk already shipped ML-DSA issuance and hybrid certs (2025).

3. **Microsoft Cloud PKI (Intune BYOCA) is displacing ADCS.** Microsoft's own cloud PKI
   lets customers plug in any SCEP-capable CA as a "Bring Your Own CA" issuing authority —
   no NDES, no on-prem CA server. Kryptkeeper already speaks SCEP. One integration unlocks
   the entire Intune-managed device fleet for every customer.

---

## Competitive Landscape (April 2026)

| Platform | Model | PQC | ADCS Replacement | Price |
|---|---|---|---|---|
| CyberArk (Venafi) | Proprietary SaaS | ✅ composite PQC v25.1 | ✅ | $100K–$1M+/yr |
| Keyfactor Command + EJBCA | Commercial + OSS core | ✅ ML-DSA hybrid v25.2 | ✅ Enterprise only | $50K+/yr |
| DigiCert ONE | SaaS PKIaaS | Roadmap | ⚠️ BYOCA only | Per-cert pricing |
| AppViewX AVX ONE | SaaS automation | Roadmap PKIaaS | ❌ | Enterprise |
| step-ca | OSS | ❌ | ❌ | Free (limited) |
| EJBCA Community | OSS (LGPL) | ❌ OSS tier | ❌ OSS tier | Free (limited) |
| HashiCorp Vault PKI | OSS infrastructure | ❌ | ❌ | Free (no CLM) |
| **Kryptkeeper** | **OSS Apache 2.0** | **Sprint 3 target** | **✅ Unique in OSS** | **Free** |

**The gap Kryptkeeper fills:** No open-source product combines CA + CLM + ADCS replacement + PQC issuance + crypto agility reporting in a single platform.

---

## Architecture: Hub + Satellite Model

```
┌──────────────────────────────────────────────────────┐
│              KRYPTKEEPER HUB (Central)                │
│                                                      │
│  CA Engine    Key Management    Policy Engine        │
│  CLM (issue/revoke/renew)       PQC Planner          │
│  Crypto Inventory               Reporting/Dashboard   │
│  OCSP/CRL    AD Sync            REST API             │
└────────────────────┬─────────────────────────────────┘
                     │  REST API / ACME / SCEP / EST / CMP
          ┌──────────┼──────────────┐
          │          │              │
   ┌──────▼──┐  ┌────▼────┐  ┌────▼──────────┐
   │ Windows │  │ Linux/  │  │ Cloud/K8s      │
   │ Satellite│  │ Mac     │  │ Connector      │
   │          │  │ Agent   │  │                │
   │ XCEP/    │  │ ACME/   │  │ cert-manager   │
   │ WSTEP    │  │ EST/CMP │  │ ACME operator  │
   │ autoenrl │  │ renewal │  │ Terraform prov │
   └──────────┘  └─────────┘  └────────────────┘
```

### Hub (Central Platform)
What Kryptkeeper is today. Runs on-prem or cloud-hosted. Holds CA keys, issues certs,
manages policy, maintains crypto inventory, generates reports.

### Satellite Agent (New — Sprint 4)
Lightweight Go binary deployed on endpoint infrastructure:
- Discovers local certs (Windows cert store, Linux /etc/ssl, IIS/Apache/nginx configs, Java keystores)
- Manages local certificate stores
- Executes renewals via ACME/SCEP/EST against Hub
- Reports crypto inventory back to Hub API
- No inbound firewall rules required (outbound only)

### Protocol Connectors (Agentless)
For systems that already speak ACME, SCEP, or EST. No agent install.
Recommended for Kubernetes, DevOps pipelines, cloud workloads.

### Microsoft Integration (Three Paths)
1. **Intune BYOCA** — Kryptkeeper SCEP endpoint = BYOCA issuing CA for Microsoft Cloud PKI.
   No ADCS, no NDES, no connector agent. Just point Intune at our SCEP URL.
2. **Windows autoenrollment (XCEP+WSTEP)** — Already implemented. GPO points at Kryptkeeper.
3. **AD certificate templates** — Already synced via adsync package.

---

## Sprint 3 Priorities

### Priority 1 — PQC Issuance: ML-DSA Certificates (~2 weeks)

**Why:** Keyfactor shipped this in v25.1/25.2. Venafi in v25.1. Being first in OSS matters.

**Algorithm:** Use Cloudflare CIRCL (`github.com/cloudflare/circl/sign/mldsa`) until Go stdlib adds ML-DSA (~Go 1.26).

**Tasks:**
- Add `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` to `Algorithm` enum in `internal/keystore/keystore.go`
- Add ML-DSA key generation to `SoftwareStore.GenerateKey` using CIRCL
- Add ML-DSA `crypto.Signer` implementation using CIRCL's signer interface
- Wire through `ca.Engine.IssueCertificate` — Go's `x509` package signs with any `crypto.Signer`
- Update `internal/pqc/planner.go` to mark ML-DSA certs as `quantum_safe`
- Add ML-DSA to Cloud KMS store (AWS KMS already supports ML-DSA via `ML_DSA_44_SHA3_256`)
- UI: add ML-DSA algorithm options to CA-create and cert-issue dialogs
- Tests: ML-DSA root CA creation, ML-DSA cert issuance, verify signature with CIRCL

**Acceptance:** `go test ./...` passes; UI can create an ML-DSA-65 root CA and issue a leaf cert; PQC planner marks the cert quantum_safe.

---

### Priority 2 — Hybrid Certificates: Classical + PQC (~1 week)

**Why:** The bridge strategy for 2025–2030. Hybrid certs work with current TLS stacks (classical path) while adding quantum resistance (ML-DSA path). This is what Keyfactor v25.2 just shipped.

**Spec:** IETF draft-ounsworth-pq-composite-sigs / draft-lamps-pq-composite-sigs
- Primary key: ECDSA P-256 or P-384 (backward compat)
- Secondary key: ML-DSA-65 (quantum resistance)
- Stored as non-critical extension OID `2.16.840.1.114027.80.6.1` (composite sig)

**Tasks:**
- Add `HybridECDSAP256_MLDSA65` and `HybridECDSAP384_MLDSA87` to Algorithm enum
- `SoftwareStore.GenerateKey` for hybrid: generates two keypairs, stores both
- `SoftwareStore.Signer` for hybrid: returns a `CompositeSigner` that signs with both algorithms
- `ca.Engine.IssueCertificate`: detect hybrid algo, embed composite sig extension
- PQC planner: hybrid certs marked as `hybrid_quantum_safe`
- UI: "Hybrid (Classical + PQC)" option in algorithm picker
- Tests: issue hybrid cert, verify both signature paths independently

**Acceptance:** Can issue a hybrid ECDSA-P256+ML-DSA-65 certificate that a standard ECDSA verifier accepts (classical path) and that ML-DSA verifier also accepts.

---

### Priority 3 — Microsoft Intune BYOCA Integration (~3 days)

**Why:** Microsoft Cloud PKI BYOCA = plug any SCEP CA into Intune without NDES or ADCS.
Kryptkeeper's SCEP server is already complete. This is mostly configuration + documentation.

**Tasks:**
- Verify SCEP challenge response matches Intune's expected format (RFC 8894 compatible)
- Add `GET /scep/mscep_admin` endpoint (Intune-specific SCEP admin URL pattern)
- Test with Microsoft Intune Cloud PKI sandbox or documentation spec
- Write setup guide: "Connect Kryptkeeper to Microsoft Intune as a BYOCA"
- Document the three Microsoft integration paths (BYOCA, XCEP/WSTEP autoenroll, AD sync)
- UI: "Microsoft Integration" section in Settings showing connection status for each path

**Acceptance:** Documentation walks through Intune BYOCA setup end-to-end; SCEP endpoint responds correctly to Intune-style challenge requests.

---

### Priority 4 — Crypto Agility Dashboard & Reporting (~1 week)

**Why:** The 47-day cert cliff forces every security team into a conversation about automation.
Kryptkeeper needs to be the tool that makes that conversation visual and actionable.

**New page: "Crypto Posture"**

Sections:
1. **Algorithm Inventory** — Donut chart: certs by algorithm (RSA-2048, RSA-4096, ECDSA-P256, ECDSA-P384, ML-DSA-65, Hybrid, etc.)
2. **PQC Readiness Score** — % of cert estate that is quantum_safe, hybrid, or classical. Trend over time.
3. **Expiry Urgency** — Certs expiring in: next 47 days / 90 days / 200 days / 1 year. Color-coded.
4. **Risk Distribution** — Certs by risk grade (A/B/C/F). Breakdown by CA, team, business unit.
5. **Policy Violations** — Certs that violate active policies (weak algo, expired, no policy enforcement).
6. **Automation Coverage** — % of certs on ACME auto-renewal vs manual.

**Reports:**
- Export PDF/CSV summary for security leadership
- Scheduled email delivery (weekly/monthly) using existing notification delivery system
- API endpoint `GET /api/v1/reports/crypto-posture` returning structured JSON for SIEM integration

**Tasks:**
- New page `ui/src/pages/CryptoPosture.tsx`
- New API handlers in `internal/bootstrap/handlers_reports.go`
- Aggregate queries against `certificates` table for all metrics
- PDF export using Go's `html/template` → headless browser or pure-Go PDF lib
- Scheduled report delivery wired to `notifications/delivery` package
- Tests: report generation, metric accuracy, API contract

**Acceptance:** Security lead can see the full crypto posture of the org in one page and export a PDF for a board meeting.

---

### Priority 5 — PKCS#11 / HSM Backend (~1 week)

**Why:** Required for government/regulated customers. Required for PQC HSMs (Thales, Utimaco,
Securosys already support ML-DSA). PKCS#11 v3.2 will standardize ML-DSA/ML-KEM for HSMs.

**Implementation:** `ThalesGroup/crypto11` package — implements `crypto.Signer` over any PKCS#11 token.

**Tasks:**
- Add `PKCS11Store` to `internal/keystore/` implementing the `Store` interface
- Config: `KRYPTKEEPER_PKCS11_LIB`, `KRYPTKEEPER_PKCS11_TOKEN_LABEL`, `KRYPTKEEPER_PKCS11_PIN`
- `GenerateKey`: calls `C_GenerateKeyPair` on the HSM
- `Signer`: returns a `crypto11`-backed signer — private key never leaves HSM boundary
- SoftHSM2 for integration tests (no hardware required)
- UI: "HSM" option in key storage type when creating CA
- Tests: generate key on SoftHSM, sign cert, verify

**Acceptance:** Can create a root CA backed by SoftHSM; signing operations go through PKCS#11; private key bytes never appear in memory.

---

### Priority 6 — Template Policy Enforcement at Issuance (~3 days)

**Why:** Templates exist as metadata but `IssueCertificate` ignores them. This is required before
ADCS replacement is credible — ADCS enforces templates strictly.

**Tasks:**
- Add `ValidateAgainstTemplate(req IssuanceRequest, tmpl Template) error` to `internal/ca/`
- Enforce: allowed algorithms, max validity period, allowed EKUs, required SANs patterns
- Return `ErrPolicyViolation` with a clear message on violation
- Wire validation into `IssueCertificate` before key generation
- Update XCEP/WSTEP handlers to pass `TemplateID` through to issuance
- Tests: each violation type returns the right error

**Acceptance:** Issuing a cert with a disallowed algorithm against a template returns 422 with a policy-violation message. ADCS-style template enforcement is testable.

---

## Key Management Story

Kryptkeeper's key management tier (what we have + what we're adding):

| Backend | Status | Use Case |
|---|---|---|
| Software (AES-256-GCM + Argon2id) | ✅ Done | Dev, small deployments |
| AWS KMS | ✅ Done | AWS-hosted customers |
| GCP Cloud KMS | ✅ Done | GCP-hosted customers |
| Azure Key Vault | ✅ Done | Azure-hosted customers |
| PKCS#11 / HSM | Sprint 3 | Government, regulated, enterprise |
| ML-DSA software key | Sprint 3 | PQC issuance |
| ML-DSA on HSM | Sprint 4 | PQC + hardware root of trust |

This positions Kryptkeeper as a **crypto-agile key management platform** — not just a CA. The key
storage backend is a pluggable abstraction. When a customer upgrades from software keys to HSM keys
to PQC keys, the CA stays the same; only the keystore changes.

---

## PQC Migration Playbook for Customers

This is a feature Kryptkeeper should surface as a guided workflow:

**Phase 1 — Inventory (now)**
- Run discovery scan: identify all certs in the estate
- Classify each cert: quantum_safe, hybrid, classical, expired
- Generate "PQC Readiness Report" (Crypto Posture dashboard)
- Identify highest-risk certs: long-lived + classical + CA certs = CRITICAL

**Phase 2 — Hybrid Migration (2026–2028)**
- Create hybrid root CA (ECDSA-P384 + ML-DSA-87) on Kryptkeeper
- Issue hybrid leaf certs for highest-risk systems first
- Old ECDSA certs continue working; hybrid certs provide forward protection
- Track migration progress in Crypto Posture dashboard

**Phase 3 — PQC Native (2028–2030)**
- Create pure ML-DSA root CA
- Retire hybrid CAs
- Update trust stores across the estate (satellite agents handle this)
- Report completion: 100% quantum_safe score in Crypto Posture

---

## Sprint 3 Delivery Timeline (Single Developer Estimate)

| Priority | Work | Estimate |
|---|---|---|
| 1 — ML-DSA issuance | Backend + tests + UI | 10 days |
| 2 — Hybrid certs | Backend + tests + UI | 5 days |
| 3 — Intune BYOCA | SCEP + docs | 3 days |
| 4 — Crypto Posture dashboard | UI + API + reports | 5 days |
| 5 — PKCS#11 / HSM | Keystore backend | 5 days |
| 6 — Template enforcement | CA engine gate | 3 days |
| **Total** | | **~31 days** |

---

## Sprint 4 Preview (After Sprint 3)

- **Satellite Agent** — Lightweight Go binary for Windows + Linux cert discovery and auto-renewal
- **Kubernetes Operator** — cert-manager-compatible CRD issuer backed by Kryptkeeper
- **Terraform Provider** — `kryptkeeper_ca`, `kryptkeeper_certificate` resources
- **AI/MCP Integration** — Kryptkeeper MCP server for Claude/Copilot (following Keyfactor's lead)
- **SIEM Integration** — Syslog/webhook for cert events (issue, revoke, expiry alert)
- **Multi-tenant** — Org/team isolation for MSP deployments

---

## Why Kryptkeeper Wins (The Pitch)

1. **Open source, no per-cert pricing** — Venafi and Keyfactor charge per cert or per node.
   At 47-day cert lifetimes, per-cert pricing becomes punishing.

2. **First OSS platform with native ADCS replacement** — XCEP+WSTEP on Linux, no Windows CA
   server required. EJBCA charges enterprise license for this.

3. **First OSS platform with ML-DSA issuance + hybrid certs** — After Sprint 3, leads all
   OSS options on PQC by a wide margin.

4. **Intune BYOCA without a connector** — Plug Kryptkeeper directly into Microsoft Cloud PKI.
   No NDES, no connector agent, no Windows server.

5. **Crypto agility reporting** — The 47-day cert cliff forces every enterprise into an
   automation conversation. Kryptkeeper's Crypto Posture dashboard makes that visual.

6. **Key management + PKI in one platform** — Software keys → Cloud KMS → HSM → PQC HSM,
   all under the same `crypto.Signer` abstraction. No rip-and-replace as customers mature.
