# Kryptkeeper — Strategic Gap Analysis

> **SUPERSEDED (recorded 2026-07-15, design review G-7):** the roadmap here was superseded by `docs/archive/GO_FORWARD_PLAN.md` (2026-06-10), and several "gaps" below (multi-tenancy, SPIFFE/SVID, MCP) have since SHIPPED (v2.0–v2.2). Historical record only.
**Date:** 2026-04-26  
**Scope:** Key management gaps, certificate management gaps, security reporting gaps,
regulatory policy landscape, and Venafi feature parity analysis.

---

## Table of Contents

1. [Where We Are Now](#1-where-we-are-now)
2. [Regulatory & Policy Landscape](#2-regulatory--policy-landscape)
3. [Key Management Gaps](#3-key-management-gaps)
4. [Certificate Management Gaps](#4-certificate-management-gaps)
5. [Security Reporting Gaps](#5-security-reporting-gaps)
6. [Venafi Feature Parity Analysis](#6-venafi-feature-parity-analysis)
7. [Priority Roadmap](#7-priority-roadmap)

---

## 1. Where We Are Now

### Implemented (v1.0.0)

| Capability | Status |
|---|---|
| CA engine (root + intermediate) | ✅ Full |
| ML-DSA-44/65/87 issuance (FIPS 204) | ✅ Full |
| Hybrid certs (ECDSA + ML-DSA alt-sig) | ✅ Full |
| PKCS#11 / HSM backend (build-tagged) | ✅ Full |
| All 6 enrollment protocols (ACME, SCEP, EST, CMP, WSTEP, XCEP) | ✅ Full |
| Microsoft Intune BYOCA SCEP | ✅ Full |
| OCSP responder | ✅ Full |
| CRL generation | ✅ Full |
| Template policy enforcement at issuance | ✅ Full |
| Certificate discovery (network scanner) | ✅ Full |
| Crypto Posture dashboard (PQC score, expiry, grades) | ✅ Partial |
| Satellite agent (Linux/Windows cert walker, ACME renewal) | ✅ Full |
| cert-manager external issuer | ✅ Full |
| Terraform provider | ✅ Full |
| Audit log | ✅ Partial |
| Notification rules (threshold-based) | ✅ Partial |
| AWS/GCP/Azure KMS signing backends | ✅ Full |
| SSH key inventory | ✅ Partial |
| Code signing tracking | ✅ Partial |

### Not Yet Implemented (v1.0.0 gaps)

See sections 3–6 for details.

---

## 2. Regulatory & Policy Landscape

### 2.1 CA/Browser Forum — Certificate Lifetime Collapse

The most significant market forcing function of the next 3 years.

| Date | Max TLS Validity | DCV Reuse | Impact |
|---|---|---|---|
| Until March 14, 2026 | 398 days | 398 days | Manual renewal feasible |
| **March 15, 2026** | **200 days** | **200 days** | ~2x renewals/year |
| **March 15, 2027** | **100 days** | **100 days** | ~4x renewals/year — automation becomes necessary |
| **March 15, 2029** | **47 days** | **10 days** | ~8x renewals/year — manual renewal impossible at scale |

**Vote:** Apple proposed, Google/Microsoft/Mozilla voted unanimously in favor (April 11, 2025, Ballot SC-081v3).

**OCSP implication:** At 47-day lifetimes, short-lived cert carve-out (≤7 days) doesn't apply, but browsers already treat OCSP as unreliable. The ballot explicitly states shorter lifetimes are intended to replace revocation. OCSP will effectively be deprecated for public TLS by 2029.

**The automation math:** An org with 1,000 certificates at 47-day lifetimes = **~8,500 renewal operations/year**. Only 5% of organizations have fully automated cert management today. This is the market.

**Let's Encrypt went further:** 6-day certificates launched January 2026. Already generally available. These require fully automated ACME with ARI (ACME Renewal Information).

**Kryptkeeper positioning:** Every org with >50 certs needs a CLM platform by 2027. We need to be the automation layer that makes 47-day certs invisible.

---

### 2.2 NIST Key Management Standards

**NIST SP 800-57 Rev. 5 (current) / Rev. 6 Draft (Dec 2025):**
- Private signature keys: recommended cryptoperiod 1–3 years
- Rev. 6 adds ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205) as approved algorithms

**NIST SP 800-131A Rev. 3 Draft (Oct 2024) — critical deprecation timeline:**
- SHA-1 for cryptographic protection: disallowed after **December 31, 2030**
- RSA-2048, ECC-224: disallowed after **December 31, 2030** (minimum security strength rises to 128-bit)
- New minimums post-2030: RSA-3072+, ECC-256+, SHA-256+

**CNSA 2.0 (NSA — National Security Systems):**
- Mandates ML-DSA, ML-KEM, SLH-DSA, AES-256, SHA-384
- Software/firmware signing: PQC preferred now, **exclusive by 2030**
- All NSS: fully PQC by **December 31, 2031**

**What this means for Kryptkeeper:**
- Need to track and report on certs that will become non-compliant after 2030 (RSA-2048, SHA-1 signed)
- Our ML-DSA issuance is not just forward-looking — it's a compliance requirement for federal customers

---

### 2.3 Compliance Frameworks Driving CLM Demand

| Framework | Cert Inventory Required? | Key Management Policy? | Cipher Review? | Automation Implied? | HSM for CA Keys? |
|---|---|---|---|---|---|
| **PCI DSS 4.0.1** | ✅ Yes (Req 4.2.1.1, mandatory March 2025) | ✅ Yes | ✅ Annual (Req 12.3.3) | Strongly | Recommended |
| **SOC 2 Type II** | ✅ Yes (audit evidence) | ✅ Yes | ✅ Best practice | ✅ Yes (renewal logs required) | Best practice |
| **FedRAMP** | ✅ Yes (CM-03(06)) | ✅ Yes (SC-12) | ✅ Annual | ✅ Required | ✅ Yes (FIPS 140-2/3) |
| **HIPAA 2025** | Implied | ✅ Yes | Best practice | ✅ Required for PHI paths | ✅ FIPS 140-2 Level 2+ |
| **ISO 27001:2022** | Best practice | ✅ Yes (A 8.24) | ✅ Annual policy review | Best practice | Best practice |
| **NIST SP 800-57** | N/A | ✅ Yes | N/A | N/A | Recommended |
| **CNSA 2.0** | N/A | ✅ Yes | N/A | Required for 2030 | ✅ Required |

**Key insight:** PCI DSS Req 4.2.1.1 (mandatory March 2025) requires a searchable, auditable certificate inventory with key strength, algorithm type, expiry dates, and issuing CA. This is already driving immediate CLM tool purchases. Every org in PCI scope needs exactly what Kryptkeeper provides.

---

## 3. Key Management Gaps

### 3.1 No Key Rotation Mechanism

**What we have:** `UpdateCAStatus()` — can suspend/revoke a CA. No `RotateCAKey()`.

**What's needed:** When a CA signing key needs to be rotated (scheduled rotation per NIST SP 800-57's 1–3 year cryptoperiod, or emergency rotation after compromise), users must:
1. Create a new CA manually
2. Migrate all active certs manually
3. Update all clients pointing to the old OCSP/CRL URLs

**Compliance impact:** NIST SP 800-57 Part 1 requires documented key rotation procedures. SOC 2 and ISO 27001 auditors expect evidence of rotation schedules. Without a rotation mechanism, customers can't pass these audits.

**Required API:**
```
POST /api/v1/cas/{id}/rotate-key
  body: { new_algorithm, effective_date }
  behavior: generates new key, re-issues CA cert signed by parent,
             marks old key as post-operational,
             existing leaf certs remain valid until their NotAfter
```

---

### 3.2 No Key Backup / Disaster Recovery

**What we have:** `SoftwareStore.GenerateKey()` uses `O_EXCL` (no overwrite). Keys encrypted with Argon2id + AES-256-GCM on disk. No export mechanism.

**What's missing:** If the server disk fails and you have no backup, or you need to migrate to a new server, all CA keys are permanently lost. Every issued certificate becomes unverifiable.

**Required capabilities:**
- Export encrypted key backup (wrapped with a separate recovery passphrase or KMS key)
- Import key from backup (for disaster recovery or CA migration)
- Key escrow: split-knowledge export (M-of-N scheme)

---

### 3.3 Vault Transit Backend Missing (README Layer 2 is a Lie)

**README says:** "Layer 2: Envelope encryption (AES-256-GCM + Vault/KMS master key)"

**Reality:** This doesn't exist. The software store uses a process-level passphrase — not Vault or KMS envelope encryption. For production, users must jump directly to PKCS#11 or cloud KMS.

**What's needed:** HashiCorp Vault transit secret engine as a wrapping layer for software-stored keys. The key material stays on disk but is wrapped by a Vault-managed master key. Vault provides:
- Audit log of every key unwrap operation
- Master key rotation without re-encrypting all leaf keys
- Access control independent of the Kryptkeeper process
- High availability via Vault HA mode

---

### 3.4 Azure KMS RSA Gap

```go
// cloudkms_azure.go:238
return nil, fmt.Errorf("azure kv: RSA JWK parsing not implemented — export as PEM from Key Vault")
```

Azure ECDSA works. Azure RSA CA keys do not. Any enterprise running Azure Key Vault with RSA CAs hits this at runtime with no workaround except switching to ECDSA. Needs to be fixed.

---

### 3.5 Signer Cache Has No TTL or Eviction

```go
signers map[string]crypto.Signer // cached decrypted signers
```

Every CA key decrypted by a `Signer()` call lives in process memory indefinitely. In a long-running Hub serving dozens of CAs, this means all private key material is in memory permanently after first use.

**Risk:** Memory dump attack, coredump file exposure, or process swap can expose all CA private keys.

**Fix:** TTL-based eviction (e.g., 15 minutes idle) or explicit cache invalidation. After eviction, the next `Signer()` call re-decrypts from disk. Slight performance cost at the benefit of minimizing in-memory key exposure window.

---

### 3.6 No ML-DSA Support in Cloud KMS (Vendor Gap — Must Document)

AWS KMS, GCP Cloud KMS, and Azure Key Vault do not yet support ML-DSA signing. This means:
- PQC CA keys MUST use the SoftwareStore or PKCS#11
- Enterprises wanting PQC + cloud HSM-level protection cannot have both today

This is a vendor limitation, not our bug, but users will hit it and blame us. We need:
1. Clear documentation
2. A recommendation: use SoftwareStore + Vault transit for PQC CAs (Vault wraps the key, Kryptkeeper holds the ML-DSA signer)

---

### 3.7 No Key Usage Tracking

There is no query to answer: *"Which certificates were signed with CA key X?"* beyond querying by `ca_id`. If a CA key is compromised, you need to know every cert that must be re-issued.

**Required:** Key lineage graph — for each key ID, show all certificates issued using that key, with their expiry status.

---

## 4. Certificate Management Gaps

### 4.1 Audit Log Missing Critical Fields

**What we record:**
```go
Timestamp, Action, ActorType, ActorID, ResourceType, ResourceID, TraceID, Outcome
```

**What's missing for SOC 2 / PCI DSS / FedRAMP:**

| Missing Field | Why It Matters |
|---|---|
| `source_ip` | Required for SOC 2 Type II evidence; "who from where issued this cert?" |
| `user_agent` | Distinguishes human operators from automation; forensic value |
| `session_id` | Ties multiple actions to one login session |
| `change_summary` | Before/after for mutations — what changed, not just that it changed |
| `geo_location` | Anomaly detection; unusual countries accessing PKI operations |

`emitAuditEvent()` already receives `r *http.Request` but never reads `r.RemoteAddr` or `r.UserAgent()`. This is a 30-line fix with large compliance impact.

---

### 4.2 Risk Scoring Too Shallow

Current model scores only 3 signals → A-F grade:

| Signal | Scored? |
|---|---|
| Certificate expiry window | ✅ |
| SHA-1/MD5 signature algorithm | ✅ |
| PQC vulnerability (RSA/ECDSA) | ✅ |
| Key size too small (RSA <2048, ECC <224) | ❌ |
| Certificate valid >200 days (post-2026 threshold) | ❌ |
| Certificate valid >100 days (post-2027 threshold) | ❌ |
| Wildcard SAN (blast radius factor) | ❌ |
| Self-signed cert detected | ❌ |
| Missing OCSP stapling URL | ❌ |
| Missing CRL distribution point | ❌ |
| Untrusted chain | ❌ |
| Key reuse across multiple certificates | ❌ |
| Algorithm disallowed after 2030 (RSA-2048, ECC-224) | ❌ |
| Cert issued with revoked CA | ❌ |
| SAN count > threshold (sprawl risk) | ❌ |

A cert with RSA-2048, no OCSP URL, wildcard SAN, and 2-year validity currently scores "A" (grade A = risk score ≤10). That is wrong.

---

### 4.3 No Certificate Ownership Model

There is no concept of "owner" on a certificate. Without ownership:
- Renewal notifications go nowhere (to whom?)
- Incident response is slow ("who owns the cert that just expired?")
- SOC 2 auditors ask "who is responsible for this certificate?" and there's no answer

**Required fields on `CertificateItem`:**
```go
OwnerEmail  string   // primary contact for renewal/expiry
OwnerTeam   string   // team/business unit
Labels      []string // arbitrary tags: env:prod, app:payments, tier:critical
ServiceName string   // the service/application this cert protects
```

---

### 4.4 No Renewal Scheduler

`RenewalMethod` is recorded at issuance time. `NotificationRules` with `ThresholdDays` exist. But there is **no background process** that:
1. Scans certs daily for approaching expiry
2. Fires ACME/SCEP auto-renewal for enrolled certs
3. Sends notifications to cert owners for manual certs
4. Escalates to secondary contact if not renewed within N days
5. Creates a dashboard alert for certs < 7 days from expiry

Without this, the notification system is pull-only (users must check the dashboard) and ACME auto-renewal only happens when the agent runs — there's no Hub-side orchestration.

---

### 4.5 No Policy Engine for Issuance Workflows

We have template policy enforcement (algorithm, validity, EKU). We don't have workflow-based policy:
- Require manual approval for certain cert types (wildcard, EV-equivalent internal)
- Require 2-person authorization (dual control) for CA key operations
- Route requests through ITSM (ServiceNow, Jira) before issuance
- Block issuance outside business hours
- Rate limiting per requestor (prevent cert spam)

Venafi calls this "Adaptable Workflow." It's a differentiating capability for regulated enterprises.

---

### 4.6 Certificate Chain Validation Not Enforced at Issuance

When a cert is issued, we store `chain_complete` and `chain_trusted` as metadata but we don't enforce that the issuing CA's chain is valid at issuance time. A CA in `suspended` status can still issue. A CA with an expired cert can still issue.

---

### 4.7 No Bulk Operations

No way to:
- Bulk revoke all certs issued by a compromised CA
- Bulk re-issue all certs approaching expiry
- Bulk update labels/owner across a set of certs
- Export filtered cert set as PEM bundle

These are essential for incident response (CA compromise scenario).

---

### 4.8 No ACME Renewal Information (ARI) Support

RFC 8555 extension (draft-ietf-acme-ari) lets the ACME server signal when a specific certificate should be renewed before its expiry — allows staggering renewals to avoid thundering-herd expiry events.

At 47-day lifetimes with thousands of certs, without ARI all certs issued on the same day will try to renew on the same day. ARI randomizes renewal windows.

Let's Encrypt already ships ARI. We don't have it.

---

## 5. Security Reporting Gaps

### 5.1 Missing Reports for Enterprise Security Reviews

| Report | What It Shows | Compliance Drivers |
|---|---|---|
| **CA Health Report** | CA cert expiry, algorithm strength, chain completeness, last CRL/OCSP generation | SOC 2, FedRAMP, PCI DSS |
| **Expiry Timeline Report** | Cert expiry calendar grouped by CA, team, owner — "what expires when?" | SOC 2 evidence, PCI DSS Req 4.2.1.1 |
| **Revocation Activity Report** | All revocations in a time window: who revoked, what reason, was OCSP updated? | SOC 2, PCI DSS |
| **Issuance Velocity Report** | Certs/day by CA, by requester — anomaly detection, capacity planning | SOC 2, FedRAMP |
| **Change Audit Report** | Full lifecycle history per cert: issued, renewed, revoked, expired | FedRAMP CM-03(06) |
| **Policy Compliance Report** | Certs that violate active templates (issued pre-policy, or bypassed) | ISO 27001, PCI DSS |
| **Algorithm Sunset Report** | Certs using RSA-2048/ECC-224 that will be non-compliant after 2030 | NIST 800-131A, FedRAMP |
| **Compliance Evidence Pack** | SOC 2 / PCI DSS formatted summary for auditor hand-off | SOC 2, PCI DSS |

We have exactly 1 report (Crypto Posture). We need 8 more.

---

### 5.2 No SIEM Integration

The audit log is in the database. Security teams need events in their SIEM in real time.

**What's needed:**
- Webhook push on: `cert.issued`, `cert.revoked`, `cert.expiry_warning`, `ca.created`, `ca.suspended`, `auth.login_failed`, `auth.login_success`
- Syslog (RFC 5424) output for Splunk Universal Forwarder / QRadar
- CEF (Common Event Format) for ArcSight

Venafi's recommended SIEM integration is syslog. We have zero SIEM output today.

---

### 5.3 No PDF / Executive Report Export

The SPRINT_3_PLAN.md specified: "PDF export for board meetings." The Crypto Posture page has CSV export. No PDF.

Enterprise security teams present to boards quarterly. They need a printable, branded one-page summary of:
- Total cert count
- PQC readiness score
- Critical/expiring certs
- Grade distribution
- Risk trends over time

---

### 5.4 Historical Trending Missing

All reports show a snapshot in time. There is no time-series data showing:
- PQC score trending up (migration progress)
- Grade distribution improving month-over-month
- Expiry distribution narrowing (certs getting shorter)
- Automation coverage growing

Without trending, security teams can't prove to auditors that the program is improving.

---

### 5.5 No Scheduled Report Delivery

Security leaders need weekly/monthly reports in their email without logging in. No scheduled delivery mechanism exists. The notification delivery infrastructure exists (`notifications/delivery`) but isn't wired to reports.

---

## 6. Venafi Feature Parity Analysis

### 6.1 Features We Have (Full or Partial Parity)

| Venafi Feature | Kryptkeeper | Notes |
|---|---|---|
| CA engine (root + intermediate) | ✅ Full | |
| ACME enrollment | ✅ Full | |
| SCEP enrollment | ✅ Full | Including Intune BYOCA |
| EST enrollment | ✅ Full | |
| CMP enrollment | ✅ Full | |
| XCEP/WSTEP (ADCS replacement) | ✅ Full | First OSS with this |
| OCSP responder | ✅ Full | Free in OSS; Venafi charges extra |
| CRL generation | ✅ Full | |
| Template policy enforcement | ✅ Full | Algorithm, validity, EKU, key size |
| Network cert discovery (TLS scan) | ✅ Full | |
| Agent-based cert discovery (Linux/macOS) | ✅ Full | |
| Agent-based cert discovery (Windows cert store) | ✅ Full | Build-tagged |
| cert-manager Kubernetes issuer | ✅ Full | |
| Terraform provider | ✅ Full | |
| ML-DSA PQC issuance | ✅ Full | Venafi has this too, but we're OSS |
| Hybrid certs (ECDSA + ML-DSA) | ✅ Full | |
| AWS/GCP/Azure KMS signing backends | ✅ Full | |
| PKCS#11 HSM backend | ✅ Full | Build-tagged |
| SSH key inventory | ✅ Partial | Inventory only, no rotation |
| Code signing tracking | ✅ Partial | Inventory only |
| Cipher suite audit | ✅ Partial | Discovery scanner + cipheraudit pkg |

---

### 6.2 Venafi Features We Don't Have (Gap List)

| Venafi Feature | Gap | Priority |
|---|---|---|
| **Certificate ownership / assignment** | No owner, team, or service fields on certs | 🔴 High |
| **Renewal scheduler** (Hub-side, daily scan → trigger) | Agent polls but Hub doesn't orchestrate | 🔴 High |
| **Approval workflow** (dual control, manager approval) | No workflow engine | 🔴 High |
| **SIEM integration** (syslog, CEF, webhook) | Zero SIEM output | 🔴 High |
| **8+ additional reports** | Only Crypto Posture exists | 🔴 High |
| **Audit log: source IP, user agent, session** | Missing from AuditEntry | 🔴 High |
| **ACME Renewal Information (ARI)** | RFC 8555 extension not implemented | 🔴 High |
| **HashiCorp Vault transit backend** | README promises it; doesn't exist | 🟡 Medium |
| **Key rotation API** | No RotateCAKey; must create new CA manually | 🟡 Medium |
| **Key backup / disaster recovery** | No export/import mechanism | 🟡 Medium |
| **Bulk operations** (revoke-all, re-issue-all) | Not implemented | 🟡 Medium |
| **ServiceNow ITSM integration** | Not implemented | 🟡 Medium |
| **SSH key rotation** (not just inventory) | Discovery only | 🟡 Medium |
| **Code signing key management** (not just tracking) | Tracking only | 🟡 Medium |
| **Short-lived certificate profiles** (≤7 days, no OCSP) | Standard profiles only | 🟡 Medium |
| **PDF executive report export** | CSV only | 🟡 Medium |
| **Historical trending / time-series reports** | Snapshots only | 🟡 Medium |
| **Scheduled report delivery** (email) | Not implemented | 🟡 Medium |
| **SPIFFE/SVID workload identity** | No SPIFFE support | 🟡 Medium |
| **Kubernetes operator** (CRD-based CA management) | cert-manager issuer only | 🟡 Medium |
| **Azure RSA KMS fix** | RSA JWK parsing not implemented | 🟡 Medium |
| **Deep Kubernetes discovery** (Ingress, Istio, Linkerd, routes) | Basic cert-manager only | 🟠 Lower |
| **IIS/Apache/nginx auto-install** (cert provisioning) | Agent discovers only; no install | 🟠 Lower |
| **Mobile/IoT cert management** (MDM integration) | Not planned | 🟠 Lower |
| **Firewall / load balancer provisioning** (F5, NetScaler) | Not planned | 🟠 Lower |
| **Multi-tenancy** (isolated orgs/teams with policy boundaries) | Single tenant | 🟠 Lower |
| **VaaS/SaaS model** (hosted version) | Self-hosted only | 🟠 Lower |

---

### 6.3 Areas Where We Beat Venafi

| Area | Kryptkeeper Advantage |
|---|---|
| **Price** | Apache 2.0 vs. $500K+/year |
| **OSS ML-DSA issuance** | We have it; Venafi's PQC is "experimental in TPP" |
| **ADCS replacement (XCEP/WSTEP)** | Fully implemented in OSS; Venafi charges enterprise license |
| **Deployment simplicity** | Single Go binary + docker compose; Venafi requires complex Java infrastructure |
| **OCSP in OSS** | Free; step-ca charges for it; Venafi requires paid tier |
| **Transparency** | Open source; customers can audit the CA code |

---

## 7. Priority Roadmap

### Sprint 5 — Security Foundations (Highest ROI, closes compliance gaps)

| # | Feature | Estimate | Compliance Driver |
|---|---|---|---|
| S5-01 | Audit log: add source_ip, user_agent, session_id, change_summary | 1 day | SOC 2, PCI DSS, FedRAMP |
| S5-02 | Risk scoring: 12 new signals (key size, validity duration, wildcard, self-signed, missing OCSP, etc.) | 2 days | PCI DSS, FedRAMP |
| S5-03 | Certificate ownership: owner_email, owner_team, labels, service_name | 1 day | SOC 2, incident response |
| S5-04 | Renewal scheduler: daily Hub-side scan, trigger auto-renewal, owner notifications | 3 days | 47-day mandate |
| S5-05 | SIEM integration: webhook + syslog output for cert lifecycle events | 2 days | SOC 2, FedRAMP, enterprise requirement |
| S5-06 | ACME Renewal Information (ARI) support | 2 days | 47-day mandate |
| S5-07 | CA Health Report | 1 day | SOC 2, FedRAMP |
| S5-08 | Expiry Timeline Report | 1 day | PCI DSS Req 4.2.1.1 |
| S5-09 | Revocation Activity Report | 1 day | SOC 2, PCI DSS |
| **Total** | | **~14 days** | |

---

### Sprint 6 — Key Management & Advanced Automation

| # | Feature | Estimate | Priority |
|---|---|---|---|
| S6-01 | Vault transit backend for software key wrapping | 3 days | 🔴 High |
| S6-02 | Key rotation API (RotateCAKey) | 3 days | 🔴 High |
| S6-03 | Key backup / encrypted export + restore | 2 days | 🔴 High |
| S6-04 | Signer cache TTL + eviction | 1 day | 🟡 Medium |
| S6-05 | Azure RSA KMS fix | 1 day | 🟡 Medium |
| S6-06 | Algorithm sunset report (RSA-2048 post-2030 non-compliant) | 1 day | NIST 800-131A |
| S6-07 | Issuance velocity + change audit reports | 2 days | SOC 2 |
| S6-08 | Approval workflow engine (basic: require manual approval per template) | 3 days | Enterprise |
| S6-09 | Bulk operations (bulk revoke, bulk re-issue) | 2 days | Incident response |
| S6-10 | Short-lived cert profiles (≤7 days, exempt from OCSP requirement) | 1 day | 47-day mandate |
| **Total** | | **~19 days** | |

---

### Sprint 7 — Enterprise Parity

| # | Feature | Estimate | Priority |
|---|---|---|---|
| S7-01 | ServiceNow ITSM integration | 3 days | Enterprise |
| S7-02 | SSH key rotation (not just inventory) | 3 days | Venafi parity |
| S7-03 | SPIFFE/SVID workload identity issuer | 4 days | Cloud native |
| S7-04 | PDF executive report export | 2 days | CISO requirement |
| S7-05 | Historical trending / time-series posture data | 3 days | SOC 2 evidence |
| S7-06 | Scheduled report delivery via email | 2 days | CISO requirement |
| S7-07 | Multi-tenancy: policy folder isolation | 5 days | Enterprise |
| S7-08 | Deep Kubernetes discovery (Ingress, Istio, routes) | 3 days | Cloud native |
| S7-09 | IIS/nginx auto-install (cert provisioning via agent) | 3 days | Venafi parity |
| S7-10 | MCP server (AI-native PKI ops) | 3 days | Differentiation |
| **Total** | | **~31 days** | |

---

## Summary: The Three Biggest Gaps Right Now

1. **Audit log missing IP/user agent** — the most common reason enterprises fail SOC 2 / PCI DSS audits related to PKI. 30-line fix with major compliance impact.

2. **No renewal scheduler** — without Hub-side scheduling, Kryptkeeper cannot claim to solve the 47-day cert cliff. This is the core value proposition and it's not fully wired.

3. **No SIEM integration** — enterprise security teams won't adopt a security product that doesn't feed their SIEM. This is a go/no-go criteria for most enterprises, not a nice-to-have.

Fix these three things and Kryptkeeper becomes enterprise-grade for SOC 2 and PCI DSS requirements. The rest of the roadmap turns it into Venafi parity.
