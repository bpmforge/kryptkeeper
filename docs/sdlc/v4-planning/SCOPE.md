# Kryptkeeper V4 — Scope
**Phase:** V4 Planning
**Date:** 2026-04-24
**Feeds into:** V4 Implementation Plan, GTM Plan

---

## V4 Boundaries

### IN SCOPE — Sprint 3 (Next ~8 weeks)

| # | Feature | Priority | Why Now |
|---|---|---|---|
| S3-1 | ML-DSA-44/65/87 key generation and certificate issuance | P0 | Competitors shipped it; OSS gap |
| S3-2 | Hybrid certificate issuance (ECDSA+ML-DSA composite) | P0 | Bridge strategy for 2025–2028 migration |
| S3-3 | Microsoft Intune BYOCA SCEP integration | P0 | Biggest Microsoft deployment channel |
| S3-4 | Crypto Posture dashboard + reporting (PDF/CSV export) | P1 | Sales driver; 47-day cert cliff |
| S3-5 | PKCS#11 / HSM keystore backend | P1 | Government + regulated customer requirement |
| S3-6 | Template policy enforcement at issuance | P1 | Required for credible ADCS replacement |

### IN SCOPE — Sprint 4 (Weeks 9–16)

| # | Feature | Priority | Why |
|---|---|---|---|
| S4-1 | Satellite Agent v1 (Windows + Linux) — cert discovery + renewal | P0 | Closes the inventory gap for endpoints |
| S4-2 | Kubernetes cert-manager issuer plugin | P1 | DevOps adoption channel |
| S4-3 | Terraform provider (`kryptkeeper_ca`, `kryptkeeper_certificate`) | P1 | IaC adoption channel |
| S4-4 | SIEM webhooks (Splunk, Elastic, generic webhook) | P2 | Enterprise requirement |
| S4-5 | Scheduled crypto posture report delivery (email) | P2 | CISO buyer requirement |
| S4-6 | MCP Server for AI assistant integration | P3 | Following Keyfactor's lead |

### IN SCOPE — OSS Launch (Week 12–16)

| # | Deliverable |
|---|---|
| L-1 | GitHub Release v1.0.0 with signed binaries (amd64 + arm64) |
| L-2 | Docker Hub + GHCR images |
| L-3 | Helm chart published to Artifact Hub |
| L-4 | Documentation site (MkDocs or Docusaurus) |
| L-5 | Getting Started guide (< 15 min to first cert issued) |
| L-6 | "Replace ADCS" guide |
| L-7 | "Connect Intune BYOCA" guide |
| L-8 | "Issue your first PQC cert" guide |
| L-9 | GitHub Actions marketplace action for cert renewal |
| L-10 | Launch blog post + HackerNews / Reddit submission |

### OUT OF SCOPE (V4)

- General-purpose secrets manager (Vault territory)
- Certificate reseller or managed CA (self-hosted only)
- SIEM platform or general security monitoring
- KMIP protocol server (Sprint 5 candidate)
- Multi-tenancy / MSP isolation (commercial tier, Sprint 5)
- FedRAMP configuration (Sprint 6)
- SLH-DSA (FIPS 205 / SPHINCS+) issuance — defer after ML-DSA stable
- ML-KEM (FIPS 203) — key encapsulation, not signing; different use case

---

## Feature Definitions

### S3-1 — ML-DSA Certificate Issuance

**In scope:**
- ML-DSA-44 (security level 2, ~2KB cert)
- ML-DSA-65 (security level 3, ~3KB cert) — recommended default
- ML-DSA-87 (security level 5, ~4.5KB cert)
- Root CA creation with ML-DSA key
- Intermediate CA creation with ML-DSA key
- Leaf certificate issuance with ML-DSA key
- Software keystore backend (Cloudflare CIRCL)
- AWS KMS backend (ML-DSA-44 via ECDSA_SHA_384 mapping — note: AWS KMS ML-DSA support TBD; use software fallback)

**Out of scope:**
- ML-DSA on HSM (Sprint 4 — depends on PKCS#11 backend from S3-5)
- SLH-DSA (SPHINCS+) — defer

### S3-2 — Hybrid Certificates

**In scope:**
- HybridECDSAP256+MLDSA65 (recommended for most use cases)
- HybridECDSAP384+MLDSA87 (high-security option)
- Composite signature per IETF draft-lamps-pq-composite-sigs-07
- Extension OID: 2.16.840.1.114027.80.6.1
- Hybrid root CA, intermediate CA, leaf cert
- Standard ECDSA verifier accepts (classical path validates)
- ML-DSA verifier also accepts (quantum-resistant path validates)
- PQC planner marks hybrid certs as `hybrid_quantum_safe`

**Out of scope:**
- Hybrid key exchange (ML-KEM + ECDH) — TLS 1.3 only, different scope
- Other composite combinations (RSA+ML-DSA) — defer

### S3-3 — Microsoft Intune BYOCA

**In scope:**
- SCEP endpoint compatible with Microsoft Cloud PKI BYOCA registration
- `GET /scep/mscep_admin` URL pattern for Intune compatibility
- Integration test against Microsoft's BYOCA spec
- Setup documentation: "Connect Kryptkeeper to Microsoft Intune"
- UI: Microsoft Integration settings section showing BYOCA status

**Out of scope:**
- Intune MDM enrollment profiles (customer configures in Intune portal)
- Azure AD / Entra ID deep integration (Sprint 4)

### S3-4 — Crypto Posture Dashboard

**In scope:**
- New `Crypto Posture` page in UI
- Algorithm inventory (cert count by algorithm, donut chart)
- PQC readiness score (% quantum_safe + hybrid_quantum_safe)
- Expiry urgency buckets: 47d / 90d / 200d / 1yr
- Risk grade distribution (A/B/C/F by CA/team)
- Policy violation summary
- Automation coverage (% on ACME auto-renewal vs manual)
- PDF export (single-page executive summary)
- CSV export (raw cert inventory with all fields)
- `GET /api/v1/reports/crypto-posture` JSON API endpoint
- Trend over time (weekly snapshots stored in DB)

**Out of scope:**
- Scheduled email delivery (Sprint 4)
- Custom report templates / white-labeling (commercial tier)
- SIEM push (Sprint 4)

### S3-5 — PKCS#11 / HSM Backend

**In scope:**
- `PKCS11Store` implementing `Store` interface in `internal/keystore/`
- Config via env: `KRYPTKEEPER_PKCS11_LIB`, `KRYPTKEEPER_PKCS11_TOKEN_LABEL`, `KRYPTKEEPER_PKCS11_PIN`
- Key generation: RSA-2048, RSA-4096, ECDSA-P256, ECDSA-P384
- Signing via PKCS#11 — private key never leaves HSM
- SoftHSM2 integration tests
- UI: "HSM (PKCS#11)" option in key storage selector for CA creation

**Out of scope:**
- ML-DSA on PKCS#11 (blocked on PKCS#11 v3.2 finalization; use software ML-DSA)
- Hardware HSM certification testing (customer responsibility)
- Multi-slot / multi-partition HSM management

### S3-6 — Template Policy Enforcement

**In scope:**
- `ValidateAgainstTemplate(req, tmpl) error` in `internal/ca/`
- Enforce: AllowedAlgorithms, MaxValidity, AllowedEKUs, MinKeySize
- Return `ErrPolicyViolation` with field-level error detail
- 422 HTTP response with `policy_violation` error type
- XCEP/WSTEP pass TemplateID through to issuance
- Tests for each violation type

**Out of scope:**
- SAN pattern enforcement (Sprint 4)
- Certificate approval workflow (Sprint 4 — human-in-the-loop gate)

---

## Done Criteria for Sprint 3

Sprint 3 is complete when ALL of the following are true:

- [ ] `go test ./...` passes with 0 failures
- [ ] ML-DSA-65 root CA can be created in UI and via API
- [ ] ML-DSA-65 leaf cert issued against ML-DSA CA, PEM downloadable
- [ ] Hybrid ECDSA-P256+ML-DSA-65 cert issues and verifies on standard TLS stack
- [ ] SCEP endpoint responds correctly to Intune BYOCA challenge format
- [ ] Crypto Posture page shows algorithm breakdown, expiry buckets, PQC readiness score
- [ ] PDF export from Crypto Posture page generates a readable one-page report
- [ ] PKCS#11 backend creates key on SoftHSM2 and signs a cert
- [ ] Issuing a cert with a forbidden algorithm against a restrictive template returns 422
- [ ] All new code has test coverage ≥ 80%
- [ ] `docker compose up` starts clean; UI loads; CA page shows ML-DSA option
