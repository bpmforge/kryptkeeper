# Kryptkeeper — Product Vision V4
# "The Crypto Trust Platform"

**Version:** 4.0
**Date:** 2026-04-24
**Phase:** V4 Planning — PQC · Key Management · Crypto Agility · Go to Market

> "The open-source crypto trust platform — manage every key, cert, and algorithm in your estate, and be quantum-ready before the deadline."

---

## 1. What Changed Since V1/V2/V3

V1 delivered the CA engine + CLM. V2 delivered ADCS replacement (XCEP/WSTEP). V3 delivered SSH inventory, code signing, cipher auditing, and PQC migration *planning*.

**V4 delivers the platform layer** — actual PQC issuance, hybrid certificates, key management as a first-class feature, Microsoft Intune integration, crypto agility reporting, and the commercial story that gets Kryptkeeper to market.

Three urgent market signals triggered this:
- **TLS lifetimes collapsing.** 200-day max is NOW (March 2026). 47-day max by 2029. 95% of orgs are unprepared.
- **PQC is no longer optional.** NIST finalized ML-DSA/ML-KEM/SLH-DSA in Aug 2024. Keyfactor and CyberArk (Venafi) shipped PQC issuance in early 2026. We need to match and beat them in OSS.
- **Market consolidation.** CyberArk bought Venafi for $1.54B. The TAM is $60B. No open-source product covers it.

---

## 2. Expanded Problem Statement

Enterprises face a six-front crypto crisis:

1. **Certificate blindness** — They don't know what certs they have, where they are, or when they expire.
2. **Renewal collapse** — At 47-day cert lifetimes, manual renewal is physically impossible.
3. **ADCS lock-in** — Microsoft ADCS runs on Windows Server; cloud migration is blocked or expensive.
4. **PQC paralysis** — FIPS 204/ML-DSA is finalized but nobody knows how to start migration.
5. **Key sprawl** — Keys live in HSMs, AWS KMS, Azure Key Vault, GCP KMS, software files — untracked.
6. **Audit gap** — No single platform shows crypto posture to auditors, boards, and regulators.

---

## 3. V4 Vision

Kryptkeeper becomes the **Crypto Trust Platform** — the single pane of glass for every certificate, key, and algorithm in the enterprise.

### What "Crypto Trust Platform" means:

**For certificates:**
- Full CA (root/intermediate/issuing), all enrollment protocols, automatic renewal
- 47-day cert lifetime support from day one — designed for automation, not for humans
- PQC issuance: ML-DSA-44/65/87 certs today; hybrid (ECDSA+ML-DSA) for backward compat
- Microsoft native: XCEP/WSTEP autoenrollment + Intune BYOCA (no ADCS server)

**For keys:**
- Pluggable keystore: software, AWS KMS, GCP KMS, Azure Key Vault, PKCS#11/HSM
- Key lifecycle: generate, rotate, retire, audit
- KMIP protocol endpoint (Sprint 4) for enterprise KMS interop

**For crypto agility:**
- Inventory every cert, key, and algorithm across the estate (cloud + on-prem + endpoints)
- Risk-score every asset: expiry urgency, algorithm weakness, PQC vulnerability
- Policy enforcement: gate new issuances to approved algorithms
- Automated migration: identify classical certs, issue hybrid/PQC replacements, track progress
- Crypto Posture dashboard: PQC readiness %, risk by BU, expiry timeline — exportable

**For automation:**
- Hub (central platform) + Satellite agent (endpoint discovery + renewal)
- Protocol connectors: ACME, SCEP, EST, CMP — no agent for protocol-native systems
- Kubernetes operator (cert-manager integration)
- Terraform provider
- REST API + webhooks for SIEM

---

## 4. Updated Target Users

### Primary: Security Engineers and PKI Administrators
Mid-to-large enterprises (500–50,000 employees). Responsible for cert infrastructure.
**New pain in V4:** They've been told by leadership to show a PQC readiness plan. They have no tooling.

### Secondary: Platform / DevOps Engineers
Kubernetes, CI/CD, containerized workloads.
**New pain in V4:** 47-day certs are breaking their pipelines. They need automation, not a CA PhD.

### Tertiary: CISOs and Security Leaders
**New pain in V4:** Auditors and boards are asking "are you quantum-ready?" They need a dashboard answer.

### Quaternary: Microsoft / Windows Shops
Active Directory environments migrating off ADCS.
**New pain in V4:** Intune BYOCA requires a third-party CA that speaks SCEP. Kryptkeeper is plug-and-play.

---

## 5. V4 Success Metrics

### 3-Month (After Sprint 3 ships)
- ML-DSA cert issuance works end-to-end (create CA → issue cert → verify)
- Hybrid cert (ECDSA+ML-DSA) issues and validates on standard TLS stacks
- Intune BYOCA integration documented and tested against Microsoft Cloud PKI spec
- Crypto Posture dashboard live with expiry/algorithm/PQC readiness metrics
- PKCS#11 backend tested against SoftHSM2

### 6-Month (OSS Launch)
- GitHub release v1.0.0 published with binaries, Docker image, Helm chart
- OSS documentation site live (docs.kryptkeeper.io or similar)
- 200+ GitHub stars within 30 days
- "Replace ADCS with Kryptkeeper" blog post + YouTube demo
- 5+ community integrations (cert-manager, Terraform, Vault)

### 12-Month (Commercial)
- 3+ paying enterprise customers on commercial tier
- Terraform provider on HashiCorp Registry
- cert-manager issuer plugin published
- Satellite agent (Windows + Linux) GA
- SIEM integrations (Splunk, Elastic) published

### 24-Month
- 1,000+ GitHub stars
- Recognized as the modern ADCS replacement in PKI community
- First paying government customer (FedRAMP roadmap)

---

## 6. Business Model

### OSS Core (Apache 2.0 — free forever)
- Full CA engine, all enrollment protocols, OCSP/CRL, discovery, ADCS replacement
- PQC issuance (ML-DSA + hybrid)
- Crypto Posture dashboard (basic)
- Satellite agent (single Hub)

### Enterprise Commercial Tier
- Multi-tenancy (org/team isolation for MSPs)
- Advanced reporting (PDF/CSV/API, scheduled delivery, custom branding)
- FIPS 140-3 validated HSM integration support and documentation
- FedRAMP-ready configuration templates
- Air-gapped CA ceremony tooling
- SLA support + professional services
- SSO (SAML + OIDC with advanced role mapping)
- HA/DR deployment templates

### Pricing Model (Commercial)
- Per-node licensing (endpoints under management) OR
- Per-CA licensing (number of issuing CAs)
- Starting ~$15K/yr for small enterprise, scaling to $100K+/yr for large

---

## 7. Design Principles (Updated for V4)

1. **OSS-first, enterprise-capable.** Core is Apache 2.0 and stays free forever.
2. **Single binary.** CA core deploys as one Go binary. Satellite is a single Go binary < 15MB.
3. **crypto.Signer is sacred.** All signing through Go's interface. Swap backends without CA changes.
4. **Discovery is not optional.** You cannot manage what you cannot see.
5. **Automate the 47-day world.** If it requires human intervention per cycle, it's not good enough.
6. **Crypto-agile by design.** Every algorithm is a pluggable backend. PQC is additive, not a rewrite.
7. **Microsoft native.** Windows shops are the largest CA market. First-class ADCS replacement matters.
8. **Report for the board.** Security leaders need numbers. Risk scores, PQC readiness %, trend lines.
