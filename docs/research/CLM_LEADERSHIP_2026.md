# CLM / Machine-Identity Category Leadership — 2026 Capability Checklist

**Date:** 2026-07-15 · external research (WebSearch, per-claim sources; UNVERIFIED items flagged).
Feeds `docs/PRODUCT_SRS.md` (FR-P) and the golden-state board.

## Market context

- **2026 IDC MarketScape for Worldwide CLM** named DigiCert and AppViewX Leaders; drivers: short TLS lifecycles (immediate pain) + PQC (executive attention). Venafi (now CyberArk Machine Identity Security) and Keyfactor (Command + EJBCA) remain the most-deployed dedicated CLM platforms.
- **The structural shift:** CA/Browser Forum Ballot SC-081v3 (passed Apr 2025, 29–0) drops max public TLS validity 398 → 200 (Mar 2026) → 100 (Mar 2027) → **47 days (Mar 2029)**, DCV reuse → 10 days (~35 re-proofs/yr/domain). Hands-off automation moves from differentiator to **survival**.
- **PQC drivers:** NIST finalized ML-KEM (FIPS 203) / ML-DSA (FIPS 204) / SLH-DSA (FIPS 205); IR 8547 deprecates classical by 2035. CNSA 2.0 (NSA, May 2025): comply new deployments by 2027, software-signing by 2030, full NSS by 2035. Microsoft shipped ML-DSA in AD CS on Windows Server 2025 (GA May 2026). **ML-KEM (TLS key exchange) is near-term; ML-DSA cert migration is a later, separate step** — first PQC certs 2026, not default.
- **AI/NHI frontier:** machine:human identity ratio ~144:1 (H1 2025); OWASP NHI Top 10 (Jun 2025); vendors repositioning to "Machine & AI Agent Identity." The AI-native story today is issuing identity *for* agents, not agents *running* the PKI.

## The 12–14 leader capabilities (prioritized)

**Tier 1 — table-stakes (absence disqualifies):**
1. CA-agnostic multi-technique discovery (network + agent + cloud + direct-CA import) → unified inventory.
2. Full enrollment set: ACME (incl. **EAB**) + SCEP + EST + CMP + REST API/SDK.
3. Closed-loop zero-touch renewal engineered for 47-day churn (request→issue→deploy→bind→validate).
4. Last-mile push integrations: F5, Citrix, IIS, nginx/Apache/HAProxy, Palo Alto, Kubernetes/cert-manager.
5. Issuance-time policy engine (algorithms/key-size/validity/CA constraints) + approvals + custom RBAC + SoD.
6. Enterprise core: HA/clustering, multi-tenancy, SSO/SCIM, HSM/KMS, key escrow/recovery.
7. Proactive multi-channel alerting (email/Slack/PagerDuty/webhook/SIEM).
8. Compliance mapped to PCI DSS 4.0 / SOC2 / FedRAMP / NIST with retained audit trail.

**Tier 2 — leader-defining differentiators:**
9. **PQC issuance** (ML-DSA + hybrid/composite) + dependency-aware phased migration — not just assessment.
10. **CBOM / cryptographic-posture** layer with **CycloneDX export** as always-current audit evidence.
11. **CT-log rogue/shadow-cert detection** for owned domains (most CLM suites cede this).
12. **SPIFFE/SPIRE-native workload & AI-agent identity** (short-lived, attested, mesh-bound).
13. **Cross-signing / multi-issuer** in-place key rotation (zero-downtime CA rollovers).

**Tier 3 — whitespace bets (largely un-owned):**
14. **SLO/error-budget-native PKI ops** — golden-signal dashboards on issuance/renewal success.
15. **AI-assisted PKI ops** — issuance-anomaly detection, auto-remediation, NL policy authoring.

## Kryptkeeper's standing (from the code assessment)

- **Already leader-tier (rare in OSS):** real ML-DSA + hybrid issuance (#9 substrate), MCP approval-gated ops (#12/#15 substrate), broad discovery incl. Windows store (#1), OSS XCEP/WSTEP ADCS path.
- **Table-stakes gaps:** working alerts (#7 — currently stubbed), closed renewal at scale (#3), install breadth (#4), policy engine (#5), HA + SSO/SCIM (#6), ACME-EAB (#2 — and shipping it *free* is a wedge vs Smallstep/commercial).
- **Differentiator gaps to seize:** PQC *execute* (finish #9), CBOM export (#10), CT-log monitoring (#11), SPIFFE workload/attestation (#12), cross-signing (#13), SLO-native + AI-assisted ops (#14/#15).

## UNVERIFIED (supported by absence, not disproof — verify before betting a claim)

- Native CT-log ingestion as a headline feature in Venafi/Keyfactor.
- That no leader ships SLO-native PKI observability.
- Absence of any shipped autonomous-agent PKI-ops product.

## Key sources

CA/B Forum SC-081v3; NIST FIPS 203/204/205 + IR 8547; NSA CNSA 2.0 (May 2025); IDC MarketScape CLM 2026 (DigiCert/AppViewX); Keyfactor EJBCA "five enrollment protocols"; Smallstep OSS (EAB/dynamic-SCEP paywalled); AppViewX Quantum Trust Hub / CBOM; HashiCorp Vault multi-issuer + cross-sign; Istio/SPIRE integration; PCI DSS 4.0 crypto reqs (mandatory Mar 2025); OWASP NHI Top 10 (Jun 2025). Full URLs in the research transcript.
