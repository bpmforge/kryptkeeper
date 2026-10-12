# Kryptkeeper — Risk Register

**Version:** 1.0
**Date:** 2026-04-05
**Phase:** 1 — Planning

Risks are rated on Likelihood (L) and Impact (I) on a Low/Medium/High scale.
Priority = composite score used to order mitigation effort.

---

## 1. Technical Risks

### R-T01 — MS-XCEP/WSTEP Undocumented Behaviors
| Field | Value |
|-------|-------|
| **Likelihood** | High |
| **Impact** | High |
| **Priority** | CRITICAL |
| **Description** | Microsoft's protocol specs (MS-XCEP, MS-WSTEP, MS-CRTD) have known documentation errors and ambiguities. Real Windows clients may behave differently than the spec describes. The `pKIExpirationPeriod` field uses little-endian negative FILETIME encoding — an example of non-obvious encoding that is easy to get wrong. |
| **Mitigation** | Budget 3–6 months for V2 (not the 2–3 weeks the spec complexity might suggest). Capture real XCEP/WSTEP traffic between Windows 10/11 and a real ADCS server using Wireshark. Implement against the capture, not just the spec. Test against Windows Server 2016, 2019, and 2022 domain controllers. Use TameMyCerts.WSTEP and cepces PROTOCOLS.md as behavioral references. |
| **Residual Risk** | Medium — some edge cases may only surface with specific client configurations |

### R-T02 — AD Schema Version Variance
| Field | Value |
|-------|-------|
| **Likelihood** | Medium |
| **Impact** | High |
| **Priority** | HIGH |
| **Description** | Active Directory template objects and schema differ across Windows Server versions (2016, 2019, 2022). Template `msPKI-Template-Schema-Version` (1=Win2000, 2=XP, 3=2008, 4=2012+) controls available features. AD sync may work on one environment and fail silently on another. |
| **Mitigation** | Explicit schema-version detection during AD sync initialization. Test suite must include VMs with WS2016, WS2019, and WS2022 DCs. Fail-safe: log and skip attributes not supported in detected schema version. |
| **Residual Risk** | Low — schema version detection makes this manageable |

### R-T03 — Go stdlib Missing ML-DSA Until ~Go 1.26
| Field | Value |
|-------|-------|
| **Likelihood** | Confirmed |
| **Impact** | Medium |
| **Priority** | HIGH |
| **Description** | Go 1.24 added ML-KEM for TLS but not ML-DSA for certificate signing. ML-DSA (FIPS 204) is needed for PQC certificate issuance. Go stdlib support is expected around Go 1.26 (estimated late 2026). |
| **Mitigation** | Use Cloudflare CIRCL (`github.com/cloudflare/circl`) for ML-DSA in V2. The `crypto.Signer` interface abstraction means swapping to stdlib requires no CA logic changes. Track Go release schedule; switch to stdlib when available. |
| **Residual Risk** | Low — CIRCL is maintained by Cloudflare and is production quality |

### R-T04 — Discovery Triggers IDS/Firewall Blocks
| Field | Value |
|-------|-------|
| **Likelihood** | Medium |
| **Impact** | Low |
| **Priority** | MEDIUM |
| **Description** | masscan at high packet rates (>10K pps) triggers IDS signatures and is blocked or rate-limited by enterprise firewalls. This can cause incomplete discovery results without clear indication of failure. |
| **Mitigation** | Default to conservative rate (10K pps, configurable down to 1K pps). Require explicit operator acknowledgment of target ranges before scanning. Provide scan permission registry (IP ranges authorized for scanning). Document clearly that network discovery requires network-level authorization. Offer agent-based discovery as an alternative that doesn't require network scanning. |
| **Residual Risk** | Low — operator-controlled rates and acknowledgment gates manage this |

### R-T05 — masscan TLS Extraction Limitations
| Field | Value |
|-------|-------|
| **Likelihood** | Confirmed |
| **Impact** | Low |
| **Priority** | MEDIUM |
| **Description** | masscan is optimized for port detection only. Its TLS handshake implementation is limited and cannot reliably extract full certificate chains. Using masscan for cert extraction directly would produce incomplete results. |
| **Mitigation** | Two-phase design: masscan for port-open detection only, then custom Go TLS scanner for certificate extraction. This is already the designed architecture (see RESEARCH_FINDINGS.md §6). |
| **Residual Risk** | None — architectural decision already addresses this |

### R-T06 — PKCS#11 HSM Vendor Compatibility
| Field | Value |
|-------|-------|
| **Likelihood** | Medium |
| **Impact** | Medium |
| **Priority** | MEDIUM |
| **Description** | PKCS#11 implementations vary by vendor (Thales, Entrust, SafeNet, SoftHSM). `ThalesGroup/crypto11` is well-maintained but may have compatibility issues with less common HSMs or firmware versions. |
| **Mitigation** | Test against SoftHSM2 (free) for CI/CD validation. Document supported HSM models. Accept contributions for vendor-specific workarounds. The `crypto.Signer` interface means a vendor-specific implementation can be dropped in without changing CA logic. |
| **Residual Risk** | Medium — some HSM vendors will require testing we cannot do in advance |

### R-T07 — SNI-Aware Scanning Accuracy
| Field | Value |
|-------|-------|
| **Likelihood** | Medium |
| **Impact** | Low |
| **Priority** | LOW |
| **Description** | SNI-aware scanning (re-scanning with hostname in SNI extension) requires a DNS dataset mapping hostnames to IPs. Without this dataset, only default certificates are discovered, missing virtual-hosted services. |
| **Mitigation** | Support import of DNS zone exports, CMDB CSV, and passive DNS data. CT log integration provides an additional hostname-to-IP correlation source. Document this limitation clearly. |
| **Residual Risk** | Low — partial coverage is still valuable and clearly communicated |

---

## 2. Business and Adoption Risks

### R-B01 — step-ca Closes OSS Feature Gap
| Field | Value |
|-------|-------|
| **Likelihood** | Medium |
| **Impact** | Medium |
| **Priority** | HIGH |
| **Description** | Smallstep could add OCSP, discovery, or ADCS replacement to the step-ca OSS tier, neutralizing key differentiators. They have the engineering capability and a commercial incentive to block competitive entry. |
| **Mitigation** | Ship V1 fast — OCSP and discovery are table stakes before they react. ADCS replacement (V2) is the durable moat: it is a 3–6 month engineering investment that requires Windows behavioral testing. Templates + ADCS integration as a cohesive system is hard to replicate piecemeal. Build community and brand before a feature race starts. |
| **Residual Risk** | Medium — this is a real competitive risk that cannot be fully mitigated |

### R-B02 — Enterprise Requires FIPS 140-2/3 Validation
| Field | Value |
|-------|-------|
| **Likelihood** | High (for government and FSI verticals) |
| **Impact** | Medium |
| **Priority** | HIGH |
| **Description** | US government agencies and financial institutions often require FIPS 140-2 or 140-3 validated cryptographic modules. Go's standard crypto is not FIPS validated without BoringCrypto or a validated build toolchain. This blocks adoption in regulated sectors. |
| **Mitigation** | Design for FIPS from the start: PKCS#11 abstraction allows routing all crypto through a FIPS-validated HSM. Document the FIPS HSM path clearly. FIPS-validated Go build (using BoringCrypto or microsoft/go) can be offered as a commercial-tier binary. Do not promise FIPS validation on the OSS tier at V1 — defer to commercial. |
| **Residual Risk** | Medium — FIPS validation is expensive and time-consuming; commercial tier must fund it |

### R-B03 — Single Developer Bottleneck
| Field | Value |
|-------|-------|
| **Likelihood** | High |
| **Impact** | High |
| **Priority** | CRITICAL |
| **Description** | A single developer building a CA, five enrollment protocol servers, a discovery engine, an agent, and a dashboard is a single point of failure for the project. Burnout, illness, or competing priorities can delay or kill the project. |
| **Mitigation** | Modular architecture is the primary mitigation — each service has clear interfaces and can be developed or contributed to independently. Publish contributing guidelines and architecture documentation from day one. Prioritize community-friendly code (extensive comments, clear module boundaries, good tests) over velocity. Consider a public roadmap that invites contributors to own specific modules. |
| **Residual Risk** | High — this is the highest-impact structural risk of the project |

### R-B04 — Enterprise Sales Cycle Length
| Field | Value |
|-------|-------|
| **Likelihood** | High |
| **Impact** | Medium |
| **Priority** | MEDIUM |
| **Description** | Enterprise security tooling has 6–18 month sales cycles, legal review, security questionnaires, and procurement processes. Commercial revenue may take 18–24 months after launch to materialize. |
| **Mitigation** | OSS adoption creates a pipeline of organizations already using the product before commercial conversations. Target platform engineers and security engineers (bottom-up adoption) who can champion internally. Offer clear deployment options (Helm chart, Docker Compose) to reduce POC friction. |
| **Residual Risk** | Medium — inherent to enterprise sales, cannot be eliminated |

### R-B05 — Certificate Lifetime Reduction Pace
| Field | Value |
|-------|-------|
| **Likelihood** | Confirmed |
| **Impact** | Low (positive driver) |
| **Priority** | WATCH |
| **Description** | SC-081 ballot mandates are driving cert lifetimes down. This is a tailwind for adoption — organizations must automate. However, if the schedule accelerates further, V1 must be ready earlier than planned. |
| **Mitigation** | Monitor CA/Browser Forum ballot activity. Ensure ACME auto-renewal is robust in V1 — this is the primary mechanism for handling short-lived certs. Treat the 47-day world as the design target, not a future concern. |
| **Residual Risk** | Low — this risk is actually an opportunity |

---

## 3. Security Risks (Project-Level)

### R-S01 — CA Core Cryptographic Vulnerability
| Field | Value |
|-------|-------|
| **Likelihood** | Low |
| **Impact** | Critical |
| **Priority** | HIGH |
| **Description** | A vulnerability in the CA core's key generation, certificate signing, or key storage logic would undermine the entire trust model of every certificate issued by Kryptkeeper. |
| **Mitigation** | Use Go stdlib `crypto/x509` for all X.509 operations — do not implement X.509 parsing or encoding. Rely on `crypto/rand` for all random number generation. External security audit of CA core before V1 release. Keep the CA signing code small and reviewable (< 1000 lines). No bespoke crypto implementations. |
| **Residual Risk** | Low — Go stdlib crypto is battle-tested; primary risk is in our integration layer |

### R-S02 — Private Key Exposure
| Field | Value |
|-------|-------|
| **Likelihood** | Low |
| **Impact** | Critical |
| **Priority** | HIGH |
| **Description** | If a CA private key is exposed, all certificates issued by that CA are compromised. This includes the software key storage path (encrypted PEM) and any misconfiguration of the PKCS#11 interface. |
| **Mitigation** | Air-gapped root CA ceremony as the default recommendation. Issuing CA key in HSM for production. Encrypted-at-rest PKCS#8 with Argon2id KDF for software keys. Key material never logged, never serialized to JSON, never returned via API. Memory-zeroed after use. Audit all code paths that touch private keys before release. |
| **Residual Risk** | Low with HSM; Medium with software keys — clearly communicated in deployment docs |

---

## 4. Risk Summary Table

| ID | Category | Description | Likelihood | Impact | Priority |
|----|----------|-------------|------------|--------|----------|
| R-T01 | Technical | XCEP/WSTEP undocumented behaviors | High | High | CRITICAL |
| R-B03 | Business | Single developer bottleneck | High | High | CRITICAL |
| R-T02 | Technical | AD schema version variance | Medium | High | HIGH |
| R-T03 | Technical | Go ML-DSA unavailable until ~1.26 | Confirmed | Medium | HIGH |
| R-B01 | Business | step-ca closes OSS feature gap | Medium | Medium | HIGH |
| R-B02 | Business | Enterprise FIPS requirement | High | Medium | HIGH |
| R-S01 | Security | CA core cryptographic vulnerability | Low | Critical | HIGH |
| R-S02 | Security | Private key exposure | Low | Critical | HIGH |
| R-T04 | Technical | Discovery triggers IDS blocks | Medium | Low | MEDIUM |
| R-T06 | Technical | PKCS#11 HSM vendor compatibility | Medium | Medium | MEDIUM |
| R-B04 | Business | Enterprise sales cycle length | High | Medium | MEDIUM |
| R-T05 | Technical | masscan TLS limitations (by design) | Confirmed | Low | RESOLVED |
| R-T07 | Technical | SNI scanning accuracy | Medium | Low | LOW |
| R-B05 | Business | Cert lifetime reduction pace | Confirmed | Low | WATCH |
