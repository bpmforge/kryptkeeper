# Kryptkeeper — Product Vision

> "Guard your cryptographic trust"

**Version:** 1.0
**Date:** 2026-04-05
**Phase:** 0 — Ideation

---

## 1. The Problem

Enterprise organizations are flying blind on cryptographic risk.

Certificates expire silently and bring down production services. Security teams don't know
what certificates they have, who owns them, or when they'll fail. Microsoft ADCS — the de
facto Windows CA — requires a Windows Server license and Domain Admin access, making it
expensive, fragile, and opaque. Post-quantum computing will break today's RSA and ECDSA
keys, and no organization has a clear migration path.

The existing solutions either cost hundreds of thousands of dollars per year (Venafi,
Keyfactor), require a Java EE stack that takes weeks to deploy (EJBCA), or are open-source
tools that stop short of the enterprise features that matter most: OCSP responders, certificate
discovery, ADCS replacement, and unified crypto inventory.

The result: certificates expire at 2 AM, silently. Security teams find out from the NOC.

---

## 2. The Opportunity

Three converging forces make 2026 the right time:

**CA/Browser Forum Ballot SC-081.** TLS certificate lifetimes are collapsing:
- 200 days by March 2026 (already in effect)
- 100 days by March 2027
- 47 days by March 2029

At 47-day lifetimes, manual certificate management is physically impossible. Every
organization with more than a handful of TLS endpoints must automate. The market for
certificate lifecycle management is about to 10x in urgency.

**ADCS migration pressure.** Microsoft ADCS runs on Windows Server, which is expensive,
requires Domain Admin access, and is increasingly difficult to justify in cloud-native
environments. No open-source CA offers a drop-in replacement. This is a clear gap.

**Post-quantum deadline.** NIST finalized ML-DSA, ML-KEM, and SLH-DSA in August 2024.
NSA's CNSA 2.0 mandate requires government systems to implement PQC by 2030. Every
organization with long-lived secrets needs a migration plan, and none of them have tooling.

---

## 3. Product Vision

Kryptkeeper is an enterprise PKI and Crypto Trust Platform that gives security teams
complete visibility and control over their cryptographic estate — certificates, keys,
endpoints, and crypto hygiene — from a single platform.

**Core capabilities at launch (V1):**
- Full Certificate Authority (root + issuing CAs, air-gapped ceremony support)
- Certificate lifecycle management with template-based issuance and auto-renewal
- Built-in certificate discovery: network scanning, SSH/WinRM agentless, lightweight Go agent
- ACME, OCSP, CRL, EST, and SCEP protocol support — free in OSS, no paywalls
- Risk scoring and alerting with owner-routed notifications

**ADCS replacement (V2):**
- Native MS-XCEP + MS-WSTEP server on Linux — first open-source implementation
- Windows auto-enrollment without a Windows CA server
- Active Directory template synchronization

**Full crypto management (V3):**
- SSH key inventory, code-signing tracking, cipher suite auditing
- Post-quantum migration planning dashboard
- PQC certificate issuance (ML-DSA via FIPS 204)

---

## 4. Target Users

### Primary: Security Engineers and PKI Administrators

Mid-to-large enterprises (500–50,000 employees) who are responsible for certificate
infrastructure. They've inherited ADCS, or are trying to move off it. They write YAML,
understand X.509, and have been burned by certificate expiry incidents.

What they want: complete visibility, automation, and a CA they control without a Windows
Server license.

### Secondary: Platform / DevOps Engineers

Teams running Kubernetes, deploying containerized workloads, integrating with CI/CD
pipelines. They consume PKI but don't want to own it. They want a REST API, a Terraform
provider, and a cert-manager integration.

What they want: self-service certificate issuance, ACME support, and K8s operator.

### Tertiary: CISOs and Security Leaders

Decision-makers who need to demonstrate cryptographic hygiene to auditors, boards, and
regulators. They care about risk dashboards, PQC readiness reporting, and compliance mapping.

What they want: a dashboard that shows "everything expires in X days, Y% are PQC-vulnerable,
Z certs are unowned."

---

## 5. Success Metrics

### 6-Month Targets (Post-V1 Launch)
- 200+ GitHub stars within 30 days of OSS launch
- 50+ active OSS installations (measured by telemetry opt-in or community survey)
- 10+ community contributors with merged PRs
- Zero critical CVEs in CA core at launch

### 12-Month Targets
- V2 (ADCS replacement) shipped and tested against Windows 10, 11, and Server 2019/2022
- 5+ enterprise pilot customers evaluating commercial tier
- Terraform provider published to HashiCorp Registry
- cert-manager integration published and verified

### 24-Month Targets (V3 + Commercial)
- First paying commercial customer
- PQC migration tooling ahead of 2030 government mandate wave
- 1,000+ GitHub stars
- Community-recognized as the modern ADCS replacement

---

## 6. Positioning Statement

**For** security engineers and PKI administrators at mid-to-large enterprises
**who** need complete control over their certificate and cryptographic infrastructure,
**Kryptkeeper** is an enterprise PKI and Crypto Trust Platform
**that** provides a full Certificate Authority, certificate lifecycle automation,
built-in discovery scanning, and a native ADCS replacement — all open-source.

**Unlike** step-ca, which withholds OCSP and discovery behind an enterprise paywall,
or EJBCA, which requires a Java EE stack and licenses discovery as an enterprise feature,
**Kryptkeeper** ships all core capabilities as Apache 2.0 open source, with a clear
upgrade path to enterprise features like FIPS validation, multi-tenancy, and HSM
key ceremony support.

---

## 7. What We Are Not Building

- A general-purpose secrets manager (that is Vault's domain)
- A certificate reseller or managed CA service (we are self-hosted)
- A replacement for Let's Encrypt (we are internal CA infrastructure)
- A SIEM or general-purpose security monitoring platform
- A Windows-only product (everything runs on Linux)

---

## 8. Design Principles

1. **OSS-first, enterprise-capable.** The core is Apache 2.0 and stays free. Commercial
   features add value on top — they don't take away what OSS users have today.

2. **Single binary where possible.** The CA core deploys as one Go binary. The agent is
   a single Go binary under 15MB. Complexity lives in the platform, not in deployment.

3. **crypto.Signer is sacred.** All signing operations go through Go's `crypto.Signer`
   interface. Swapping from software to HSM to cloud KMS never changes CA logic.

4. **Discovery is not optional.** An organization cannot manage what it cannot see. Discovery
   is built in, not bolted on.

5. **Operators are not always domain experts.** Risk scoring, grades, and actionable
   recommendations should let a platform engineer make the right call without a PKI PhD.

6. **Automate the 47-day world.** Every design decision should work at 47-day cert
   lifetimes. If it requires human intervention per renewal cycle, it's not good enough.
