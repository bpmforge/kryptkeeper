# Kryptkeeper — Software Requirements Specification

**Version:** 1.0
**Date:** 2026-04-05
**Phase:** 2 — Requirements
**Standard:** Based on IEEE 830

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Product Overview](#2-product-overview)
3. [Functional Requirements](#3-functional-requirements)
   - [3.1 CA Engine](#31-ca-engine)
   - [3.2 Certificate Lifecycle](#32-certificate-lifecycle)
   - [3.3 Certificate Templates](#33-certificate-templates)
   - [3.4 ACME Server](#34-acme-server)
   - [3.5 OCSP Responder](#35-ocsp-responder)
   - [3.6 CRL Generation and Distribution](#36-crl-generation-and-distribution)
   - [3.7 EST Server](#37-est-server)
   - [3.8 SCEP Server](#38-scep-server)
   - [3.9 Discovery — Network Scanning](#39-discovery--network-scanning)
   - [3.10 Discovery — Agentless Host](#310-discovery--agentless-host)
   - [3.11 Discovery — Agent](#311-discovery--agent)
   - [3.12 Certificate Inventory](#312-certificate-inventory)
   - [3.13 Risk Scoring](#313-risk-scoring)
   - [3.14 Ownership and Alerting](#314-ownership-and-alerting)
   - [3.15 Management Dashboard](#315-management-dashboard)
   - [3.16 REST API and Authentication](#316-rest-api-and-authentication)
   - [3.17 ADCS Replacement — V2](#317-adcs-replacement--v2)
   - [3.18 Full Crypto Management — V3](#318-full-crypto-management--v3)
4. [Non-Functional Requirements](#4-non-functional-requirements)
5. [Interface Requirements](#5-interface-requirements)
6. [Traceability Matrix](#6-traceability-matrix)

---

## 1. Introduction

### 1.1 Purpose

This document specifies the software requirements for Kryptkeeper — an enterprise PKI and
Crypto Trust Platform. It is the authoritative requirements reference for V1 design and
implementation and records V2 and V3 requirements for forward planning.

Every functional requirement has measurable acceptance criteria. Every non-functional
requirement has a numeric metric. These are the exit criteria for implementation.

### 1.2 Scope

Kryptkeeper is a self-hosted platform that provides:
- A full Certificate Authority (root + issuing CAs) with air-gapped ceremony support
- Certificate lifecycle management (issuance, renewal, revocation) via templates
- Automated certificate enrollment via ACME, EST, and SCEP protocols
- OCSP and CRL revocation services
- Certificate discovery via network scanning, agentless SSH/WinRM, and a lightweight Go agent
- A risk-scored, owner-routed certificate inventory and alert system
- A REST API and web dashboard for management

**V1** is in scope for this document as the primary implementation target.
**V2** (ADCS replacement via MS-XCEP/MS-WSTEP) and **V3** (SSH keys, code signing, PQC
migration dashboard) are documented for planning purposes and marked accordingly.

### 1.3 Definitions and Acronyms

| Term | Definition |
|------|-----------|
| **CA** | Certificate Authority — an entity that signs and issues X.509 certificates |
| **Root CA** | Top-level CA whose key signs issuing CA certificates; typically kept offline |
| **Issuing CA** | Subordinate CA whose key signs end-entity certificates; online |
| **CSR** | Certificate Signing Request — PKCS#10 formatted public key + attributes |
| **EKU** | Extended Key Usage — purpose restrictions on a certificate (e.g., TLS Server, Code Signing) |
| **ACME** | Automatic Certificate Management Environment — RFC 8555 |
| **OCSP** | Online Certificate Status Protocol — RFC 5019 (lightweight profile) |
| **CRL** | Certificate Revocation List — RFC 5280 |
| **EST** | Enrollment over Secure Transport — RFC 7030 |
| **SCEP** | Simple Certificate Enrollment Protocol — network device enrollment |
| **HSM** | Hardware Security Module — tamper-resistant key storage device |
| **PKCS#11** | Cryptographic Token Interface Standard — vendor-neutral HSM API |
| **MS-XCEP** | Microsoft Certificate Enrollment Policy Protocol |
| **MS-WSTEP** | Microsoft WS-Trust X.509 Token Enrollment Extension |
| **ADCS** | Active Directory Certificate Services — Microsoft's Windows CA |
| **PQC** | Post-Quantum Cryptography — algorithms resistant to quantum computing attacks |
| **ML-DSA** | Module-Lattice Digital Signature Algorithm — NIST FIPS 204 |
| **SNI** | Server Name Indication — TLS extension identifying the target hostname |
| **CT** | Certificate Transparency — RFC 6962 public log of issued TLS certificates |
| **fingerprint_sha256** | SHA-256 hash of the DER-encoded certificate; used as the dedup key |
| **Risk flag** | A named condition on a certificate (e.g., EXPIRED, WEAK_KEY) that contributes to risk score |
| **kk** | CLI alias for the `kryptkeeper` command-line tool |
| **SAN** | Subject Alternative Name — X.509v3 extension listing hostnames/IPs covered by a certificate |

---

## 2. Product Overview

### 2.1 Product Perspective

Kryptkeeper is a self-hosted enterprise PKI platform deployed as a set of Go microservices
and a TypeScript web dashboard. It does not depend on Windows Server, Active Directory, or
any external CA service. It integrates with external systems (Vault, cloud KMS, Slack,
PagerDuty, AWS ACM, Azure Key Vault, Kubernetes) via optional connectors — none are required
for core operation.

The platform sits between certificate consumers (ACME clients, EST/SCEP devices, manual
requestors) and certificate producers (the CA engine and its key storage backends). Discovery
runs independently, feeding the same certificate inventory regardless of how a certificate
was issued.

### 2.2 Product Features

| Feature Area | V1 | V2 | V3 |
|-------------|----|----|-----|
| CA Engine (root + issuing CA, key hierarchy) | Required | — | — |
| Certificate lifecycle (issuance, renewal, revocation) | Required | — | — |
| Certificate templates with policy enforcement | Required | Required | — |
| ACME server (RFC 8555, 3 challenge types) | Required | — | — |
| OCSP responder (RFC 5019) | Required | — | — |
| CRL generation and distribution (RFC 5280) | Required | — | — |
| EST server (RFC 7030) | Required | — | — |
| SCEP server | Required | — | — |
| Discovery — network scanning (masscan + Go TLS) | Required | — | — |
| Discovery — agentless SSH and WinRM | Required | — | — |
| Discovery — lightweight Go agent | Required | — | — |
| Discovery — cloud APIs (ACM, Key Vault, GCP CM, K8s) | Required | — | — |
| Discovery — Certificate Transparency log monitoring | Required | — | — |
| Certificate inventory with dedup and chain validation | Required | — | — |
| Risk scoring (0–100, flags, A–F grades) | Required | — | — |
| Ownership assignment and multi-tier alerting | Required | — | — |
| Web dashboard | Required | — | — |
| REST API (OpenAPI, RBAC, API keys, OIDC) | Required | — | — |
| Key storage: software, PKCS#11 HSM, cloud KMS | Required | Extended | — |
| MS-XCEP server (Windows enrollment policy) | — | Required | — |
| MS-WSTEP server (Windows enrollment service) | — | Required | — |
| AD LDAP template synchronization | — | Required | — |
| SSH key inventory | — | — | Required |
| Code-signing certificate tracking | — | — | Required |
| Cipher suite auditing | — | — | Required |
| PQC migration planning dashboard | — | — | Required |

### 2.3 User Classes

| Class | Description | Primary Version Target |
|-------|-------------|----------------------|
| **PKI Administrator (Alex)** | Manages CA infrastructure, templates, revocation, ADCS migration | V1, V2 |
| **Platform/DevOps Engineer (Jordan)** | Consumes PKI via ACME, REST API, Terraform, cert-manager | V1 |
| **CISO / Security Leader (Sam)** | Reviews risk dashboards and compliance exports | V1, V3 |
| **Network/Infrastructure Engineer (Riley)** | Enrolls and renews network device certificates via SCEP/EST | V1 |
| **Open-Source Contributor (Casey)** | Contributes code to specific service modules | V1+ |

### 2.4 Operating Environment

- **Server:** Linux x86_64 or ARM64. Minimum: 4 vCPU, 8 GB RAM, 50 GB disk.
- **Database:** PostgreSQL 14+ (production). SQLite (single-node dev/embedded mode).
- **Containers:** Docker or Podman. Docker Compose for single-node. Kubernetes + Helm for multi-node.
- **Agent:** Linux, macOS, and Windows (discovery agent). Static Go binary, no runtime.
- **Dashboard:** Modern browsers (Chrome 120+, Firefox 120+, Safari 17+, Edge 120+).
- **Network device enrollment:** Any device supporting RFC 7030 (EST) or SCEP.

### 2.5 Constraints

See CONSTRAINTS.md for the full constraint register. Key constraints affecting requirements:

- All CA signing operations MUST go through Go's `crypto.Signer` interface (C-Tech03)
- No custom cryptographic implementations — Go stdlib and Cloudflare CIRCL only (C-Tech02)
- No private key material in any API response (C-Sec03)
- Audit log is append-only; no UPDATE or DELETE on audit records (C-Sec02)
- Root CA must support offline/air-gapped key ceremony (C-Sec01)
- No telemetry without explicit operator opt-in (C-Sec04)
- Platform starts without internet connection (C-Ops03)
- pki-agent binary must remain under 15MB compressed (C-Ops02)
- Apache 2.0 license boundary — no GPL/AGPL/LGPL in core (C-Tech05)

### 2.6 Assumptions

- Operators have an accessible PostgreSQL 14+ instance or use the bundled Docker Compose stack.
- Network discovery requires operator authorization of target IP ranges before any scan is initiated.
- Agentless SSH discovery assumes key-based authentication is available on target Linux hosts.
- Agentless WinRM discovery assumes WinRM is enabled and accessible on target Windows hosts.
- Root CA key ceremonies using air-gapped workflows require operator-managed physical security.
- CA/Browser Forum Ballot SC-081 enforcement dates (100 days by March 2027, 47 days by March 2029) are treated as hard design targets.

---

## 3. Functional Requirements

Requirements are organized by feature area. Each requirement table uses the following fields:

| Field | Description |
|-------|-------------|
| **ID** | Unique identifier (FR-xxx) |
| **Title** | Short descriptive name |
| **Description** | Full behavioral specification |
| **Priority** | Must-have / Should-have / Could-have |
| **Version** | V1 / V2 / V3 |
| **Personas** | Which user classes this serves |
| **Acceptance Criteria** | Given/When/Then test conditions |
| **Dependencies** | Other FRs that must be in place first |

---

### 3.1 CA Engine

#### FR-001

| Field | Value |
|-------|-------|
| **ID** | FR-001 |
| **Title** | Create Root CA |
| **Description** | The system shall allow a PKI Administrator to create a self-signed root CA. The operator specifies: common name, organization, country, validity period (years), key algorithm (RSA-4096, ECDSA P-384, or Ed25519), and key storage backend (software, PKCS#11, or cloud KMS). The system generates the root CA key via the configured `crypto.Signer` implementation and stores the self-signed certificate. Root CA creation MUST support an offline/air-gapped workflow: the operator may generate key material on an air-gapped machine and import the signed root certificate without the private key being exposed to the online platform. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given a valid root CA configuration, when the operator submits the creation request, then the system generates the CA key via `crypto.Signer`, stores the signed root certificate, and returns the certificate's `fingerprint_sha256`. The root CA appears as `status=active` in the CA hierarchy. Given an air-gapped workflow, when the operator provides an externally-signed root certificate without a private key, then the system imports the certificate as a trust anchor and allows issuing CAs to be subordinated to it. |
| **Dependencies** | FR-003 (key storage backends) |

#### FR-002

| Field | Value |
|-------|-------|
| **ID** | FR-002 |
| **Title** | Create Issuing (Subordinate) CA |
| **Description** | The system shall allow a PKI Administrator to create an issuing CA subordinate to an existing root CA or to an externally-provided parent CA. The operator specifies: parent CA, common name, organization, validity period, key algorithm, and key storage backend. The system generates the issuing CA key via `crypto.Signer`, generates a CSR, submits the CSR to the parent CA for signing, and stores the resulting issuing CA certificate. An issuing CA may be subordinate to another issuing CA (multi-tier hierarchy). |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given an active root CA, when the operator creates an issuing CA with valid parameters, then the issuing CA certificate is signed by the root CA (verified by chain validation), stored with `status=active`, and appears nested under the root CA in the hierarchy view. Given an external root CA (no private key in the platform), when the operator creates an issuing CA, then the system produces a CSR for external signing and imports the signed issuing CA certificate upon submission. |
| **Dependencies** | FR-001, FR-003 |

#### FR-003

| Field | Value |
|-------|-------|
| **ID** | FR-003 |
| **Title** | Key Storage Backend — Software |
| **Description** | The system shall support software-based key storage for CA keys. Layer 1: Encrypted PKCS#8 PEM on disk using Argon2id KDF (minimum: 64 MB memory, 4 iterations). Layer 2: Envelope encryption — AES-256-GCM data key, master key stored in HashiCorp Vault or a cloud KMS. The key decryption passphrase or Vault token must be provided at startup and must not be written to disk in plaintext. All signing operations MUST invoke `crypto.Signer.Sign()` — no direct access to the private key bytes after initial generation. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin), Jordan (Platform Eng) |
| **Acceptance Criteria** | Given a new CA configured with software key storage, when the CA key is generated, then the key file on disk is encrypted PKCS#8 and is not readable without the correct passphrase. Given a correct passphrase at startup, when a signing operation is requested, then the system decrypts the key, calls `crypto.Signer.Sign()`, and zeroes the in-memory key material after use. Given an incorrect passphrase, when the system attempts to start, then startup fails with a clear error message and no partial key material is written. |
| **Dependencies** | None |

#### FR-004

| Field | Value |
|-------|-------|
| **ID** | FR-004 |
| **Title** | Key Storage Backend — PKCS#11 HSM |
| **Description** | The system shall support PKCS#11 HSM-based key storage via `ThalesGroup/crypto11`. The operator configures: PKCS#11 library path, slot/token PIN, key label. All CA signing operations on HSM-backed CAs MUST invoke the `crypto11.Signer` implementation, which in turn calls the PKCS#11 `C_Sign` function. The private key material never leaves the HSM. The platform MUST start up without an HSM present if no CAs are configured to use PKCS#11. |
| **Priority** | Should-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given a configured PKCS#11 HSM (or SoftHSM2 in test), when a CA is created with PKCS#11 storage, then the key is generated on the token and the CA certificate is signed using the HSM key. The signing operation completes without the private key bytes being accessible in Go heap memory. Given SoftHSM2 configured as the PKCS#11 provider, then all CI integration tests for PKCS#11 pass. |
| **Dependencies** | FR-003 |

#### FR-005

| Field | Value |
|-------|-------|
| **ID** | FR-005 |
| **Title** | Process Certificate Signing Requests (CSRs) |
| **Description** | The system shall accept PKCS#10 CSRs and sign them using an active issuing CA. The signing operation SHALL: validate the CSR signature, validate the public key algorithm and key size against the template's policy, enforce subject field requirements from the template, apply configured extensions (EKU, key usage, SAN, CDP URLs, OCSP URLs, AIA), generate a unique serial number (RFC 5280 requires at least 20 bytes of entropy), and return the signed DER-encoded certificate. CSRs MUST be submitted via the REST API (FR-044) or via protocol servers (ACME, EST, SCEP). |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin), Jordan (Platform Eng), Riley (Network Eng) |
| **Acceptance Criteria** | Given a valid PKCS#10 CSR and a matching template, when the signing request is submitted, then the system returns a DER-encoded certificate with: correct issuer DN, correct validity period, correct EKU matching the template, correct serial number (unique within this CA), and correct AIA/CDP extension URLs. Given a CSR with a key size below the template minimum (e.g., RSA-1024 when template requires RSA-2048), when submitted, then the system rejects the CSR with a 400 error and a descriptive message. |
| **Dependencies** | FR-002, FR-020 (templates) |

#### FR-006

| Field | Value |
|-------|-------|
| **ID** | FR-006 |
| **Title** | External CA Import |
| **Description** | The system shall allow import of an existing CA certificate from an external CA (e.g., an organizational root CA not managed by Kryptkeeper). The imported CA is stored as a trust anchor but has no associated private key in the platform. Issuing CAs may be created subordinate to an imported external CA by generating a CSR, signing it externally, and importing the signed certificate. |
| **Priority** | Should-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given a PEM-encoded external CA certificate, when the operator submits it via the import API, then the certificate is stored as an external CA entry with `type=external`, its chain is validated, and it appears in the CA hierarchy. Issuing CAs can be created beneath it via the CSR workflow. |
| **Dependencies** | FR-001 |

---

### 3.2 Certificate Lifecycle

#### FR-010

| Field | Value |
|-------|-------|
| **ID** | FR-010 |
| **Title** | Issue Certificate from Template |
| **Description** | The system shall issue a certificate by accepting a CSR and a template name. The issuing CA enforces all template policies (key usage, EKU, minimum key size, allowed algorithms, validity period, subject name requirements, enrollment permissions) before signing. The issued certificate is stored in the `certificates` table with `fingerprint_sha256` as the primary key. Duplicate submissions of the same CSR (same public key + same template) return the existing certificate if it is still valid. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin), Jordan (Platform Eng), Riley (Network Eng) |
| **Acceptance Criteria** | Given a CSR meeting all template requirements, when a certificate is issued, then the certificate is stored, its `fingerprint_sha256` is indexable, and the API returns both the certificate and the full issuing chain in PEM format. Given a CSR violating a template constraint (wrong EKU, key too small, disallowed algorithm), when issuance is attempted, then the system returns HTTP 400 with the specific violated constraint identified. |
| **Dependencies** | FR-005, FR-020 |

#### FR-011

| Field | Value |
|-------|-------|
| **ID** | FR-011 |
| **Title** | Certificate Renewal |
| **Description** | The system shall support certificate renewal by accepting a new CSR for an existing certificate that is approaching expiry or has expired. On renewal: the new certificate's `predecessor_fingerprint` is set to the expiring certificate's `fingerprint_sha256`, and the predecessor's `successor_fingerprint` is updated. The new certificate is issued using the same template as the predecessor. The ACME auto-renewal path (FR-031) triggers this workflow automatically. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin), Jordan (Platform Eng), Riley (Network Eng) |
| **Acceptance Criteria** | Given an active certificate within 30 days of expiry, when a renewal CSR is submitted, then the system issues a new certificate, links it to the predecessor via `predecessor_fingerprint`/`successor_fingerprint`, and the predecessor's `renewal_status` is set to `renewed`. Given a certificate renewed via ACME, then the predecessor chain is correctly populated without operator intervention. |
| **Dependencies** | FR-010 |

#### FR-012

| Field | Value |
|-------|-------|
| **ID** | FR-012 |
| **Title** | Revoke Certificate |
| **Description** | The system shall allow a PKI Administrator or authorized API caller to revoke a certificate by `fingerprint_sha256` and revocation reason code (RFC 5280 reason codes: 0=unspecified, 1=keyCompromise, 2=cACompromise, 3=affiliationChanged, 4=superseded, 5=cessationOfOperation, 6=certificateHold, 9=removeFromCRL). Revocation MUST: add the certificate to the issuing CA's CRL, update the OCSP responder's response cache, and write an audit log entry with actor, timestamp, and reason. Revocation is permanent for reasons 0–5 and 9; reason 6 (certificateHold) may be reversed by reason 9 (removeFromCRL). |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given an active certificate, when an authorized caller revokes it with reason `keyCompromise`, then: (1) the certificate's status becomes `revoked`, (2) the next CRL generation includes the serial number with the correct reason code, (3) an OCSP query for the serial returns `revoked` within 60 seconds. Given a certificateHold revocation, when `removeFromCRL` is subsequently applied, then the certificate's status returns to `active` and the next CRL omits the serial. |
| **Dependencies** | FR-035 (CRL), FR-040 (OCSP) |

#### FR-013

| Field | Value |
|-------|-------|
| **ID** | FR-013 |
| **Title** | Expiry Monitoring and Tracking |
| **Description** | The system shall continuously evaluate all certificates in the inventory for expiry proximity. The platform SHALL maintain the following alert thresholds, configurable per certificate template or globally: 90 days, 60 days, 30 days, 14 days, 7 days, and at expiry. For each threshold breach, the system shall: mark the certificate with the corresponding risk flag (`EXPIRING_90_DAYS`, `EXPIRING_30_DAYS`, `EXPIRING_7_DAYS`, `EXPIRED`), recalculate the risk score, and trigger the configured alert routing for the certificate's owner (FR-052). |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin), Sam (CISO), Riley (Network Eng) |
| **Acceptance Criteria** | Given a certificate with `valid_until` 29 days from now, when the expiry monitor runs, then the certificate's risk flags include `EXPIRING_30_DAYS` and the risk score includes the +20 weight for that flag. Given a certificate with `valid_until` in the past, then `risk_flags` includes `EXPIRED`, risk score includes +40, and grade is F. Expiry checks MUST run at minimum every 6 hours. |
| **Dependencies** | FR-010, FR-052 |

#### FR-014

| Field | Value |
|-------|-------|
| **ID** | FR-014 |
| **Title** | Renewal History and Chain Tracking |
| **Description** | The system shall maintain the full renewal chain for any certificate by tracking `predecessor_fingerprint` and `successor_fingerprint` on the `certificates` table. The API shall provide an endpoint to retrieve the full chain (all predecessors and successors) for a given `fingerprint_sha256`. |
| **Priority** | Should-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given a certificate that has been renewed 3 times, when the renewal chain endpoint is queried for the latest certificate, then the response includes all 4 certificates in chain order (oldest first), each linked by `predecessor_fingerprint`. Given the oldest certificate in the chain, when queried, then `successor_fingerprint` correctly points to the next certificate. |
| **Dependencies** | FR-011 |

---

### 3.3 Certificate Templates

#### FR-020

| Field | Value |
|-------|-------|
| **ID** | FR-020 |
| **Title** | Create and Manage Certificate Templates |
| **Description** | The system shall provide full CRUD operations for certificate templates. A template defines the policy applied during certificate issuance. Template fields: `name`, `display_name`, `oid` (unique OID in the organization's arc), `key_usage` (bitmask, RFC 5280), `extended_key_usage[]` (OID list), `min_key_size` (bits), `allowed_algorithms[]` (e.g., RSA, ECDSA, Ed25519), `validity_period` (days), `renewal_overlap` (days before expiry when renewal is permitted), `subject_requirements` (JSONB — required CN, OU, O fields), `enrollment_permissions` (JSONB — role-based allow list), `issuance_requirements` (JSONB — manager approval, CA operator countersign), `auto_enroll` (bool), `schema_version` (integer — ADCS-compatible: 1, 2, 3, or 4), `revision` (integer). |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given a valid template definition, when created via the API, then the template is stored with a unique OID, appears in the template list, and can be retrieved by name or ID. Given a template update, when the template's `validity_period` is changed, then the `revision` counter increments and new certificates issued from this template use the updated validity period; existing issued certificates are unaffected. Given an attempt to delete a template that has active issued certificates, then the system rejects the deletion with HTTP 409 and the count of blocking certificates. |
| **Dependencies** | FR-005 |

#### FR-021

| Field | Value |
|-------|-------|
| **ID** | FR-021 |
| **Title** | Template Policy Enforcement |
| **Description** | The system shall enforce all template policies at issuance time with no operator bypass path. Enforced constraints: minimum key size (reject CSR if public key size < `min_key_size`), allowed algorithms (reject if `public_key_algorithm` not in `allowed_algorithms`), key usage (add required usages, reject if CSR requests disallowed usages), EKU (enforce `extended_key_usage` list exactly), validity period (issue with template `validity_period` regardless of what CSR requests), subject name requirements (reject if required DN fields are absent or non-conforming). Policy violations MUST return HTTP 400 with a structured error response identifying each violation. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given a TLS Server template with `min_key_size=2048` and `allowed_algorithms=[RSA, ECDSA]`, when a CSR with RSA-1024 is submitted, then the system returns HTTP 400 with error code `WEAK_KEY` and the message specifying the minimum required size. Given the same template, when a valid RSA-2048 CSR is submitted, then the issued certificate has exactly the EKU specified in the template, not the EKU in the CSR. |
| **Dependencies** | FR-020 |

#### FR-022

| Field | Value |
|-------|-------|
| **ID** | FR-022 |
| **Title** | Template Enrollment Permissions |
| **Description** | The system shall enforce role-based enrollment permissions on templates. Each template's `enrollment_permissions` field defines which RBAC roles may enroll certificates from that template. An enrollment attempt by a principal lacking the required role SHALL be rejected with HTTP 403. Permissions support: `enroll` (issue new certificate) and `auto_enroll` (allow automated renewal without human approval). |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given a template with `enrollment_permissions: {enroll: ["pki-admin", "service-account"]}`, when a caller with role `readonly` attempts to issue a certificate from this template, then the system returns HTTP 403. Given a caller with role `pki-admin`, when the same template is used, then issuance proceeds. |
| **Dependencies** | FR-020, FR-045 (RBAC) |

#### FR-023

| Field | Value |
|-------|-------|
| **ID** | FR-023 |
| **Title** | Template Versioning |
| **Description** | The system shall track template revisions via the `revision` integer field. Every modification to a template's policy fields (key_usage, EKU, validity_period, min_key_size, allowed_algorithms, subject_requirements) SHALL increment `revision`. The `schema_version` field (1–4, ADCS-compatible) SHALL be set at template creation and SHALL NOT be changed except when explicitly migrating to a higher schema version via a documented migration operation. The system SHALL store a complete revision history for audit purposes. |
| **Priority** | Should-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given a template at revision 3, when the `validity_period` is changed, then the template's revision becomes 4 and the audit log records the change with old and new values. Given a query for the template's revision history, then all past revisions (1–4) with their diff and actor are returned. |
| **Dependencies** | FR-020 |

---

### 3.4 ACME Server

#### FR-030

| Field | Value |
|-------|-------|
| **ID** | FR-030 |
| **Title** | ACME Server — RFC 8555 Compliance |
| **Description** | The system shall provide an RFC 8555-compliant ACME server. The server MUST implement all required ACME endpoints: `GET /directory`, `HEAD/GET /nonce`, `POST /accounts`, `POST /orders`, `POST /authorizations`, `POST /challenges`, `POST /finalizations`, `GET /certificates`. The server MUST support account creation, account key rollover, certificate issuance from an order, and certificate revocation via ACME. ACME accounts are provisioner-scoped: each ACME provisioner defines the allowed domain set, template, and rate limits. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Jordan (Platform Eng), Alex (PKI Admin) |
| **Acceptance Criteria** | Given a running ACME server at `https://<host>/acme/<provisioner>`, when `certbot --server https://<host>/acme/<provisioner>/directory certonly -d example.internal` is run against the platform, then a certificate is issued and stored without any platform-specific client modification. The response to `GET /directory` contains all required fields per RFC 8555 §7.1.1. |
| **Dependencies** | FR-005, FR-020 |

#### FR-031

| Field | Value |
|-------|-------|
| **ID** | FR-031 |
| **Title** | ACME HTTP-01 Challenge |
| **Description** | The system shall implement the ACME HTTP-01 challenge (RFC 8555 §8.3). The challenge token is served by the ACME client at `http://<domain>/.well-known/acme-challenge/<token>`. The server validates the key authorization from the HTTP response, marks the challenge as `valid`, and proceeds with authorization. HTTP-01 challenges MUST NOT be used for wildcard certificates. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Jordan (Platform Eng) |
| **Acceptance Criteria** | Given an ACME order for `host.internal`, when the HTTP-01 challenge is initiated and the client serves the correct token at the well-known URL, then the challenge status transitions to `valid` within 30 seconds. Given a wildcard order `*.internal`, when HTTP-01 is the only available challenge type, then the server returns HTTP 400 with error `malformed` indicating HTTP-01 is not valid for wildcards. |
| **Dependencies** | FR-030 |

#### FR-032

| Field | Value |
|-------|-------|
| **ID** | FR-032 |
| **Title** | ACME DNS-01 Challenge |
| **Description** | The system shall implement the ACME DNS-01 challenge (RFC 8555 §8.4). The platform notifies the client of the required TXT record (`_acme-challenge.<domain>`) and queries the authoritative DNS server to validate it. DNS-01 MUST be supported for wildcard certificates. The server MUST be configurable to use custom DNS resolvers (for internal DNS zones). |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Jordan (Platform Eng), Alex (PKI Admin) |
| **Acceptance Criteria** | Given an ACME order for `*.internal`, when the DNS-01 challenge is initiated and the correct TXT record is published, then the challenge status transitions to `valid`. Given a custom DNS resolver configured for `.internal` zones, when DNS-01 validation runs, then the platform queries the configured resolver, not the public DNS resolver. |
| **Dependencies** | FR-030 |

#### FR-033

| Field | Value |
|-------|-------|
| **ID** | FR-033 |
| **Title** | ACME TLS-ALPN-01 Challenge |
| **Description** | The system shall implement the ACME TLS-ALPN-01 challenge (RFC 8737). The client must serve a self-signed certificate with the `acmeValidation` extension over TLS with the `acme-tls/1` ALPN protocol identifier. The platform connects to port 443 on the target domain and validates the certificate. |
| **Priority** | Should-have |
| **Version** | V1 |
| **Personas** | Jordan (Platform Eng) |
| **Acceptance Criteria** | Given an ACME order using TLS-ALPN-01, when the client serves the correct validation certificate, then the challenge transitions to `valid`. Given a challenge where the target port is unreachable, then the system retries up to 3 times with exponential backoff before marking the challenge `invalid`. |
| **Dependencies** | FR-030 |

#### FR-034

| Field | Value |
|-------|-------|
| **ID** | FR-034 |
| **Title** | ACME Scoped Provisioners |
| **Description** | The system shall support multiple named ACME provisioners, each with independent configuration: allowed domain patterns (glob or regex), bound certificate template, rate limits (certificates per domain per day), and account policy (allow any ACME account vs. pre-registered accounts only). A provisioner may be enabled or disabled without affecting other provisioners. Provisioner configuration is managed via the REST API and the dashboard. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given a provisioner `internal-tls` configured to allow `*.internal` only, when an ACME order is placed for `external.example.com` against this provisioner, then the server returns HTTP 400 with error `rejectedIdentifier`. Given two provisioners bound to different templates, when certificates are issued through each, then the resulting certificates have the EKU of their respective templates. |
| **Dependencies** | FR-030, FR-020 |

---

### 3.5 OCSP Responder

#### FR-040

| Field | Value |
|-------|-------|
| **ID** | FR-040 |
| **Title** | OCSP Responder — RFC 5019 Lightweight Profile |
| **Description** | The system shall provide an RFC 5019-compliant OCSP responder. The responder MUST: accept both HTTP GET (base64-encoded request in URL path) and HTTP POST requests, return pre-signed OCSP responses with correct HTTP caching headers (`Cache-Control: max-age`, `Expires`, `Last-Modified`), support `GET` request URLs long enough for SHA-256-based requests (RFC 5019 §2.1), sign responses using a dedicated OCSP signing certificate (not the CA signing key) with the `OCSPSigning` EKU, and return `good`, `revoked`, or `unknown` status per RFC 2560. Pre-signed responses are generated for all active certificates on a configurable schedule (default: every 4 hours) and cached in the database. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given an active certificate from this CA, when `openssl ocsp -issuer ca.pem -cert issued.pem -url http://<ocsp-host>/ocsp` is run, then the response is `good` within 500ms. Given a revoked certificate, when the same OCSP query is run, then the response is `revoked` with the correct `revokedInfo` (time and reason). Given a cached response, when an HTTP GET request is made, then the response includes `Cache-Control: max-age=14400` (or the configured interval). The OCSP responder MUST be available in the Apache 2.0 OSS tier without any commercial license. |
| **Dependencies** | FR-012 |

#### FR-041

| Field | Value |
|-------|-------|
| **ID** | FR-041 |
| **Title** | OCSP Signing Certificate |
| **Description** | The system shall generate and manage a dedicated OCSP signing certificate for each issuing CA. The signing certificate MUST have: `extendedKeyUsage = OCSPSigning`, `noCheck` extension (RFC 2560 §4.2.2.2.1 — prevents OCSP recursion), validity period of 90 days (configurable), and be signed by the corresponding issuing CA. The signing certificate is automatically renewed before expiry without operator intervention. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given a new issuing CA, when the OCSP service starts, then a dedicated OCSP signing certificate is automatically generated with the correct extensions. Given the signing certificate within 14 days of expiry, when the renewal job runs, then a new signing certificate is issued and the responder switches to it without service interruption. |
| **Dependencies** | FR-040, FR-002 |

---

### 3.6 CRL Generation and Distribution

#### FR-042

| Field | Value |
|-------|-------|
| **ID** | FR-042 |
| **Title** | CRL Generation — RFC 5280 |
| **Description** | The system shall generate X.509 Certificate Revocation Lists per RFC 5280 for each issuing CA. CRL generation MUST: sign the CRL with the issuing CA key (or a dedicated CRL signing key if configured), include all revoked certificates with their serial numbers, revocation dates, and reason codes, set `thisUpdate` to the generation time and `nextUpdate` to `thisUpdate + CRL validity period` (default: 24 hours for base CRL, 4 hours for delta CRL), and support delta CRLs (RFC 5280 §5.2.4) listing only changes since the last base CRL. CRLs MUST be regenerated immediately after any revocation event, not only on the scheduled interval. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given a certificate revoked with reason `superseded`, when the CRL is generated, then `openssl crl -text -noout -in ca.crl` shows the certificate serial in the revoked list with the correct reason code and revocation time. Given a revocation event at any time, then a new CRL is generated within 60 seconds. Given the configured delta CRL interval, then a delta CRL containing only the revocation since the last base CRL is available at the delta distribution point URL. |
| **Dependencies** | FR-012 |

#### FR-043

| Field | Value |
|-------|-------|
| **ID** | FR-043 |
| **Title** | CRL Distribution Points |
| **Description** | The system shall serve CRLs at the CRL Distribution Point (CDP) URLs embedded in issued certificates. CRL URLs are of the form `http://<crl-host>/crl/<issuing-ca-id>/crl.pem`. The system MUST serve both DER and PEM-encoded CRLs. CRL responses MUST include HTTP `Cache-Control` headers with `max-age` set to half the CRL validity period. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given a certificate with CDP extension `http://crl.example.internal/crl/<id>/crl.der`, when an HTTP GET is made to that URL, then the response is a valid DER-encoded CRL with `Content-Type: application/pkix-crl` and correct `Cache-Control` headers. |
| **Dependencies** | FR-042 |

---

### 3.7 EST Server

#### FR-044

| Field | Value |
|-------|-------|
| **ID** | FR-044 |
| **Title** | EST Server — RFC 7030 |
| **Description** | The system shall provide an RFC 7030-compliant EST (Enrollment over Secure Transport) server. Required operations: `/cacerts` (GET CA certificates), `/simpleenroll` (POST CSR, return signed certificate), `/simplereenroll` (POST CSR for existing certificate renewal), `/fullcmc` (full PKI request — Could-have). The EST server MUST be TLS-only. Clients authenticate via: (a) HTTP Basic authentication with pre-registered credentials, (b) TLS client certificate with an existing certificate from this CA. Each EST endpoint is bound to a named certificate template (same provisioner model as ACME). |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin), Riley (Network Eng) |
| **Acceptance Criteria** | Given a valid client credential and a PKCS#10 CSR, when `POST /est/<provisioner>/simpleenroll` is called with `Content-Type: application/pkcs10`, then the system returns HTTP 200 with the signed certificate in `application/pkcs7-mime; smime-type=certs-only`. Given an invalid credential, then HTTP 401 is returned. Given a CSR violating the bound template's policy, then HTTP 400 is returned. |
| **Dependencies** | FR-005, FR-020 |

---

### 3.8 SCEP Server

#### FR-045

| Field | Value |
|-------|-------|
| **ID** | FR-045 |
| **Title** | SCEP Server — Network Device Enrollment |
| **Description** | The system shall provide a SCEP server for network device certificate enrollment (F5 BIG-IP, Palo Alto Networks PAN-OS, Citrix ADC, Cisco IOS/ASA). Required SCEP operations: `GetCACert`, `GetCACaps`, `PKIOperation` (for `PKCSReq`, `CertPoll`, `GetCert`, `GetCRL`). SCEP authentication is via a pre-shared challenge password configured per provisioner. Automatic approval policy: CSRs meeting the provisioner's challenge password are auto-approved; otherwise, they enter a manual approval queue. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Riley (Network Eng) |
| **Acceptance Criteria** | Given an F5 BIG-IP configured with the platform's SCEP URL and challenge password, when the F5 requests a new certificate via SCEP `PKCSReq`, then a certificate meeting the provisioner's template is issued and returned. Given an invalid challenge password in a `PKCSReq`, then the response is a SCEP `FAILURE` `PKIOperation` message with `failInfo = badRequest`. |
| **Dependencies** | FR-005, FR-020 |

---

### 3.9 Discovery — Network Scanning

#### FR-050

| Field | Value |
|-------|-------|
| **ID** | FR-050 |
| **Title** | Network Port Discovery — Phase 1 |
| **Description** | The system shall perform Phase 1 network scanning using masscan to detect open TLS ports on target IP ranges. The operator defines: target CIDR ranges (requires explicit scan authorization acknowledgment), port list (default: 443, 8443, 636, 993, 995, 6443, 10250, and configurable custom ports), and scan rate (default: 10,000 pps, configurable down to 1,000 pps). Scan results (IP:port tuples of open ports) are stored in the `scan_jobs` table and fed to Phase 2. The scan authorization acknowledgment — confirming the operator has permission to scan the target ranges — MUST be a required field in the scan job creation request. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given a target /24 CIDR with scan authorization acknowledged, when a network scan job is created, then Phase 1 completes within 5 minutes and the IP:port list is stored in the scan job result. Given a scan job submitted without scan authorization acknowledgment, then the system returns HTTP 400 and does not initiate scanning. Given a rate of 10,000 pps, then the scan does not exceed this rate (verified by packet capture or rate metric). |
| **Dependencies** | None |

#### FR-051

| Field | Value |
|-------|-------|
| **ID** | FR-051 |
| **Title** | Certificate Extraction — Phase 2 |
| **Description** | The system shall perform Phase 2 certificate extraction using a concurrent Go TLS scanner against the IP:port list produced by Phase 1. The scanner MUST: perform a full TLS handshake (SNI-aware, with the known hostname in the SNI extension if available), extract the full certificate chain, record TLS protocol version and cipher suite negotiated, attempt non-SNI connection first to get the default certificate, then re-scan with known SNI hostnames from DNS/CT log/CMDB data. Worker pool: 200 concurrent TLS connections (configurable). Target throughput: 10,000 endpoints in under 30 minutes from a single scan host. Extracted certificates are deduplicated by `fingerprint_sha256` and merged into the `certificates` table. Each `(ip, port, sni_name)` tuple creates or updates an `endpoints` row. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given a /24 with 1,000 TLS endpoints, when Phase 2 extraction runs, then all reachable certificates are extracted and stored with correct `fingerprint_sha256`, subject, issuer, valid_from, valid_until, and SAN fields. Given a host serving different certificates for different SNI names, when the scanner re-scans with each hostname, then each distinct certificate is stored as a separate `certificates` row linked to the same IP via separate `endpoints` rows. The scan completes 10,000 endpoints in under 30 minutes on a 10 Gbps-capable scan host. |
| **Dependencies** | FR-050 |

#### FR-052

| Field | Value |
|-------|-------|
| **ID** | FR-052 |
| **Title** | CT Log Monitoring |
| **Description** | The system shall monitor Certificate Transparency logs via the crt.sh API for certificates matching configured domain patterns. Operators configure: domain patterns (e.g., `*.example.com`, `example.com`), polling interval (default: 4 hours for new cert detection). Newly discovered certificates are fetched from crt.sh, parsed, and added to the inventory if not already present (dedup by `fingerprint_sha256`). CT monitoring allows detection of certificates issued by other CAs for the operator's domains (shadow IT, rogue certificates). |
| **Priority** | Should-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin), Sam (CISO) |
| **Acceptance Criteria** | Given a configured domain pattern `*.example.com`, when crt.sh returns new certificate records matching the pattern, then those certificates are added to the inventory within 4 hours of CT log inclusion. Given a certificate already in the inventory, when the CT monitor encounters it, then no duplicate is created (dedup by `fingerprint_sha256`). |
| **Dependencies** | FR-060 (certificate inventory) |

---

### 3.10 Discovery — Agentless Host

#### FR-055

| Field | Value |
|-------|-------|
| **ID** | FR-055 |
| **Title** | Agentless Discovery — Linux SSH |
| **Description** | The system shall discover certificates on Linux hosts via SSH using key-based authentication. SSH credentials (private key, username) are stored encrypted in the platform and referenced by host group. Discovery operations: `find` command to locate PEM, DER, PFX, JKS, and P12 files (excluding `/dev`, `/proc`, `/sys`, configurable exclusion list), parse web server configuration files (`nginx ssl_certificate`, Apache `SSLCertificateFile`, Tomcat `keystoreFile`), invoke `openssl x509 -noout -text` to extract certificate metadata without retrieving the file bytes. All discovered certificates are stored in the `certificates` table (dedup by `fingerprint_sha256`). |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given a Linux host with SSH key-based access configured, when a host discovery job is run, then all PEM/CRT files in non-excluded paths are discovered, parsed, and added to the inventory within 10 minutes. Given a certificate already in the inventory, when discovered again via SSH, then the existing record is updated with the new `last_scanned` timestamp without creating a duplicate. |
| **Dependencies** | FR-060 |

#### FR-056

| Field | Value |
|-------|-------|
| **ID** | FR-056 |
| **Title** | Agentless Discovery — Windows WinRM |
| **Description** | The system shall discover certificates on Windows hosts via WinRM (port 5985 HTTP or 5986 HTTPS). Discovery operations: `Get-ChildItem Cert:\LocalMachine\My` (enumerate Windows certificate stores), `Get-ChildItem Cert:\LocalMachine\Root`, `Get-WebBinding` (IIS HTTPS bindings), file system scan for `.pfx`, `.cer`, `.p12`, `.pem` files. WinRM credentials (username + password or Kerberos) are stored encrypted. All discovered certificates are stored in the `certificates` table (dedup by `fingerprint_sha256`). |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given a Windows host with WinRM enabled and valid credentials, when a WinRM discovery job is run, then all certificates in `LocalMachine\My` and IIS HTTPS bindings are discovered and added to the inventory. Given an IIS site with a certificate binding, then the discovery result includes the certificate's `fingerprint_sha256` and a corresponding `endpoints` row with `hostname` and `port` from the IIS binding. |
| **Dependencies** | FR-060 |

#### FR-057

| Field | Value |
|-------|-------|
| **ID** | FR-057 |
| **Title** | Cloud API Discovery — AWS ACM, Azure Key Vault, GCP Certificate Manager |
| **Description** | The system shall integrate with cloud certificate management APIs in read-only inventory mode. AWS ACM: `ListCertificates` + `DescribeCertificate` to enumerate and fetch metadata. Azure Key Vault: `CertificateClient.listPropertiesOfCertificates` per vault. GCP Certificate Manager: `ListCertificates` per project. Discovered cloud certificates are added to the inventory with `source=cloud_aws_acm`, `source=cloud_azure_kv`, or `source=cloud_gcp_cm`. Cloud credentials (IAM role ARN for AWS, service principal for Azure, service account for GCP) are stored encrypted. |
| **Priority** | Should-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin), Jordan (Platform Eng) |
| **Acceptance Criteria** | Given AWS credentials with `acm:ListCertificates` and `acm:DescribeCertificate` permissions, when a cloud discovery job runs, then all ACM certificates in the configured region are added to the inventory with `source=cloud_aws_acm` and correct `valid_until` dates. Cloud discovery jobs MUST NOT require any outbound network access at platform startup — only when a job is triggered. |
| **Dependencies** | FR-060 |

#### FR-058

| Field | Value |
|-------|-------|
| **ID** | FR-058 |
| **Title** | Kubernetes Discovery |
| **Description** | The system shall discover certificates from Kubernetes clusters via the Kubernetes API. Discovery operations: enumerate `cert-manager.io/Certificate` CRDs, enumerate TLS `Secrets` (kind: `kubernetes.io/tls`), enumerate `Ingress` resources and their TLS hostnames. Authentication: kubeconfig file or in-cluster service account. Discovered certificates are added to the inventory with `source=kubernetes` and tagged with namespace and cluster name. |
| **Priority** | Should-have |
| **Version** | V1 |
| **Personas** | Jordan (Platform Eng), Alex (PKI Admin) |
| **Acceptance Criteria** | Given a kubeconfig with `get`/`list` permission on Secrets and cert-manager CRDs, when a Kubernetes discovery job runs, then all TLS secrets and cert-manager certificates in the configured namespaces are added to the inventory. Each certificate includes a `source_reference` field with the format `kubernetes/<cluster>/<namespace>/<secret-name>`. |
| **Dependencies** | FR-060 |

---

### 3.11 Discovery — Agent

#### FR-060

| Field | Value |
|-------|-------|
| **ID** | FR-060 |
| **Title** | Go Discovery Agent — Binary |
| **Description** | The system shall provide a lightweight Go discovery agent (`pki-agent`) as a single static binary. Binary size constraint: under 15MB compressed. The agent operates in read-only discovery mode by default. Configuration: YAML file specifying scan paths, cert stores to enumerate, process inspection scope, polling interval, and server URL + API key. The agent MUST start and operate without any Go runtime or external dependencies on the target host. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin), Jordan (Platform Eng) |
| **Acceptance Criteria** | Given a target Linux host with no Go runtime installed, when the `pki-agent` binary is copied to the host and started with a valid config file, then the agent starts, discovers local certificates, and reports them to the platform within 15 minutes. The compressed binary size MUST NOT exceed 15MB (measured in CI via `wc -c` on the gzip-compressed binary). |
| **Dependencies** | None |

#### FR-061

| Field | Value |
|-------|-------|
| **ID** | FR-061 |
| **Title** | Agent — HTTPS Polling Protocol |
| **Description** | The agent shall communicate with the platform server exclusively via HTTPS (TLS 1.2 minimum). Communication model: polling (pull, not push). Default poll interval: 15 minutes (configurable to 1 minute minimum). Each poll cycle: (1) agent reports delta inventory (changed or new certificates since last poll), (2) server returns updated configuration if changed. Delta reporting: agent maintains a local cache (SHA-256 of last-sent inventory state); only changed entries are transmitted. The agent authenticates using an API key issued by the platform (FR-047). |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given an agent with 1,000 known certificates and no changes since last poll, when the poll interval fires, then the agent sends a delta report containing zero certificate changes (only a heartbeat). Given 3 new PEM files written to a monitored directory, when the next poll fires, then only those 3 new certificates are transmitted. |
| **Dependencies** | FR-060 |

#### FR-062

| Field | Value |
|-------|-------|
| **ID** | FR-062 |
| **Title** | Agent — Real-Time File System Events |
| **Description** | The agent shall use OS-native file system event mechanisms for real-time certificate change detection: inotify on Linux, FSEvents on macOS. When a monitored certificate file is created, modified, or deleted, the agent SHALL report the change to the platform within 60 seconds without waiting for the next poll cycle. The polling fallback MUST remain active in case the inotify/FSEvents watcher fails. |
| **Priority** | Should-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given an agent monitoring `/etc/ssl/certs`, when a new `.pem` file is written to that directory, then the agent reports the new certificate to the platform within 60 seconds. Given the inotify watcher experiencing an error, then the agent falls back to polling and logs a warning. |
| **Dependencies** | FR-061 |

#### FR-063

| Field | Value |
|-------|-------|
| **ID** | FR-063 |
| **Title** | Agent — Auto-Update |
| **Description** | DESCOPED from v1.0 by D-128: agent upgrades use the package manager, MSI or image replacement (packaging/README.md, "Upgrading the agent"). The text below is retained as the v1.x candidate. The agent shall support signed auto-update. The platform serves a signed manifest (JSON) containing the latest agent version, binary URL, and SHA-256 hash. The manifest is signed by an Ed25519 key whose public key is embedded in the agent binary at build time. On update: the agent downloads the new binary, verifies the SHA-256 hash, verifies the Ed25519 manifest signature, replaces the current binary, and restarts. If verification fails at any step, the current binary is kept and an error is reported. |
| **Priority** | Descoped (D-128) |
| **Version** | Descoped from v1.0; v1.x candidate |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given a new agent version published with a valid signed manifest, when the agent checks for updates and a new version is available, then the agent downloads the binary, verifies hash and signature, replaces itself, and restarts within 5 minutes. Given a manifest with an invalid signature, when the agent processes it, then no update is applied and the current binary continues running. |
| **Dependencies** | FR-060 |

---

### 3.12 Certificate Inventory

#### FR-070

| Field | Value |
|-------|-------|
| **ID** | FR-070 |
| **Title** | Unified Certificate Inventory |
| **Description** | The system shall maintain a unified certificate inventory in the `certificates` table, regardless of how a certificate was discovered (CA issuance, network scan, agentless, agent, cloud API, CT log). Deduplication is by `fingerprint_sha256` (SHA-256 of DER-encoded certificate) — a certificate with the same fingerprint from multiple discovery sources creates a single `certificates` row with multiple `endpoints` rows. The inventory MUST support at least 100,000 certificates without degradation in API response times. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin), Sam (CISO) |
| **Acceptance Criteria** | Given the same certificate discovered via network scan and via agent, when both discovery events are processed, then the inventory contains exactly one `certificates` row with `fingerprint_sha256` as the key, and two `endpoints` rows (one for each discovery source). Given a 100,000 certificate inventory, when the certificate list API is queried with filtering, then the response time is under 500ms at P95 (see NFR-002). |
| **Dependencies** | FR-051, FR-055, FR-057 |

#### FR-071

| Field | Value |
|-------|-------|
| **ID** | FR-071 |
| **Title** | Inventory Filtering, Sorting, and Search |
| **Description** | The system shall support filtering, sorting, and text search across the certificate inventory. Required filter dimensions: `valid_until` range, risk grade (A–F), issuer CN or CA ID, key algorithm, key size, EKU, SAN domain pattern (wildcard match), `source` (ca_issued, network_scan, ssh, winrm, cloud_*, agent, ct_log), expiry status (active, expiring_soon, expired, revoked). Required sort fields: `valid_until`, `risk_score`, `common_name`, `issuer_cn`, `created_at`. Text search: prefix match on `common_name`, `subject_dn`, `subject_alt_names[]`. All filters are combinable. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin), Sam (CISO) |
| **Acceptance Criteria** | Given a filter of `{grade: ["C", "D", "F"], expiry_days_max: 90}`, when the API is queried, then only certificates with risk grades C, D, or F AND `valid_until` within 90 days are returned. Given a text search for `mail.`, when executed, then all certificates with `common_name` starting with `mail.` are returned. |
| **Dependencies** | FR-070 |

#### FR-072

| Field | Value |
|-------|-------|
| **ID** | FR-072 |
| **Title** | Certificate Chain Validation |
| **Description** | The system shall validate the certificate chain for all certificates in the inventory. Chain validation checks: (a) each certificate's issuer matches the next certificate's subject, (b) each certificate in the chain is within its validity period, (c) the chain terminates at a known trusted root (or is flagged as `chain_trusted=false` if it does not). Chain validation results are stored on the `certificates` row: `chain_complete` (boolean) and `chain_trusted` (boolean). An incomplete or untrusted chain contributes risk flags `CHAIN_INCOMPLETE` and `UNTRUSTED_ROOT` respectively. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given a certificate whose issuing CA certificate is in the inventory, when chain validation runs, then `chain_complete=true`. Given a self-signed certificate not in the trusted roots list, then `chain_trusted=false` and the `UNTRUSTED_ROOT` risk flag is set. |
| **Dependencies** | FR-070 |

---

### 3.13 Risk Scoring

#### FR-075

| Field | Value |
|-------|-------|
| **ID** | FR-075 |
| **Title** | Risk Score Calculation |
| **Description** | The system shall calculate a numeric risk score (0–100, clamped at 100) for each certificate in the inventory using a weighted flag model. Risk flags and weights are defined as follows: `EXPIRED` (+40), `EXPIRING_7_DAYS` (+35), `EXPIRING_30_DAYS` (+20), `WEAK_KEY` for RSA < 2048 bits (+30), `SELF_SIGNED` (+25), `SHA1_SIGNATURE` (+25), `UNTRUSTED_ROOT` (+15), `TLS_OLD` for SSLv3, TLS 1.0, or TLS 1.1 negotiated (+15), `NULL_EXPORT_CIPHER` (+20), `CHAIN_INCOMPLETE` (+10), `WILDCARD` (+5), `PQC_VULNERABLE` for RSA or ECDSA public key (+5). Risk scores are recalculated whenever a flag is added or removed. Scores accumulate additively; the result is clamped to 100. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin), Sam (CISO) |
| **Acceptance Criteria** | Given a certificate with flags `EXPIRED` (+40) and `WEAK_KEY` (+30), when risk score is calculated, then the score is 70 and the grade is D (41–60 maps to D per the grade table). Given a certificate with `EXPIRED` (+40) + `WEAK_KEY` (+30) + `SHA1_SIGNATURE` (+25) + `SELF_SIGNED` (+25), then the score is clamped to 100 and the grade is F. Given a certificate with no flags, then the score is 0 and the grade is A. |
| **Dependencies** | FR-070, FR-072 |

#### FR-076

| Field | Value |
|-------|-------|
| **ID** | FR-076 |
| **Title** | Risk Grades |
| **Description** | The system shall assign a letter grade (A through F) to each certificate based on its risk score. Grade boundaries: A (0–10), B (11–25), C (26–40), D (41–60), F (61–100). Grades are stored on the `certificates` row and indexed for fast filtering. The dashboard MUST display grade distribution across the inventory as a summary metric. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Sam (CISO), Alex (PKI Admin) |
| **Acceptance Criteria** | Given the grade boundaries defined above, when risk scores across the inventory are 5, 15, 30, 50, 80, then the corresponding grades are A, B, C, D, F respectively. Given a dashboard summary query, when the endpoint returns the grade distribution, then the response includes counts for each grade A–F summing to the total inventory count. |
| **Dependencies** | FR-075 |

---

### 3.14 Ownership and Alerting

#### FR-080

| Field | Value |
|-------|-------|
| **ID** | FR-080 |
| **Title** | Certificate Ownership Assignment |
| **Description** | The system shall support ownership assignment for each certificate. Owner fields on `certificates`: `owner_team` (string), `owner_email` (string), `ownership_source` (enum: manual, cmdb, dns_lookup, ca_metadata, heuristic). Ownership assignment priority order (highest to lowest): (1) manual claim via API or dashboard, (2) CMDB integration (ServiceNow or CSV import — IP/hostname to team mapping), (3) DNS-based hostname-to-team lookup, (4) CA metadata (requestor team from cert Subject O/OU), (5) SAN domain heuristic match. Unowned certificates are surfaced in the discovery inbox. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin), Sam (CISO) |
| **Acceptance Criteria** | Given an unowned certificate, when an operator claims it via `PATCH /api/v1/certificates/{fingerprint}/owner`, then `owner_team` and `owner_email` are updated, `ownership_source=manual`, and the certificate is removed from the unowned inbox. Given a CMDB CSV import mapping IPs to teams, when a certificate's endpoint IP matches a CMDB entry, then the certificate is auto-assigned with `ownership_source=cmdb`. |
| **Dependencies** | FR-070 |

#### FR-081

| Field | Value |
|-------|-------|
| **ID** | FR-081 |
| **Title** | Multi-Tier Expiry Alerts |
| **Description** | The system shall send expiry alerts at configurable thresholds routed to the certificate's owner. Default thresholds: 90, 60, 30, 14, and 7 days before expiry, and at expiry. Each threshold fires once per certificate per expiry cycle (not repeated). Alert routing: by `owner_team` or `owner_email` → Slack channel, email address, or PagerDuty service key, as configured in the notification routing table. Alerts for unowned certificates are routed to a configurable global inbox. Alert content MUST include: certificate CN/SAN, expiry date, days remaining, risk score, and direct link to the certificate in the dashboard. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin), Sam (CISO), Riley (Network Eng) |
| **Acceptance Criteria** | Given a certificate with `owner_team=platform-eng` and a Slack channel configured for that team, when the certificate reaches the 30-day threshold, then a Slack message is sent to the configured channel containing the CN, expiry date, days remaining, and dashboard link. Given a certificate with no owner, when the 30-day threshold is reached, then the alert is sent to the global inbox. Each alert fires exactly once per threshold per certificate (no duplicate alerts). |
| **Dependencies** | FR-080, FR-013 |

#### FR-082

| Field | Value |
|-------|-------|
| **ID** | FR-082 |
| **Title** | Change Detection Alerting |
| **Description** | The system shall alert on the following certificate change events detected during scanning or agent check-in: certificate replaced (same CN/SAN, different `fingerprint_sha256`), new certificate on a known endpoint, certificate disappeared from a previously known endpoint, algorithm or key size downgrade (e.g., RSA-4096 replaced by RSA-2048), unexpected issuer CA (not in the expected issuer whitelist for that endpoint), self-signed certificate appearing on an endpoint that previously served a CA-issued certificate. Each event generates an audit log entry and optionally sends a notification to the configured owner or global inbox. |
| **Priority** | Should-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin), Sam (CISO) |
| **Acceptance Criteria** | Given a network scan detecting a different certificate on `host:443` compared to the previous scan result (different `fingerprint_sha256`, same hostname), when the scan result is processed, then an alert event `CERTIFICATE_REPLACED` is generated with the old and new fingerprints, and the endpoint's `certificate_fingerprint` FK is updated. |
| **Dependencies** | FR-051, FR-081 |

---

### 3.15 Management Dashboard

#### FR-085

| Field | Value |
|-------|-------|
| **ID** | FR-085 |
| **Title** | Certificate Inventory View |
| **Description** | The dashboard shall provide a paginated certificate inventory view with: sortable columns (common name, expiry date, risk grade, issuer, source), filter panel (all filters from FR-071), quick-view certificate detail (sans opening a new page), bulk actions (assign owner, export CSV), and an "unowned inbox" tab showing certificates without an assigned owner. The inventory view MUST load within 2 seconds for the default unfiltered view against a 100,000-certificate inventory. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin), Sam (CISO) |
| **Acceptance Criteria** | Given a 100,000-certificate inventory, when the inventory page is loaded, then the first page of results renders within 2 seconds. Given an active filter for `grade=F AND expiry_days_max=30`, when applied, then the displayed certificates all match the filter criteria and the result count is shown. |
| **Dependencies** | FR-071 |

#### FR-086

| Field | Value |
|-------|-------|
| **ID** | FR-086 |
| **Title** | CA Hierarchy View |
| **Description** | The dashboard shall display the CA hierarchy as a tree visualization showing root CAs, issuing CAs, and their relationships. Each CA node shows: name, status (active/suspended/revoked), key storage type, expiry date of the CA certificate, number of certificates issued. Selecting a CA node shows the CA certificate details and provides actions: issue certificate, create subordinate CA, revoke CA, view CRL, download CA certificate. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given a root CA with two subordinate issuing CAs, when the CA hierarchy page is loaded, then a tree with 3 nodes is displayed with parent-child edges correct. Given a CA with `status=revoked`, then the CA node is visually distinguished (red border or similar) and no new issuance actions are available. |
| **Dependencies** | FR-001, FR-002 |

#### FR-087

| Field | Value |
|-------|-------|
| **ID** | FR-087 |
| **Title** | Risk Dashboard |
| **Description** | The dashboard shall provide a risk summary page for security leaders showing: total certificate count by grade (A–F) as a bar chart, certificates expiring in 7/14/30/60/90 days as a count and timeline chart, count of unowned certificates, count of certificates with each risk flag, PQC-vulnerable certificate count (RSA or ECDSA), and a filterable table of highest-risk certificates. The risk dashboard is the primary view for CISOs and security leaders. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Sam (CISO), Alex (PKI Admin) |
| **Acceptance Criteria** | Given an inventory with known risk distributions, when the risk dashboard loads, then the grade distribution counts exactly match the inventory state. The risk dashboard MUST load within 3 seconds against a 100,000-certificate inventory. |
| **Dependencies** | FR-076, FR-071 |

#### FR-088

| Field | Value |
|-------|-------|
| **ID** | FR-088 |
| **Title** | Discovery Management |
| **Description** | The dashboard shall provide a discovery management page where operators can: create, schedule, and trigger scan jobs (network, SSH, WinRM, cloud, Kubernetes), view scan job status and progress, view scan job results (certificates discovered, updated, errors), configure agent registration and status. Scan jobs show start time, end time, scan type, target, certificates found, and any errors. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given a running scan job, when the discovery management page is viewed, then the job status shows `running` with a progress percentage (certificates processed vs. expected). Given a completed scan job, when selected, then the results show new vs. updated vs. unchanged certificate counts and any error details. |
| **Dependencies** | FR-050, FR-055 |

#### FR-089

| Field | Value |
|-------|-------|
| **ID** | FR-089 |
| **Title** | Template Management |
| **Description** | The dashboard shall provide a template management page with: template list (name, OID, validity period, revision), template create/edit form with all template fields (FR-020), template detail view showing issued certificate count, and template-level enrollment permission configuration. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given an existing template, when the edit form is submitted with a changed `validity_period`, then the template revision increments and the change is reflected in the template list. |
| **Dependencies** | FR-020 |

---

### 3.16 REST API and Authentication

#### FR-090

| Field | Value |
|-------|-------|
| **ID** | FR-090 |
| **Title** | REST API — Full CRUD for All Resources |
| **Description** | The system shall expose a REST API (JSON over HTTPS) providing full CRUD operations for all platform resources: Certificate Authorities, Certificates, Certificate Templates, Discovery Jobs, Scan Targets, Agents, Notification Rules, Users, RBAC Roles, and API Keys. All API responses MUST conform to the OpenAPI 3.1 specification published at `/api/v1/openapi.yaml`. Pagination: all list endpoints use cursor-based pagination. Error responses: RFC 7807 Problem Details format. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Jordan (Platform Eng), Alex (PKI Admin), Casey (Contributor) |
| **Acceptance Criteria** | Given the OpenAPI spec at `/api/v1/openapi.yaml`, when the spec is validated with `openapi-cli validate`, then zero errors are reported. Given any list endpoint, when queried with `cursor` and `limit` parameters, then the response includes `next_cursor` for the next page and `items` containing at most `limit` items. All error responses MUST include `type`, `title`, and `status` fields per RFC 7807. |
| **Dependencies** | FR-001 through FR-082 |

#### FR-091

| Field | Value |
|-------|-------|
| **ID** | FR-091 |
| **Title** | API Key Authentication |
| **Description** | The system shall support API key authentication for programmatic access. API keys: generated with cryptographically random 32-byte token encoded as base64url, prefixed with `kk_` for identifiability, stored as SHA-256 hash (never the plaintext), associated with a specific RBAC role at creation time, optionally scoped to specific resource types, optionally expiring (with configurable expiry). API keys are presented in the `Authorization: Bearer kk_<token>` header. An API key used in a request is logged to the audit log with the key ID (not the key value). |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Jordan (Platform Eng), Alex (PKI Admin) |
| **Acceptance Criteria** | Given a valid API key in the Authorization header, when an API request is made, then the request is authenticated and the audit log entry for the action contains the API key ID. Given a revoked or expired API key, then the API returns HTTP 401. Private key material MUST NOT appear in API responses under any circumstances (constraint C-Sec03). |
| **Dependencies** | FR-092 (RBAC) |

#### FR-092

| Field | Value |
|-------|-------|
| **ID** | FR-092 |
| **Title** | Role-Based Access Control (RBAC) |
| **Description** | The system shall enforce role-based access control on all API endpoints and dashboard actions. Built-in roles: `pki-admin` (full access), `pki-operator` (issue/revoke/renew, no CA creation), `pki-viewer` (read-only inventory and dashboard), `discovery-operator` (manage scan jobs, read inventory), `service-account` (issue certificates only, scoped by template). Custom roles with configurable permission sets. Role assignment is per-user or per-API-key. All access control decisions are logged to the audit log. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given a principal with role `pki-viewer`, when a request is made to `POST /api/v1/cas` (create CA), then HTTP 403 is returned. Given a principal with role `pki-operator`, when a certificate revocation request is submitted, then the revocation succeeds. Given any access control decision (allow or deny), then an audit log entry is written with actor, action, resource, and decision. |
| **Dependencies** | None |

#### FR-093

| Field | Value |
|-------|-------|
| **ID** | FR-093 |
| **Title** | OIDC Authentication for Dashboard |
| **Description** | The dashboard shall support OIDC (OpenID Connect) for user authentication. Configurable: OIDC discovery URL (`/.well-known/openid-configuration`), client ID and secret, redirect URI, claims-to-role mapping (map OIDC `groups` claim to Kryptkeeper RBAC roles). OIDC is optional — the platform can operate with local user accounts only if no OIDC provider is configured. |
| **Priority** | Should-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given an OIDC provider configured (e.g., Keycloak or Okta), when a user authenticates via the dashboard login flow, then the user is redirected to the OIDC provider, authenticates, and returns to the dashboard with a session mapped to the correct RBAC role per the groups claim mapping. |
| **Dependencies** | FR-092 |

#### FR-094

| Field | Value |
|-------|-------|
| **ID** | FR-094 |
| **Title** | Audit Log |
| **Description** | The system shall maintain an append-only audit log for all state-changing operations. Audit log fields: `id` (UUID), `timestamp` (UTC nanosecond precision), `action` (e.g., `ca.create`, `cert.issue`, `cert.revoke`, `template.update`), `actor` (user ID or API key ID), `resource_type`, `resource_id`, `details` (JSONB — full before/after state for updates). The audit log MUST be append-only: no UPDATE or DELETE operations are permitted on audit records (enforced at the database level via row-level security or a dedicated append-only store). The API provides a paginated read endpoint for audit log queries. |
| **Priority** | Must-have |
| **Version** | V1 |
| **Personas** | Alex (PKI Admin), Sam (CISO) |
| **Acceptance Criteria** | Given any state-changing API operation (create, update, delete, issue, revoke), when the operation completes (success or failure), then an audit log entry is written within the same database transaction. Given a direct SQL UPDATE or DELETE against the `audit_log` table, the operation is rejected by the database-level constraint. The audit log export endpoint returns records in chronological order with full `details` JSONB. |
| **Dependencies** | None |

---

### 3.17 ADCS Replacement — V2

*V2 requirements are included for planning and forward-compatibility design decisions in V1. Implementation is deferred until V1 is shipped and stable.*

#### FR-100

| Field | Value |
|-------|-------|
| **ID** | FR-100 |
| **Title** | MS-XCEP Server — Certificate Enrollment Policy Protocol |
| **Description** | The system shall implement a Microsoft MS-XCEP server (`pki-xcep` Go service) implementing the `GetPolicies` SOAP operation over HTTPS. The server returns the list of certificate templates available for enrollment, in the MS-XCEP response format, including template OIDs, key requirements (`msPKI-Certificate-Name-Flag`, `msPKI-Private-Key-Flag`), and enrollment policies. Templates are sourced from the Kryptkeeper template store (FR-020). The XCEP endpoint URL is configured in Group Policy as the Certificate Enrollment Policy URL. |
| **Priority** | Must-have |
| **Version** | V2 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given a Windows 10 or Windows 11 client with GPO pointing to the XCEP endpoint, when the Windows Certificate Enrollment client queries `GetPolicies`, then the response is a valid MS-XCEP `GetPoliciesResponse` listing the configured templates. Validated against real Windows client using `CertificateServicesClient` event log trace. |
| **Dependencies** | FR-020 |

#### FR-101

| Field | Value |
|-------|-------|
| **ID** | FR-101 |
| **Title** | MS-WSTEP Server — Certificate Enrollment Service |
| **Description** | The system shall implement a Microsoft MS-WSTEP server (`pki-wstep` Go service) implementing the WS-Trust `RequestSecurityToken` SOAP operation over HTTPS. The server accepts a PKCS#10 or PKCS#7 wrapped CSR in a WS-Trust RST envelope, validates it against the requested template, issues a certificate from the Kryptkeeper CA engine, and returns the certificate in a WS-Trust RSTR envelope. Reference implementations: TameMyCerts.WSTEP (C#/.NET) for protocol wire format; cepces `PROTOCOLS.md` for client-side wire format documentation. |
| **Priority** | Must-have |
| **Version** | V2 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given a Windows 10/11 client configured to use the WSTEP endpoint, when the client submits a certificate enrollment request for a configured template, then the client receives a signed certificate issued by the Kryptkeeper CA. The issued certificate appears in the Windows Certificate Store (`Cert:\LocalMachine\My`) without any manual intervention. |
| **Dependencies** | FR-100, FR-005 |

#### FR-102

| Field | Value |
|-------|-------|
| **ID** | FR-102 |
| **Title** | AD LDAP Template Synchronization |
| **Description** | The `pki-adsync` service shall synchronize Kryptkeeper certificate templates to Active Directory's Configuration partition (`CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=...`). Sync operations: create template LDAP objects if absent, update existing objects when template revision changes, set all required `msPKI-*` attributes per MS-CRTD. The sync service MUST detect the AD schema version and set only attributes supported by that schema version. Failing to write an unsupported attribute MUST log a warning and continue — it MUST NOT fail the sync. |
| **Priority** | Must-have |
| **Version** | V2 |
| **Personas** | Alex (PKI Admin) |
| **Acceptance Criteria** | Given a Kryptkeeper template at revision N, when AD sync runs, then the corresponding LDAP object in `CN=Certificate Templates` contains the correct `msPKI-Cert-Template-OID`, `pkiKeyUsage`, `pkiextendedkeyusage`, `pKIExpirationPeriod` (correctly encoded as little-endian negative FILETIME), and `nTSecurityDescriptor`. Given an AD schema at version 2 (Windows XP era), when sync runs for a schema version 4 template, then version-4-only attributes are skipped with a warning. |
| **Dependencies** | FR-020, FR-100 |

---

### 3.18 Full Crypto Management — V3

*V3 requirements define the post-V2 roadmap. They constrain V1 data model design to avoid breaking schema changes.*

#### FR-110

| Field | Value |
|-------|-------|
| **ID** | FR-110 |
| **Title** | SSH Key Inventory |
| **Description** | The system shall discover and inventory SSH public keys across the estate. Discovery sources: SSH `authorized_keys` files (via SSH/agent discovery), known_hosts files, and Git hosting API (GitHub, GitLab — deploy keys). SSH keys are tracked with: fingerprint (SHA-256 of public key), algorithm, key size, host, last seen date, rotation status. Stale key alerts (keys not rotated within a configurable threshold, default: 365 days). |
| **Priority** | Must-have |
| **Version** | V3 |
| **Personas** | Alex (PKI Admin), Sam (CISO) |
| **Acceptance Criteria** | V3 milestone. |
| **Dependencies** | FR-055, FR-060 |

#### FR-111

| Field | Value |
|-------|-------|
| **ID** | FR-111 |
| **Title** | PQC Migration Planning Dashboard |
| **Description** | The system shall provide a post-quantum cryptography migration planning view. The dashboard shows: all RSA and ECDSA certificates flagged as `PQC_VULNERABLE`, grouped by validity period and owner, a migration readiness score (0–100%), a timeline tool for planning cutover to ML-DSA-issued certificates, and a compliance tracker against NSA CNSA 2.0 milestones (2030 deadline). ML-DSA certificate issuance via the CA engine (using FIPS 204 / Go stdlib when available, or Cloudflare CIRCL as bridge). |
| **Priority** | Must-have |
| **Version** | V3 |
| **Personas** | Sam (CISO), Alex (PKI Admin) |
| **Acceptance Criteria** | V3 milestone. |
| **Dependencies** | FR-075, FR-076 |

---

## 4. Non-Functional Requirements

| ID | Category | Requirement | Metric | Version |
|----|----------|-------------|--------|---------|
| NFR-001 | Performance | Certificate issuance latency (CA signing) | < 200ms at P95 for a single-node software key backend | V1 |
| NFR-002 | Performance | Certificate list API response time | < 500ms at P95 for a 100,000-cert inventory with filtering | V1 |
| NFR-003 | Performance | Dashboard initial load time | < 2s for the certificate inventory view on a 100,000-cert inventory | V1 |
| NFR-004 | Performance | Risk dashboard load time | < 3s for the risk summary page on a 100,000-cert inventory | V1 |
| NFR-005 | Performance | Network scan throughput | 10,000 endpoints in < 30 minutes for Phase 2 certificate extraction | V1 |
| NFR-006 | Performance | OCSP response latency | < 500ms at P95 for a cached response | V1 |
| NFR-007 | Performance | Audit log write overhead | < 5ms additional latency added to any API operation by audit logging | V1 |
| NFR-008 | Scalability | Certificate inventory | Support 100,000+ certificates without query degradation below NFR-002 | V1 |
| NFR-009 | Scalability | Concurrent ACME requests | Handle 50 concurrent ACME order flows without error | V1 |
| NFR-010 | Scalability | Agent fleet | Support 1,000 concurrent agent check-ins per minute | V1 |
| NFR-011 | Security | CA private key protection | Root CA key: air-gapped or HSM. Issuing CA key: HSM recommended, software encrypted-at-rest minimum | V1 |
| NFR-012 | Security | Key derivation | Software key encryption uses Argon2id with minimum 64MB memory, 4 iterations | V1 |
| NFR-013 | Security | No private keys in API | Zero API endpoints return private key material. Validated by security audit. | V1 |
| NFR-014 | Security | TLS everywhere | All service-to-service communication and all external endpoints use TLS 1.2 minimum. TLS 1.3 preferred. | V1 |
| NFR-015 | Security | Password hashing | User account passwords hashed with bcrypt, cost factor >= 12 | V1 |
| NFR-016 | Security | Audit log integrity | Audit log is append-only; enforced at database level (row-level security or separate store). No gaps permitted. | V1 |
| NFR-017 | Security | Dependency license compliance | Zero GPL, AGPL, or SSPL dependencies in the core Apache 2.0 distribution. Verified in CI by `go-licenses`. | V1 |
| NFR-018 | Availability | Single-node mode | Platform remains operational during scheduled database maintenance windows with < 30s interruption | V1 |
| NFR-019 | Availability | OCSP SLA | OCSP responder answers queries within 500ms during all maintenance windows (uses pre-cached responses) | V1 |
| NFR-020 | Compatibility | Server platform | Runs on Linux x86_64 and ARM64. Primary CI target: Ubuntu 22.04 LTS. | V1 |
| NFR-021 | Compatibility | Agent platform | Agent binary runs on Linux (x86_64, ARM64), macOS (x86_64, ARM64), Windows (x86_64) | V1 |
| NFR-022 | Compatibility | Browser support | Dashboard works on Chrome 120+, Firefox 120+, Safari 17+, Edge 120+ | V1 |
| NFR-023 | Compatibility | Database | Supports PostgreSQL 14+ for production. Supports SQLite for single-node dev/embedded mode. | V1 |
| NFR-024 | Observability | Structured logging | All services emit structured JSON logs (level, timestamp, service, trace_id, message, fields) | V1 |
| NFR-025 | Observability | Prometheus metrics | All services expose `/metrics` in Prometheus exposition format. Required metrics: request count, error rate, latency histogram (p50, p95, p99), active connections | V1 |
| NFR-026 | Observability | Health endpoints | All services expose `GET /health/live` (liveness) and `GET /health/ready` (readiness) | V1 |
| NFR-027 | Deployment | Docker Compose quickstart | A new operator can deploy a working CA in < 15 minutes using `docker compose up` and the quickstart guide | V1 |
| NFR-028 | Deployment | No internet at startup | Platform starts and serves requests without any external network access | V1 |
| NFR-029 | Deployment | Agent binary size | `pki-agent` compressed binary is < 15MB | V1 |
| NFR-030 | Maintainability | Test coverage | Unit test coverage >= 80% for `pki-core` (CA engine). Integration tests for all enrollment protocol endpoints. | V1 |
| NFR-031 | Maintainability | OpenAPI spec | REST API has a valid OpenAPI 3.1 spec at `/api/v1/openapi.yaml` before any API endpoint ships | V1 |

---

## 5. Interface Requirements

### 5.1 User Interfaces

The web dashboard (TypeScript / React + shadcn/ui) provides:

- **Certificate Inventory** — paginated table with filter panel, bulk actions, CSV export (FR-085)
- **CA Hierarchy** — tree visualization of CAs (FR-086)
- **Risk Dashboard** — grade distribution, expiry timeline, top risks (FR-087)
- **Discovery Management** — scan job CRUD, agent status, scan results (FR-088)
- **Template Management** — template CRUD, permission configuration (FR-089)
- **Certificate Detail** — full certificate metadata, chain view, renewal history, risk flags
- **Alert Configuration** — notification routing, threshold configuration
- **User Management** — RBAC roles, API keys, OIDC configuration
- **Audit Log Viewer** — searchable, filterable audit log

All dashboard pages MUST comply with WCAG 2.1 AA accessibility standards.

### 5.2 API Interfaces

The REST API (Go, served by `pki-api`) exposes the following resource groups:

| Resource Group | Base Path | Key Operations |
|----------------|-----------|---------------|
| Certificate Authorities | `/api/v1/cas` | CRUD, generate CSR, import |
| Certificates | `/api/v1/certificates` | List, get, revoke, renew, assign owner |
| Templates | `/api/v1/templates` | CRUD, list issued |
| ACME | `/acme/{provisioner}` | RFC 8555 standard endpoints |
| EST | `/est/{provisioner}` | RFC 7030 `/cacerts`, `/simpleenroll`, `/simplereenroll` |
| SCEP | `/scep/{provisioner}` | `GetCACert`, `PKIOperation` |
| OCSP | `/ocsp` | HTTP GET + POST (RFC 5019) |
| CRL | `/crl/{ca-id}/crl.{pem,der}` | HTTP GET |
| Discovery | `/api/v1/discovery/jobs` | CRUD scan jobs |
| Scan Targets | `/api/v1/discovery/targets` | CRUD |
| Agents | `/api/v1/agents` | List, get, register, revoke |
| Risk | `/api/v1/risk` | Inventory summary, grade distribution |
| Alerts | `/api/v1/alerts/rules` | CRUD notification rules |
| Users | `/api/v1/users` | CRUD |
| Roles | `/api/v1/roles` | CRUD |
| API Keys | `/api/v1/apikeys` | Create, list, revoke |
| Audit Log | `/api/v1/audit` | List (paginated, filterable) |

All endpoints require authentication (API key or session token). All responses are `application/json`. All HTTPS on TLS 1.2+.

### 5.3 Data Interfaces

**PostgreSQL (primary):**
Core tables from RESEARCH_FINDINGS.md §3 data model:
- `certificates` — `fingerprint_sha256` PK, full X.509 metadata, risk scoring, renewal chain
- `certificate_authorities` — CA hierarchy, key storage type, status
- `certificate_templates` — ADCS-compatible template model with enrollment permissions
- `endpoints` — `(ip, port, sni_name)` tuples linked to certificates
- `scan_jobs` — discovery job state and results
- `audit_log` — append-only, partitioned by month

**SQLite (dev/embedded):**
Same schema as PostgreSQL via the repository pattern interface (C-Tech04). SQLite-specific SQL MUST NOT appear in business logic.

**External interfaces:**
- Slack: Incoming webhooks (`POST` JSON payload)
- PagerDuty: Events API v2
- Email: SMTP with TLS (STARTTLS minimum)
- AWS ACM: `acm:ListCertificates`, `acm:DescribeCertificate`
- Azure Key Vault: Certificate client SDK
- GCP Certificate Manager: REST API
- Kubernetes: `k8s.io/client-go` with kubeconfig or in-cluster service account
- HashiCorp Vault: KV secrets engine v2 (master key storage for envelope encryption)

---

## 6. Traceability Matrix

| Requirement | Feature Area | Service | Test |
|-------------|-------------|---------|------|
| FR-001 | CA Engine | `pki-core` | `tests/ca/root_create_test.go` |
| FR-002 | CA Engine | `pki-core` | `tests/ca/issuing_create_test.go` |
| FR-003 | Key Storage | `pki-core` | `tests/ca/key_storage_software_test.go` |
| FR-004 | Key Storage | `pki-core` | `tests/ca/key_storage_pkcs11_test.go` |
| FR-005 | CA Engine | `pki-core` | `tests/ca/csr_sign_test.go` |
| FR-006 | CA Engine | `pki-core` | `tests/ca/external_ca_import_test.go` |
| FR-010 | Lifecycle | `pki-core` | `tests/lifecycle/issue_test.go` |
| FR-011 | Lifecycle | `pki-core` | `tests/lifecycle/renewal_test.go` |
| FR-012 | Lifecycle | `pki-core` | `tests/lifecycle/revoke_test.go` |
| FR-013 | Lifecycle | `pki-core` | `tests/lifecycle/expiry_monitor_test.go` |
| FR-014 | Lifecycle | `pki-core` | `tests/lifecycle/renewal_chain_test.go` |
| FR-020 | Templates | `pki-core` | `tests/templates/crud_test.go` |
| FR-021 | Templates | `pki-core` | `tests/templates/policy_enforcement_test.go` |
| FR-022 | Templates | `pki-api` | `tests/templates/enrollment_permissions_test.go` |
| FR-023 | Templates | `pki-core` | `tests/templates/versioning_test.go` |
| FR-030 | ACME | `pki-acme` | `tests/acme/rfc8555_compliance_test.go` |
| FR-031 | ACME | `pki-acme` | `tests/acme/http01_test.go` |
| FR-032 | ACME | `pki-acme` | `tests/acme/dns01_test.go` |
| FR-033 | ACME | `pki-acme` | `tests/acme/tls_alpn01_test.go` |
| FR-034 | ACME | `pki-acme` | `tests/acme/provisioner_test.go` |
| FR-040 | OCSP | `pki-ocsp` | `tests/ocsp/rfc5019_test.go` |
| FR-041 | OCSP | `pki-ocsp` | `tests/ocsp/signing_cert_test.go` |
| FR-042 | CRL | `pki-core` | `tests/crl/generation_test.go` |
| FR-043 | CRL | `pki-core` | `tests/crl/distribution_test.go` |
| FR-044 | EST | `pki-est` | `tests/est/rfc7030_test.go` |
| FR-045 | SCEP | `pki-scep` | `tests/scep/enrollment_test.go` |
| FR-050 | Discovery | `pki-discovery` | `tests/discovery/network_scan_test.go` |
| FR-051 | Discovery | `pki-discovery` | `tests/discovery/cert_extract_test.go` |
| FR-052 | Discovery | `pki-discovery` | `tests/discovery/ct_log_test.go` |
| FR-055 | Discovery | `pki-discovery` | `tests/discovery/ssh_test.go` |
| FR-056 | Discovery | `pki-discovery` | `tests/discovery/winrm_test.go` |
| FR-057 | Discovery | `pki-discovery` | `tests/discovery/cloud_api_test.go` |
| FR-058 | Discovery | `pki-discovery` | `tests/discovery/kubernetes_test.go` |
| FR-060 | Agent | `pki-agent` | `tests/agent/binary_size_test.go` |
| FR-061 | Agent | `pki-agent` | `tests/agent/polling_test.go` |
| FR-062 | Agent | `pki-agent` | `tests/agent/inotify_test.go` |
| FR-063 | Agent | `pki-agent` | `tests/agent/autoupdate_test.go` (descoped, D-128) |
| FR-070 | Inventory | `pki-core` | `tests/inventory/dedup_test.go` |
| FR-071 | Inventory | `pki-api` | `tests/inventory/filter_test.go` |
| FR-072 | Inventory | `pki-core` | `tests/inventory/chain_validation_test.go` |
| FR-075 | Risk | `pki-core` | `tests/risk/scoring_test.go` |
| FR-076 | Risk | `pki-core` | `tests/risk/grades_test.go` |
| FR-080 | Alerting | `pki-core` | `tests/alerting/ownership_test.go` |
| FR-081 | Alerting | `pki-core` | `tests/alerting/expiry_alerts_test.go` |
| FR-082 | Alerting | `pki-core` | `tests/alerting/change_detection_test.go` |
| FR-085–089 | Dashboard | `pki-dashboard` | `tests/e2e/dashboard_test.ts` |
| FR-090 | API | `pki-api` | `tests/api/openapi_validation_test.go` |
| FR-091 | API | `pki-api` | `tests/api/api_key_auth_test.go` |
| FR-092 | API | `pki-api` | `tests/api/rbac_test.go` |
| FR-093 | API | `pki-api` | `tests/api/oidc_test.go` |
| FR-094 | API | `pki-api` | `tests/api/audit_log_test.go` |
| FR-100–102 | ADCS (V2) | `pki-xcep`, `pki-wstep`, `pki-adsync` | `tests/v2/xcep_test.go`, `wstep_test.go`, `adsync_test.go` |
| NFR-001 | Performance | `pki-core` | `tests/perf/issuance_latency_bench_test.go` |
| NFR-002 | Performance | `pki-api` | `tests/perf/list_query_bench_test.go` |
| NFR-029 | Deployment | `pki-agent` | `ci/agent_size_check.sh` |
