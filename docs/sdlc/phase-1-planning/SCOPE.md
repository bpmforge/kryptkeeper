# Kryptkeeper — Scope Definition

**Version:** 1.0
**Date:** 2026-04-05
**Phase:** 1 — Planning

---

## 1. MVP Boundary (V1)

V1 is a functional, production-deployable PKI platform. It is not a feature-complete
enterprise product. The MVP boundary is defined by what an organization needs to replace
their current CA and stop flying blind on certificate expiry.

### V1 — In Scope

**Certificate Authority Engine**
- Root CA creation with offline/air-gapped key ceremony support
- Intermediate (issuing) CA creation, subordinate to root
- External CA import (for organizations with an existing root CA)
- Certificate issuance from CSR
- Certificate revocation (CRL + OCSP)
- CRL generation and distribution

**Enrollment Protocols**
- ACME (RFC 8555): HTTP-01, DNS-01, TLS-ALPN-01 challenges
- EST (RFC 7030): enterprise enrollment
- SCEP: network device enrollment (F5, Citrix, Palo Alto)
- OCSP responder (RFC 5019): free in OSS — this is a direct competitor differentiator

**Certificate Templates**
- Template definition: key usage, EKU, validity period, key size constraints
- Template-based issuance (operator selects template, platform enforces policy)
- Template versioning (schema-version tracking for future ADCS compatibility)

**Certificate Lifecycle Management**
- Expiry monitoring with configurable alert thresholds (90/60/30/14/7 days)
- Auto-renewal via ACME for ACME-enrolled certificates
- Renewal history and predecessor/successor chain tracking
- Risk scoring (0–100) with letter grades (A–F) per the defined flag/weight model

**Certificate Discovery**
- Network scanning: masscan port detection + Go TLS handshake for cert extraction
- Agentless SSH: Linux hosts, find + parse cert files and web server configs
- Agentless WinRM: Windows hosts, PowerShell cert store enumeration
- Lightweight Go agent: deployed on hosts, HTTPS polling, inotify/FSEvents real-time detection
- Certificate Transparency log monitoring (crt.sh API for public cert detection)

**Platform Integration (V1)**
- Kubernetes: cert-manager CRD monitoring, TLS Secrets, Ingress resources
- Cloud (basic): AWS ACM, Azure Key Vault, GCP Certificate Manager (read-only inventory)

**Management Dashboard**
- Certificate inventory view with filtering, sorting, search
- CA hierarchy visualization
- Discovery scan management (schedule, trigger, view results)
- Risk dashboard: expiring soon, high-risk certs, unowned certs
- Alert configuration and notification routing (Slack, email, PagerDuty)
- User management with RBAC

**API and Integrations**
- REST API for all platform operations
- API key authentication + OIDC for dashboard SSO

**Key Storage**
- Layer 1: Encrypted PKCS#8 PEM on disk (Argon2id KDF) — dev and single-node prod
- Layer 2: Envelope encryption (AES-256-GCM data key + Vault/KMS master key) — production
- Layer 3: PKCS#11 HSM via ThalesGroup/crypto11 — enterprise hardware
- All signing through `crypto.Signer` interface (Layer 4 cloud KMS is V1 design, V2 full support)

**Deployment**
- Docker Compose (single-node, PostgreSQL bundled)
- Kubernetes Helm chart
- SQLite mode for single-user / development deployments

---

### V1 — Out of Scope

**ADCS Replacement (V2)**
- MS-XCEP server (Certificate Enrollment Policy Protocol)
- MS-WSTEP server (WS-Trust Certificate Enrollment Service)
- Active Directory LDAP template synchronization
- Windows auto-enrollment via GPO

**Full Crypto Management (V3)**
- SSH key inventory and lifecycle management
- Code-signing certificate tracking
- Cipher suite auditing (TLS configuration scoring beyond cert metadata)
- PQC migration planning dashboard and ML-DSA issuance
- CMP (RFC 4210) certificate management protocol

**Enterprise Commercial Features (deferred)**
- FIPS 140-2/3 validated mode
- Multi-tenancy (multiple isolated organizations in one deployment)
- Advanced ADCS integration beyond V2 baseline
- Commercial SLA and support tooling

**Not In Scope (Ever)**
- General-purpose secrets management (Vault's domain)
- Certificate reselling or managed CA service
- General-purpose SIEM or security monitoring
- Windows-only or Windows-server-required deployment

---

## 2. V2 Scope (ADCS Replacement)

V2 ships when the Windows auto-enrollment story is complete and tested against real
Windows 10/11 and Server 2019/2022 environments.

**In Scope for V2:**
- MS-XCEP server (`pki-xcep` Go service, SOAP/HTTPS, `GetPolicies` operation)
- MS-WSTEP server (`pki-wstep` Go service, WS-Trust `RequestSecurityToken`)
- AD LDAP sync (`pki-adsync` Go service): write/update template objects in AD Configuration partition
- AD enrollment service registration (`pKIEnrollmentService` object)
- V1 template engine extended with ADCS attribute mapping (msPKI-* attributes)
- GPO configuration documentation and validation tooling
- PQC vulnerability flag in certificate inventory (ML-DSA readiness scoring)
- Cloud KMS signing backend (Layer 4): AWS KMS, GCP, Azure Key Vault

---

## 3. V3 Scope (Full Crypto Management)

V3 ships when V2 is stable in production and commercial adoption validates investment.

**In Scope for V3:**
- SSH key inventory: detect, inventory, track rotation, alert on stale keys
- Code-signing certificate tracking and policy enforcement
- Cipher suite auditing: endpoint TLS configuration scoring (not just cert metadata)
- PQC migration planning: identify vulnerable certs, generate migration roadmap
- ML-DSA certificate issuance (via Go stdlib when available, ~Go 1.26)
- Full PQC migration dashboard
- CMP (RFC 4210) protocol support

---

## 4. Service Inventory

| Service | V1 | V2 | V3 | Language |
|---------|----|----|----|----|
| `pki-core` | Required | — | — | Go |
| `pki-acme` | Required | — | — | Go |
| `pki-ocsp` | Required | — | — | Go |
| `pki-est` | Required | — | — | Go |
| `pki-scep` | Required | — | — | Go |
| `pki-api` | Required | — | — | Go |
| `pki-discovery` | Required | — | — | Go |
| `pki-agent` | Required | — | — | Go |
| `pki-dashboard` | Required | — | — | TypeScript |
| `pki-xcep` | — | Required | — | Go |
| `pki-wstep` | — | Required | — | Go |
| `pki-adsync` | — | Required | — | Go |

---

## 5. What Done Looks Like for V1

V1 is complete when:

1. A security engineer can create a root CA, create an issuing CA beneath it, and issue
   a certificate from a CSR — all without touching a Windows server.
2. An ACME client (certbot, acme.sh) can obtain and auto-renew a certificate.
3. An OCSP client can verify certificate revocation status.
4. A network scan discovers all TLS endpoints in a /24 network in under 30 minutes.
5. The dashboard shows all discovered certificates with expiry dates, risk scores, and owners.
6. An alert fires (Slack or email) when a certificate is within 30 days of expiry.
7. The platform is deployable via Docker Compose with a single `docker compose up`.
8. The REST API is documented (OpenAPI spec) and usable by a third-party client.
