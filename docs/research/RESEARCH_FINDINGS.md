# PKI Platform — Deep Research Findings

**Date:** 2026-04-05
**Scope:** Feasibility and architecture research for an enterprise PKI & Crypto Management Platform

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Product Vision & Versioning](#product-vision)
3. [Technology Stack Decision](#technology-stack)
4. [CA Engine Architecture](#ca-engine)
5. [ADCS Replacement Strategy](#adcs-replacement)
6. [Certificate Discovery & Scanning](#discovery-scanning)
7. [Data Model](#data-model)
8. [Competitive Landscape](#competitive-landscape)
9. [Post-Quantum Readiness](#pqc)
10. [Recommended Architecture](#recommended-architecture)
11. [Risk Register](#risks)
12. [References](#references)

---

## 1. Executive Summary <a name="executive-summary"></a>

This document presents findings from three parallel deep research streams investigating the feasibility of building an enterprise PKI and Certificate Management platform that can:

- Act as a full Certificate Authority (root + issuing CAs)
- Manage certificate lifecycle with template-based issuance
- Discover and inventory all certificates and encryption across an enterprise
- Replace Microsoft ADCS without requiring a Windows CA server
- Support agent and agentless management
- Prepare for post-quantum cryptography migration

**Key findings:**

| Area | Finding | Confidence |
|------|---------|------------|
| **Tech Stack** | Go for CA core, TypeScript for dashboard, PostgreSQL for storage | High |
| **License** | Apache 2.0 core + proprietary enterprise tier | High |
| **ADCS Replacement** | MS-XCEP + MS-WSTEP (HTTP/SOAP) is the viable path — no DCOM needed | High |
| **ADCS Feasibility** | 3-6 months engineering for production-quality XCEP/WSTEP server | Medium |
| **Discovery** | Two-phase scan (masscan port detect + sslyze cert extract) at scale | High |
| **PQC** | ML-DSA/ML-KEM standards finalized; Go support via Cloudflare CIRCL until Go 1.26 | High |
| **Differentiation** | First open-source CA with native ADCS replacement + modern UX + PQC-ready | High |

---

## 2. Product Vision & Versioning <a name="product-vision"></a>

### Release Plan

| Version | Focus | Core Capabilities |
|---------|-------|-------------------|
| **V1** | CA + Management | CA engine (root/issuing), cert lifecycle, templates, discovery scanning, dashboard, ACME/OCSP/CRL |
| **V2** | ADCS Integration | MS-XCEP + MS-WSTEP server, AD template sync, Windows auto-enrollment without ADCS |
| **V3** | Full Crypto Mgmt | SSH key inventory, code-signing tracking, cipher suite auditing, PQC migration planning |

### Name: **Kryptkeeper**

- Tagline: *"Guard your cryptographic trust"*
- CLI: `kryptkeeper` (alias: `kk`)
- Covers full scope: PKI, key management, crypto inventory, PQC migration

---

## 3. Technology Stack Decision <a name="technology-stack"></a>

### Definitive Stack

| Component | Choice | Rationale |
|-----------|--------|-----------|
| **CA Core Language** | Go | Every successful modern CA uses Go (step-ca, Boulder, cfssl). `crypto/x509` stdlib is battle-tested. Single static binary deployment. |
| **Dashboard/API** | TypeScript / React + shadcn/ui | Right tool for UI layer. Separate service from CA core. shadcn for consistent, accessible components. |
| **Database** | PostgreSQL (primary) + SQLite (dev/embedded) | Concurrent writes, HA, full SQL analytics. SQLite for single-node dev. |
| **Crypto Core** | `crypto/x509` (stdlib) | No third-party dependency for core X.509 operations |
| **HSM Interface** | `ThalesGroup/crypto11` | Implements `crypto.Signer` — vendor-neutral PKCS#11 |
| **ACME Server** | Custom implementation per RFC 8555 | Study step-ca's Apache 2.0 implementation as reference |
| **OCSP** | `golang.org/x/crypto/ocsp` | RFC 5019 lightweight profile with pre-signed caching |
| **PQC (near-term)** | Cloudflare CIRCL for ML-DSA | Until Go stdlib adds ML-DSA (~Go 1.26) |
| **License** | Apache 2.0 | Maximum enterprise adoption. Patent grant included. |
| **Agent** | Go (single static binary, <15MB) | HTTPS polling + inotify/FSEvents for real-time detection |

### Why Go Over Rust or Node

| Criteria | Go | Rust | Node/TS |
|----------|-----|------|---------|
| PKI ecosystem | Excellent (stdlib) | Good but fragmented | Limited |
| Production CAs using it | step-ca, Boulder, cfssl | None of note | None |
| Deployment | Single static binary | Static binary, complex build | Runtime dependency |
| Crypto stdlib | Complete X.509 lifecycle | Requires multiple crates | Depends on node-forge (unaudited) |
| Developer pool | Large | Growing | Large but wrong domain |
| **Verdict** | **Recommended** | Future modules (OCSP) | Dashboard only |

### Why Apache 2.0

- **Patent grant** — Enterprise legal teams require this. MIT/BSD lack it.
- **No copyleft** — Companies can integrate without open-sourcing their code.
- **Precedent** — step-ca, cfssl, XiPKI, Kubernetes all use Apache 2.0.
- **AGPL kills adoption** — Enterprise legal routinely blocks AGPL dependencies.
- **Commercial model**: Apache 2.0 core (free) + proprietary enterprise add-ons (FIPS validation, multi-tenancy, advanced ADCS integration, SLA/support).

### Database Schema (Core Tables)

```sql
-- Certificate inventory
certificates (
  fingerprint_sha256 PRIMARY KEY,
  serial_number, subject_dn, common_name,
  issuer_dn, issuer_cn, ca_id FK,
  valid_from, valid_until,
  public_key_algorithm, key_size_bits, signature_algorithm,
  extended_key_usage[], subject_alt_names[],
  chain_complete, chain_trusted,
  risk_score, risk_flags[],
  pqc_vulnerable BOOL,
  renewal_method, renewal_status,
  created_at, updated_at
)

-- Certificate templates (ADCS-compatible concepts)
certificate_templates (
  id, name, display_name, oid,
  key_usage, extended_key_usage[],
  min_key_size, allowed_algorithms[],
  validity_period, renewal_overlap,
  subject_requirements JSONB,
  enrollment_permissions JSONB,
  issuance_requirements JSONB,
  auto_enroll BOOL,
  schema_version, revision
)

-- Discovery endpoints
endpoints (
  id, ip_address, hostname, port, protocol,
  tls_versions[], cipher_suites[],
  certificate_fingerprint FK,
  sni_name, is_default_cert,
  last_scanned, scan_job_id FK
)

-- CA hierarchy
certificate_authorities (
  id, name, type ENUM('root','issuing','external'),
  certificate_fingerprint FK,
  parent_ca_id FK (self-ref),
  key_storage_type ENUM('software','pkcs11','cloud_kms'),
  status ENUM('active','suspended','revoked')
)

-- Audit log (append-only, partitioned by month)
audit_log (
  id, timestamp, action, actor,
  resource_type, resource_id,
  details JSONB
)

-- Scan jobs
scan_jobs (
  id, type ENUM('network','ssh','winrm','cloud','k8s'),
  status, started_at, completed_at,
  scope JSONB, results_summary JSONB
)
```

---

## 4. CA Engine Architecture <a name="ca-engine"></a>

### Key Hierarchy

```
Root CA Key (offline — air-gapped ceremony, HSM or encrypted cold storage)
  └── Intermediate/Issuing CA Key (online — HSM or encrypted software key)
       └── End-Entity Certificates (user-generated CSRs, ACME, templates)
```

### Key Storage Layers (Progressive)

| Layer | Method | Use Case |
|-------|--------|----------|
| 1 | Encrypted PKCS#8 PEM on disk (Argon2id KDF) | Dev / single-node |
| 2 | Envelope encryption: AES-256-GCM data key, master key in Vault/KMS | Production software |
| 3 | PKCS#11 HSM via `crypto11` (`crypto.Signer` interface) | Enterprise hardware |
| 4 | Cloud KMS (AWS KMS, GCP, Azure Key Vault) via Go SDKs | Cloud deployments |

The `crypto.Signer` interface is the critical abstraction — all signing code calls `Sign()` on the interface. The underlying implementation can be software, PKCS#11, or cloud KMS without changing CA logic.

### Protocols to Support

| Protocol | Purpose | Priority |
|----------|---------|----------|
| **ACME** (RFC 8555) | Automated cert issuance/renewal | V1 — table stakes |
| **OCSP** (RFC 5019) | Real-time revocation checking | V1 — differentiator vs step-ca OSS |
| **CRL** (RFC 5280) | Revocation lists | V1 |
| **EST** (RFC 7030) | Enterprise enrollment | V1 |
| **SCEP** | Network device enrollment (F5, Citrix, Palo Alto) | V1 |
| **MS-XCEP** | Windows certificate enrollment policy | V2 |
| **MS-WSTEP** | Windows certificate enrollment service | V2 |
| **CMP** (RFC 4210) | Certificate management protocol | V3 |

### ACME Design Notes

- Support HTTP-01, DNS-01, TLS-ALPN-01 challenges
- DNS-01 required for wildcards and internal hostnames
- **Scoped provisioners** — restrict which domains/hostnames ACME can issue for (differentiator vs Boulder)
- Multiple provisioner types: ACME, OIDC, JWT, cloud identity (study step-ca's model)

### OCSP Design Notes

- Pre-sign OCSP responses for caching (stapling-friendly)
- HTTP GET + caching headers per RFC 5019 lightweight profile
- Dedicated OCSP signing certificate with `OCSPSigning` EKU
- Study XiPKI's caching architecture (most performant open-source OCSP)

---

## 5. ADCS Replacement Strategy <a name="adcs-replacement"></a>

### The Core Insight

Windows certificate auto-enrollment has TWO protocol paths:

1. **DCOM/RPC (MS-WCCE + MS-ICPR)** — Legacy. Requires Windows CA server. No Linux server implementation exists. 6-18 months to build. **NOT recommended.**
2. **HTTP/SOAP (MS-XCEP + MS-WSTEP)** — Modern. Group Policy can point Windows clients at HTTPS URLs instead of LDAP. Well-documented SOAP protocols. TameMyCerts.WSTEP proves server-side is feasible. **THIS IS THE PATH.**

When GPO points to an `HTTPS://` CEP URL, Windows clients use XCEP + WSTEP instead of DCOM. No Windows CA server needed.

### Protocol Details

**MS-XCEP (Certificate Enrollment Policy Protocol):**
- Single SOAP operation: `GetPolicies`
- Returns list of certificate templates the client can enroll for
- Includes template OIDs, key requirements, enrollment policies
- Simple enough to implement in 1-2 weeks

**MS-WSTEP (WS-Trust X.509 Enrollment Extensions):**
- SOAP/HTTPS service accepting CSRs wrapped in WS-Trust `RequestSecurityToken`
- Returns issued certificates in `RequestSecurityTokenResponse`
- More complex (WS-Trust profile) but well-specified
- cepces `PROTOCOLS.md` documents wire format thoroughly

### What Must Be Done for Windows Auto-Enrollment

1. **Implement MS-XCEP server** — Returns template policies over SOAP/HTTPS
2. **Implement MS-WSTEP server** — Accepts CSR enrollment requests, issues certs from our CA
3. **Write template objects into AD** — Non-negotiable. Windows auto-enrollment queries AD's Configuration partition (`CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration`) via LDAP. Templates MUST exist in AD for GPO-triggered enrollment.
4. **Register enrollment service in AD** — `pKIEnrollmentService` objects in Configuration partition
5. **Configure GPO** — Point `Certificate Enrollment Policy` to our HTTPS CEP URL

### GPO Configuration

```
Computer Configuration
  → Windows Settings
    → Security Settings
      → Public Key Policies
        → Certificate Services Client – Certificate Enrollment Policy
          URI: https://your-linux-ca.example.com/cep
```

Registry: `HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment\`

### Template System Design

ADCS templates are AD LDAP objects with these critical attributes (from MS-CRTD):

| Attribute | Purpose |
|-----------|---------|
| `cn` | Template display name |
| `msPKI-Cert-Template-OID` | Unique OID |
| `msPKI-Certificate-Name-Flag` | Subject name source (user-supplied SAN, etc.) |
| `msPKI-Enrollment-Flag` | Auto-enrollment behavior |
| `msPKI-Private-Key-Flag` | Key exportability, CSP requirements |
| `pkiextendedkeyusage` | EKU OIDs |
| `pkiKeyUsage` | Key usage bits |
| `pKIExpirationPeriod` | Validity period |
| `pKIKeySize` | Minimum key size |
| `nTSecurityDescriptor` | ACL — who can Enroll/AutoEnroll |
| `msPKI-Template-Schema-Version` | 1=Win2000, 2=XP, 3=2008, 4=2012+ |

**Our system needs:**
- Internal template engine mirroring these concepts
- LDAP sync to write/update template objects in AD's Configuration partition
- CEP server that reads our templates and returns them in MS-XCEP format
- CES server that enforces template policies when issuing

### Existing Reference Implementations

| Project | What It Does | Use As |
|---------|-------------|--------|
| **TameMyCerts.WSTEP** | C#/.NET server-side MS-WSTEP | Primary reference for protocol implementation |
| **cepces** (openSUSE) | Python client-side XCEP+WSTEP | Wire format documentation (`PROTOCOLS.md`) |
| **EJBCA Enterprise** | Production MSAE (XCEP+WSTEP) | Correctness reference (enterprise-only feature) |
| **Secardeo certEP** | Commercial XCEP+WSTEP proxy | Architecture reference |
| **acme2certifier** | ACME → ADCS bridge via MS-WCCE client | Shows RPC client approach (not needed for our path) |

### V2 Implementation Plan (High-Level)

1. Study TameMyCerts.WSTEP source code — port XCEP/WSTEP logic to Go
2. Study cepces `PROTOCOLS.md` for wire format details
3. Build MS-XCEP endpoint (Go, SOAP/HTTPS)
4. Build MS-WSTEP endpoint (Go, SOAP/HTTPS, backed by our CA engine)
5. Build AD LDAP sync for template objects
6. Build AD enrollment service registration
7. Test against Windows 10/11 with debug logging (`CertificateServicesClient` event log)
8. Validate with Wireshark packet capture of real XCEP/WSTEP traffic

### Important Caveats

- MS-CRTD and MS-WCCE specs have **known documentation errors** — implementation requires behavioral testing against real Windows clients
- Template `pKIExpirationPeriod` is stored as little-endian negative FILETIME — non-obvious encoding
- `IF_ENFORCEENCRYPTICERTREQUEST` flag on Windows 2012+ requires encrypted RPC (DCOM path only — not relevant for XCEP/WSTEP)
- EJBCA CE source should be inspected to determine if any MSAE code is available in the community edition

---

## 6. Certificate Discovery & Scanning <a name="discovery-scanning"></a>

### Architecture: Three Pillars

```
┌─────────────────────────────────────────────────────────┐
│                   Discovery Engine                       │
├──────────────┬──────────────────┬────────────────────────┤
│ Network Scan │ Host Discovery   │ Platform Integration   │
│              │                  │                        │
│ Phase 1:     │ Agentless:       │ Cloud APIs:            │
│  masscan     │  SSH (Linux)     │  AWS ACM               │
│  (port detect)│  WinRM (Windows)│  Azure Key Vault       │
│              │                  │  GCP Cert Manager      │
│ Phase 2:     │ Agent:           │                        │
│  sslyze/Go   │  Go binary       │ Kubernetes:            │
│  (cert extract)│ <15MB, inotify │  cert-manager CRDs     │
│              │  HTTPS polling   │  TLS Secrets           │
│ CT Logs:     │                  │  Ingress resources     │
│  crt.sh API  │                  │                        │
│  (real-time) │                  │ Load Balancers:        │
│              │                  │  F5 iControl REST      │
│              │                  │  Citrix NITRO API      │
└──────────────┴──────────────────┴────────────────────────┘
```

### Network Scanning at Scale

**Phase 1 — Port Discovery (masscan):**
- Scan target IP ranges on known TLS ports (443, 8443, 636, 993, 995, 6443, 10250, etc.)
- Conservative rate: 10,000-50,000 pps to avoid IDS triggers
- masscan for port-open detection only (its TLS handshake is limited)

**Phase 2 — Certificate Extraction:**
- Feed confirmed IP:port list to sslyze or custom Go TLS scanner
- Worker pool of 200-500 concurrent TLS handshakes
- 10,000 endpoints in under 30 minutes from single scan host
- Extract: leaf cert, full chain, cipher suites, protocol versions

**SNI-Aware Scanning:**
- Initial scan without SNI → default cert
- Cross-reference DNS/hostname data for candidate hostnames per IP
- Re-scan with each hostname in SNI extension
- Requires DNS dataset (passive enumeration, CT logs, or CMDB import)

### Agentless Discovery

**SSH (Linux):**
- Key-based auth (credentials stored in vault)
- Find PEM/DER/PFX/JKS files: `find / -name "*.pem" -o -name "*.crt" ...`
- Parse web server configs: nginx `ssl_certificate`, Apache `SSLCertificateFile`, Tomcat `keystoreFile`
- `openssl x509 -noout -text` for metadata extraction
- Exclude `/dev`, `/proc`

**WinRM (Windows):**
- Port 5985 (HTTP) or 5986 (HTTPS)
- `Get-ChildItem Cert:\LocalMachine\My` — enumerate cert stores
- `Get-WebBinding` — IIS HTTPS bindings
- File system scan for .pfx, .cer, .p12, .pem

### Agent Architecture

| Aspect | Design |
|--------|--------|
| Binary | Single Go static binary, <15MB |
| Mode | Read-only discovery by default; write mode (install/rotate) requires elevated trust |
| Communication | HTTPS polling (15 min default, configurable to 1 min) |
| Real-time | inotify (Linux) / FSEvents (macOS) for cert file change detection |
| Optional | gRPC streaming for near-real-time environments |
| Config | YAML — scan paths, cert stores, process inspection scope |
| Update | Signed manifest (SHA-256 + Ed25519), auto-download, verify, replace, restart |
| Delta | Local cache of last inventory; only transmit changes |

### Scan Scheduling

| Environment | Network Scan | Agent Check-in |
|-------------|-------------|----------------|
| Stable internal | Weekly full + daily delta | 15 min |
| Cloud/container | Every 4-6 hours | 5 min or event-driven |
| Internet-facing | Daily | N/A |
| Post-deployment | CI/CD webhook trigger | Event-triggered |

**Note:** CA/Browser Forum Ballot SC-081 mandates TLS lifetimes of 200 days (March 2026), 100 days (March 2027), 47 days (March 2029). Daily scanning becomes mandatory as lifetimes shrink.

### Change Detection & Alerting

Alert-worthy events:
- Certificate replaced (thumbprint changed, same CN/SAN)
- New certificate on known endpoint
- Certificate disappeared from endpoint
- Expiry within threshold (90/60/30/14/7 days — configurable multi-tier)
- Algorithm or key size downgrade
- Unexpected CA (policy violation)
- Self-signed where CA-issued expected

Alert routing: by ownership metadata (team → Slack/email/PagerDuty), not global inbox.

---

## 7. Data Model <a name="data-model"></a>

### Core Entities

```
Certificate (fingerprint_sha256 = dedup key)
  ├── 1:N → Endpoint (same cert on multiple hosts)
  ├── N:1 → CertificateAuthority (issuer)
  ├── N:1 → CertificateTemplate (if template-issued)
  ├── 1:N → AuditLog entries
  └── 1:1 → predecessor/successor (renewal chain)

Endpoint
  ├── IP, hostname, port, protocol
  ├── TLS versions, cipher suites (endpoint-level, not cert-level)
  └── SNI name, scan metadata

CertificateAuthority
  ├── Root → Issuing hierarchy (self-referential FK)
  ├── Key storage type
  └── Status (active/suspended/revoked)

CertificateTemplate
  ├── Key usage, EKU, validity, enrollment permissions
  ├── Schema version (ADCS-compatible concepts)
  └── AD sync status (for V2 ADCS integration)
```

### Risk Scoring (0-100)

| Flag | Weight | Rationale |
|------|--------|-----------|
| EXPIRED | +40 | Immediate impact |
| EXPIRING_7_DAYS | +35 | High urgency |
| EXPIRING_30_DAYS | +20 | Action required |
| WEAK_KEY (RSA<2048) | +30 | Cryptographically weak |
| SELF_SIGNED | +25 | No external validation |
| SHA1_SIGNATURE | +25 | Deprecated |
| UNTRUSTED_ROOT | +15 | Potential MITM |
| TLS_OLD (SSLv3/1.0/1.1) | +15 | Protocol weakness |
| NULL/EXPORT_CIPHER | +20 | Critical cipher weakness |
| CHAIN_INCOMPLETE | +10 | Client failures |
| WILDCARD | +5 | Overly broad scope |
| PQC_VULNERABLE | +5 | Forward-looking |

Grades: A (0-10), B (11-25), C (26-40), D (41-60), F (61-100)

### Ownership Assignment (Priority Order)

1. CMDB integration (ServiceNow, etc.) — inherit app owner from IP/hostname
2. DNS-based resolution → CMDB lookup
3. CA metadata (requestor team in cert extensions or Subject O/OU)
4. Heuristic: match SAN domains against domain ownership registry
5. Manual claim workflow — unowned certs surface in discovery inbox

---

## 8. Competitive Landscape <a name="competitive-landscape"></a>

### Open-Source CA Comparison

| Project | Language | License | ACME | OCSP (OSS) | HSM | PQC | ADCS Replace | Verdict |
|---------|----------|---------|------|------------|-----|-----|-------------|---------|
| **step-ca** | Go | Apache 2.0 | Yes | No | Yes | No | No XCEP/WSTEP | Closest competitor |
| **EJBCA CE** | Java | LGPL | Yes | Yes | Yes | Partial | Enterprise only | Feature benchmark |
| **XiPKI** | Java | Apache 2.0 | Yes | Yes | Yes | **Yes** | No | PQC reference |
| **Dogtag** | Java | LGPL | Partial | Yes | Yes | No | No | Red Hat only |
| **cfssl** | Go | BSD-2 | No | No | No | No | No | Signing API ref |
| **Boulder** | Go | Apache 2.0 | Only | No | No | No | No | ACME reference |
| **Lemur** | Python | Apache 2.0 | N/A | N/A | N/A | N/A | No | UX reference |

### Commercial CLM Comparison

| Product | Discovery | ADCS | PQC | SSH Keys | Developer UX | Scale |
|---------|-----------|------|-----|----------|-------------|-------|
| **Venafi (CyberArk)** | Excellent | Integration | Roadmap | Best (SSH Protect) | Poor | 500K+ |
| **Keyfactor Command** | Very Good | Via EJBCA | Best (AgileSec) | Moderate | Moderate | 100K+ |
| **Sectigo CM** | Weak | Limited | No | No | Poor | Moderate |
| **AppViewX CERT+** | Best rated (G2) | Limited | No | No | Moderate | Good |

### Market Gaps We Can Exploit

1. **No open-source CA has native ADCS replacement** — EJBCA hides it behind enterprise license
2. **step-ca withholds OCSP from open-source** — we ship it free
3. **No product has real-time event-driven discovery** — agents with inotify/FSEvents detect cert changes in seconds
4. **No developer-native PKI** — REST API + Terraform provider + K8s operator + GitHub Actions
5. **No unified crypto inventory** — TLS certs + SSH keys + code signing + cipher suites in one model
6. **Transparent pricing** — vs. complex per-cert/per-node enterprise licensing
7. **CT log integration as first-class discovery** — free, real-time public cert detection

---

## 9. Post-Quantum Readiness <a name="pqc"></a>

### Standards (Finalized August 2024)

| Standard | Algorithm | Purpose | Key Size |
|----------|-----------|---------|----------|
| FIPS 203 | ML-KEM (Kyber) | Key encapsulation | ~800-1568 bytes |
| FIPS 204 | ML-DSA (Dilithium) | Digital signatures | ~1.3KB public key |
| FIPS 205 | SLH-DSA (SPHINCS+) | Hash-based signatures | Varies |
| RFC 9881 | ML-DSA in X.509 | Certificate encoding | N/A |

NSA CNSA 2.0 mandate: Government systems must implement PQC by 2030.

### Library Support

| Algorithm | Go stdlib | Go (CIRCL) | Rust | Java (BC) |
|-----------|-----------|------------|------|-----------|
| ML-KEM | 1.24 (TLS only) | Yes | Yes | Yes |
| ML-DSA | ~Go 1.26 | Yes | Yes | Yes |
| SLH-DSA | No | Yes | Yes | Yes |

### Our PQC Roadmap

| Phase | What | When |
|-------|------|------|
| V1 | Classical only (RSA, ECDSA, Ed25519). Good `crypto.Signer` abstraction. | Launch |
| V1.x | Hybrid TLS for CA API (Go 1.24 gives X25519MLKEM768 free) | Soon after |
| V2 | ML-DSA cert issuance via Cloudflare CIRCL. PQC vulnerability flagging in discovery. | V2 |
| V3 | Native ML-DSA in CA signing keys when Go stdlib ships. Full PQC migration planning dashboard. | V3 |

---

## 10. Recommended Architecture <a name="recommended-architecture"></a>

### System Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        Web Dashboard                          │
│                    (TypeScript / React)                        │
│  Certificate inventory, CA management, templates, discovery,  │
│  risk scoring, alerts, PQC dashboard                          │
└────────────────────────────┬─────────────────────────────────┘
                             │ REST API
┌────────────────────────────┴─────────────────────────────────┐
│                      API Gateway (Go)                         │
│            Auth, RBAC, rate limiting, audit logging            │
└──┬──────────┬──────────┬──────────┬──────────┬───────────────┘
   │          │          │          │           │
┌──┴──┐  ┌───┴───┐  ┌───┴───┐  ┌──┴──┐   ┌───┴────┐
│ CA  │  │ ACME  │  │ OCSP  │  │ EST │   │ SCEP   │
│Core │  │Server │  │Respdr │  │     │   │        │
└──┬──┘  └───┬───┘  └───┬───┘  └──┬──┘   └───┬────┘
   │         │          │         │           │
   └─────────┴──────────┴─────────┴───────────┘
                        │
              ┌─────────┴─────────┐
              │    crypto.Signer   │ ← abstraction layer
              ├───────────────────┤
              │ Software  │ HSM   │ Cloud KMS │
              └───────────────────┘
                        │
              ┌─────────┴─────────┐
              │    PostgreSQL      │
              │  (certs, templates,│
              │   audit, scans)    │
              └───────────────────┘

V2 additions:
┌───────────┐  ┌───────────┐  ┌──────────────┐
│ MS-XCEP   │  │ MS-WSTEP  │  │ AD LDAP Sync │
│ (CEP)     │  │ (CES)     │  │ (Templates)  │
└───────────┘  └───────────┘  └──────────────┘

Discovery Engine (separate service):
┌──────────────┬──────────────┬────────────────┐
│ Network Scan │ Host Scanner │ Cloud/K8s APIs │
│ (masscan +   │ (SSH/WinRM)  │ (ACM, KV, GCM,│
│  Go TLS)     │              │  cert-manager) │
└──────────────┴──────────────┴────────────────┘
         ↑
    Agent Fleet (Go binaries, HTTPS polling + inotify)
```

### Service Boundaries

| Service | Language | Responsibility |
|---------|----------|---------------|
| `pki-core` | Go | CA operations, signing, cert issuance, CRL generation |
| `pki-acme` | Go | ACME server (RFC 8555) |
| `pki-ocsp` | Go | OCSP responder (RFC 5019) |
| `pki-est` | Go | EST server (RFC 7030) |
| `pki-scep` | Go | SCEP server |
| `pki-api` | Go | REST API gateway, auth, RBAC |
| `pki-discovery` | Go | Network scanning, host scanning, cloud API integration |
| `pki-agent` | Go | Lightweight discovery agent (deployed on hosts) |
| `pki-dashboard` | TypeScript | Web UI |
| `pki-xcep` (V2) | Go | MS-XCEP server |
| `pki-wstep` (V2) | Go | MS-WSTEP server |
| `pki-adsync` (V2) | Go | AD LDAP template synchronization |

### Differentiation vs. step-ca

| Feature | step-ca (OSS) | Our Platform |
|---------|---------------|-------------|
| OCSP responder | Enterprise only | Free in OSS |
| Certificate templates/policy engine | Basic provisioners | Full template system |
| Management UI | Minimal | Full dashboard with risk scoring |
| Discovery/scanning | None | Built-in network + host + cloud |
| Multi-tenancy | No | Multiple CAs in one deployment |
| ADCS replacement | No | V2 — native XCEP/WSTEP |
| PQC | Not yet | V2 ML-DSA issuance |
| CT log monitoring | No | Built-in for public cert detection |

---

## 11. Risk Register <a name="risks"></a>

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|-----------|--------|------------|
| 1 | MS-XCEP/WSTEP specs have undocumented behaviors | High | High | Test against real Windows 10/11 clients with Wireshark; budget extra time |
| 2 | AD template sync breaks on different AD schema versions | Medium | High | Test against Windows Server 2016/2019/2022 DCs |
| 3 | Go stdlib lacks ML-DSA until ~1.26 | Confirmed | Medium | Use Cloudflare CIRCL as bridge; track Go release schedule |
| 4 | step-ca adds OCSP/discovery to OSS, neutralizing differentiation | Medium | Medium | Move fast; templates + ADCS replacement are harder to replicate |
| 5 | Enterprise adoption requires FIPS 140-2/3 validation | High | Medium | Design for it (PKCS#11 abstraction); defer validation to enterprise tier |
| 6 | Single-developer bottleneck on Go CA core | High | High | Modular design; consider community contribution model early |
| 7 | masscan triggers IDS/firewall blocks during discovery | Medium | Low | Configurable rate limiting; scan permission registry; document clearly |

---

## 12. References <a name="references"></a>

### Microsoft Protocol Specifications
- [MS-WCCE: Windows Client Certificate Enrollment Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/MS-WCCE/)
- [MS-ICPR: ICertPassage Remote Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/)
- [MS-XCEP: Certificate Enrollment Policy Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/)
- [MS-WSTEP: WS-Trust X.509 Token Enrollment](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cersod/)
- [MS-CRTD: Certificate Templates Structure](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/)
- [MS-CAESO: Certificate Autoenrollment System Overview](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/WinArchive/%5BMS-CAESO%5D.pdf)
- [MS-CERSOD: Certificate Services Overview](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cersod/)

### Open-Source Projects
- [step-ca (Smallstep) — Apache 2.0](https://github.com/smallstep/certificates)
- [EJBCA Community Edition — LGPL](https://github.com/Keyfactor/ejbca-ce)
- [XiPKI — Apache 2.0, PQC support](https://github.com/xipki/xipki)
- [Dogtag PKI — LGPL](https://github.com/dogtagpki/pki)
- [cfssl (Cloudflare) — BSD-2](https://github.com/cloudflare/cfssl)
- [Boulder (Let's Encrypt) — Apache 2.0](https://github.com/letsencrypt/boulder)
- [Lemur (Netflix) — Apache 2.0](https://github.com/Netflix/lemur)
- [TameMyCerts.WSTEP — MS-WSTEP reference](https://github.com/Sleepw4lker/TameMyCerts.WSTEP)
- [cepces (openSUSE) — XCEP/WSTEP client](https://github.com/openSUSE/cepces)
- [acme2certifier — ACME proxy](https://github.com/grindsa/acme2certifier)
- [Cloudflare CIRCL — PQC crypto library](https://github.com/cloudflare/circl)
- [ThalesGroup/crypto11 — PKCS#11 crypto.Signer](https://github.com/ThalesGroup/crypto11)
- [mholt/acmez — ACME RFC 8555 Go library](https://github.com/mholt/acmez)

### Go Crypto
- [crypto/x509 package](https://pkg.go.dev/crypto/x509)
- [golang.org/x/crypto/ocsp](https://pkg.go.dev/golang.org/x/crypto/ocsp)
- [golang.org/x/crypto/acme](https://pkg.go.dev/golang.org/x/crypto/acme)

### PQC Standards
- [FIPS 204 — ML-DSA (NIST)](https://csrc.nist.gov/pubs/fips/204/final)
- [RFC 9881 — ML-DSA in X.509](https://datatracker.ietf.org/doc/rfc9881/)
- [PKI Consortium PQC Capabilities Matrix](https://pkic.org/wg/pqc/pqccm/)

### Discovery & Scanning
- [sslyze — SSL/TLS scanning library](https://github.com/nabla-c0d3/sslyze)
- [Venafi Discovery Documentation (v25.1)](https://docs.venafi.com/Docs/currentSDK/TopNav/Content/Discovery/)
- [Keyfactor SSL Discovery Reference](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/SSLDiscovery.htm)
- [CA/Browser Forum Ballot SC-081 — 47-day TLS lifetimes](https://cabforum.org/)

### ADCS Integration
- [EJBCA Microsoft Auto-enrollment Overview](https://docs.keyfactor.com/ejbca/latest/microsoft-auto-enrollment-overview)
- [Secardeo certEP](https://www.secardeo.com/products/certep-certificate-autoenrollment)
- [Samba Certificate Auto Enrollment](https://wiki.samba.org/index.php/Certificate_Auto_Enrollment)
- [cepces PROTOCOLS.md](https://github.com/openSUSE/cepces/blob/master/doc/PROTOCOLS.md)
- [CEP/CES Basics — Uwe Gradenegger](https://www.gradenegger.eu/en/basics-certificate-application-via-certificate-enrollment-web-services-cep-ces/)
- [PKI Solutions — ADCS Open Protocols](https://www.pkisolutions.com/blog/adcs-open-protocols-specifications/)
