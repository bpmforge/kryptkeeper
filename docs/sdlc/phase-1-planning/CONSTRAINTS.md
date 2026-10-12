# Kryptkeeper — Constraints

**Version:** 1.0
**Date:** 2026-04-05
**Phase:** 1 — Planning

---

## 1. Team Constraints

### C-T01 — Single Developer (Initial)
The project begins with a single developer. This is the primary constraint shaping every
architectural decision. It drives:
- Modular, interface-driven design so individual services can be handed off or community-contributed
- Go monorepo or clear module boundaries — minimize cross-module coupling
- No frameworks or abstractions that require deep expertise to maintain
- Deferred complexity: V1 ships a smaller, solid feature set rather than a sprawling one

**Constraint impact:** Scope is strictly V1 only until contributor capacity grows.
V2 ADCS work is deliberately deferred to protect V1 quality.

### C-T02 — No Dedicated QA
Testing is the developer's responsibility. This means:
- Unit tests written alongside every new function, not after
- Integration tests for all enrollment protocols (ACME, EST, SCEP, OCSP)
- Behavioral tests for the CA core (sign, revoke, CRL generation, chain validation)
- No manual QA step — the CI gate is the quality gate

---

## 2. Technology Constraints

### C-Tech01 — Language Choice is Fixed
**Go for all backend services.** This decision is final (see RESEARCH_FINDINGS.md §3).
TypeScript/React for the dashboard only. Rationale:
- Go `crypto/x509` stdlib is the correct tool for CA operations
- Every successful modern CA (step-ca, Boulder, cfssl) uses Go
- Single static binary deployment reduces operational complexity

No runtime dependencies other than PostgreSQL (or SQLite in dev mode).

### C-Tech02 — No Custom Crypto Implementations
All cryptographic operations MUST use Go stdlib (`crypto/tls`, `crypto/x509`, `crypto/rand`,
`golang.org/x/crypto`). ML-DSA uses Cloudflare CIRCL until Go stdlib ships it.

No bespoke X.509 parsing, no custom TLS, no custom key derivation functions.

**Rationale:** Bespoke crypto implementations are where PKI software dies. The attack
surface is enormous and the failure modes are silent.

### C-Tech03 — crypto.Signer Interface is Non-Negotiable
All CA signing operations MUST go through Go's `crypto.Signer` interface. No code path
may call a specific key type's signing method directly. This enables HSM, cloud KMS, and
software key backends to be swapped without modifying CA logic.

### C-Tech04 — Database Abstraction Required
The platform must support both PostgreSQL (production) and SQLite (single-node dev/embedded).
The data access layer MUST use a repository pattern with a database interface — no
PostgreSQL-specific SQL in business logic.

### C-Tech05 — Apache 2.0 License Boundary
Core platform is Apache 2.0. Third-party libraries included in the core MUST be compatible:
- Permitted: Apache 2.0, MIT, BSD-2, BSD-3, ISC, MPL-2.0 (with care)
- Not permitted in core: LGPL (dynamic linking only), GPL, AGPL, SSPL, BSL
- Check: `go-licenses` or `license-checker` in CI for any new dependency

**Rationale:** Enterprise legal teams will reject AGPL and GPL transitively. Apache 2.0's
patent grant is required for enterprise adoption.

### C-Tech06 — No Windows Server Required
Every service MUST run on Linux. No Windows-specific libraries, no COM/DCOM,
no Windows Registry access. ADCS replacement (V2) is achieved via protocol implementation
(XCEP/WSTEP/LDAP) not Windows APIs.

---

## 3. Timeline Constraints

### C-Time01 — V1 Feature Freeze
V1 scope is frozen at what is defined in SCOPE.md. Adding features to V1 requires an
explicit scope change decision with a documented rationale. The goal is a solid, complete
V1 — not a sprawling one.

### C-Time02 — V2 (ADCS) Is a 3–6 Month Investment
ADCS replacement cannot be rushed. MS-XCEP/WSTEP require behavioral testing against real
Windows clients. The research finding (3–6 months for production-quality implementation)
is a hard constraint. Do not commit to V2 timelines until V1 is shipped and stable.

### C-Time03 — CA/Browser Forum Deadline Awareness
SC-081 enforcement dates are hard external deadlines that affect our users:
- 200 days: March 2026 (already in effect)
- 100 days: March 2027
- 47 days: March 2029

V1 MUST be production-ready before the 100-day deadline creates a wave of automation demand.

---

## 4. Security and Compliance Constraints

### C-Sec01 — Root CA Must Support Air-Gapped Key Ceremony
The root CA private key ceremony documentation and tooling must support an air-gapped
workflow. Operators cannot be required to generate root CA keys on an internet-connected
machine. The platform must support offline root CA signing with online issuing CA.

### C-Sec02 — Audit Log is Append-Only
The audit log (`audit_log` table) MUST be append-only. No UPDATE or DELETE operations
are permitted on audit records. This is a hard constraint for compliance (SOC 2, ISO 27001).
Implement with database-level controls (row-level security or a separate append-only store).

### C-Sec03 — Private Key Material Never in API Responses
No API endpoint may return private key material. Key generation always returns the
certificate only. If a client needs the private key, it generates the CSR and submits
the public key — the platform never touches the private key.

Exception: PKCS#12 export for legacy systems (operator-enabled feature, with audit log
entry, disabled by default).

### C-Sec04 — No Telemetry Without Explicit Opt-In
The platform MUST NOT send telemetry, usage data, or crash reports without explicit
operator opt-in. Enterprise deployments in air-gapped environments cannot have phone-home
behavior. If telemetry is implemented, it must be documented clearly with an easy off switch.

---

## 5. Operational Constraints

### C-Ops01 — Single Docker Compose Deployment
V1 MUST be deployable with a single `docker compose up` command. An operator who has
never used the platform before must be able to have a working CA in under 15 minutes
following the quickstart documentation.

### C-Ops02 — Agent Size Limit
The `pki-agent` binary MUST remain under 15MB compressed. This ensures it can be deployed
via standard software distribution tools without special handling. Monitor binary size
in CI.

### C-Ops03 — No Required External Services at Startup
The platform MUST start without an internet connection. No external service calls at
startup. HSM and cloud KMS are optional integrations, not startup requirements.

---

## 6. Constraint Summary

| ID | Category | Constraint | Impact |
|----|----------|------------|--------|
| C-T01 | Team | Single developer initially | Scope discipline required |
| C-T02 | Team | No dedicated QA | Tests alongside code, CI is the gate |
| C-Tech01 | Technology | Go backend, TypeScript dashboard | Non-negotiable |
| C-Tech02 | Technology | No custom crypto | Use stdlib + CIRCL only |
| C-Tech03 | Technology | crypto.Signer mandatory | All signing through interface |
| C-Tech04 | Technology | PostgreSQL + SQLite support | Repository pattern required |
| C-Tech05 | Technology | Apache 2.0 license boundary | No GPL/AGPL dependencies |
| C-Tech06 | Technology | No Windows Server required | Linux-only server side |
| C-Time01 | Timeline | V1 scope is frozen | Scope changes require decision |
| C-Time02 | Timeline | V2 is 3–6 months | Don't commit until V1 ships |
| C-Time03 | Timeline | SC-081 deadlines are real | V1 before 100-day mandate |
| C-Sec01 | Security | Air-gapped root CA ceremony | Offline key workflow required |
| C-Sec02 | Security | Audit log is append-only | DB-level controls required |
| C-Sec03 | Security | No private keys in API | CSR model is the only path |
| C-Sec04 | Security | No telemetry without opt-in | Air-gap compatible by default |
| C-Ops01 | Operations | Single `docker compose up` | 15-minute quickstart target |
| C-Ops02 | Operations | Agent < 15MB | Monitor in CI |
| C-Ops03 | Operations | No internet at startup | Offline-first design |
