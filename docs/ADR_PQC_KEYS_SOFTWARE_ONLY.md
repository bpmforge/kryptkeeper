# ADR: PQC keys are software-keystore-only (for now)

- **Status**: Accepted (W9-08, 2026-08-19)
- **Decision id**: D-086 / FR-P48
- **Owners**: platform / ca

## Context

Kryptkeeper generates and signs with ML-DSA-44/65/87 and the two hybrid
algorithms (ECDSA-P256+ML-DSA-65, ECDSA-P384+ML-DSA-87) — but only in the
**software keystore** (Argon2id + AES-256-GCM encrypted files). The
PKCS#11/HSM backend supports RSA and ECDSA only, and the cloud KMS and
Vault transit backends have no ML-DSA offering wired here either. For a
PQC-forward product this is a real contradiction: our strongest
classical keys can live in hardware; our post-quantum keys cannot.

## Why we are not implementing HSM ML-DSA in this ticket

Verified against the vendored module sources (not from memory):

- `github.com/ThalesGroup/crypto11 v1.6.1` exposes RSA/ECDSA generation
  only; no ML-DSA/Dilithium key generation or signing surface exists in
  the module.
- Its underlying `github.com/miekg/pkcs11 v1.1.2` predates PKCS#11 v3.2
  and defines **no `CKM_ML_DSA` mechanism constants** — ML-DSA
  mechanisms were standardized in PKCS#11 v3.2 (2025).
- Reaching real HSM ML-DSA therefore requires either a major-version
  dependency upgrade or raw mechanism plumbing against a v3.2-capable
  HSM — a new-dependency decision reserved for a human (house rule), and
  untestable in this environment (no v3.2 HSM, SoftHSM2 has no ML-DSA).

## Decision

1. **PQC (ML-DSA and hybrid) keys are generated and held in the software
   keystore only.** The HSM/KMS/Vault backends refuse them explicitly
   (`keystore.CheckHSMPQCSupport`), citing this ADR, rather than failing
   with a generic "unsupported algorithm".
2. Revisit when (a) a PKCS#11 v3.2 Go binding with ML-DSA mechanisms is
   available and approved as a dependency, or (b) a cloud KMS ships
   ML-DSA key support we can integrate (AWS KMS announced ML-DSA
   support in 2025 — integrating it is future work under a new ticket).

## Risk accepted

- **Extraction risk**: software-kept ML-DSA private keys are protected
  by Argon2id+AES-256-GCM at rest and zeroization on eviction (W9-07),
  but unlike HSM keys they exist in process memory while in use and can
  be exfiltrated by a root-level compromise of the host. An attacker who
  steals a hybrid CA's ML-DSA component degrades the hybrid chain to
  classical-only security.
- **Compliance**: deployments requiring FIPS 140-3 hardware key custody
  cannot claim it for PQC keys. The W9-11 FIPS posture assessment must
  (and does) reflect this.
- **Mitigations in place**: escrow under dual control (W9-12), dual
  control for destructive ops (W9-10), keygen policy floors (W9-05),
  zeroization (W9-07), append-only audit of every key operation.

## Consequences

- `keystore.CheckHSMPQCSupport(backend, algo)` is the single refusal
  surface; its message names this ADR so an operator hitting the wall
  finds the reasoning.
- The software store remains the only backend advertising ML-DSA/hybrid
  in `SupportedAlgorithms` terms; documentation and the keygen policy do
  not pretend otherwise.
