# FIPS 140-2/3 Posture (W9-11, D-089, FR-P51)

Kryptkeeper's FIPS posture uses **Go's native FIPS 140-3 Cryptographic
Module** — no BoringCrypto fork, no cgo, no third-party crypto vendor.
The module is part of the Go toolchain (Go ≥ 1.24) and is what NIST's
CMVP validates; stdlib `crypto/fips140` reports its state at run time.

## How to build and run each posture level

| Level | Build | Run | Meaning |
|---|---|---|---|
| Off (default) | `go build ./...` | — | Standard Go crypto; no FIPS claim. |
| FIPS mode | `GOFIPS140=latest go build ./...` (pins the module version into the binary) | `GODEBUG=fips140=on` | All crypto routed through the FIPS 140-3 module; `keystore.FIPSPosture()` reports `mode_140_3: true` and the module version. |
| FIPS enforced | as above | `GODEBUG=fips140=only` | Non-approved algorithm use fails at runtime rather than silently falling outside the boundary. |
| + Root custody | any of the above | `KRYPTKEEPER_KEY_BACKEND=pkcs11` (or `cloudkms`) | NFR-011: root keys live in an HSM. **Enforced**: with FIPS mode on (or `KRYPTKEEPER_FIPS_ROOT_HSM=true`), the CA role refuses to boot on a software or Vault keystore. |

## The validated boundary

**Inside the boundary** (when FIPS mode is on):

- All Go standard-library cryptography this product uses — TLS, X.509
  signing/verification, RSA/ECDSA/Ed25519 operations, SHA-2, AES-GCM,
  Argon2's underlying primitives as exposed via the module — executes in
  the validated module.
- ML-DSA (FIPS 204) signatures are FIPS-approved as an algorithm family.
- Key custody for CA/root keys: a PKCS#11 HSM (`pkcs11` backend) or a
  cloud KMS whose HSMs carry their own FIPS 140 validations
  (`cloudkms`: AWS KMS, GCP Cloud KMS, Azure Key Vault).

**Outside the boundary** (explicitly not claimed):

- **Hybrid composite signatures** (ECDSA+ML-DSA): no NIST specification
  covers the composite format; `keystore.CheckFIPSAlgorithm` refuses
  hybrids in FIPS mode rather than letting a deployment claim them.
- **Software-kept PQC private keys**: per
  `docs/ADR_PQC_KEYS_SOFTWARE_ONLY.md` (W9-08), ML-DSA keys currently
  live only in the software keystore — approved *algorithm*, but not
  hardware *custody*. A FIPS-custody deployment therefore cannot use
  ML-DSA CA keys until HSM ML-DSA lands (revisit triggers in the ADR).
- **Vault transit backend**: not FIPS-validated in its default
  distribution; does not qualify as root custody.
- The Argon2id passphrase KDF for software-keystore files is outside
  the module's approved-KDF list; in a FIPS-custody deployment root
  keys are not in that store at all.

## Enforcement points (not just claims)

1. **Boot**: `cmd/kryptkeeper/main.go` calls
   `keystore.CheckRootKeyCustody(backend)` when the CA role starts; a
   violation is fatal. A FIPS-posture CA cannot come up on a software
   keystore.
2. **Key generation API**: `CheckFIPSAlgorithm` runs alongside the
   W9-05 keygen policy — non-approved algorithms are refused with the
   reason while FIPS mode is on.
3. **Inspection**: `keystore.FIPSPosture()` reports mode, enforcement,
   module version, and custody requirement from the live
   `crypto/fips140` state — what an auditor sees is what the process
   actually runs.

## Residuals

- FIPS 140-**2** validations are sunsetting industry-wide; this posture
  targets 140-3 via the Go module. Buyers holding 140-2-only
  requirements are covered by the same mechanisms (the module's lineage
  is documented in Go's security docs).
- The module version pinned by `GOFIPS140` at build time is the version
  whose CMVP certificate applies; record it in release notes for each
  FIPS build (`keystore.FIPSPosture().ModuleVersion` prints it).
