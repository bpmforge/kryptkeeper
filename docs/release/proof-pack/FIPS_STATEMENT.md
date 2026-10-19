# Kryptkeeper FIPS statement

## 1. Claim

> Kryptkeeper uses the Go FIPS 140-3 module (CMVP status: certificate #5247, Active).

The CMVP certificate number, status and date checked are recorded per release in
[`../CMVP_STATUS.md`](../CMVP_STATUS.md): Go Cryptographic Module v1.0.0 (the `GOFIPS140=v1.0.0`
pin), NIST CMVP certificate #5247, Active, sunset 2031-04-26, checked 2026-10-17. The certificate
belongs to the Go module, not to Kryptkeeper. It applies only to builds made with that pin (the
`-fips` image and `make fips` builds).

## 2. What this means and does not mean

- The cryptographic module is the Go FIPS 140-3 Cryptographic Module, pinned at build time
  (`GOFIPS140=v1.0.0`). Kryptkeeper calls it through the Go standard library; it ships no
  cryptographic module of its own for the algorithms inside the boundary.
- Kryptkeeper itself is not a CMVP-listed product. Only the pinned Go module is a candidate for a
  CMVP entry, and its status is whatever section 1 says.
- Not covered by the claim: the product as a whole, ML-DSA and hybrid (ECDSA+ML-DSA) signatures,
  the Argon2id keystore KDF, the Vault transit backend, and the web UI.

## 3. Boundary

Inside, when FIPS mode is on: Go standard-library cryptography the product uses (TLS, X.509
signing and verification, RSA / ECDSA / Ed25519, SHA-2, AES-GCM). CA and root keys held in a
PKCS#11 HSM or a cloud KMS (AWS KMS, GCP Cloud KMS, Azure Key Vault) rely on the validations those
services carry themselves, not on this statement.

Outside (not claimed): ML-DSA (implemented by `github.com/cloudflare/circl`, outside the pinned
module), hybrid composite signatures (refused in FIPS mode), software-kept PQC private keys, the
Vault transit backend, and the Argon2id passphrase KDF for software keystore files.

Source: [`../../design/FIPS_POSTURE.md`](../../design/FIPS_POSTURE.md).

## 4. Build and run flags

| Level | Build | Run | Meaning |
|---|---|---|---|
| Default | `go build ./...` | none | Standard Go crypto. No FIPS claim. |
| FIPS mode | `GOFIPS140=latest go build ./...` | `GODEBUG=fips140=on` | Crypto routed through the FIPS 140-3 module. `keystore.FIPSPosture()` reports `mode_140_3: true` and the module version. |
| FIPS enforced | as above | `GODEBUG=fips140=only` | Non-approved algorithm use fails at run time. |
| Root custody | any of the above | `KRYPTKEEPER_KEY_BACKEND=pkcs11` (or `cloudkms`); `KRYPTKEEPER_FIPS_ROOT_HSM=true` | Root keys live in an HSM or KMS. With FIPS mode on, or `KRYPTKEEPER_FIPS_ROOT_HSM=true`, the CA role refuses to boot on a software or Vault keystore. |

Release builds pin the module with `GOFIPS140=v1.0.0` (`Makefile`, `Dockerfile.fips`). The image
tagged `<version>-fips` (built by `Dockerfile.fips`) sets `GODEBUG=fips140=on`, not `only`; the
software keystore's AES-GCM cannot run under `only`. An operator can override `GODEBUG` at run
time, so read the posture from the running process (section 5) rather than from the image tag.
`make fips-smoke` checks a built image.

What the repository tests:

| Setting | Evidence |
|---|---|
| `fips140=only` | CI job `fips-only` in `.github/workflows/ci-pr.yml` runs a scoped set (`TestFIPSOnly*`, `TestCheckFIPSAlgorithm`, `TestFIPSPosture*`, `TestRootKeyCustody*`) in `internal/keystore/fips_test.go`, with `KK_EXPECT_FIPS_ONLY=1` so it cannot pass vacuously. The whole keystore suite is not run under `only`. |
| `fips140=on` | `make fips-smoke` (`scripts/fips-smoke.sh`) starts the `-fips` image, asserts `/api/v1/meta` reports `mode_140_3`, a module version and `root_hsm_required`, and asserts a software root key is refused at boot. It is run by an operator; no CI workflow in this repository runs it. |
| default (unset) | the normal `go test ./...` suite. `internal/keystore/fips_test.go` branches on the live module state. |

## 5. How a customer verifies

- `GET /api/v1/meta`, field `.fips` (`mode_140_3`, `enforced`, `module_version`,
  `root_hsm_required`). It reads the live `crypto/fips140` state of the running process
  (`keystore.FIPSPosture()`).
- Boot refusal: in FIPS-custody mode, `keystore.CheckRootKeyCustody` stops the CA role starting on
  a software keystore. The refusal text names NFR-011.

## 6. Algorithm matrix

Module = the pinned Go module `v1.0.0` (`GOFIPS140=v1.0.0`).

| Algorithm | Inside Go module v1.0.0 | Behaviour under `fips140=on` | Under `fips140=only` |
|---|---|---|---|
| ECDSA P-256 / P-384 | inside | allowed | allowed |
| RSA-2048 / RSA-4096 (PKCS#1 v1.5, PSS) | inside | allowed | allowed |
| Ed25519 | inside | allowed | allowed |
| ML-DSA-44 / 65 / 87 | outside (circl) | allowed | refused, error names the posture doc |
| Hybrid ECDSA+ML-DSA | outside | refused (`CheckFIPSAlgorithm`) | refused |
| Argon2id keystore KDF | outside | n.a. | n.a. |
| Software-keystore AES-GCM | inside, but arbitrary-IV GCM is refused | allowed | not usable |
| Vault transit | not covered | not root custody | not root custody |

Root keys must be HSM or KMS custody regardless (NFR-011), so the software keystore's
incompatibility with `only` does not widen the claim.

## 7. Known residuals

- FIPS 140-2 validations are sunsetting industry-wide. This posture targets 140-3 through the Go
  module; a buyer whose requirement names 140-2 specifically should ask us.
- ML-DSA private keys are software-only today, so a FIPS-custody deployment cannot use ML-DSA CA
  keys until HSM support lands. See [`../../ADR_PQC_KEYS_SOFTWARE_ONLY.md`](../../ADR_PQC_KEYS_SOFTWARE_ONLY.md).

## 8. Version and date

Release tag: `<tag>` (replaced by the proof-pack index at publish).
Last reviewed: `<YYYY-MM-DD>` (PENDING-RUN: set by the human reviewer).
Reviewer: PENDING-RUN.
