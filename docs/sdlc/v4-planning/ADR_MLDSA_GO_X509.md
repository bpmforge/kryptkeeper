# ADR: ML-DSA Certificate Creation — Custom DER Path

**Date:** 2026-04-24
**Status:** ACCEPTED
**Spike result:** T-02 risk materialized as expected

## Decision

Use a custom `CreateCertificateMLDSA` function that manually builds DER-encoded
certificates for ML-DSA keys. Do NOT use `x509.CreateCertificate` for PQC keys.

## Context

Go 1.26 `x509.CreateCertificate` is hardcoded to only support RSA, ECDSA, and Ed25519:

```
x509: only RSA, ECDSA and Ed25519 keys supported
```

Go 1.26 includes `crypto/mlkem` (FIPS 203) but NOT `crypto/mldsa` (FIPS 204).
ML-DSA stdlib support is expected in Go 1.27+.

## CIRCL OIDs (FIPS 204 / draft-ietf-lamps-dilithium-certificates)

- ML-DSA-44: `2.16.840.1.101.3.4.3.17`
- ML-DSA-65: `2.16.840.1.101.3.4.3.18`
- ML-DSA-87: `2.16.840.1.101.3.4.3.19`

## Implementation

`internal/keystore/mldsa_cert.go` provides:

```go
func CreateCertificateMLDSA(
    rand io.Reader,
    template, parent *x509.Certificate,
    pub mldsaPublicKey,       // CIRCL public key (any ML-DSA variant)
    signer crypto.Signer,     // wrapping CIRCL private key
    oid asn1.ObjectIdentifier,
) ([]byte, error)
```

Approach:
1. Marshal ML-DSA public key bytes via `pub.MarshalBinary()`
2. Encode as `SubjectPublicKeyInfo { algorithm { OID }, subjectPublicKey BIT STRING }`
3. Build `TBSCertificate` using `encoding/asn1` with all fields from template
4. Call `signer.Sign(rand, tbsDER, nil)` — ML-DSA signs the full message
5. Assemble final `Certificate { tbsCertificate, signatureAlgorithm { OID }, signature BIT STRING }`

## Migration Path

When Go stdlib adds `crypto/mldsa` (expected Go 1.27):
- Drop the custom `CreateCertificateMLDSA` function
- Replace with `x509.CreateCertificate` directly
- All callers use the same interface; change is internal to `internal/ca/`
