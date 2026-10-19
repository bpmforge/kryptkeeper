# PQC hybrid certificate encoding, revocation signing, and LAMPS status

- **Decision ids**: D-086, D-104 / FR-P48 (UC-G02, UC-G06)
- **Ticket**: W31-07
- **Scope**: what Kryptkeeper actually emits for hybrid (ECDSA + ML-DSA) keys, how CRLs and
  OCSP responses are signed for ML-DSA CAs, and what is *not* claimed. Every statement below
  is checked against the file cited next to it.

## 1. Algorithms

| Algorithm | Classical part | ML-DSA part | Defined in |
|---|---|---|---|
| `Hybrid-ECDSA-P256-ML-DSA-65` | ECDSA P-256 | ML-DSA-65 | `internal/keystore/keystore.go` |
| `Hybrid-ECDSA-P384-ML-DSA-87` | ECDSA P-384 | ML-DSA-87 | `internal/keystore/keystore.go` |

A hybrid key is two independent key pairs under one key id: `keystore.HybridComponents(algo)`
(`internal/keystore/hybrid.go`) returns the classical and ML-DSA component algorithms, and the
software store persists both (`hybridMeta`, `{id}.hybrid.json`). Callers get the pair through
`keystore.HybridKeyLoader.LoadHybridKeyPair`. A plain `Signer(id)` on a hybrid key returns the
classical (primary) signer only.

## 2. Certificate encoding

The scheme follows `draft-ounsworth-x509-alt-sig-alg-07` (header of
`internal/ca/hybrid_cert.go`). The certificate is an ordinary X.509 v3 certificate:

- `SubjectPublicKeyInfo`: the **classical** public key.
- `subjectAltPublicKeyInfo`, OID `2.5.29.72`: the ML-DSA public key.
- `altSignatureAlgorithm`, OID `2.5.29.73`: the ML-DSA algorithm OID.
- `altSignatureValue`, OID `2.5.29.74`: the ML-DSA signature.

All three are **non-critical** extensions, so a classical verifier ignores them and checks the
ordinary ECDSA signature. Signing order in `CreateCertificateHybrid` (`internal/ca/hybrid_cert.go`):
build the TBS with the alt public key and alt algorithm extensions; sign that TBS with ML-DSA;
add `altSignatureValue`; sign the complete TBS (including `altSignatureValue`) with ECDSA.

## 3. Hybrid CSR

`internal/ca/hybrid_csr.go`:

- PEM type `HYBRID CERTIFICATE REQUEST`.
- Two-pass self-signature: ML-DSA signs the pass-1 `CertificationRequestInfo`, then ECDSA signs
  the final bytes including the alt signature, so both keys prove possession.
- The alt extensions ride in the PKCS#9 `extensionRequest` attribute.
- Both self-signatures are verified at parse time (`ParseCertificateRequestHybrid`), which is why
  `issueCertificateFromHybridCSR` (`internal/ca/engine.go`) does not re-prove possession.

## 4. Which call sites build which certificate

| Certificate | Builder | What it carries |
|---|---|---|
| Hybrid-keyed **root CA** (`Engine.CreateRootCA`) | `createCertDERHybrid` -> `CreateCertificateHybrid` (`internal/ca/engine.go`, the only caller) | full dual signature: 2.5.29.72, .73 and .74 |
| CA-issued **leaf** from a hybrid CSR (`issueCertificateFromHybridCSR`) | `createCertDER` (classical branch) with the alt public key added via `ExtraExtensions` | 2.5.29.72 only; **no** `altSignatureValue`; issuer signature is the CA's own algorithm (D-104) |

D-104 consequence: a CA-issued hybrid leaf is labelled `quantum_safe_leaf_only`
(`pqcReadinessLeafOnly` / `computePQCReadiness`, `internal/bootstrap/certificate_ca_provider.go`),
never `quantum_safe`, whenever any signature in its chain is classical. The leaf's key is
protected; the chain's authenticity is not.

Not covered: `CreateIntermediateCA` does not call `CreateCertificateHybrid`; it signs through
`createCertDER` with the parent's signer. `CreateIntermediateCSR` refuses ML-DSA and hybrid
outright ("CSR flow supports classical algorithms only").

## 5. Interoperability: what is and is not claimed

- The encoding is **the project's own**. **Interoperability with the IETF LAMPS composite
  signature work (`draft-ietf-lamps-pq-composite-sigs`) is not claimed.** The composite drafts use
  different OIDs and a single composite key/signature; this encoding uses the separate
  alt-signature extensions above.
- Verification by third-party tools is claimed only for the classical path: the ECDSA chain of a
  hybrid certificate verifies in a classical verifier because the alt extensions are non-critical.
  No OpenSSL run of a hybrid *alt* signature is claimed. The live OpenSSL job for the classical
  chain path is planned as `tests/live/pqc` (W31-04); that directory is not present on this
  branch at the time of writing, so no result from it is cited here.
- ML-DSA-only certificates (non-hybrid) are standard PKIX encodings and verify under OpenSSL
  3.5 or later.
- **FIPS mode**: hybrids are refused. `keystore.CheckFIPSAlgorithm` (`internal/keystore/fips.go`)
  returns an error for any hybrid when the FIPS module is active, because no NIST specification
  covers the composite format. See `docs/design/FIPS_POSTURE.md`.
- **Decision**: track LAMPS composite OIDs after v1.0; the encoding stays our own until then
  (recorded in `docs/DECISIONS.md`).

## 6. CRL and OCSP for ML-DSA CAs (W31-05)

`x509.CreateRevocationList` and `golang.org/x/crypto/ocsp.CreateResponse` reject the keystore's
ML-DSA signers, so ML-DSA CAs sign revocation data with hand-rolled DER in `internal/revsign`
(its own package: `internal/ca` would create an import cycle through `internal/ca`'s tests).

- **CRL**: `revsign.CreateRevocationList` is called from `internal/crl/generator.go`,
  `internal/crl/shard.go` and `internal/crl/delta.go`. For an ML-DSA issuer it emits an RFC 5280
  `CertificateList` signed by ML-DSA over the whole TBS (never a pre-hash); for any other issuer
  it delegates to the stdlib. It requires the `crlSign` key usage and a subject key identifier on
  the issuer certificate.
- **OCSP**: `internal/ocsp/responder.go` `createResponse` routes ML-DSA issuers to
  `revsign.CreateOCSPResponseMLDSA`: an RFC 6960 `BasicOCSPResponse` with `responderID` byKey
  (SHA-1 of the issuer key bits), signed directly by the issuer key (no delegated responder, the
  issuer certificate is not embedded). The CertID hash echoes the request (SHA-1/256/384/512).
  Non-ML-DSA issuers use `golang.org/x/crypto/ocsp`.
- **Detection** keys off the issuer's SPKI OID (`revsign.IsMLDSAIssuer`), not
  `x509.SignatureAlgorithm`, which differs between Go toolchains.
- **API**: `GET /api/v1/cas` items carry `revocation_signing`, `"ml-dsa"` or `"classical"`
  (`CAListItem`, `internal/bootstrap/ca_provider.go`; set in `internal/bootstrap/ca_engine_provider.go`).
- **Hybrid CAs report `classical`.** A hybrid CA's SPKI is the classical ECDSA key, so
  `IsMLDSAIssuer` is false and its CRLs and OCSP responses are signed with the ECDSA primary key
  only. No alt signature is added to revocation data. Clients that need ML-DSA-signed revocation
  data must use an ML-DSA (non-hybrid) CA.
- **Observed with OpenSSL 3.6.5** (W31-05 verification run; not yet an automated repository
  test): `openssl crl -verify` OK; `openssl verify -crl_check` reports the certificate revoked;
  `openssl ocsp -respin` prints "Response verify OK" for both a good and a revoked status.

## 7. Software-only keys

ML-DSA and hybrid keys exist only in the software keystore; PKCS#11, cloud KMS and Vault refuse
them via `keystore.CheckHSMPQCSupport` (error `keystore.ErrPQCHSMUnsupported`). Reasoning and
accepted risk: [ADR_PQC_KEYS_SOFTWARE_ONLY.md](ADR_PQC_KEYS_SOFTWARE_ONLY.md).
