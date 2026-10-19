// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

// hybrid_cert.go — X.509 hybrid certificate creation (classical + ML-DSA).
//
// A hybrid certificate has:
//   1. Standard classical (ECDSA) primary key in SubjectPublicKeyInfo
//   2. ML-DSA public key in id-ce-subjectAltPublicKeyInfo extension (OID 2.5.29.72)
//   3. ML-DSA signature over TBSCertificate in id-ce-altSignatureValue extension (OID 2.5.29.74)
//   4. Standard ECDSA signature over the complete TBSCertificate (including alt-sig extensions)
//
// This follows draft-ounsworth-x509-alt-sig-alg-07:
//   - Classical verifiers: ignore unknown non-critical extensions, verify ECDSA sig ✓
//   - Hybrid-aware verifiers: also verify ML-DSA sig over TBS ✓
//
// Algorithm protocol (order matters):
//   Step 1: Build TBS with primary ECDSA key + AltPublicKey extension + AltSigAlgorithm extension
//   Step 2: Sign TBS (from step 1) with ML-DSA → altSig
//   Step 3: Add AltSignatureValue extension (containing altSig) to TBS
//   Step 4: Sign complete TBS (including AltSignatureValue) with ECDSA → primary sig
//   Step 5: Assemble Certificate = { TBS, ECDSA-AlgID, ECDSA-Sig }

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"

	"kryptkeeper/internal/keystore"
)

// Alt-signature extension OIDs per draft-ounsworth-x509-alt-sig-alg-07.
var (
	// OID for SubjectAltPublicKeyInfo — contains the ML-DSA public key.
	oidAltSubjectPublicKeyInfo = asn1.ObjectIdentifier{2, 5, 29, 72}
	// OID for AltSignatureAlgorithm — identifies the ML-DSA algorithm OID.
	oidAltSignatureAlgorithm = asn1.ObjectIdentifier{2, 5, 29, 73}
	// OID for AltSignatureValue — contains the ML-DSA signature bytes.
	oidAltSignatureValue = asn1.ObjectIdentifier{2, 5, 29, 74}
)

// CreateCertificateHybrid creates a DER-encoded X.509 hybrid certificate.
// The returned cert has a classical ECDSA primary signature plus an ML-DSA
// secondary signature stored in non-critical extensions.
func CreateCertificateHybrid(
	template, parent *x509.Certificate,
	classicalSigner crypto.Signer, // ECDSA P-256 or P-384
	mldsaSigner crypto.Signer, // ML-DSA-65 or ML-DSA-87
	algo keystore.Algorithm, // e.g. HybridECDSAP256MLDSA65
) ([]byte, error) {
	_, mldsaAlgo, ok := keystore.HybridComponents(algo)
	if !ok {
		return nil, fmt.Errorf("not a hybrid algorithm: %s", algo)
	}

	mldsaOID, ok := keystore.MLDSAOIDForAlgo(mldsaAlgo)
	if !ok {
		return nil, fmt.Errorf("no OID for ML-DSA algorithm %s", mldsaAlgo)
	}

	// Step 1: Encode ML-DSA public key for the AltPublicKey extension.
	mlPub, ok := mldsaSigner.Public().(keystore.MLDSAPublicKey)
	if !ok {
		return nil, fmt.Errorf("ML-DSA signer public key is not MLDSAPublicKey: %T", mldsaSigner.Public())
	}
	mlPubBytes, err := mlPub.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal ML-DSA public key: %w", err)
	}

	// Encode ML-DSA SubjectPublicKeyInfo (for extension value).
	altSPKI := certSPKI{
		Algorithm: certAlgID{Algorithm: mldsaOID},
		PublicKey: asn1.BitString{Bytes: mlPubBytes, BitLength: len(mlPubBytes) * 8},
	}
	altSPKIDER, err := asn1.Marshal(altSPKI)
	if err != nil {
		return nil, fmt.Errorf("marshal alt SPKI: %w", err)
	}

	// Step 2: Build the first TBS (without AltSignatureValue) and sign with ML-DSA.
	// Add AltPublicKey and AltSigAlgorithm extensions, but NOT AltSignatureValue yet.
	altSigAlgoDER, err := asn1.Marshal(certAlgID{Algorithm: mldsaOID})
	if err != nil {
		return nil, fmt.Errorf("marshal alt sig algorithm: %w", err)
	}

	tbsForMLDSA := *template
	tbsForMLDSA.ExtraExtensions = append(tbsForMLDSA.ExtraExtensions,
		pkix.Extension{Id: oidAltSubjectPublicKeyInfo, Value: altSPKIDER},
		pkix.Extension{Id: oidAltSignatureAlgorithm, Value: altSigAlgoDER},
	)

	tbsOnlyDER, err := buildTBSCertificate(&tbsForMLDSA, parent, classicalSigner.Public(), classicalSigner)
	if err != nil {
		return nil, fmt.Errorf("build TBS for ML-DSA signing: %w", err)
	}

	// Sign TBS with ML-DSA (signs the full message, not a hash).
	altSig, err := mldsaSigner.Sign(rand.Reader, tbsOnlyDER, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("ML-DSA sign TBS: %w", err)
	}

	// Step 3: Encode the ML-DSA signature as AltSignatureValue extension.
	altSigDER, err := asn1.Marshal(asn1.BitString{Bytes: altSig, BitLength: len(altSig) * 8})
	if err != nil {
		return nil, fmt.Errorf("marshal alt signature value: %w", err)
	}

	// Step 4: Build final TBS with all three alt-sig extensions including AltSignatureValue.
	finalTemplate := *template
	finalTemplate.ExtraExtensions = append(finalTemplate.ExtraExtensions,
		pkix.Extension{Id: oidAltSubjectPublicKeyInfo, Value: altSPKIDER},
		pkix.Extension{Id: oidAltSignatureAlgorithm, Value: altSigAlgoDER},
		pkix.Extension{Id: oidAltSignatureValue, Value: altSigDER},
	)

	// Step 5: Use standard x509.CreateCertificate with the ECDSA signer.
	// This produces a classical cert that all current TLS stacks can verify,
	// with the ML-DSA extensions carried transparently as non-critical.
	certDER, err := x509.CreateCertificate(rand.Reader, &finalTemplate, parent, classicalSigner.Public(), classicalSigner)
	if err != nil {
		return nil, fmt.Errorf("create hybrid certificate: %w", err)
	}

	return certDER, nil
}

// buildTBSCertificate creates just the TBSCertificate DER bytes by creating a
// throwaway certificate with x509.CreateCertificate and extracting the TBS portion.
// The throwaway signature is discarded — we only need the TBS bytes for ML-DSA signing.
func buildTBSCertificate(template, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) ([]byte, error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
	if err != nil {
		return nil, fmt.Errorf("build TBS (throwaway cert): %w", err)
	}
	return extractTBSCertificate(certDER)
}

// extractTBSCertificate parses a DER certificate and returns the raw TBSCertificate bytes.
func extractTBSCertificate(certDER []byte) ([]byte, error) {
	var outer struct {
		TBSCertificate asn1.RawValue
		Rest           asn1.RawValue
	}
	rest, err := asn1.Unmarshal(certDER, &outer)
	if err != nil || len(rest) > 0 {
		return nil, fmt.Errorf("parse outer certificate: %w", err)
	}
	return outer.TBSCertificate.FullBytes, nil
}

// HybridCertInfo extracts hybrid certificate information from a parsed cert.
// Returns (hasAltKey, hasAltSig, mldsaPublicKeyBytes, mldsaSigBytes).
func HybridCertInfo(cert *x509.Certificate) (hasAltKey, hasAltSig bool, altPubBytes, altSigBytes []byte) {
	for _, ext := range cert.Extensions {
		switch {
		case ext.Id.Equal(oidAltSubjectPublicKeyInfo):
			hasAltKey = true
			// Decode SPKI to get the raw public key bytes.
			var spki certSPKI
			if _, err := asn1.Unmarshal(ext.Value, &spki); err == nil {
				altPubBytes = spki.PublicKey.Bytes
			}
		case ext.Id.Equal(oidAltSignatureValue):
			hasAltSig = true
			var bs asn1.BitString
			if _, err := asn1.Unmarshal(ext.Value, &bs); err == nil {
				altSigBytes = bs.Bytes
			}
		}
	}
	return
}

// suppress unused import warning
var _ = time.Now
