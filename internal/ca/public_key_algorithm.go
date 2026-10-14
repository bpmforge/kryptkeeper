// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509"
	"encoding/asn1"
)

// StoredPublicKeyAlgorithm names a certificate's subject key algorithm in the
// vocabulary the certificates.public_key_algorithm CHECK admits (RSA, ECDSA,
// Ed25519, ML-DSA). crypto/x509 reports an ML-DSA SubjectPublicKeyInfo as
// UnknownPublicKeyAlgorithm ("unknown") on the pinned toolchain, which the
// CHECK rejects -- so every ML-DSA issuance was signed but never recorded.
// The SPKI OID is the authority; a hybrid cert's subject SPKI is classical by
// design, so it keeps its classical name.
func StoredPublicKeyAlgorithm(cert *x509.Certificate) string {
	if isMLDSASPKI(cert.RawSubjectPublicKeyInfo) {
		return "ML-DSA"
	}
	return cert.PublicKeyAlgorithm.String()
}

func isMLDSASPKI(rawSPKI []byte) bool {
	if len(rawSPKI) == 0 {
		return false
	}
	var spki struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(rawSPKI, &spki); err != nil {
		return false
	}
	_, ok := mldsaAlgoFromOID(spki.Algorithm.Algorithm)
	return ok
}
