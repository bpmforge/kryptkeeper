// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

	"kryptkeeper/internal/keystore"
)

// keyAlgorithmDisplay names the ML-DSA parameter set (ML-DSA-44/65/87) of a
// certificate's subject key. The stored public_key_algorithm column only
// allows the family name "ML-DSA" and key_size_bits is 0 for these keys, so
// the parameter set is read from the SubjectPublicKeyInfo algorithm OID --
// which, unlike x509.Certificate.PublicKeyAlgorithm, works on toolchains whose
// stdlib cannot parse ML-DSA keys. Returns "" for any other key.
func keyAlgorithmDisplay(cert *x509.Certificate) string {
	if cert == nil || len(cert.RawSubjectPublicKeyInfo) == 0 {
		return ""
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if rest, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil || len(rest) != 0 {
		return ""
	}
	switch {
	case spki.Algorithm.Algorithm.Equal(keystore.OIDMLDsa44):
		return string(keystore.MLDSA44)
	case spki.Algorithm.Algorithm.Equal(keystore.OIDMLDsa65):
		return string(keystore.MLDSA65)
	case spki.Algorithm.Algorithm.Equal(keystore.OIDMLDsa87):
		return string(keystore.MLDSA87)
	}
	return ""
}
