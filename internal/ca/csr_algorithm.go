// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"encoding/asn1"
	"fmt"
)

// csrInfoHead is CertificationRequestInfo (RFC 2986 §4) up to and including
// subjectPKInfo. Attributes are not declared: encoding/asn1 ignores unread
// trailing elements of a SEQUENCE, and this reader must not depend on them.
type csrInfoHead struct {
	Version   int `asn1:"default:0"`
	Subject   asn1.RawValue
	PublicKey certSPKI
}

// CSRPublicKeyAlgorithmOID returns the subjectPKInfo algorithm OID of a
// PKCS#10 CertificationRequest DER without verifying anything. It exists so
// callers can route a CSR to the right parser deterministically, by the OID
// the structure itself declares, rather than by PEM label or by trying
// parsers in turn.
func CSRPublicKeyAlgorithmOID(der []byte) (asn1.ObjectIdentifier, error) {
	var outer outerCSR
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil {
		return nil, fmt.Errorf("unmarshal CertificationRequest: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("trailing data after CertificationRequest")
	}
	var head csrInfoHead
	if _, err := asn1.Unmarshal(outer.CertificationRequestInfo.FullBytes, &head); err != nil {
		return nil, fmt.Errorf("unmarshal CertificationRequestInfo: %w", err)
	}
	return head.PublicKey.Algorithm.Algorithm, nil
}

// IsMLDSACSR reports whether der declares an ML-DSA subject public key
// (FIPS 204 OIDs). Malformed DER reports false: it then takes the stdlib
// path, which rejects it with its own parse error.
func IsMLDSACSR(der []byte) bool {
	oid, err := CSRPublicKeyAlgorithmOID(der)
	if err != nil {
		return false
	}
	_, ok := mldsaAlgoFromOID(oid)
	return ok
}
