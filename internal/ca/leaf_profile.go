// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

var (
	oidExtKeyUsage     = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidKPTimeStamping  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidOCSPNoCheck     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}
	signingOnlyEKUs    = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageTimeStamping, x509.ExtKeyUsageOCSPSigning}
	encipherKeyUsageKU = x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment
)

// leafKeyUsage drops key-encipherment bits a leaf cannot honestly carry. The
// callers (REST, ACME, EST, SCEP, CMP, WSTEP) all default to
// digitalSignature|keyEncipherment, which RFC 5480 (EC), RFC 8410 and the ML-DSA
// X.509 profile prohibit for non-RSA keys, and which makes no sense on a
// signing-only certificate (code signing, time stamping, OCSP responder). RSA
// TLS/client leaves keep the bits: TLS 1.2 RSA key exchange and SCEP rely on them.
func leafKeyUsage(ku x509.KeyUsage, ekus []x509.ExtKeyUsage, pub crypto.PublicKey) x509.KeyUsage {
	_, isRSA := pub.(*rsa.PublicKey)
	signingOnly := false
	for _, e := range ekus {
		for _, s := range signingOnlyEKUs {
			signingOnly = signingOnly || e == s
		}
	}
	if isRSA && !signingOnly {
		return ku
	}
	if ku&encipherKeyUsageKU == 0 {
		return ku
	}
	if ku &^= encipherKeyUsageKU; ku == 0 {
		ku = x509.KeyUsageDigitalSignature
	}
	return ku
}

// leafProfileExtensions returns the extensions standards require on specific
// EKU profiles but that crypto/x509 cannot express, and whether the template's
// ExtKeyUsage must be carried by them instead of by the stdlib field.
//
//   - RFC 3161 2.3: a time-stamping certificate's EKU MUST be critical, and
//     id-kp-timeStamping must be the only purpose. crypto/x509 always writes the
//     EKU non-critical, so the extension is built here and the template field
//     cleared to avoid a duplicate.
//   - RFC 6960 4.2.2.2.1: a delegated OCSP responder certificate carries
//     id-pkix-ocsp-nocheck so relying parties do not recurse into its own status.
func leafProfileExtensions(ekus []x509.ExtKeyUsage) (exts []pkix.Extension, clearEKU bool) {
	if len(ekus) == 1 && ekus[0] == x509.ExtKeyUsageTimeStamping {
		if val, err := asn1.Marshal([]asn1.ObjectIdentifier{oidKPTimeStamping}); err == nil {
			exts = append(exts, pkix.Extension{Id: oidExtKeyUsage, Critical: true, Value: val})
			clearEKU = true
		}
	}
	for _, e := range ekus {
		if e == x509.ExtKeyUsageOCSPSigning {
			exts = append(exts, pkix.Extension{Id: oidOCSPNoCheck, Value: []byte{0x05, 0x00}})
			break
		}
	}
	return exts, clearEKU
}

func hasExtension(exts []pkix.Extension, id asn1.ObjectIdentifier) bool {
	for _, e := range exts {
		if e.Id.Equal(id) {
			return true
		}
	}
	return false
}
