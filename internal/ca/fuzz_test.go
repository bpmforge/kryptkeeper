// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509/pkix"
	"testing"

	"kryptkeeper/internal/keystore"
)

// FuzzParseCertificateRequestMLDSA covers the in-house ML-DSA PKCS#10
// parser (hand-rolled ASN.1 plus attribute decoding), which the stdlib
// x509 parser cannot read. A successful parse must carry a usable key.
func FuzzParseCertificateRequestMLDSA(f *testing.F) {
	for _, algo := range []keystore.Algorithm{keystore.MLDSA44, keystore.MLDSA65} {
		keys, err := keystore.NewSoftwareStore(f.TempDir(), []byte("fuzz-passphrase-not-for-production"))
		if err != nil {
			f.Fatal(err)
		}
		const keyID = "fuzz-key"
		if _, err := keys.GenerateKey(keyID, algo); err != nil {
			f.Fatal(err)
		}
		signer, err := keys.Signer(keyID)
		if err != nil {
			f.Fatal(err)
		}
		der, err := CreateCertificateRequestMLDSA(pkix.Name{CommonName: "fuzz.example.com"}, []string{"fuzz.example.com"}, nil, signer, algo)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(der)
		f.Add(der[:len(der)/2])
	}
	f.Add([]byte{0x30, 0x00})

	f.Fuzz(func(t *testing.T, der []byte) {
		csr, err := ParseCertificateRequestMLDSA(der)
		if err == nil && (csr == nil || csr.PublicKey == nil) {
			t.Fatal("successful parse returned nil request or key")
		}
		_, _ = CSRPublicKeyAlgorithmOID(der)
		_ = IsMLDSACSR(der)
	})
}
