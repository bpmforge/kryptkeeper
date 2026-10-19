// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package crl

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// W31-05: the generator signs a base CRL for an ML-DSA CA (the stdlib refused
// the keystore signer) and the signature verifies under the CA key.
func TestGenerateMLDSACA(t *testing.T) {
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("mldsa-test-passphrase-32chars!!!!"))
	if err != nil {
		t.Fatal(err)
	}
	root, err := ca.NewEngine(keys, ca.NewMemStore()).CreateRootCA("ML-DSA CRL Root", pkix.Name{CommonName: "ML-DSA CRL Root"}, keystore.MLDSA65, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := keys.Signer(root.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	gen := NewGenerator(
		func(string) ([]RevokedCert, error) {
			return []RevokedCert{{SerialNumber: big.NewInt(4242), RevokedAt: time.Now().Add(-time.Hour), ReasonCode: 1}}, nil
		},
		func(string) (*x509.Certificate, crypto.Signer, error) { return root.Certificate, signer, nil },
		time.Hour,
	)
	out, err := gen.Generate(root.ID)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	parsed, err := x509.ParseRevocationList(out.DER)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed.RevokedCertificateEntries) != 1 || parsed.RevokedCertificateEntries[0].SerialNumber.Int64() != 4242 {
		t.Fatalf("serial 4242 not listed: %+v", parsed.RevokedCertificateEntries)
	}
	var signed struct {
		TBS asn1.RawValue
		Alg pkix.AlgorithmIdentifier
		Sig asn1.BitString
	}
	if _, err := asn1.Unmarshal(out.DER, &signed); err != nil {
		t.Fatal(err)
	}
	pub := signer.Public().(*mldsa65.PublicKey)
	if !mldsa65.Verify(pub, signed.TBS.FullBytes, nil, signed.Sig.Bytes) {
		t.Fatal("CRL signature does not verify under the CA key")
	}
}
