// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"kryptkeeper/internal/keystore"
)

// classicalTestSigner builds a real classical signer for algo, for testing
// CreateCertificateMixedLeaf against every supported CA signature scheme.
func classicalTestSigner(t *testing.T, algo keystore.Algorithm) crypto.Signer {
	t.Helper()
	switch algo {
	case keystore.ECDSAP256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate ECDSA-P256 key: %v", err)
		}
		return key
	case keystore.ECDSAP384:
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("generate ECDSA-P384 key: %v", err)
		}
		return key
	case keystore.RSA2048:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate RSA-2048 key: %v", err)
		}
		return key
	case keystore.Ed25519:
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate Ed25519 key: %v", err)
		}
		return key
	}
	t.Fatalf("unsupported test algorithm %s", algo)
	return nil
}

// verifyClassicalSignature independently verifies sig over msg with pub via
// the production verifyClassicalCSRSignature (mixed_cert.go) -- proves
// CreateCertificateMixedLeaf produced a genuinely usable certificate
// signature, not just well-formed DER, without duplicating the dispatch
// logic in test code.
func verifyClassicalSignature(t *testing.T, algo keystore.Algorithm, pub crypto.PublicKey, msg, sig []byte, hash crypto.Hash) bool {
	t.Helper()
	return verifyClassicalCSRSignature(algo, hash, pub, msg, sig)
}

func TestCreateCertificateMixedLeaf_ClassicalCASignsMLDSALeaf(t *testing.T) {
	for _, algo := range []keystore.Algorithm{keystore.ECDSAP256, keystore.ECDSAP384, keystore.RSA2048, keystore.Ed25519} {
		t.Run(string(algo), func(t *testing.T) {
			caSigner := classicalTestSigner(t, algo)

			leafKeys, leafKeyID := newTestMLDSASigner(t, keystore.MLDSA65)
			leafSigner, err := leafKeys.Signer(leafKeyID)
			if err != nil {
				t.Fatalf("leaf signer: %v", err)
			}

			caTemplate := &x509.Certificate{
				SerialNumber:          big.NewInt(1),
				Subject:               pkix.Name{CommonName: "Mixed Test CA"},
				NotBefore:             time.Now(),
				NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
				IsCA:                  true,
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageCertSign,
			}
			caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, publicFromSigner(t, algo, caSigner), caSigner)
			if err != nil {
				t.Fatalf("create classical CA cert: %v", err)
			}
			caCert, err := x509.ParseCertificate(caDER)
			if err != nil {
				t.Fatalf("parse classical CA cert: %v", err)
			}

			leafTemplate := &x509.Certificate{
				SerialNumber: big.NewInt(2),
				Subject:      pkix.Name{CommonName: "mixed-leaf.example.com"},
				NotBefore:    time.Now(),
				NotAfter:     time.Now().Add(90 * 24 * time.Hour),
			}
			leafDER, err := CreateCertificateMixedLeaf(leafTemplate, caCert, leafSigner.Public(), caSigner, algo)
			if err != nil {
				t.Fatalf("CreateCertificateMixedLeaf: %v", err)
			}

			reparsed, err := x509.ParseCertificate(leafDER)
			if err != nil {
				t.Fatalf("x509.ParseCertificate on the issued leaf: %v", err)
			}
			if reparsed.Subject.CommonName != "mixed-leaf.example.com" {
				t.Errorf("CommonName = %q, want mixed-leaf.example.com", reparsed.Subject.CommonName)
			}

			var outer outerCert
			if _, err := asn1.Unmarshal(leafDER, &outer); err != nil {
				t.Fatalf("unmarshal issued leaf: %v", err)
			}
			_, hash, ok := classicalSignatureAlgOID(algo)
			if !ok {
				t.Fatalf("no signature alg OID for %s", algo)
			}
			if hash == 0 {
				if !ed25519.Verify(publicFromSigner(t, algo, caSigner).(ed25519.PublicKey), outer.TBSCertificate.FullBytes, outer.Signature.Bytes) {
					t.Fatal("issued leaf's Ed25519 signature does not verify against the CA's public key")
				}
			} else if !verifyClassicalSignature(t, algo, caSigner.Public(), outer.TBSCertificate.FullBytes, outer.Signature.Bytes, hash) {
				t.Fatal("issued leaf's signature does not verify against the CA's public key -- not a usable cert")
			}
		})
	}
}

func TestCreateCertificateMixedLeaf_TamperedSignatureRejected(t *testing.T) {
	caSigner := classicalTestSigner(t, keystore.ECDSAP256)
	leafKeys, leafKeyID := newTestMLDSASigner(t, keystore.MLDSA65)
	leafSigner, err := leafKeys.Signer(leafKeyID)
	if err != nil {
		t.Fatalf("leaf signer: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Tamper Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, publicFromSigner(t, keystore.ECDSAP256, caSigner), caSigner)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "tamper-leaf.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	leafDER, err := CreateCertificateMixedLeaf(leafTemplate, caCert, leafSigner.Public(), caSigner, keystore.ECDSAP256)
	if err != nil {
		t.Fatalf("CreateCertificateMixedLeaf: %v", err)
	}

	var outer outerCert
	if _, err := asn1.Unmarshal(leafDER, &outer); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	tamperedSig := append([]byte(nil), outer.Signature.Bytes...)
	tamperedSig[0] ^= 0xFF
	_, hash, _ := classicalSignatureAlgOID(keystore.ECDSAP256)
	if verifyClassicalSignature(t, keystore.ECDSAP256, caSigner.Public(), outer.TBSCertificate.FullBytes, tamperedSig, hash) {
		t.Fatal("expected tampered signature to fail verification, but it verified")
	}
}

// publicFromSigner returns the crypto.PublicKey for a classicalTestSigner
// result, since ed25519.PrivateKey.Public() returns ed25519.PublicKey (a
// value type) while the others return pointer types -- x509.CreateCertificate
// needs the right concrete type either way, this just centralizes the call.
func publicFromSigner(t *testing.T, algo keystore.Algorithm, signer crypto.Signer) crypto.PublicKey {
	t.Helper()
	return signer.Public()
}
