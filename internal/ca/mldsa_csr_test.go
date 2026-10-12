// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"testing"
	"time"

	"kryptkeeper/internal/keystore"
)

func newTestMLDSASigner(t *testing.T, algo keystore.Algorithm) (keystore.Store, string) {
	t.Helper()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("test-passphrase-not-for-production"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	keyID := "csr-test-key"
	if _, err := keys.GenerateKey(keyID, algo); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return keys, keyID
}

func TestCreateAndParseCertificateRequestMLDSA_RoundTrip(t *testing.T) {
	for _, algo := range []keystore.Algorithm{keystore.MLDSA44, keystore.MLDSA65, keystore.MLDSA87} {
		t.Run(string(algo), func(t *testing.T) {
			keys, keyID := newTestMLDSASigner(t, algo)
			signer, err := keys.Signer(keyID)
			if err != nil {
				t.Fatalf("signer: %v", err)
			}

			subject := pkix.Name{CommonName: "leaf.example.com"}
			der, err := CreateCertificateRequestMLDSA(subject, nil, nil, signer, algo)
			if err != nil {
				t.Fatalf("CreateCertificateRequestMLDSA: %v", err)
			}

			parsed, err := ParseCertificateRequestMLDSA(der)
			if err != nil {
				t.Fatalf("ParseCertificateRequestMLDSA: %v", err)
			}
			if parsed.Subject.CommonName != "leaf.example.com" {
				t.Errorf("CommonName = %q, want leaf.example.com", parsed.Subject.CommonName)
			}
			if parsed.Algorithm != algo {
				t.Errorf("Algorithm = %s, want %s", parsed.Algorithm, algo)
			}
			originalPub, err := signer.Public().(keystore.MLDSAPublicKey).MarshalBinary()
			if err != nil {
				t.Fatalf("marshal original pub: %v", err)
			}
			parsedPubBytes, err := parsed.PublicKey.MarshalBinary()
			if err != nil {
				t.Fatalf("marshal parsed pub: %v", err)
			}
			if string(originalPub) != string(parsedPubBytes) {
				t.Errorf("public key mismatch after round-trip")
			}
		})
	}
}

func TestCreateAndParseCertificateRequestMLDSA_SANsRoundTrip(t *testing.T) {
	keys, keyID := newTestMLDSASigner(t, keystore.MLDSA65)
	signer, err := keys.Signer(keyID)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	wantDNS := []string{"a.example.com", "b.example.com"}
	der, err := CreateCertificateRequestMLDSA(pkix.Name{CommonName: "leaf.example.com"}, wantDNS, nil, signer, keystore.MLDSA65)
	if err != nil {
		t.Fatalf("CreateCertificateRequestMLDSA: %v", err)
	}
	parsed, err := ParseCertificateRequestMLDSA(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequestMLDSA: %v", err)
	}
	if len(parsed.DNSNames) != len(wantDNS) {
		t.Fatalf("DNSNames = %v, want %v", parsed.DNSNames, wantDNS)
	}
	for i, want := range wantDNS {
		if parsed.DNSNames[i] != want {
			t.Errorf("DNSNames[%d] = %q, want %q", i, parsed.DNSNames[i], want)
		}
	}
}

func TestParseCertificateRequestMLDSA_TamperedSignatureRejected(t *testing.T) {
	keys, keyID := newTestMLDSASigner(t, keystore.MLDSA65)
	signer, err := keys.Signer(keyID)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	der, err := CreateCertificateRequestMLDSA(pkix.Name{CommonName: "leaf.example.com"}, nil, nil, signer, keystore.MLDSA65)
	if err != nil {
		t.Fatalf("CreateCertificateRequestMLDSA: %v", err)
	}

	tampered := append([]byte(nil), der...)
	tampered[len(tampered)-1] ^= 0xFF // flip a byte inside the signature bit string
	if _, err := ParseCertificateRequestMLDSA(tampered); err == nil {
		t.Fatal("expected tampered CSR to fail signature verification, got nil error")
	}
}

// TestIssueCertificateFromPQCCSR_PolicyAlgorithmEnforced proves the Known
// Traps gap this ticket must not leave silent: ValidateAgainstTemplate's own
// algorithm check can't see req.PQCCSR (it only inspects req.CSR), so
// issueCertificateFromPQCCSR needs its own allowlist check -- this test
// fails without it.
func TestIssueCertificateFromPQCCSR_PolicyAlgorithmEnforced(t *testing.T) {
	engine := newMLDSATestEngine(t)
	root, err := engine.CreateRootCA("Policy Root", pkix.Name{CommonName: "Policy Root CA"}, keystore.MLDSA65, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}

	keys, keyID := newTestMLDSASigner(t, keystore.MLDSA65)
	signer, err := keys.Signer(keyID)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	der, err := CreateCertificateRequestMLDSA(pkix.Name{CommonName: "leaf.example.com"}, nil, nil, signer, keystore.MLDSA65)
	if err != nil {
		t.Fatalf("CreateCertificateRequestMLDSA: %v", err)
	}
	pqcCSR, err := ParseCertificateRequestMLDSA(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequestMLDSA: %v", err)
	}

	policy := &TemplatePolicy{ID: "ecdsa-only", AllowedAlgorithms: []string{"ECDSA"}}
	_, err = engine.IssueCertificate(root.ID, IssuanceRequest{
		PQCCSR: pqcCSR,
		Policy: policy,
	})
	if err == nil {
		t.Fatal("expected policy violation for ML-DSA against an ECDSA-only allowlist, got nil")
	}
	if !errors.Is(err, ErrPolicyViolation) {
		t.Errorf("expected ErrPolicyViolation, got %v", err)
	}
}

// TestIssueCertificateFromPQCCSR_ClassicalCAWorks proves G-69's fix: a
// classical CA can now issue an ML-DSA leaf end-to-end (this test asserted
// the OPPOSITE, a rejection, before W4-08's createCertDER widening --
// updated per W4-08's spec rather than left stale asserting old, now-wrong
// behavior). Verifies the issued cert's signature independently against the
// CA's real public key, not just "no error returned".
func TestIssueCertificateFromPQCCSR_ClassicalCAWorks(t *testing.T) {
	engine := newTestEngine(t)
	classicalRoot, err := engine.CreateRootCA("Classical Root", pkix.Name{CommonName: "Classical Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create classical root CA: %v", err)
	}

	mlKeys, mlKeyID := newTestMLDSASigner(t, keystore.MLDSA65)
	mlSigner, err := mlKeys.Signer(mlKeyID)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	der, err := CreateCertificateRequestMLDSA(pkix.Name{CommonName: "leaf.example.com"}, nil, nil, mlSigner, keystore.MLDSA65)
	if err != nil {
		t.Fatalf("CreateCertificateRequestMLDSA: %v", err)
	}
	pqcCSR, err := ParseCertificateRequestMLDSA(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequestMLDSA: %v", err)
	}

	issued, err := engine.IssueCertificate(classicalRoot.ID, IssuanceRequest{PQCCSR: pqcCSR})
	if err != nil {
		t.Fatalf("expected a classical CA to successfully issue an ML-DSA leaf, got: %v", err)
	}

	var outer outerCert
	if _, err := asn1.Unmarshal(issued.Certificate.Raw, &outer); err != nil {
		t.Fatalf("unmarshal issued cert: %v", err)
	}
	caObj, err := engine.GetCA(classicalRoot.ID)
	if err != nil {
		t.Fatalf("get CA: %v", err)
	}
	caSigner, err := engine.keys.Signer(caObj.KeyID)
	if err != nil {
		t.Fatalf("get CA signer: %v", err)
	}
	caEcdsaPub, ok := caSigner.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", caSigner.Public())
	}
	h := crypto.SHA256.New()
	h.Write(outer.TBSCertificate.FullBytes)
	if !ecdsa.VerifyASN1(caEcdsaPub, h.Sum(nil), outer.Signature.Bytes) {
		t.Fatal("issued certificate's signature does not verify against the classical CA's public key")
	}
}

// TestIssueCertificateFromPQCCSR_SignatureVerifiable proves the issued
// certificate is a cryptographically USABLE cert, not just well-formed DER
// with the right bytes in the right place: independently re-derives the
// TBSCertificate bytes and verifies the CA's ML-DSA signature over them with
// the CA's own public key. Neither stdlib x509.Certificate.CheckSignatureFrom
// nor anything elsewhere in this codebase does this for a hand-rolled ML-DSA
// cert (stdlib doesn't recognize the algorithm at all) -- this is the first
// real chain-verification proof for CreateCertificateMLDSA's leaf-issuance
// path, exercised here via the new PQCCSR route.
func TestIssueCertificateFromPQCCSR_SignatureVerifiable(t *testing.T) {
	engine := newMLDSATestEngine(t)
	root, err := engine.CreateRootCA("Verify Root", pkix.Name{CommonName: "Verify Root CA"}, keystore.MLDSA65, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}

	keys, keyID := newTestMLDSASigner(t, keystore.MLDSA65)
	signer, err := keys.Signer(keyID)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	der, err := CreateCertificateRequestMLDSA(pkix.Name{CommonName: "verify.example.com"}, nil, nil, signer, keystore.MLDSA65)
	if err != nil {
		t.Fatalf("CreateCertificateRequestMLDSA: %v", err)
	}
	pqcCSR, err := ParseCertificateRequestMLDSA(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequestMLDSA: %v", err)
	}

	issued, err := engine.IssueCertificate(root.ID, IssuanceRequest{PQCCSR: pqcCSR})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Re-derive the TBS bytes and verify against the CA's own public key --
	// same dispatch (verifyMLDSA) used to verify a CSR's self-signature.
	var outer outerCert
	if _, err := asn1.Unmarshal(issued.Certificate.Raw, &outer); err != nil {
		t.Fatalf("unmarshal issued cert: %v", err)
	}
	caObj, err := engine.GetCA(root.ID)
	if err != nil {
		t.Fatalf("get CA: %v", err)
	}
	caSigner, err := engine.keys.Signer(caObj.KeyID)
	if err != nil {
		t.Fatalf("get CA signer: %v", err)
	}
	caPub, ok := caSigner.Public().(keystore.MLDSAPublicKey)
	if !ok {
		t.Fatal("CA public key is not ML-DSA")
	}
	if !verifyMLDSA(keystore.MLDSA65, caPub, outer.TBSCertificate.FullBytes, outer.Signature.Bytes) {
		t.Fatal("issued certificate's signature does not verify against the CA's public key -- not a usable cert")
	}
}
