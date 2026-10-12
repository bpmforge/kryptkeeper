// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"kryptkeeper/internal/keystore"
)

// suppress unused import
var _ = pkix.Name{}

func newHybridTestEngine(t *testing.T) *Engine {
	t.Helper()
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("hybrid-test-passphrase-32chars!!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	return NewEngine(keys, NewMemStore())
}

func TestCreateRootCAWithHybridP256MLDSA65(t *testing.T) {
	engine := newHybridTestEngine(t)

	ca, err := engine.CreateRootCA("Hybrid Root CA", pkix.Name{
		CommonName:   "Hybrid Test Root CA",
		Organization: []string{"Kryptkeeper Test"},
	}, keystore.HybridECDSAP256MLDSA65, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA hybrid: %v", err)
	}

	if ca.Certificate == nil {
		t.Fatal("certificate is nil")
	}
	if ca.Certificate.Subject.CommonName != "Hybrid Test Root CA" {
		t.Errorf("unexpected CN: %s", ca.Certificate.Subject.CommonName)
	}

	// The primary signature algorithm should be ECDSA (classical path).
	sigAlgo := ca.Certificate.SignatureAlgorithm
	if sigAlgo != x509.ECDSAWithSHA256 && sigAlgo != x509.ECDSAWithSHA384 {
		t.Errorf("expected ECDSA primary signature, got %v", sigAlgo)
	}

	// The cert should have the alt-signature extensions.
	hasAltKey, hasAltSig, altPubBytes, altSigBytes := HybridCertInfo(ca.Certificate)
	if !hasAltKey {
		t.Error("expected AltSubjectPublicKeyInfo extension")
	}
	if !hasAltSig {
		t.Error("expected AltSignatureValue extension")
	}
	if len(altPubBytes) == 0 {
		t.Error("expected non-empty alt public key bytes")
	}
	if len(altSigBytes) == 0 {
		t.Error("expected non-empty alt signature bytes")
	}

	// Verify the ML-DSA signature over the TBSCertificate.
	altSigValid := verifyMLDSA65AltSig(t, ca.Certificate, altPubBytes, altSigBytes)
	if !altSigValid {
		t.Error("ML-DSA alt signature verification failed")
	}

	t.Logf("Hybrid cert size: %d bytes DER (ECDSA-P256 + ML-DSA-65)", len(ca.Certificate.Raw))
}

func TestCreateRootCAWithHybridP384MLDSA87(t *testing.T) {
	engine := newHybridTestEngine(t)
	ca, err := engine.CreateRootCA("Hybrid-P384", pkix.Name{CommonName: "Hybrid P384 Root"}, keystore.HybridECDSAP384MLDSA87, 5*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA Hybrid-P384: %v", err)
	}
	if ca.Certificate == nil {
		t.Fatal("certificate is nil")
	}
	_, hasAltSig, _, _ := HybridCertInfo(ca.Certificate)
	if !hasAltSig {
		t.Error("expected AltSignatureValue in Hybrid-P384 cert")
	}
}

func TestHybridCertClassicalVerifierAccepts(t *testing.T) {
	// The classical ECDSA verifier must accept the hybrid cert — this is the
	// backward-compatibility guarantee.
	engine := newHybridTestEngine(t)
	ca, err := engine.CreateRootCA("Classical Verify", pkix.Name{CommonName: "Classical Verify CA"}, keystore.HybridECDSAP256MLDSA65, 5*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	// x509.Certificate.CheckSignatureFrom on a self-signed cert verifies the primary sig.
	if err := ca.Certificate.CheckSignatureFrom(ca.Certificate); err != nil {
		t.Errorf("classical ECDSA signature verification failed: %v", err)
	}
}

func TestHybridKeyStoredAndReloadable(t *testing.T) {
	engine := newHybridTestEngine(t)
	ca, err := engine.CreateRootCA("Reload Test", pkix.Name{CommonName: "Reload CA"}, keystore.HybridECDSAP256MLDSA65, 5*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	got, err := engine.GetCA(ca.ID)
	if err != nil {
		t.Fatalf("GetCA: %v", err)
	}
	if got.ID != ca.ID {
		t.Errorf("ID mismatch: %s vs %s", got.ID, ca.ID)
	}
}

func TestIssueCertFromHybridCA(t *testing.T) {
	engine := newHybridTestEngine(t)
	rootCA, err := engine.CreateRootCA("Hybrid Issuer", pkix.Name{CommonName: "Hybrid Issuer CA"}, keystore.HybridECDSAP256MLDSA65, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create hybrid CA: %v", err)
	}

	// Issue a classical ECDSA leaf cert from the hybrid CA.
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "leaf.example.com"},
	}, clientKey)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, _ := x509.ParseCertificateRequest(csrDER)

	issued, err := engine.IssueCertificate(rootCA.ID, IssuanceRequest{
		CSR:         csr,
		Validity:    90 * 24 * time.Hour,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("IssueCertificate from hybrid CA: %v", err)
	}

	if issued.Certificate.Subject.CommonName != "leaf.example.com" {
		t.Errorf("unexpected CN: %s", issued.Certificate.Subject.CommonName)
	}

	// Leaf cert should have ECDSA primary signature from hybrid CA.
	if err := issued.Certificate.CheckSignatureFrom(rootCA.Certificate); err != nil {
		t.Errorf("leaf cert ECDSA signature invalid: %v", err)
	}
}

// verifyMLDSA65AltSig reconstructs the TBS (without AltSignatureValue extension)
// and verifies the ML-DSA signature.
func verifyMLDSA65AltSig(t *testing.T, cert *x509.Certificate, altPubBytes, altSigBytes []byte) bool {
	t.Helper()

	var pub mldsa65.PublicKey
	if err := pub.UnmarshalBinary(altPubBytes); err != nil {
		t.Logf("unmarshal ML-DSA-65 public key: %v", err)
		return false
	}

	// Reconstruct TBS without the AltSignatureValue extension.
	tbsBytes, err := extractTBSWithoutAltSigValue(cert)
	if err != nil {
		t.Logf("extract TBS without alt sig: %v", err)
		return false
	}

	return mldsa65.Verify(&pub, tbsBytes, nil, altSigBytes)
}

// extractTBSWithoutAltSigValue reconstructs the TBSCertificate as it existed
// before the AltSignatureValue extension was added. The ML-DSA signature was
// computed over this TBS (per draft-ounsworth-x509-alt-sig-alg).
func extractTBSWithoutAltSigValue(cert *x509.Certificate) ([]byte, error) {
	return rebuildTBSWithoutExtension(cert.Raw, oidAltSignatureValue)
}

// rebuildTBSWithoutExtension parses a DER certificate, strips the named extension
// from the TBSCertificate, and returns the re-encoded TBS bytes.
func rebuildTBSWithoutExtension(certDER []byte, stripOID asn1.ObjectIdentifier) ([]byte, error) {
	// Parse outer cert to get TBS raw bytes.
	var outer struct {
		TBSCertRaw asn1.RawValue
		SigAlg     asn1.RawValue
		Sig        asn1.RawValue
	}
	if _, err := asn1.Unmarshal(certDER, &outer); err != nil {
		return nil, fmt.Errorf("unmarshal cert: %w", err)
	}
	tbsBytes := outer.TBSCertRaw.FullBytes

	// Parse TBSCertificate to find and remove the target extension.
	var tbs struct {
		Version  asn1.RawValue `asn1:"optional,explicit,tag:0"`
		Serial   asn1.RawValue
		SigAlg   asn1.RawValue
		Issuer   asn1.RawValue
		Validity asn1.RawValue
		Subject  asn1.RawValue
		SPKI     asn1.RawValue
		ExtsWrap asn1.RawValue `asn1:"optional,explicit,tag:3"`
	}
	if _, err := asn1.Unmarshal(tbsBytes, &tbs); err != nil {
		return nil, fmt.Errorf("unmarshal TBS: %w", err)
	}

	// Parse the extensions SEQUENCE.
	var exts []struct {
		OID      asn1.ObjectIdentifier
		Critical bool `asn1:"optional"`
		Value    []byte
	}
	if _, err := asn1.Unmarshal(tbs.ExtsWrap.Bytes, &exts); err != nil {
		return nil, fmt.Errorf("unmarshal extensions: %w", err)
	}

	// Filter out the target extension.
	var filtered []struct {
		OID      asn1.ObjectIdentifier
		Critical bool `asn1:"optional"`
		Value    []byte
	}
	for _, ext := range exts {
		if !ext.OID.Equal(stripOID) {
			filtered = append(filtered, ext)
		}
	}

	// Re-encode the filtered extensions.
	filteredDER, err := asn1.Marshal(filtered)
	if err != nil {
		return nil, fmt.Errorf("marshal filtered extensions: %w", err)
	}

	// Wrap in explicit [3] tag.
	wrappedExts := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        3,
		IsCompound: true,
		Bytes:      filteredDER,
	}

	// Rebuild TBSCertificate fields (in order, omitting ExtsWrap if empty).
	fields := []asn1.RawValue{
		tbs.Version, tbs.Serial, tbs.SigAlg, tbs.Issuer,
		tbs.Validity, tbs.Subject, tbs.SPKI,
	}
	if len(filtered) > 0 {
		fields = append(fields, wrappedExts)
	}
	// Remove zero-length optional fields (Version may be absent for v1).
	var tbsBody []byte
	for _, f := range fields {
		if len(f.FullBytes) == 0 && len(f.Bytes) == 0 {
			continue
		}
		b, err := asn1.Marshal(f)
		if err != nil {
			return nil, err
		}
		if len(f.FullBytes) > 0 {
			tbsBody = append(tbsBody, f.FullBytes...)
		} else {
			tbsBody = append(tbsBody, b...)
		}
	}

	// Wrap body in SEQUENCE.
	rebuilt, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      tbsBody,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal rebuilt TBS: %w", err)
	}
	return rebuilt, nil
}
