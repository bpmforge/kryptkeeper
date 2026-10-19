// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"kryptkeeper/internal/keystore"
)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("test-ca-passphrase-32chars-min!!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	return NewEngine(keys, NewMemStore())
}

func TestCreateRootCA(t *testing.T) {
	engine := newTestEngine(t)

	root, err := engine.CreateRootCA("Test Root CA", pkix.Name{
		CommonName:   "Test Root CA",
		Organization: []string{"Kryptkeeper Test"},
		Country:      []string{"US"},
	}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}

	if root.Type != "root" {
		t.Errorf("expected type root, got %s", root.Type)
	}
	if root.Status != "active" {
		t.Errorf("expected active status, got %s", root.Status)
	}
	if root.Certificate == nil {
		t.Fatal("expected non-nil certificate")
	}
	if !root.Certificate.IsCA {
		t.Error("expected IsCA=true")
	}
	if root.Certificate.Subject.CommonName != "Test Root CA" {
		t.Errorf("expected CN=Test Root CA, got %s", root.Certificate.Subject.CommonName)
	}
	if root.ParentCAID != "" {
		t.Errorf("root CA should have empty ParentCAID, got %s", root.ParentCAID)
	}

	// Verify self-signed.
	if err := root.Certificate.CheckSignatureFrom(root.Certificate); err != nil {
		t.Errorf("root CA should be self-signed: %v", err)
	}

	// W19-08: default (no SetKeyBackend call) must report "software", not
	// leave the field blank or silently claim a backend never configured.
	if root.KeyStorageType != "software" {
		t.Errorf("expected default KeyStorageType=software, got %q", root.KeyStorageType)
	}
}

// TestCreateRootCARecordsConfiguredKeyBackend is the regression test for
// W19-08: CA.KeyStorageType was previously hardcoded to "software" in both
// the DB row and the API projection regardless of which keystore.Store
// backend actually generated the key -- an HSM-held root CA key was
// misreported as software custody. SetKeyBackend now makes the engine tell
// the truth about which backend it was constructed with.
func TestCreateRootCARecordsConfiguredKeyBackend(t *testing.T) {
	engine := newTestEngine(t)
	engine.SetKeyBackend("pkcs11")

	root, err := engine.CreateRootCA("Test Root CA", pkix.Name{CommonName: "Test Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}
	if root.KeyStorageType != "pkcs11" {
		t.Errorf("expected KeyStorageType=pkcs11, got %q", root.KeyStorageType)
	}
}

// TestCreateRootCARefusesPQCOnHardwareBackend is the regression test for the
// dead CheckHSMPQCSupport gate found alongside the KeyStorageType bug: the
// ADR-mandated refusal (docs/ADR_PQC_KEYS_SOFTWARE_ONLY.md) was defined and
// unit-tested in isolation but never called from any CA-creation path, so a
// hardware-backed engine would attempt real ML-DSA keygen against a backend
// that cannot do it (a raw crypto11/PKCS#11 error, not the documented
// refusal) instead of being stopped up front.
func TestCreateRootCARefusesPQCOnHardwareBackend(t *testing.T) {
	engine := newTestEngine(t)
	engine.SetKeyBackend("pkcs11")

	_, err := engine.CreateRootCA("Test PQC Root", pkix.Name{CommonName: "Test PQC Root"}, keystore.MLDSA44, 10*365*24*time.Hour)
	if err == nil {
		t.Fatal("expected error creating ML-DSA root CA on pkcs11 backend")
	}
	if !errors.Is(err, keystore.ErrPQCHSMUnsupported) {
		t.Errorf("expected wrapped ErrPQCHSMUnsupported, got: %v", err)
	}
}

func TestCreateIntermediateCA(t *testing.T) {
	engine := newTestEngine(t)

	root, err := engine.CreateRootCA("Test Root", pkix.Name{
		CommonName: "Test Root CA",
	}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}

	intermediate, err := engine.CreateIntermediateCA("Test Issuing CA", pkix.Name{
		CommonName:   "Test Issuing CA",
		Organization: []string{"Kryptkeeper Test"},
	}, keystore.ECDSAP256, root.ID, 5*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create intermediate: %v", err)
	}

	if intermediate.Type != "intermediate" {
		t.Errorf("expected type intermediate, got %s", intermediate.Type)
	}
	if intermediate.ParentCAID != root.ID {
		t.Errorf("expected ParentCAID=%s, got %s", root.ID, intermediate.ParentCAID)
	}
	if !intermediate.Certificate.IsCA {
		t.Error("intermediate should be a CA")
	}

	// Verify signed by root.
	if err := intermediate.Certificate.CheckSignatureFrom(root.Certificate); err != nil {
		t.Errorf("intermediate should be signed by root: %v", err)
	}

	// Verify intermediate validity doesn't exceed root.
	if intermediate.Certificate.NotAfter.After(root.Certificate.NotAfter) {
		t.Error("intermediate validity should not exceed root")
	}
}

func TestIntermediateCARequiresActiveParent(t *testing.T) {
	engine := newTestEngine(t)

	_, err := engine.CreateIntermediateCA("Orphan", pkix.Name{
		CommonName: "Orphan CA",
	}, keystore.ECDSAP256, "nonexistent-parent", 5*365*24*time.Hour)
	if err != ErrCANotFound {
		t.Fatalf("expected ErrCANotFound, got: %v", err)
	}
}

func TestIssueCertificateFromCSR(t *testing.T) {
	engine := newTestEngine(t)

	root, err := engine.CreateRootCA("Test Root", pkix.Name{
		CommonName: "Test Root CA",
	}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}

	// Generate a client key and CSR.
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		DNSNames: []string{"test.example.com", "www.test.example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, clientKey)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}

	issued, err := engine.IssueCertificate(root.ID, IssuanceRequest{
		CSR:           csr,
		Validity:      90 * 24 * time.Hour,
		KeyUsage:      x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		OCSPServer:    []string{"http://ocsp.example.com"},
		CRLDistPoints: []string{"http://crl.example.com/root.crl"},
	})
	if err != nil {
		t.Fatalf("issue certificate: %v", err)
	}

	if issued.Certificate.Subject.CommonName != "test.example.com" {
		t.Errorf("expected CN=test.example.com, got %s", issued.Certificate.Subject.CommonName)
	}
	if len(issued.Certificate.DNSNames) != 2 {
		t.Errorf("expected 2 SANs, got %d", len(issued.Certificate.DNSNames))
	}
	if issued.Fingerprint == "" {
		t.Error("expected non-empty fingerprint")
	}
	if issued.SerialNumber == nil {
		t.Error("expected non-nil serial number")
	}

	// Verify signed by root.
	if err := issued.Certificate.CheckSignatureFrom(root.Certificate); err != nil {
		t.Errorf("issued cert should be signed by root: %v", err)
	}

	// Verify OCSP and CRL extensions.
	if len(issued.Certificate.OCSPServer) != 1 || issued.Certificate.OCSPServer[0] != "http://ocsp.example.com" {
		t.Errorf("unexpected OCSP servers: %v", issued.Certificate.OCSPServer)
	}
	if len(issued.Certificate.CRLDistributionPoints) != 1 {
		t.Errorf("unexpected CRL dist points: %v", issued.Certificate.CRLDistributionPoints)
	}

	// Verify PEM is valid.
	block, _ := pem.Decode(issued.CertPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Error("expected valid PEM certificate")
	}
}

func TestIssueCertificateRejectsNilCSR(t *testing.T) {
	engine := newTestEngine(t)

	root, _ := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)

	_, err := engine.IssueCertificate(root.ID, IssuanceRequest{CSR: nil})
	if err != ErrInvalidCSR {
		t.Fatalf("expected ErrInvalidCSR, got: %v", err)
	}
}

func TestIssueCertificateRejectsInactiveCA(t *testing.T) {
	engine := newTestEngine(t)

	_, err := engine.IssueCertificate("nonexistent", IssuanceRequest{})
	if err != ErrCANotFound {
		t.Fatalf("expected ErrCANotFound, got: %v", err)
	}
}

func TestGetCAChain(t *testing.T) {
	engine := newTestEngine(t)

	root, _ := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	inter, _ := engine.CreateIntermediateCA("Intermediate", pkix.Name{CommonName: "Intermediate"}, keystore.ECDSAP256, root.ID, 5*365*24*time.Hour)

	chain, err := engine.GetCAChain(inter.ID)
	if err != nil {
		t.Fatalf("get chain: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("expected chain length 2, got %d", len(chain))
	}
	if chain[0].ID != inter.ID {
		t.Errorf("chain[0] should be intermediate, got %s", chain[0].ID)
	}
	if chain[1].ID != root.ID {
		t.Errorf("chain[1] should be root, got %s", chain[1].ID)
	}
}

func selfSignedRootPEM(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestImportCA(t *testing.T) {
	engine := newTestEngine(t)

	imported, err := engine.ImportCA("Imported Root", selfSignedRootPEM(t, "Source Root"))
	if err != nil {
		t.Fatalf("import CA: %v", err)
	}
	if imported.Type != "root" {
		t.Errorf("expected root type, got %s", imported.Type)
	}
	if imported.KeyID != "" {
		t.Error("imported CA should have no KeyID")
	}
	if imported.KeyStorageType != "external" {
		t.Errorf("imported CA key storage = %q, want external", imported.KeyStorageType)
	}
	if imported.Certificate.Subject.CommonName != "Source Root" {
		t.Errorf("expected CN=Source Root, got %s", imported.Certificate.Subject.CommonName)
	}
}

func TestImportCADuplicateAndTrustAnchorRemoval(t *testing.T) {
	engine := newTestEngine(t)
	rootPEM := selfSignedRootPEM(t, "Ext Root")
	imported, err := engine.ImportCA("Ext", rootPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.ImportCA("Ext again", rootPEM); !errors.Is(err, ErrCAAlreadyImported) {
		t.Fatalf("duplicate import: err = %v, want ErrCAAlreadyImported", err)
	}
	// A root the hub generated itself (it holds the key) is not a trust anchor.
	own, err := engine.CreateRootCA("Own", pkix.Name{CommonName: "Own"}, keystore.ECDSAP256, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.RemoveTrustAnchor(own.ID); !errors.Is(err, ErrNotTrustAnchor) {
		t.Fatalf("remove keyed root: err = %v, want ErrNotTrustAnchor", err)
	}
	if err := engine.RemoveTrustAnchor("missing"); !errors.Is(err, ErrCANotFound) {
		t.Fatalf("remove unknown: err = %v, want ErrCANotFound", err)
	}
	if err := engine.RemoveTrustAnchor(imported.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := engine.GetCA(imported.ID); got.Status != "revoked" {
		t.Fatalf("status = %s, want revoked", got.Status)
	}
	again, err := engine.ImportCA("Ext", rootPEM)
	if err != nil || again.ID != imported.ID || again.Status != "active" {
		t.Fatalf("re-import: %+v %v, want reactivation of %s", again, err, imported.ID)
	}
}

func TestImportCARjectsNonCA(t *testing.T) {
	engine := newTestEngine(t)

	// Create a leaf cert (non-CA) to try importing.
	root, _ := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)

	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "leaf.example.com"},
	}, clientKey)
	csr, _ := x509.ParseCertificateRequest(csrDER)

	leaf, _ := engine.IssueCertificate(root.ID, IssuanceRequest{
		CSR:      csr,
		Validity: 90 * 24 * time.Hour,
		KeyUsage: x509.KeyUsageDigitalSignature,
	})

	_, err := engine.ImportCA("Not A CA", leaf.CertPEM)
	if err == nil {
		t.Fatal("expected error importing non-CA certificate")
	}
}

// Task 0.4: naked intermediate import must be rejected; ImportCAChain must succeed.
func TestImportCARejectsNakedIntermediate(t *testing.T) {
	engine := newTestEngine(t)

	root, _ := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	inter, _ := engine.CreateIntermediateCA("Inter", pkix.Name{CommonName: "Inter"}, keystore.ECDSAP256, root.ID, 5*365*24*time.Hour)

	_, err := engine.ImportCA("Naked Inter", inter.CertPEM)
	if err == nil {
		t.Fatal("expected error importing naked intermediate via ImportCA")
	}
}

func TestImportCAChainSucceeds(t *testing.T) {
	engine := newTestEngine(t)

	root, _ := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	inter, _ := engine.CreateIntermediateCA("Inter", pkix.Name{CommonName: "Inter"}, keystore.ECDSAP256, root.ID, 5*365*24*time.Hour)

	chainPEM := bytes.Join([][]byte{inter.CertPEM, root.CertPEM}, nil)

	imported, err := engine.ImportCAChain("Imported Inter", chainPEM)
	if err != nil {
		t.Fatalf("ImportCAChain: %v", err)
	}
	if imported.Type != "intermediate" {
		t.Errorf("expected intermediate type, got %s", imported.Type)
	}
	if imported.Certificate.Subject.CommonName != "Inter" {
		t.Errorf("expected CN=Inter, got %s", imported.Certificate.Subject.CommonName)
	}
}

func TestImportCAChainRejectsIncompleteChain(t *testing.T) {
	engine := newTestEngine(t)

	root, _ := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	inter, _ := engine.CreateIntermediateCA("Inter", pkix.Name{CommonName: "Inter"}, keystore.ECDSAP256, root.ID, 5*365*24*time.Hour)

	// Only the intermediate, no root — chain is incomplete.
	_, err := engine.ImportCAChain("Incomplete", inter.CertPEM)
	if err == nil {
		t.Fatal("expected error for incomplete chain (no root)")
	}
}

// Task 0.5: request-level IPAddresses must appear on the issued certificate.
func TestIssueCertificateHonorsRequestIPAddresses(t *testing.T) {
	engine := newTestEngine(t)
	root, _ := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)

	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "server.example.com"},
	}, clientKey)
	csr, _ := x509.ParseCertificateRequest(csrDER)

	requestIP := net.ParseIP("10.0.0.1")
	issued, err := engine.IssueCertificate(root.ID, IssuanceRequest{
		CSR:         csr,
		Validity:    90 * 24 * time.Hour,
		IPAddresses: []net.IP{requestIP},
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	block, _ := pem.Decode(issued.CertPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(requestIP) {
		t.Errorf("expected IP %s on certificate, got %v", requestIP, cert.IPAddresses)
	}
}

func TestListCAs(t *testing.T) {
	engine := newTestEngine(t)

	engine.CreateRootCA("Root 1", pkix.Name{CommonName: "Root 1"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	engine.CreateRootCA("Root 2", pkix.Name{CommonName: "Root 2"}, keystore.Ed25519, 10*365*24*time.Hour)

	cas, err := engine.ListCAs()
	if err != nil {
		t.Fatalf("list CAs: %v", err)
	}
	if len(cas) != 2 {
		t.Errorf("expected 2 CAs, got %d", len(cas))
	}
}

// Task 1.2/1.3: CA store persistence — CAs written by one engine instance are visible
// to a second engine pointing at the same store.
func TestCAStorePersistsAcrossEngineRestarts(t *testing.T) {
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("test-ca-passphrase-32chars-min!!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	store := NewMemStore()

	// First engine: create a root CA.
	e1 := NewEngine(keys, store)
	root, err := e1.CreateRootCA("Persistent Root", pkix.Name{CommonName: "Persistent Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}

	// Second engine using the SAME store (simulates restart with shared persistent storage).
	e2 := NewEngine(keys, store)
	cas, err := e2.ListCAs()
	if err != nil {
		t.Fatalf("list CAs on second engine: %v", err)
	}
	if len(cas) != 1 || cas[0].ID != root.ID {
		t.Errorf("expected persisted CA %s to be visible on second engine, got %+v", root.ID, cas)
	}
	// Issued certs must chain to the same SKI.
	loaded, err := e2.GetCA(root.ID)
	if err != nil {
		t.Fatalf("GetCA on second engine: %v", err)
	}
	if string(loaded.Certificate.SubjectKeyId) != string(root.Certificate.SubjectKeyId) {
		t.Errorf("SKI mismatch: original %x, loaded %x", root.Certificate.SubjectKeyId, loaded.Certificate.SubjectKeyId)
	}
}

// Task 1.4: Revocation store unit test.
func TestMemRevocationStore(t *testing.T) {
	engine := newTestEngine(t)
	root, _ := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)

	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test.example.com"},
	}, clientKey)
	csr, _ := x509.ParseCertificateRequest(csrDER)

	issued, err := engine.IssueCertificate(root.ID, IssuanceRequest{
		CSR:      csr,
		Validity: 90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("issue certificate: %v", err)
	}

	revStore := NewMemRevocationStore()

	// Before revocation: not revoked.
	revoked, _, _, err := revStore.IsRevoked(issued.SerialNumber, root.ID)
	if err != nil {
		t.Fatalf("IsRevoked before revoke: %v", err)
	}
	if revoked {
		t.Fatal("expected cert to be not revoked before Revoke call")
	}

	// Revoke with reason code 1 (keyCompromise).
	when := time.Now().UTC().Truncate(time.Second)
	if err := revStore.Revoke(issued.SerialNumber, root.ID, 1, when); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// After revocation: revoked with correct reason and time.
	revoked, revokedAt, reason, err := revStore.IsRevoked(issued.SerialNumber, root.ID)
	if err != nil {
		t.Fatalf("IsRevoked after revoke: %v", err)
	}
	if !revoked {
		t.Fatal("expected cert to be revoked after Revoke call")
	}
	if reason != 1 {
		t.Errorf("expected reason 1, got %d", reason)
	}
	if !revokedAt.Equal(when) {
		t.Errorf("expected revokedAt %v, got %v", when, revokedAt)
	}

	// ListRevoked returns the entry.
	entries, err := revStore.ListRevoked(root.ID)
	if err != nil {
		t.Fatalf("ListRevoked: %v", err)
	}
	if len(entries) != 1 || entries[0].Serial.Cmp(issued.SerialNumber) != 0 {
		t.Errorf("ListRevoked returned unexpected entries: %+v", entries)
	}
}

func TestUpdateCAStatus(t *testing.T) {
	engine := newTestEngine(t)
	root, err := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}

	if err := engine.UpdateCAStatus(root.ID, "suspended"); err != nil {
		t.Fatalf("UpdateCAStatus: %v", err)
	}

	updated, err := engine.GetCA(root.ID)
	if err != nil {
		t.Fatalf("GetCA after status update: %v", err)
	}
	if updated.Status != "suspended" {
		t.Errorf("expected suspended, got %q", updated.Status)
	}

	// Verify it rejects issuance when suspended.
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test"},
	}, clientKey)
	csr, _ := x509.ParseCertificateRequest(csrDER)
	_, issErr := engine.IssueCertificate(root.ID, IssuanceRequest{CSR: csr})
	if issErr == nil {
		t.Error("expected error issuing from suspended CA")
	}
}

func TestMemStoreUpdateStatus(t *testing.T) {
	store := NewMemStore()
	meta := &CA{ID: "ca-1", Name: "Test CA", Status: "active"}
	if err := store.Save(meta); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := store.UpdateStatus("ca-1", "suspended"); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}
	loaded, err := store.Load("ca-1")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Status != "suspended" {
		t.Errorf("expected suspended, got %q", loaded.Status)
	}
	if err := store.UpdateStatus("nonexistent", "active"); err == nil {
		t.Error("expected error updating nonexistent CA")
	}
}

func TestIssueCertificateWithSPIFFEURISAN(t *testing.T) {
	engine := newTestEngine(t)
	root, err := engine.CreateRootCA("Test Root", pkix.Name{CommonName: "Test Root CA"},
		keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "workload"}}, clientKey)
	csr, _ := x509.ParseCertificateRequest(csrDER)

	spiffeID, _ := url.Parse("spiffe://example.org/ns/prod/sa/checkout")
	issued, err := engine.IssueCertificate(root.ID, IssuanceRequest{
		CSR:      csr,
		Validity: time.Hour,
		KeyUsage: x509.KeyUsageDigitalSignature,
		URIs:     []*url.URL{spiffeID},
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(issued.Certificate.URIs) != 1 {
		t.Fatalf("expected 1 URI SAN, got %d", len(issued.Certificate.URIs))
	}
	if issued.Certificate.URIs[0].String() != "spiffe://example.org/ns/prod/sa/checkout" {
		t.Errorf("unexpected SPIFFE URI SAN: %s", issued.Certificate.URIs[0])
	}
}

func TestIssueCertificateFallsBackToCSRURIs(t *testing.T) {
	engine := newTestEngine(t)
	root, _ := engine.CreateRootCA("Root", pkix.Name{CommonName: "Root"},
		keystore.ECDSAP256, 10*365*24*time.Hour)
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	uri, _ := url.Parse("spiffe://example.org/db")
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "db"}, URIs: []*url.URL{uri}}, clientKey)
	csr, _ := x509.ParseCertificateRequest(csrDER)

	// No explicit URIs in the request → engine takes them from the CSR.
	issued, err := engine.IssueCertificate(root.ID, IssuanceRequest{CSR: csr, Validity: time.Hour})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(issued.Certificate.URIs) != 1 || issued.Certificate.URIs[0].String() != "spiffe://example.org/db" {
		t.Errorf("expected CSR URI SAN to carry through, got %v", issued.Certificate.URIs)
	}
}
