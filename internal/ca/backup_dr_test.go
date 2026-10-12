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
	"testing"
	"time"

	"kryptkeeper/internal/keystore"
)

// TestBackupRestore_RecoveredCACanStillIssue is the scripted integration
// check the W10-03 spec's Test section calls for: back up a seeded
// instance's keystore, restore it into a fresh keystore + CA store, and
// prove the recovered CA can still issue a certificate — not just that the
// HTTP round trip returns 200. Mirrors the real, manually-executed local
// drill in docs/ops/DR_RUNBOOK.md (same shape: create CA, back up, restore
// into a fresh instance, issue a leaf, assert the chain validates), as a
// repeatable, fast, no-server-process automated equivalent.
func TestBackupRestore_RecoveredCACanStillIssue(t *testing.T) {
	backupPassphrase := []byte("dr-drill-backup-passphrase-32ch")

	// --- "source" instance: create a real root CA. ---
	srcDir := t.TempDir()
	srcKeys, err := keystore.NewSoftwareStore(srcDir, []byte("source-store-passphrase-32chars!"))
	if err != nil {
		t.Fatalf("create source keystore: %v", err)
	}
	srcEngine := NewEngine(srcKeys, NewMemStore())
	root, err := srcEngine.CreateRootCA("Drill Root CA", pkix.Name{CommonName: "Drill Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	// --- Back up the source keystore. ---
	bundle, err := keystore.BackupAll(srcKeys, backupPassphrase)
	if err != nil {
		t.Fatalf("BackupAll: %v", err)
	}

	// --- "destination" instance: completely fresh keystore + CA store. ---
	dstDir := t.TempDir()
	dstKeys, err := keystore.NewSoftwareStore(dstDir, []byte("destination-store-passphrase-32c"))
	if err != nil {
		t.Fatalf("create destination keystore: %v", err)
	}
	imported, err := keystore.RestoreAll(dstKeys, bundle, backupPassphrase)
	if err != nil {
		t.Fatalf("RestoreAll: %v", err)
	}
	if imported != 1 {
		t.Fatalf("imported = %d, want 1", imported)
	}

	// Simulate the DB-restore half (pg_dump/psql in the real runbook): the
	// CA row itself carries no secret material, so re-creating it directly
	// via Store.Save (mirroring the source CA's real fields) is exactly
	// what restoring the pg_dump into a fresh DB accomplishes.
	dstStore := NewMemStore()
	if err := dstStore.Save(&CA{
		ID:          root.ID,
		Name:        root.Name,
		Type:        root.Type,
		KeyID:       root.KeyID,
		Certificate: root.Certificate,
		CertPEM:     root.CertPEM,
		ParentCAID:  root.ParentCAID,
		Status:      root.Status,
		CreatedAt:   root.CreatedAt,
	}); err != nil {
		t.Fatalf("restore CA row: %v", err)
	}
	dstEngine := NewEngine(dstKeys, dstStore)

	// --- Decisive check: the recovered CA must still be able to issue a
	// real certificate that validates as genuinely signed by it. ---
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "drill-leaf.example.com"},
	}, clientKey)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}

	leaf, err := dstEngine.IssueCertificate(root.ID, IssuanceRequest{
		CSR:      csr,
		Validity: 90 * 24 * time.Hour,
		KeyUsage: x509.KeyUsageDigitalSignature,
	})
	if err != nil {
		t.Fatalf("IssueCertificate from recovered CA: %v", err)
	}

	// Verify the issued leaf's signature actually chains to the recovered
	// root's certificate — proving the recovered private key, not just the
	// bookkeeping, is genuinely usable.
	roots := x509.NewCertPool()
	roots.AddCert(root.Certificate)
	if _, err := leaf.Certificate.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		t.Fatalf("issued leaf does not chain to the recovered root: %v", err)
	}
}
