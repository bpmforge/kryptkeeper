// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package pqc

import (
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

func TestBuildMigrationCSR_MLDSA(t *testing.T) {
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("test-passphrase-not-for-production"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	subject := pkix.Name{CommonName: "migrate-me.example.com"}
	migrated, err := BuildMigrationCSR(keys, "pqc-migrate-test-key", keystore.MLDSA65, subject, []string{"migrate-me.example.com"}, nil)
	if err != nil {
		t.Fatalf("BuildMigrationCSR: %v", err)
	}
	if migrated.KeyID != "pqc-migrate-test-key" {
		t.Errorf("KeyID = %q, want pqc-migrate-test-key", migrated.KeyID)
	}

	block, _ := pem.Decode([]byte(migrated.CSRPEM))
	if block == nil {
		t.Fatal("CSRPEM did not PEM-decode")
	}
	if block.Type != "ML-DSA CERTIFICATE REQUEST" {
		t.Errorf("PEM block type = %q, want ML-DSA CERTIFICATE REQUEST", block.Type)
	}

	parsed, err := ca.ParseCertificateRequestMLDSA(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificateRequestMLDSA: %v", err)
	}
	if parsed.Subject.CommonName != "migrate-me.example.com" {
		t.Errorf("CommonName = %q, want migrate-me.example.com", parsed.Subject.CommonName)
	}
	if len(parsed.DNSNames) != 1 || parsed.DNSNames[0] != "migrate-me.example.com" {
		t.Errorf("DNSNames = %v, want [migrate-me.example.com]", parsed.DNSNames)
	}
	if parsed.Algorithm != keystore.MLDSA65 {
		t.Errorf("Algorithm = %s, want %s", parsed.Algorithm, keystore.MLDSA65)
	}

	// The generated key must actually be usable via the keystore afterward
	// (the whole point: a caller submits migrated.CSRPEM through the real
	// issuance path, which signs against this same stored key later via the
	// keystore, not the CSR bytes themselves).
	if _, err := keys.Signer(migrated.KeyID); err != nil {
		t.Errorf("generated key not retrievable from keystore: %v", err)
	}
}

// TestBuildMigrationCSR_Hybrid proves W4-08's hybrid support (this test
// asserted a REJECTION before W4-08 landed -- updated per its own spec's
// discipline, rather than left stale asserting old, now-wrong behavior).
func TestBuildMigrationCSR_Hybrid(t *testing.T) {
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("test-passphrase-not-for-production"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	subject := pkix.Name{CommonName: "migrate-hybrid.example.com"}
	migrated, err := BuildMigrationCSR(keys, "pqc-migrate-hybrid-key", keystore.HybridECDSAP256MLDSA65, subject, []string{"migrate-hybrid.example.com"}, nil)
	if err != nil {
		t.Fatalf("BuildMigrationCSR: %v", err)
	}

	block, _ := pem.Decode([]byte(migrated.CSRPEM))
	if block == nil {
		t.Fatal("CSRPEM did not PEM-decode")
	}
	if block.Type != "HYBRID CERTIFICATE REQUEST" {
		t.Errorf("PEM block type = %q, want HYBRID CERTIFICATE REQUEST", block.Type)
	}

	parsed, err := ca.ParseCertificateRequestHybrid(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificateRequestHybrid: %v", err)
	}
	if parsed.Subject.CommonName != "migrate-hybrid.example.com" {
		t.Errorf("CommonName = %q, want migrate-hybrid.example.com", parsed.Subject.CommonName)
	}
	if parsed.Algorithm != keystore.HybridECDSAP256MLDSA65 {
		t.Errorf("Algorithm = %s, want %s", parsed.Algorithm, keystore.HybridECDSAP256MLDSA65)
	}
}

func TestBuildMigrationCSR_RejectsUnsupportedAlgorithm(t *testing.T) {
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("test-passphrase-not-for-production"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	_, err = BuildMigrationCSR(keys, "pqc-migrate-bad-key", keystore.ECDSAP256, pkix.Name{CommonName: "x"}, nil, nil)
	if err == nil {
		t.Fatal("expected an error for a non-PQC target algorithm")
	}
}
