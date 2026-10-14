// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509/pkix"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"kryptkeeper/internal/ca"
	kkdb "kryptkeeper/internal/db"
	"kryptkeeper/internal/keystore"
)

// The in-memory stores the other ML-DSA tests use have no
// certificates.public_key_algorithm CHECK, so they could not notice that
// crypto/x509 reports an ML-DSA SPKI as "unknown": the real schema rejected
// the row and the hub answered 503 "signed but could not be recorded".
func runMLDSAPersistCase(t *testing.T, db *sql.DB, postgres bool) {
	t.Helper()
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("integration-passphrase-32bytes!!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewDBStore(db, postgres))
	root, err := engine.CreateRootCA("ML-DSA Persist Root", pkix.Name{CommonName: "ML-DSA Persist Root CA"},
		keystore.MLDSA65, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create ML-DSA root CA: %v", err)
	}
	t.Cleanup(func() {
		if postgres {
			_, _ = db.Exec(`DELETE FROM certificates WHERE ca_id = $1`, root.ID)
			_, _ = db.Exec(`DELETE FROM certificate_authorities WHERE id = $1`, root.ID)
		}
	})
	provider := NewCACertificateProvider(engine, ca.NewDBRevocationStore(db, postgres), db, postgres)
	ctx := context.Background()

	csrPEM, _ := generateTestMLDSACSRPEM(t, keys, "persist-mldsa.example.com", "persist-mldsa.example.com")
	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID: root.ID, TemplateID: "tpl-tls", CSRPEM: csrPEM, TeamID: "team-mldsa-persist",
	})
	if err != nil {
		t.Fatalf("issue ML-DSA cert on a DB-backed store: %v", err)
	}
	if issued.PublicKeyAlgorithm != "ML-DSA" {
		t.Fatalf("issued PublicKeyAlgorithm = %q, want ML-DSA", issued.PublicKeyAlgorithm)
	}

	renewCSR, _ := generateTestMLDSACSRPEM(t, keys, "persist-mldsa-2.example.com", "persist-mldsa.example.com")
	renewed, err := provider.RenewCertificate(ctx, issued.FingerprintSHA256, CertificateRenewRequest{CSRPEM: renewCSR})
	if err != nil {
		t.Fatalf("renew ML-DSA cert on a DB-backed store: %v", err)
	}

	engine2 := ca.NewEngine(keys, ca.NewDBStore(db, postgres))
	provider2 := NewCACertificateProvider(engine2, ca.NewDBRevocationStore(db, postgres), db, postgres)
	list, err := provider2.ListCertificates(ctx, CertificateListQuery{TeamID: "team-mldsa-persist"})
	if err != nil {
		t.Fatalf("list after restart: %v", err)
	}
	for _, fp := range []string{issued.FingerprintSHA256, renewed.FingerprintSHA256} {
		got := findCertByFingerprint(list.Items, fp)
		if got == nil {
			t.Fatalf("cert %s not persisted across restart", fp)
		}
		if got.PublicKeyAlgorithm != "ML-DSA" {
			t.Errorf("persisted PublicKeyAlgorithm = %q, want ML-DSA", got.PublicKeyAlgorithm)
		}
	}
}

func TestIntegration_MLDSAIssueRenewPersist(t *testing.T) {
	runMLDSAPersistCase(t, setupIntegrationDB(t), false)
}

func TestIntegration_MLDSAIssueRenewPersist_Postgres(t *testing.T) {
	dsn := os.Getenv("KRYPTKEEPER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("KRYPTKEEPER_TEST_POSTGRES_DSN not set — skipping live Postgres integration test")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := kkdb.RunMigrations(db, "postgres"); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	runMLDSAPersistCase(t, db, true)
}
