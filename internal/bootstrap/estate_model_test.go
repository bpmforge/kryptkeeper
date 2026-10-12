// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	kkdb "kryptkeeper/internal/db"
	"kryptkeeper/internal/keystore"
)

// W11-01 estate model: origin + management_state through the PRODUCTION
// writer/reader (S-66 lesson), surviving a provider restart, with filters
// and the summary split observing the same rows.

// estateTestCertPEM generates a throwaway self-signed cert for import tests.
func estateTestCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "estate-import.example.com"},
		DNSNames:     []string{"estate-import.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestEstateModelPersistsAcrossRestart(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()

	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       getFirstCAID(t, engine),
		CSRPEM:     generateTestCSRPEM(t, "estate.example.com", "estate.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-estate",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if issued.CertificateItem.Origin != "internal" || issued.CertificateItem.ManagementState != "managed" {
		t.Fatalf("issued cert estate fields wrong: %+v", issued.CertificateItem)
	}

	imported, err := provider.ImportCertificate(ctx, CertificateImportRequest{
		CertificatePEM: estateTestCertPEM(t),
		TeamID:         "team-estate",
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if imported.CertificateItem.Origin != "imported" || imported.CertificateItem.ManagementState != "unmanaged" {
		t.Fatalf("imported cert estate fields wrong: origin=%q state=%q",
			imported.CertificateItem.Origin, imported.CertificateItem.ManagementState)
	}

	// Restart: a second provider on the same DB must load the same estate
	// fields — this is what fails if the writer or the loader drops them.
	provider2 := NewCACertificateProvider(engine, ca.NewDBRevocationStore(db, false), db, false)
	after, ok, err := provider2.GetCertificate(ctx, imported.CertificateItem.FingerprintSHA256)
	if err != nil || !ok {
		t.Fatalf("reload imported cert: ok=%v err=%v", ok, err)
	}
	if after.Origin != "imported" || after.ManagementState != "unmanaged" {
		t.Fatalf("estate fields lost across restart: origin=%q state=%q", after.Origin, after.ManagementState)
	}

	// Filters see the split.
	unmanaged, err := provider2.ListCertificates(ctx, CertificateListQuery{ManagementState: "unmanaged", Limit: 50})
	if err != nil {
		t.Fatalf("list unmanaged: %v", err)
	}
	if unmanaged.Total != 1 || unmanaged.Items[0].Origin != "imported" {
		t.Fatalf("management_state filter wrong: %+v", unmanaged)
	}
	internalOnly, err := provider2.ListCertificates(ctx, CertificateListQuery{Origin: "internal", Limit: 50})
	if err != nil {
		t.Fatalf("list internal: %v", err)
	}
	if internalOnly.Total != 1 || internalOnly.Items[0].FingerprintSHA256 != issued.CertificateItem.FingerprintSHA256 {
		t.Fatalf("origin filter wrong: %+v", internalOnly)
	}

	// The DB summary provider splits the same rows.
	store, err := newSQLiteCertSummaryStore("file:" + dbPathOf(t, db) + "?cache=shared&_fk=1")
	if err != nil {
		t.Fatalf("summary store: %v", err)
	}
	summary, err := store.LoadSummary(ctx)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if summary.Total != 2 || summary.Managed != 1 || summary.Unmanaged != 1 || summary.External != 0 {
		t.Fatalf("summary split wrong: %+v", summary)
	}
}

// dbPathOf digs the sqlite file path back out of the test DB (the summary
// store opens its own connection to the same file).
func dbPathOf(t *testing.T, db *sql.DB) string {
	t.Helper()
	var _, file string
	rows, err := db.Query("PRAGMA database_list")
	if err != nil {
		t.Fatalf("pragma: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var seq int
		var name string
		if err := rows.Scan(&seq, &name, &file); err != nil {
			t.Fatalf("scan pragma: %v", err)
		}
		if name == "main" {
			return file
		}
	}
	t.Fatal("main database not found")
	return ""
}

func TestEstateModelPersists_Postgres(t *testing.T) {
	dsn := os.Getenv("KRYPTKEEPER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("KRYPTKEEPER_TEST_POSTGRES_DSN not set — skipping live Postgres estate test")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := kkdb.RunMigrations(db, "postgres"); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("integration-passphrase-32bytes!!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewDBStore(db, true))
	rootCA, err := engine.CreateRootCA("W11-01 Estate Root", pkix.Name{CommonName: "W11-01 Estate Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM certificate_authorities WHERE id = $1`, rootCA.ID) })

	provider := NewCACertificateProvider(engine, ca.NewDBRevocationStore(db, true), db, true)
	ctx := context.Background()

	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       rootCA.ID,
		CSRPEM:     generateTestCSRPEM(t, "estate-pg.example.com", "estate-pg.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-estate-pg",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	fp := issued.CertificateItem.FingerprintSHA256
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM certificates WHERE fingerprint_sha256 = $1`, fp) })

	// The row the production writer persisted carries the estate columns.
	var origin, state string
	if err := db.QueryRow(`SELECT origin, management_state FROM certificates WHERE fingerprint_sha256 = $1`, fp).
		Scan(&origin, &state); err != nil {
		t.Fatalf("select estate columns: %v", err)
	}
	if origin != "internal" || state != "managed" {
		t.Fatalf("postgres estate columns wrong: origin=%q state=%q", origin, state)
	}
}
