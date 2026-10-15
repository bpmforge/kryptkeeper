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

// TestIntegration_IssuedCertSurvivesProviderRestart_Postgres is the Postgres
// half of S-66's acceptance criteria. It is the sqlite
// TestIntegration_IssuedCertSurvivesProviderRestart test
// (certificate_ca_provider_integration_test.go), pointed at a live Postgres
// instead: a certificate issued through provider.IssueCertificate — which
// calls the production writer writeCertToDB internally, never a hand-written
// INSERT — must actually land in the certificates table and still be listed
// by a brand-new provider instance backed by the same DB. Before this
// ticket, writeCertToDB sent int 0/1 for the BOOLEAN columns
// (chain_complete, chain_trusted, pqc_vulnerable) and JSON-encoded strings
// for the TEXT[] columns (subject_alt_names, extended_key_usage, key_usage,
// risk_flags); Postgres rejected all seven, RunMigrations succeeded, and the
// row silently never existed. A hand-written INSERT in this test could have
// omitted exactly those columns and stayed green, which is why this test
// goes through IssueCertificate/writeCertToDB rather than its own SQL.
//
// Skipped unless a live Postgres is reachable via
// KRYPTKEEPER_TEST_POSTGRES_DSN, matching the skip convention already used
// by internal/db/migrate_test.go's live-Postgres tests.
func TestIntegration_IssuedCertSurvivesProviderRestart_Postgres(t *testing.T) {
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

	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("integration-passphrase-32bytes!!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	caStore := ca.NewDBStore(db, true)
	engine := ca.NewEngine(keys, caStore)

	rootCA, err := engine.CreateRootCA("S-66 Postgres Root", pkix.Name{
		CommonName: "S-66 Postgres Root CA",
	}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}
	// Use the CA this test just created, never getFirstCAID: unlike the sqlite
	// tests' per-test temp DB, KRYPTKEEPER_TEST_POSTGRES_DSN is a shared
	// database, and ca.DBStore.List orders by created_at — so cas[0] is the
	// oldest row in whatever DB the DSN points at, which is somebody else's CA
	// to both issue against and DELETE (S-67 documents the shared-DSN hazard).
	caID := rootCA.ID
	// certificates.ca_id keeps its FK to certificate_authorities (S-51), so
	// clean up in FK order: the certificate row first (registered second,
	// t.Cleanup runs LIFO), then the CA row.
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM certificate_authorities WHERE id = $1`, caID)
	})

	revStore := ca.NewDBRevocationStore(db, true)
	provider := NewCACertificateProvider(engine, revStore, db, true)
	ctx := context.Background()

	csrPEM := generateTestCSRPEM(t, "s66-postgres-test.example.com", "s66-postgres-test.example.com")

	const principal = "team-s66-postgres-test" // the issuing principal's identifier, not a `teams` row
	const templateID = "file-backed-default"   // a file-backed template ID, not a `certificate_templates` row

	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       caID,
		CSRPEM:     csrPEM,
		TemplateID: templateID,
		TeamID:     principal,
	})
	if err != nil {
		t.Fatalf("issue cert: %v", err)
	}
	fp := issued.CertificateItem.FingerprintSHA256
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM certificates WHERE fingerprint_sha256 = $1`, fp)
	})

	// The whole point of S-66: writeCertToDB must have actually persisted a
	// row. Before the fix this Exec failed (encode error on the BOOLEAN/TEXT[]
	// args) and writeCertToDB's error was discarded by its caller, so the
	// in-memory map looked fine while the table stayed empty.
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM certificates WHERE fingerprint_sha256 = $1`, fp).Scan(&count); err != nil {
		t.Fatalf("count certificates row: %v", err)
	}
	if count != 1 {
		t.Fatalf("writeCertToDB did not persist the issued certificate: found %d rows for fingerprint %q", count, fp)
	}

	// Select by fingerprint rather than asserting Total == 1: on the shared DSN
	// a leaked row from an earlier crashed run can carry the same principal,
	// and a count assertion would then report a false red for a cert that did
	// persist.
	list1, err := provider.ListCertificates(ctx, CertificateListQuery{TeamID: principal})
	if err != nil {
		t.Fatalf("list before restart: %v", err)
	}
	if findCertByFingerprint(list1.Items, fp) == nil {
		t.Fatalf("issued cert %q not listed before restart for principal %q (%d certs listed)", fp, principal, list1.Total)
	}

	// Simulate process restart: a brand-new provider backed by the same DB,
	// which must reload this cert from the certificates table (loadCertsFromDB).
	dir2 := t.TempDir()
	keys2, err := keystore.NewSoftwareStore(dir2, []byte("integration-passphrase-32bytes!!"))
	if err != nil {
		t.Fatalf("create second keystore: %v", err)
	}
	engine2 := ca.NewEngine(keys2, ca.NewDBStore(db, true))
	provider2 := NewCACertificateProvider(engine2, ca.NewDBRevocationStore(db, true), db, true)

	list2, err := provider2.ListCertificates(ctx, CertificateListQuery{TeamID: principal})
	if err != nil {
		t.Fatalf("list after restart: %v", err)
	}
	got := findCertByFingerprint(list2.Items, fp)
	if got == nil {
		t.Fatalf("cert %q must survive restart for the issuing principal %q: not among the %d certs listed", fp, principal, list2.Total)
	}
	if got.CommonName != "s66-postgres-test.example.com" {
		t.Fatalf("unexpected CN after restart: %q", got.CommonName)
	}
	if got.TemplateID != templateID {
		t.Fatalf("template_id after restart = %q, want %q", got.TemplateID, templateID)
	}
	if got.TeamID != principal {
		t.Fatalf("team_id after restart = %q, want %q", got.TeamID, principal)
	}

	// These checks are acceptance criterion 2: the writer must send types the
	// Postgres schema accepts (booleans for BOOLEAN columns, arrays for
	// TEXT[] columns). If writeCertToDB regresses to sending JSON strings or
	// 0/1 ints, either the INSERT above fails (caught by the count check) or
	// the round trip through loadCertsFromDB comes back empty/wrong here.
	if len(got.SubjectAltNames) != 1 || got.SubjectAltNames[0] != "s66-postgres-test.example.com" {
		t.Fatalf("subject_alt_names after restart = %#v, want [s66-postgres-test.example.com] (TEXT[] round-trip)", got.SubjectAltNames)
	}
	if len(got.KeyUsage) == 0 {
		t.Fatalf("key_usage after restart is empty, want non-empty (TEXT[] round-trip)")
	}
	if !boolVal(got.ChainComplete) || !boolVal(got.ChainTrusted) {
		t.Fatalf("chain_complete/chain_trusted after restart = %v/%v, want true/true (BOOLEAN round-trip)", got.ChainComplete, got.ChainTrusted)
	}
}

// findCertByFingerprint returns the listed cert with the given fingerprint, or
// nil. Rows a shared Postgres already holds must never be mistaken for this
// test's own, so every assertion above resolves its subject this way instead of
// indexing Items[0].
func findCertByFingerprint(items []CertificateItem, fp string) *CertificateItem {
	for i := range items {
		if items[i].FingerprintSHA256 == fp {
			return &items[i]
		}
	}
	return nil
}
