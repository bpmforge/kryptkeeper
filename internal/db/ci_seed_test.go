// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// S-42. Migration 000007 describes itself as "deterministic seed data for
// CI/test" and ran on every install, putting a fake root CA, a fake
// certificate, two active privileged users and an API key into production
// databases — and into the report endpoints, which is why crypto-posture
// claimed 4 certificates while the inventory listed 3.

func openMigrated(t *testing.T) *sql.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func countSeedUsers(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM users WHERE id IN (?, ?)`,
		ciSeedUserIDs[0], ciSeedUserIDs[1],
	).Scan(&n); err != nil {
		t.Fatalf("count seed users: %v", err)
	}
	return n
}

func TestFreshInstallHasNoCISeedData(t *testing.T) {
	t.Setenv(ciSeedEnvVar, "")
	db := openMigrated(t)

	if n := countSeedUsers(t, db); n != 0 {
		t.Fatalf("a fresh install must not contain CI seed users; found %d", n)
	}

	// The seeded CA and certificate are the ones that reached the trust
	// inventory and the compliance reports.
	var cas, certs int
	if err := db.QueryRow(`SELECT COUNT(*) FROM certificate_authorities WHERE id = ?`,
		"00000000-0000-0000-0000-000000000107").Scan(&cas); err != nil {
		t.Fatalf("count seed CAs: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM certificates WHERE fingerprint_sha256 = ?`,
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").Scan(&certs); err != nil {
		t.Fatalf("count seed certs: %v", err)
	}
	if cas != 0 || certs != 0 {
		t.Fatalf("fresh install carries seeded PKI objects: %d CA(s), %d certificate(s)", cas, certs)
	}
}

func TestSeedMigrationIsLeftUnappliedSoItCanBeEnabledLater(t *testing.T) {
	t.Setenv(ciSeedEnvVar, "")
	db := openMigrated(t)

	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`,
		ciSeedVersion).Scan(&n); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if n != 0 {
		t.Fatal("skipped seed migration must not be recorded as applied, " +
			"or enabling the flag later would silently do nothing")
	}
}

func TestCISeedDataStillAvailableWhenExplicitlyRequested(t *testing.T) {
	// CI depends on these fixtures. Gating must not mean removing them.
	t.Setenv(ciSeedEnvVar, "true")
	db := openMigrated(t)

	if n := countSeedUsers(t, db); n != 2 {
		t.Fatalf("KRYPTKEEPER_SEED_CI_DATA=true must apply the seed; got %d users", n)
	}
}

func TestRemoveCISeedDataClearsAnAlreadySeededDatabase(t *testing.T) {
	// The upgrade path: a database that applied 000007 before it was gated.
	t.Setenv(ciSeedEnvVar, "true")
	db := openMigrated(t)
	if n := countSeedUsers(t, db); n != 2 {
		t.Fatalf("precondition: expected seeded database, got %d users", n)
	}

	removed, err := RemoveCISeedData(db, "sqlite")
	if err != nil {
		t.Fatalf("RemoveCISeedData: %v", err)
	}
	if removed == 0 {
		t.Fatal("expected rows to be removed")
	}
	if n := countSeedUsers(t, db); n != 0 {
		t.Fatalf("seed users remain after removal: %d", n)
	}

	// Bookkeeping row is gone too, so a later opt-in can re-apply it.
	var applied int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`,
		ciSeedVersion).Scan(&applied); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if applied != 0 {
		t.Fatal("removal must clear the schema_migrations row for the seed migration")
	}
}

func TestRemoveCISeedDataIsIdempotent(t *testing.T) {
	t.Setenv(ciSeedEnvVar, "")
	db := openMigrated(t)

	if _, err := RemoveCISeedData(db, "sqlite"); err != nil {
		t.Fatalf("first removal on a clean database: %v", err)
	}
	if _, err := RemoveCISeedData(db, "sqlite"); err != nil {
		t.Fatalf("second removal must be a no-op, got: %v", err)
	}
}

func TestRemoveCISeedDataRejectsUnknownEngine(t *testing.T) {
	if _, err := RemoveCISeedData(nil, "mysql"); err == nil {
		t.Fatal("expected an error for an unsupported engine")
	}
}
