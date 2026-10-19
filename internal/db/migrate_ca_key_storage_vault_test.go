// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package db

import "testing"

// 000121 widens certificate_authorities.key_storage_type to allow `vault`.
// SQLite does it by table rebuild, so rows, indexes and triggers must survive
// both directions.
func TestMigration000121_SQLite_VaultKeyStorage(t *testing.T) {
	db := freshSQLiteDB(t)
	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	const ins = `INSERT INTO certificate_authorities (id, name, display_name, type, key_storage_type, status)
		VALUES (?, ?, ?, 'root', ?, 'active')`
	if _, err := db.Exec(ins, "ca-1", "n1", "N1", "vault"); err != nil {
		t.Fatalf("vault must be accepted after 000121: %v", err)
	}
	if _, err := db.Exec(ins, "ca-2", "n2", "N2", "external"); err != nil {
		t.Fatalf("external must keep validating: %v", err)
	}
	if _, err := db.Exec(ins, "ca-bad", "n3", "N3", "bogus"); err == nil {
		t.Fatal("an unknown key_storage_type must still be rejected")
	}

	if err := RollbackMigration(db, "sqlite", 120); err != nil {
		t.Fatalf("RollbackMigration: %v", err)
	}
	var kst string
	if err := db.QueryRow(`SELECT key_storage_type FROM certificate_authorities WHERE id = 'ca-1'`).Scan(&kst); err != nil || kst != "external" {
		t.Fatalf("rolled-back vault CA: key_storage_type=%q err=%v (want external)", kst, err)
	}
	if _, err := db.Exec(ins, "ca-3", "n4", "N4", "vault"); err == nil {
		t.Fatal("vault must be rejected again after rolling back 000121")
	}
	for _, name := range []string{"idx_ca_parent", "idx_ca_status", "trg_certificate_authorities_set_updated_at", "trg_ca_certificate_fingerprint_fk_ins", "trg_ca_certificate_fingerprint_fk_upd"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = ?`, name).Scan(&n); err != nil || n != 1 {
			t.Fatalf("%s missing after rebuild (n=%d err=%v)", name, n, err)
		}
	}

	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if _, err := db.Exec(ins, "ca-4", "n5", "N5", "vault"); err != nil {
		t.Fatalf("vault after re-apply: %v", err)
	}
}

func TestMigration000121_Postgres_VaultKeyStorage(t *testing.T) {
	db := freshPostgresDB(t, livePostgresDSN(t))
	if err := RunMigrations(db, "postgres"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	const ins = `INSERT INTO certificate_authorities (name, display_name, type, key_storage_type, status)
		VALUES ($1, $2, 'root', $3, 'active')`
	if _, err := db.Exec(ins, "n1", "N1", "vault"); err != nil {
		t.Fatalf("vault must be accepted after 000121: %v", err)
	}
	if _, err := db.Exec(ins, "n2", "N2", "bogus"); err == nil {
		t.Fatal("an unknown key_storage_type must still be rejected")
	}
	if err := RollbackMigration(db, "postgres", 120); err != nil {
		t.Fatalf("RollbackMigration: %v", err)
	}
	var kst string
	if err := db.QueryRow(`SELECT key_storage_type FROM certificate_authorities WHERE name = 'n1'`).Scan(&kst); err != nil || kst != "external" {
		t.Fatalf("rolled-back key_storage_type=%q err=%v", kst, err)
	}
	if _, err := db.Exec(ins, "n3", "N3", "vault"); err == nil {
		t.Fatal("vault must be rejected after rollback")
	}
	if err := RunMigrations(db, "postgres"); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
}
