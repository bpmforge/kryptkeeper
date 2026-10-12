// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package db

import "testing"

// 000075 widens certificate_authorities.status to allow pending_ceremony.
// SQLite does it by table rebuild, so data, the FK from child tables, the
// indexes and the updated_at trigger must all survive both directions.
func TestMigration000075_SQLite_PendingCeremonyStatus(t *testing.T) {
	db := freshSQLiteDB(t)
	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	const ins = `INSERT INTO certificate_authorities (id, name, display_name, type, key_storage_type, status)
		VALUES (?, ?, ?, 'root', 'software', ?)`
	if _, err := db.Exec(ins, "ca-1", "n1", "N1", "pending_ceremony"); err != nil {
		t.Fatalf("pending_ceremony must be accepted after 000075: %v", err)
	}
	if _, err := db.Exec(ins, "ca-bad", "n2", "N2", "bogus"); err == nil {
		t.Fatal("an unknown status must still be rejected")
	}

	if err := RollbackMigration(db, "sqlite", 74); err != nil {
		t.Fatalf("RollbackMigration: %v", err)
	}
	var status string
	if err := db.QueryRow(`SELECT status FROM certificate_authorities WHERE id = 'ca-1'`).Scan(&status); err != nil || status != "suspended" {
		t.Fatalf("rolled-back pending_ceremony CA: status=%q err=%v (want suspended)", status, err)
	}
	if _, err := db.Exec(ins, "ca-2", "n3", "N3", "pending_ceremony"); err == nil {
		t.Fatal("pending_ceremony must be rejected again after rolling back 000075")
	}
	for _, name := range []string{"idx_ca_parent", "idx_ca_status", "trg_certificate_authorities_set_updated_at", "trg_ca_certificate_fingerprint_fk_ins"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = ?`, name).Scan(&n); err != nil || n != 1 {
			t.Fatalf("%s missing after rebuild (n=%d err=%v)", name, n, err)
		}
	}

	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if _, err := db.Exec(ins, "ca-3", "n4", "N4", "pending_ceremony"); err != nil {
		t.Fatalf("pending_ceremony after re-apply: %v", err)
	}
}

func TestMigration000075_Postgres_PendingCeremonyStatus(t *testing.T) {
	db := freshPostgresDB(t, livePostgresDSN(t))
	if err := RunMigrations(db, "postgres"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	const ins = `INSERT INTO certificate_authorities (name, display_name, type, key_storage_type, status)
		VALUES ($1, $2, 'root', 'software', $3)`
	if _, err := db.Exec(ins, "n1", "N1", "pending_ceremony"); err != nil {
		t.Fatalf("pending_ceremony must be accepted after 000075: %v", err)
	}
	if _, err := db.Exec(ins, "n2", "N2", "bogus"); err == nil {
		t.Fatal("an unknown status must still be rejected")
	}
	if err := RollbackMigration(db, "postgres", 74); err != nil {
		t.Fatalf("RollbackMigration: %v", err)
	}
	var status string
	if err := db.QueryRow(`SELECT status FROM certificate_authorities WHERE name = 'n1'`).Scan(&status); err != nil || status != "suspended" {
		t.Fatalf("rolled-back status=%q err=%v", status, err)
	}
	if _, err := db.Exec(ins, "n3", "N3", "pending_ceremony"); err == nil {
		t.Fatal("pending_ceremony must be rejected after rollback")
	}
	if err := RunMigrations(db, "postgres"); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
}
