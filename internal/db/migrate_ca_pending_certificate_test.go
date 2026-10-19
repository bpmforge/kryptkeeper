// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package db

import "testing"

// 000122 adds certificate_authorities.csr_pem and the pending_certificate
// status. SQLite does it by table rebuild, so rows, the earlier 000121 vault
// label, indexes and triggers must survive both directions.
func TestMigration000122_SQLite_PendingCertificate(t *testing.T) {
	db := freshSQLiteDB(t)
	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	const ins = `INSERT INTO certificate_authorities (id, name, display_name, type, key_storage_type, status, csr_pem)
		VALUES (?, ?, ?, 'root', ?, ?, ?)`
	if _, err := db.Exec(ins, "ca-1", "n1", "N1", "vault", "pending_certificate", "CSR"); err != nil {
		t.Fatalf("pending_certificate + csr_pem must be accepted after 000122: %v", err)
	}
	if _, err := db.Exec(ins, "ca-2", "n2", "N2", "software", "pending_ceremony", nil); err != nil {
		t.Fatalf("pending_ceremony (000075) must keep validating: %v", err)
	}
	if _, err := db.Exec(ins, "ca-bad", "n3", "N3", "software", "bogus", nil); err == nil {
		t.Fatal("an unknown status must still be rejected")
	}
	if _, err := db.Exec(ins, "ca-bad2", "n4", "N4", "floppy", "active", nil); err == nil {
		t.Fatal("an unknown key_storage_type must still be rejected (000121 CHECK kept)")
	}

	if err := RollbackMigration(db, "sqlite", 121); err != nil {
		t.Fatalf("RollbackMigration: %v", err)
	}
	var status, kst string
	if err := db.QueryRow(`SELECT status, key_storage_type FROM certificate_authorities WHERE id = 'ca-1'`).Scan(&status, &kst); err != nil ||
		status != "suspended" || kst != "vault" {
		t.Fatalf("rolled-back pending CA: status=%q kst=%q err=%v (want suspended/vault)", status, kst, err)
	}
	if columnExists(t, db, "certificate_authorities", "csr_pem") {
		t.Fatal("csr_pem must be dropped by the rollback")
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
	if !columnExists(t, db, "certificate_authorities", "csr_pem") {
		t.Fatal("csr_pem missing after re-apply")
	}
	if _, err := db.Exec(ins, "ca-3", "n5", "N5", "software", "pending_certificate", "CSR"); err != nil {
		t.Fatalf("pending_certificate after re-apply: %v", err)
	}
}

func TestMigration000122_Postgres_PendingCertificate(t *testing.T) {
	db := freshPostgresDB(t, livePostgresDSN(t))
	if err := RunMigrations(db, "postgres"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	const ins = `INSERT INTO certificate_authorities (name, display_name, type, key_storage_type, status, csr_pem)
		VALUES ($1, $2, 'root', 'software', $3, $4)`
	if _, err := db.Exec(ins, "n1", "N1", "pending_certificate", "CSR"); err != nil {
		t.Fatalf("pending_certificate must be accepted after 000122: %v", err)
	}
	if _, err := db.Exec(ins, "n2", "N2", "bogus", nil); err == nil {
		t.Fatal("an unknown status must still be rejected")
	}
	if err := RollbackMigration(db, "postgres", 121); err != nil {
		t.Fatalf("RollbackMigration: %v", err)
	}
	var status string
	if err := db.QueryRow(`SELECT status FROM certificate_authorities WHERE name = 'n1'`).Scan(&status); err != nil || status != "suspended" {
		t.Fatalf("rolled-back status=%q err=%v", status, err)
	}
	var cols int
	if err := db.QueryRow(`SELECT COUNT(*) FROM information_schema.columns WHERE table_name = 'certificate_authorities' AND column_name = 'csr_pem'`).Scan(&cols); err != nil || cols != 0 {
		t.Fatalf("csr_pem must be dropped by the rollback (n=%d err=%v)", cols, err)
	}
	if err := RunMigrations(db, "postgres"); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
}
