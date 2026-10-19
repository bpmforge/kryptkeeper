// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package db

import "testing"

const insCeremony = `INSERT INTO key_ceremonies (id, ca_id, ca_name, common_name, algorithm, validity_days,
	initiator, approvers, quorum, status, created_at, updated_at)
	VALUES (?, 'ca', 'n', 'cn', 'ECDSA-P256', 365, 'i', '["a","b"]', 2, ?, 't', 't')`

// 000120 adds the terminal `expired` ceremony status and reminder_sent_at.
func TestMigration000120_SQLite_CeremonyExpired(t *testing.T) {
	db := freshSQLiteDB(t)
	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	if _, err := db.Exec(insCeremony, "c1", "expired"); err != nil {
		t.Fatalf("expired must be accepted after 000120: %v", err)
	}
	if _, err := db.Exec(insCeremony, "c-bad", "bogus"); err == nil {
		t.Fatal("an unknown status must still be rejected")
	}
	if _, err := db.Exec(`UPDATE key_ceremonies SET reminder_sent_at = 'x' WHERE id = 'c1'`); err != nil {
		t.Fatalf("reminder_sent_at column missing: %v", err)
	}

	if err := RollbackMigration(db, "sqlite", 119); err != nil {
		t.Fatalf("RollbackMigration: %v", err)
	}
	var status string
	if err := db.QueryRow(`SELECT status FROM key_ceremonies WHERE id = 'c1'`).Scan(&status); err != nil || status != "aborted" {
		t.Fatalf("rolled-back expired ceremony: status=%q err=%v (want aborted)", status, err)
	}
	if _, err := db.Exec(insCeremony, "c2", "expired"); err == nil {
		t.Fatal("expired must be rejected again after rolling back 000120")
	}

	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if _, err := db.Exec(insCeremony, "c3", "expired"); err != nil {
		t.Fatalf("expired after re-apply: %v", err)
	}
}

func TestMigration000120_Postgres_CeremonyExpired(t *testing.T) {
	db := freshPostgresDB(t, livePostgresDSN(t))
	if err := RunMigrations(db, "postgres"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	const ins = `INSERT INTO key_ceremonies (id, ca_id, ca_name, common_name, algorithm, validity_days,
		initiator, approvers, quorum, status, created_at, updated_at)
		VALUES ($1, 'ca', 'n', 'cn', 'ECDSA-P256', 365, 'i', '["a","b"]', 2, $2, 't', 't')`
	if _, err := db.Exec(ins, "c1", "expired"); err != nil {
		t.Fatalf("expired must be accepted after 000120: %v", err)
	}
	if _, err := db.Exec(ins, "c-bad", "bogus"); err == nil {
		t.Fatal("an unknown status must still be rejected")
	}
	if err := RollbackMigration(db, "postgres", 119); err != nil {
		t.Fatalf("RollbackMigration: %v", err)
	}
	var status string
	if err := db.QueryRow(`SELECT status FROM key_ceremonies WHERE id = 'c1'`).Scan(&status); err != nil || status != "aborted" {
		t.Fatalf("rolled-back status=%q err=%v", status, err)
	}
	if _, err := db.Exec(ins, "c2", "expired"); err == nil {
		t.Fatal("expired must be rejected after rollback")
	}
	if err := RunMigrations(db, "postgres"); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
}

// 000124 adds crl_numbers (W23-49); up and down on both engines.
func TestMigration000124_SQLite_CRLNumbers(t *testing.T) {
	d := freshSQLiteDB(t)
	if err := RunMigrations(d, "sqlite"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	if _, err := d.Exec(`INSERT INTO crl_numbers (scope, last_number) VALUES ('ca', 1)`); err != nil {
		t.Fatalf("crl_numbers missing: %v", err)
	}
	if err := RollbackMigration(d, "sqlite", 123); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if _, err := d.Exec(`SELECT 1 FROM crl_numbers`); err == nil {
		t.Fatal("crl_numbers must be gone after rollback")
	}
	if err := RunMigrations(d, "sqlite"); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
}

func TestMigration000124_Postgres_CRLNumbers(t *testing.T) {
	d := freshPostgresDB(t, livePostgresDSN(t))
	if err := RunMigrations(d, "postgres"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	if _, err := d.Exec(`INSERT INTO crl_numbers (scope, last_number) VALUES ('ca', 1)`); err != nil {
		t.Fatalf("crl_numbers missing: %v", err)
	}
	if err := RollbackMigration(d, "postgres", 123); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if _, err := d.Exec(`SELECT 1 FROM crl_numbers`); err == nil {
		t.Fatal("crl_numbers must be gone after rollback")
	}
	if err := RunMigrations(d, "postgres"); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
}
