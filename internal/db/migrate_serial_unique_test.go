// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"strings"
	"testing"
)

// W23-25: the (issuer CA, serial) unique index is proven on both engines.
// Postgres twin is skipped unless KRYPTKEEPER_TEST_POSTGRES_DSN names a
// disposable "test" database.

const serialInsertPG = `INSERT INTO certificates
	(fingerprint_sha256, serial_number, subject_dn, issuer_dn, ca_id, valid_from, valid_until,
	 public_key_algorithm, signature_algorithm)
	VALUES ($1, $2, 'CN=x', 'CN=ca', $3, '2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z', 'ECDSA', 'ecdsa-with-SHA256')`

func TestIssuerSerialUnique_SQLite(t *testing.T) {
	d := openMigrated(t)
	for _, id := range []string{"ca-1", "ca-2"} {
		if _, err := d.Exec(`INSERT INTO certificate_authorities (id, name, display_name, type, key_storage_type, status)
			VALUES (?, ?, ?, 'root', 'software', 'active')`, id, id, id); err != nil {
			t.Fatalf("seed ca: %v", err)
		}
	}
	const ins = `INSERT INTO certificates
		(fingerprint_sha256, serial_number, subject_dn, issuer_dn, ca_id, valid_from, valid_until,
		 public_key_algorithm, signature_algorithm)
		VALUES (?, ?, 'CN=x', 'CN=ca', ?, '2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z', 'ECDSA', 'ecdsa-with-SHA256')`
	if _, err := d.Exec(ins, "fp-1", "9", "ca-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(ins, "fp-2", "9", "ca-1"); err == nil {
		t.Fatal("duplicate (ca_id, serial) must be rejected")
	}
	if _, err := d.Exec(ins, "fp-3", "9", "ca-2"); err != nil {
		t.Fatalf("same serial under another CA must be allowed: %v", err)
	}
}

func TestIssuerSerialUnique_Postgres(t *testing.T) {
	d := freshPostgresDB(t, livePostgresDSN(t))
	if err := RunMigrations(d, "postgres"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	const ca1 = "00000000-0000-0000-0000-000000000001"
	if _, err := d.Exec(`INSERT INTO certificate_authorities (id, name, display_name, type, key_storage_type, status)
		VALUES ($1, 'ca1', 'CA1', 'root', 'software', 'active')`, ca1); err != nil {
		t.Fatalf("seed ca: %v", err)
	}
	if _, err := d.Exec(serialInsertPG, "fp-1", "9", ca1); err != nil {
		t.Fatal(err)
	}
	_, err := d.Exec(serialInsertPG, "fp-2", "9", ca1)
	if err == nil || !strings.Contains(err.Error(), "idx_cert_serial_ca") {
		t.Fatalf("duplicate must violate idx_cert_serial_ca, got %v", err)
	}
	if err := RollbackMigration(d, "postgres", 78); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if _, err := d.Exec(serialInsertPG, "fp-3", "9", ca1); err == nil {
		t.Fatal("index must survive rollback of later migrations")
	}
	if err := RunMigrations(d, "postgres"); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if _, err := d.Exec(serialInsertPG, "fp-4", "9", ca1); err == nil {
		t.Fatal("index must hold after re-apply")
	}
}
