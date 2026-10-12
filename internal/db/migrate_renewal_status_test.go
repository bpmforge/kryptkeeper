// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package db

import "testing"

// 000073 widens certificates.renewal_status to accept 'reissue_required'
// (written by the CA-key-compromise flow). The rollback must reset flagged
// rows rather than fail on, or silently keep, a value the old constraint
// forbids, and must preserve the other columns/indexes of the rebuilt table.
func TestMigration000073_RenewalStatusReissueRequired(t *testing.T) {
	db := freshSQLiteDB(t)
	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	colsAfterUp := tableColumnNames(t, db, "certificates")

	const insert = `INSERT INTO certificates
		(fingerprint_sha256, serial_number, subject_dn, issuer_dn, valid_from, valid_until,
		 public_key_algorithm, signature_algorithm, renewal_status)
		VALUES (?, ?, 'CN=x', 'CN=ca', '2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z', 'ECDSA', 'ecdsa-with-SHA256', ?)`

	if _, err := db.Exec(insert, "fp-73-a", "1", "reissue_required"); err != nil {
		t.Fatalf("reissue_required must be accepted after 000073: %v", err)
	}
	if _, err := db.Exec(insert, "fp-73-bad", "2", "bogus"); err == nil {
		t.Fatal("an unknown renewal_status must still be rejected")
	}

	if err := RollbackMigration(db, "sqlite", 72); err != nil {
		t.Fatalf("RollbackMigration: %v", err)
	}
	assertSameColumnSet(t, "000073 down", colsAfterUp, tableColumnNames(t, db, "certificates"))

	var status string
	if err := db.QueryRow(`SELECT renewal_status FROM certificates WHERE fingerprint_sha256 = 'fp-73-a'`).Scan(&status); err != nil {
		t.Fatalf("flagged row lost by rollback: %v", err)
	}
	if status != "active" {
		t.Fatalf("rollback must reset reissue_required to active, got %q", status)
	}
	if _, err := db.Exec(insert, "fp-73-b", "3", "reissue_required"); err == nil {
		t.Fatal("reissue_required must be rejected again after rolling back 000073")
	}
}
