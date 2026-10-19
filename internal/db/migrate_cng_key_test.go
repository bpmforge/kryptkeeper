// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"database/sql"
	"testing"
)

func TestMigration000348_DiscoveredFilesCNGKey(t *testing.T) {
	fingerprintEngines(t, func(t *testing.T, db *sql.DB, engine string) {
		if err := RunMigrations(db, engine); err != nil {
			t.Fatalf("RunMigrations: %v", err)
		}
		ins := `INSERT INTO discovered_files (id, tenant, host, path, kind, posture, findings) VALUES (?, ?, ?, ?, ?, ?, '[]')`
		if err := execQ(db, engine, ins, "w1", "t", "win", `C:\k1`, "cng_key", "standard"); err != nil {
			t.Fatalf("cng_key rejected: %v", err)
		}
		if err := execQ(db, engine, ins, "w2", "t", "win", `C:\k2`, "bogus", "standard"); err == nil {
			t.Fatal("unknown kind must still violate the CHECK")
		}
		if err := execQ(db, engine, ins, "l1", "t", "lin", "/etc/x.pem", "pem", "standard"); err != nil {
			t.Fatal(err)
		}
		if err := execQ(db, engine, `INSERT INTO certificate_files (certificate_fingerprint, file_id) VALUES (?, ?)`, "fp1", "l1"); err != nil {
			t.Fatal(err)
		}

		if err := RollbackMigration(db, engine, 347); err != nil {
			t.Fatalf("RollbackMigration: %v", err)
		}
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM discovered_files WHERE kind = 'cng_key'`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("cng_key rows must go on rollback: n=%d err=%v", n, err)
		}
		if err := execQ(db, engine, ins, "w3", "t", "win", `C:\k3`, "cng_key", "standard"); err == nil {
			t.Fatal("cng_key must be rejected after rollback")
		}
		if err := db.QueryRow(`SELECT COUNT(*) FROM certificate_files WHERE file_id = 'l1'`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("the rebuild must keep certificate links: n=%d err=%v", n, err)
		}
		if err := RunMigrations(db, engine); err != nil {
			t.Fatalf("re-apply: %v", err)
		}
		if err := execQ(db, engine, ins, "w4", "t", "win", `C:\k4`, "cng_key", "standard"); err != nil {
			t.Fatalf("cng_key rejected after re-apply: %v", err)
		}
		if err := db.QueryRow(`SELECT COUNT(*) FROM certificate_files WHERE file_id = 'l1'`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("links survive the up rebuild too: n=%d err=%v", n, err)
		}
	})
}
