// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"database/sql"
	"testing"
)

func insertTargetMode(db *sql.DB, engine, id, mode string) error {
	// Postgres declares created_at/updated_at NOT NULL without a default.
	q := "INSERT INTO managed_targets (id, name, host, install_mode, created_at, updated_at) VALUES (?, ?, 'h.example.com', ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
	if engine == "postgres" {
		q = "INSERT INTO managed_targets (id, name, host, install_mode, created_at, updated_at) VALUES ($1, $2, 'h.example.com', $3, now(), now())"
	}
	_, err := db.Exec(q, id, id, mode)
	return err
}

// 000363 admits the sqlserver and rdp install modes; its down migration drops
// rows in those modes (they cannot satisfy the narrower CHECK) and keeps the
// rest, columns added after 000068 included.
func TestMigration000363_SQLServerRDPInstallModes(t *testing.T) {
	fingerprintEngines(t, func(t *testing.T, db *sql.DB, engine string) {
		if err := RunMigrations(db, engine); err != nil {
			t.Fatalf("RunMigrations: %v", err)
		}
		for _, mode := range []string{"sqlserver", "rdp", "iis"} {
			if err := insertTargetMode(db, engine, "t-"+mode, mode); err != nil {
				t.Fatalf("install_mode %q must be accepted: %v", mode, err)
			}
		}
		if err := insertTargetMode(db, engine, "t-bogus", "bogus"); err == nil {
			t.Fatal("an unknown install_mode must still violate the CHECK")
		}

		if err := RollbackMigration(db, engine, 359); err != nil {
			t.Fatalf("RollbackMigration: %v", err)
		}
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM managed_targets WHERE install_mode IN ('sqlserver', 'rdp')").Scan(&n); err != nil || n != 0 {
			t.Fatalf("new-mode rows after rollback = %d (err %v), want 0", n, err)
		}
		if err := db.QueryRow("SELECT COUNT(*) FROM managed_targets WHERE install_mode = 'iis'").Scan(&n); err != nil || n != 1 {
			t.Fatalf("iis row after rollback = %d (err %v), want it preserved", n, err)
		}
		if err := insertTargetMode(db, engine, "t-again", "sqlserver"); err == nil {
			t.Fatal("sqlserver must violate the CHECK again after rollback")
		}
		// A column added after 000068 must have survived the SQLite rebuild.
		if _, err := db.Exec("SELECT key_handling_mode, ssh_host_key, blocked_at, verify_host_port FROM managed_targets"); err != nil {
			t.Fatalf("later columns lost in the rebuild: %v", err)
		}
		// And up again.
		if err := RunMigrations(db, engine); err != nil {
			t.Fatalf("re-apply: %v", err)
		}
		if err := insertTargetMode(db, engine, "t-up", "rdp"); err != nil {
			t.Fatalf("rdp after re-apply: %v", err)
		}
	})
}
