// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"database/sql"
	"testing"
)

func TestMigration000347_FindingExceptionsTargetFile(t *testing.T) {
	fingerprintEngines(t, func(t *testing.T, db *sql.DB, engine string) {
		if err := RunMigrations(db, engine); err != nil {
			t.Fatalf("RunMigrations: %v", err)
		}
		ins := `INSERT INTO finding_exceptions (id, target_type, target_id, finding_code, justification_code, created_by, created_at, expires_at)
                VALUES (?, ?, ?, 'SERVICE_RUNS_AS_ROOT', 'risk_accepted', 'u', '2026-10-17T00:00:00Z', '2027-01-01T00:00:00Z')`
		for id, tt := range map[string]string{"e-cert": "certificate", "e-ca": "ca", "e-file": "target_file"} {
			if err := execQ(db, engine, ins, id, tt, "x-"+id); err != nil {
				t.Fatalf("%s rejected: %v", tt, err)
			}
		}
		if err := execQ(db, engine, ins, "e-bad", "endpoint", "x"); err == nil {
			t.Fatal("unknown target_type must still violate the CHECK")
		}
		if err := execQ(db, engine, `INSERT INTO finding_exception_tenants (exception_id, tenant_id) VALUES (?, ?)`, "e-file", "acme"); err != nil {
			t.Fatal(err)
		}

		if err := RollbackMigration(db, engine, 346); err != nil {
			t.Fatalf("RollbackMigration: %v", err)
		}
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM finding_exceptions WHERE target_type = 'target_file'`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("file exceptions must go on rollback: n=%d err=%v", n, err)
		}
		if err := db.QueryRow(`SELECT COUNT(*) FROM finding_exceptions`).Scan(&n); err != nil || n != 2 {
			t.Fatalf("certificate and CA exceptions must survive: n=%d err=%v", n, err)
		}
		if err := db.QueryRow(`SELECT COUNT(*) FROM finding_exception_tenants WHERE exception_id = 'e-file'`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("the orphaned tenant stamp must go too: n=%d err=%v", n, err)
		}
		if err := execQ(db, engine, ins, "e-file2", "target_file", "y"); err == nil {
			t.Fatal("target_file must be rejected after rollback")
		}
		if err := RunMigrations(db, engine); err != nil {
			t.Fatalf("re-apply: %v", err)
		}
		if err := execQ(db, engine, ins, "e-file3", "target_file", "z"); err != nil {
			t.Fatalf("target_file rejected after re-apply: %v", err)
		}
	})
}
