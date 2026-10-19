// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
)

func hasTable(t *testing.T, db *sql.DB, engine, table string) bool {
	t.Helper()
	ok, err := tableExists(db, engine, table)
	if err != nil {
		t.Fatalf("table lookup: %v", err)
	}
	return ok
}

func execQ(db *sql.DB, engine, q string, args ...any) error {
	if engine == "postgres" {
		n := 0
		for strings.Contains(q, "?") {
			n++
			q = strings.Replace(q, "?", fmt.Sprintf("$%d", n), 1)
		}
	}
	_, err := db.Exec(q, args...)
	return err
}

func TestMigration000342_DiscoveredFiles(t *testing.T) {
	fingerprintEngines(t, func(t *testing.T, db *sql.DB, engine string) {
		if err := RunMigrations(db, engine); err != nil {
			t.Fatalf("RunMigrations: %v", err)
		}
		for _, tbl := range []string{"discovered_files", "certificate_files"} {
			if !hasTable(t, db, engine, tbl) {
				t.Fatalf("%s missing after 000342", tbl)
			}
		}
		ins := `INSERT INTO discovered_files (id, tenant, host, path, kind, posture, findings) VALUES (?, ?, ?, ?, ?, ?, '[]')`
		if err := execQ(db, engine, ins, "f1", "t", "h", "/p", "jks", "privileged"); err != nil {
			t.Fatalf("valid row rejected: %v", err)
		}
		if err := execQ(db, engine, ins, "f2", "t", "h", "/p", "pem", "standard"); err == nil {
			t.Fatal("(tenant, host, path) must be unique")
		}
		if err := execQ(db, engine, ins, "f3", "other", "h", "/p", "pem", "standard"); err != nil {
			t.Fatalf("another tenant may hold the same path: %v", err)
		}
		if err := execQ(db, engine, ins, "f4", "t", "h", "/q", "txt", "standard"); err == nil {
			t.Fatal("unknown kind must violate the CHECK")
		}
		if err := execQ(db, engine, ins, "f5", "t", "h", "/r", "pem", "weird"); err == nil {
			t.Fatal("unknown posture must violate the CHECK")
		}
		if err := execQ(db, engine, `INSERT INTO certificate_files (certificate_fingerprint, file_id) VALUES (?, ?)`, "fp", "f1"); err != nil {
			t.Fatal(err)
		}

		// renewal_privilege_required defaults to false on existing targets.
		if err := execQ(db, engine, `INSERT INTO managed_targets (id, name, host, created_at, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`, "mt1", "n", "h"); err != nil {
			t.Fatalf("managed target insert: %v", err)
		}
		var v any
		if err := db.QueryRow(`SELECT renewal_privilege_required FROM managed_targets WHERE id = 'mt1'`).Scan(&v); err != nil {
			t.Fatalf("column missing: %v", err)
		}

		if err := RollbackMigration(db, engine, 341); err != nil {
			t.Fatalf("RollbackMigration: %v", err)
		}
		if hasTable(t, db, engine, "discovered_files") || hasTable(t, db, engine, "certificate_files") {
			t.Fatal("tables still present after rollback")
		}
		if err := db.QueryRow(`SELECT renewal_privilege_required FROM managed_targets LIMIT 1`).Scan(&v); err == nil {
			t.Fatal("renewal_privilege_required still present after rollback")
		}
		if err := RunMigrations(db, engine); err != nil {
			t.Fatalf("re-apply: %v", err)
		}
		if !hasTable(t, db, engine, "discovered_files") {
			t.Fatal("tables missing after re-apply")
		}
	})
}

func TestMigration000343_CredentialPrivileged(t *testing.T) {
	fingerprintEngines(t, func(t *testing.T, db *sql.DB, engine string) {
		if err := RunMigrations(db, engine); err != nil {
			t.Fatalf("RunMigrations: %v", err)
		}
		ins := `INSERT INTO outbound_credentials (id, name, credential_type, tenant, envelope, created_at, updated_at) VALUES (?, 'n', 'ssh_key', 't', 'e', 'now', 'now')`
		if err := execQ(db, engine, ins, "c1"); err != nil {
			t.Fatalf("insert: %v", err)
		}
		var v any
		if err := db.QueryRow(`SELECT privileged FROM outbound_credentials WHERE id = 'c1'`).Scan(&v); err != nil {
			t.Fatalf("privileged column missing: %v", err)
		}
		if err := execQ(db, engine, `UPDATE outbound_credentials SET privileged_reason = ?, privileged_set_by = ?, privileged_set_at = ? WHERE id = 'c1'`, "r", "auto:preflight", "now"); err != nil {
			t.Fatalf("reason columns: %v", err)
		}
		if err := RollbackMigration(db, engine, 342); err != nil {
			t.Fatalf("rollback: %v", err)
		}
		if err := db.QueryRow(`SELECT privileged FROM outbound_credentials LIMIT 1`).Scan(&v); err == nil {
			t.Fatal("privileged still present after rollback")
		}
		if err := RunMigrations(db, engine); err != nil {
			t.Fatalf("re-apply: %v", err)
		}
	})
}

func TestMigration000345_TargetPrivilegeState(t *testing.T) {
	fingerprintEngines(t, func(t *testing.T, db *sql.DB, engine string) {
		if err := RunMigrations(db, engine); err != nil {
			t.Fatalf("RunMigrations: %v", err)
		}
		if err := execQ(db, engine, `INSERT INTO managed_targets (id, name, host, created_at, updated_at) VALUES (?, 'n', 'h', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`, "mt"); err != nil {
			t.Fatalf("insert: %v", err)
		}
		var mode, kind sql.NullString
		var n int
		var anyV any
		if err := db.QueryRow(`SELECT last_privilege_mode, unreadable_count, blocked_kind FROM managed_targets WHERE id = 'mt'`).Scan(&mode, &n, &kind); err != nil {
			t.Fatalf("columns missing: %v", err)
		}
		if mode.Valid || n != 0 || kind.Valid {
			t.Fatalf("defaults: %v %d %v", mode, n, kind)
		}
		if err := execQ(db, engine, `UPDATE managed_targets SET last_privilege_mode = ?, unreadable_count = ?, last_scanned_at = ?, blocked_kind = ?, blocked_reason = ?, blocked_at = ? WHERE id = 'mt'`, "helper", 2, "now", "rollback", "r", "now"); err != nil {
			t.Fatalf("update: %v", err)
		}
		if err := RollbackMigration(db, engine, 344); err != nil {
			t.Fatalf("rollback: %v", err)
		}
		if err := db.QueryRow(`SELECT blocked_kind FROM managed_targets LIMIT 1`).Scan(&kind); err == nil {
			t.Fatal("blocked_kind still present after rollback")
		}
		if err := db.QueryRow(`SELECT renewal_privilege_required FROM managed_targets LIMIT 1`).Scan(&anyV); err != nil {
			t.Fatalf("000342's column must survive the 000345 rollback: %v", err)
		}
		if err := RunMigrations(db, engine); err != nil {
			t.Fatalf("re-apply: %v", err)
		}
	})
}

func TestMigration000346_AgentHostReport(t *testing.T) {
	fingerprintEngines(t, func(t *testing.T, db *sql.DB, engine string) {
		if err := RunMigrations(db, engine); err != nil {
			t.Fatalf("RunMigrations: %v", err)
		}
		if err := execQ(db, engine, `INSERT INTO agents (id, name, type, token, registered_at) VALUES (?, 'n', 'linux', 't', 'now')`, "a1"); err != nil {
			t.Fatalf("insert: %v", err)
		}
		var v sql.NullString
		if err := db.QueryRow(`SELECT host_report FROM agents WHERE id = 'a1'`).Scan(&v); err != nil || v.Valid {
			t.Fatalf("host_report must exist and default NULL (a pre-W34 agent): %v %v", v, err)
		}
		if err := execQ(db, engine, `UPDATE agents SET host_report = ? WHERE id = 'a1'`, `{"posture_known":true}`); err != nil {
			t.Fatal(err)
		}
		if err := RollbackMigration(db, engine, 345); err != nil {
			t.Fatalf("rollback: %v", err)
		}
		if err := db.QueryRow(`SELECT host_report FROM agents LIMIT 1`).Scan(&v); err == nil {
			t.Fatal("host_report still present after rollback")
		}
		if err := RunMigrations(db, engine); err != nil {
			t.Fatalf("re-apply: %v", err)
		}
	})
}
