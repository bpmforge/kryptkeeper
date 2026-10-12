// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"database/sql"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// 000076 widens audit_log.outcome / actor_type. audit_log is append-only, so
// on SQLite the rebuild must keep every row, column, index and trigger, and
// the down must refuse rather than drop rows it cannot represent.

var newAuditOutcomes = []string{"skipped", "pending_approval", "proposed", "executed", "issuance_failed", "partial"}

const insertAuditSQLite = `INSERT INTO audit_log (action, actor_type, actor_id, resource_type, resource_id, outcome, change_summary, tenant)
	VALUES (?, ?, 'alice', 'test', ?, ?, ?, 'default')`

type sqliteColumn struct {
	Name, Type string
	NotNull    int
	Default    sql.NullString
	PK         int
}

func auditColumns(t *testing.T, db *sql.DB) []sqliteColumn {
	t.Helper()
	rows, err := db.Query(`PRAGMA table_info(audit_log)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var cols []sqliteColumn
	for rows.Next() {
		var cid int
		var c sqliteColumn
		if err := rows.Scan(&cid, &c.Name, &c.Type, &c.NotNull, &c.Default, &c.PK); err != nil {
			t.Fatal(err)
		}
		cols = append(cols, c)
	}
	return cols
}

// auditObjects returns name -> normalized SQL for every index and trigger on
// audit_log.
func auditObjects(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	rows, err := db.Query(`SELECT name, COALESCE(sql, '') FROM sqlite_master
		WHERE tbl_name = 'audit_log' AND type IN ('index', 'trigger') AND name NOT LIKE 'sqlite_autoindex%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var name, stmt string
		if err := rows.Scan(&name, &stmt); err != nil {
			t.Fatal(err)
		}
		out[name] = strings.Join(strings.Fields(stmt), " ")
	}
	return out
}

func auditRows(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT id, timestamp, action, actor_type, actor_id, COALESCE(actor_email,'~'), resource_type,
		resource_id, COALESCE(client_ip,'~'), COALESCE(trace_id,'~'), details, COALESCE(diff,'~'), outcome,
		COALESCE(source_ip,'~'), COALESCE(user_agent,'~'), COALESCE(session_id,'~'), COALESCE(change_summary,'~'), tenant
		FROM audit_log ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		v := make([]any, 18)
		ptrs := make([]any, 18)
		for i := range v {
			ptrs[i] = &v[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprint(v...))
	}
	return out
}

func TestMigration000076_SQLite_AuditOutcomeVocabulary(t *testing.T) {
	db := freshSQLiteDB(t)
	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	// Back to the pre-000076 (narrow) table, then give it history.
	if err := RollbackMigration(db, "sqlite", 75); err != nil {
		t.Fatalf("RollbackMigration to 75: %v", err)
	}
	if _, err := db.Exec(insertAuditSQLite, "certificate.issue", "user", "r1", "success", "first"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(insertAuditSQLite, "auth.login_failed", "system", "r2", "denied", "second"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(insertAuditSQLite, "certificate.revoke", "api_key", "r3", "failure", "third"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(insertAuditSQLite, "x", "user", "r4", newAuditOutcomes[0], "no"); err == nil {
		t.Fatal("test setup: the narrow table must reject a new outcome")
	}
	beforeRows, beforeCols, beforeObjs := auditRows(t, db), auditColumns(t, db), auditObjects(t, db)
	if len(beforeRows) != 3 {
		t.Fatalf("setup rows = %d", len(beforeRows))
	}
	var maxID int64
	_ = db.QueryRow(`SELECT MAX(id) FROM audit_log`).Scan(&maxID)

	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("re-apply 000076: %v", err)
	}

	if got := auditRows(t, db); !reflect.DeepEqual(got, beforeRows) {
		t.Fatalf("rows changed by the rebuild:\nbefore %v\nafter  %v", beforeRows, got)
	}
	if got := auditColumns(t, db); !reflect.DeepEqual(got, beforeCols) {
		t.Fatalf("columns changed by the rebuild:\nbefore %+v\nafter  %+v", beforeCols, got)
	}
	afterObjs := auditObjects(t, db)
	for _, name := range []string{"idx_audit_timestamp", "idx_audit_resource", "idx_audit_actor", "idx_audit_outcome_ts", "idx_audit_tenant", "trg_audit_log_no_update", "trg_audit_log_no_delete"} {
		if afterObjs[name] == "" {
			t.Errorf("%s missing after the rebuild", name)
		} else if beforeObjs[name] != afterObjs[name] {
			t.Errorf("%s changed:\nbefore %s\nafter  %s", name, beforeObjs[name], afterObjs[name])
		}
	}
	if len(afterObjs) != len(beforeObjs) {
		t.Errorf("index/trigger set changed: before %v after %v", beforeObjs, afterObjs)
	}

	// Append-only still holds.
	if _, err := db.Exec(`UPDATE audit_log SET outcome = 'failure' WHERE id = 1`); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("UPDATE must be refused by the trigger, got %v", err)
	}
	if _, err := db.Exec(`DELETE FROM audit_log WHERE id = 1`); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("DELETE must be refused by the trigger, got %v", err)
	}

	// New vocabulary accepted, unknown still refused, ids never reused.
	for i, o := range newAuditOutcomes {
		if _, err := db.Exec(insertAuditSQLite, "x", "user", fmt.Sprintf("n%d", i), o, ""); err != nil {
			t.Errorf("outcome %q must be accepted after 000076: %v", o, err)
		}
	}
	if _, err := db.Exec(insertAuditSQLite, "x", "workload", "w", "success", ""); err != nil {
		t.Errorf("actor_type workload must be accepted after 000076: %v", err)
	}
	if _, err := db.Exec(insertAuditSQLite, "x", "user", "bad", "renewed_install_failed", ""); err == nil {
		t.Error("an outcome outside the vocabulary must still be rejected")
	}
	if _, err := db.Exec(insertAuditSQLite, "x", "robot", "bad", "success", ""); err == nil {
		t.Error("an unknown actor_type must still be rejected")
	}
	var minNew int64
	_ = db.QueryRow(`SELECT MIN(id) FROM audit_log WHERE resource_id = 'n0'`).Scan(&minNew)
	if minNew <= maxID {
		t.Fatalf("id %d reused or not past the old maximum %d", minNew, maxID)
	}
}

func TestMigration000076_SQLite_DownRefusesInsteadOfDroppingAuditRows(t *testing.T) {
	db := freshSQLiteDB(t)
	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	if _, err := db.Exec(insertAuditSQLite, "certificate.issue", "user", "r1", "success", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(insertAuditSQLite, "renewal_notification_sent", "system", "r2", "skipped", ""); err != nil {
		t.Fatal(err)
	}
	before := auditRows(t, db)

	err := RollbackMigration(db, "sqlite", 75)
	if err == nil || !strings.Contains(err.Error(), "audit_log_has_rows_that_need_the_000076_vocabulary") {
		t.Fatalf("rollback must refuse with a named reason, got %v", err)
	}
	if got := auditRows(t, db); !reflect.DeepEqual(got, before) {
		t.Fatalf("a refused rollback changed audit rows:\nbefore %v\nafter  %v", before, got)
	}
	if objs := auditObjects(t, db); objs["trg_audit_log_no_delete"] == "" || objs["trg_audit_log_no_update"] == "" {
		t.Fatalf("append-only triggers missing after a refused rollback: %v", objs)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 76`).Scan(&n)
	if n != 1 {
		t.Fatal("000076 must still be recorded as applied after a refused rollback")
	}
	var stray int
	_ = db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name IN ('audit_log_new', 'refuse_000076_down')`).Scan(&stray)
	if stray != 0 {
		t.Fatal("a refused rollback left scratch tables behind")
	}
}

func TestMigration000076_Postgres_AuditOutcomeVocabulary(t *testing.T) {
	db := freshPostgresDB(t, livePostgresDSN(t))
	if err := RunMigrations(db, "postgres"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	const ins = `INSERT INTO audit_log (action, actor_type, actor_id, resource_type, resource_id, outcome)
		VALUES ('x', $1, 'alice', 'test', $2, $3)`

	for i, o := range append([]string{"success", "failure", "denied"}, newAuditOutcomes...) {
		if _, err := db.Exec(ins, "user", fmt.Sprintf("r%d", i), o); err != nil {
			t.Errorf("outcome %q must be accepted: %v", o, err)
		}
	}
	if _, err := db.Exec(ins, "workload", "w", "success"); err != nil {
		t.Errorf("actor_type workload must be accepted: %v", err)
	}
	if _, err := db.Exec(ins, "user", "bad", "renewed_install_failed"); err == nil {
		t.Error("an outcome outside the vocabulary must still be rejected")
	}
	if _, err := db.Exec(`UPDATE audit_log SET outcome = 'failure'`); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("UPDATE must stay refused, got %v", err)
	}

	// Every partition carries the widened constraint, not only the parent.
	var stale int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pg_constraint c
		WHERE c.conname = 'audit_log_outcome_check'
		  AND (c.conrelid = 'audit_log'::regclass OR c.conrelid IN (SELECT inhrelid FROM pg_inherits WHERE inhparent = 'audit_log'::regclass))
		  AND pg_get_constraintdef(c.oid) NOT LIKE '%pending_approval%'`).Scan(&stale); err != nil || stale != 0 {
		t.Fatalf("narrow outcome constraints remain: %d err=%v", stale, err)
	}

	// Down refuses while new-vocabulary rows exist, and changes nothing.
	var before int
	_ = db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&before)
	if err := RollbackMigration(db, "postgres", 75); err == nil || !strings.Contains(err.Error(), "cannot roll back 000076") {
		t.Fatalf("rollback must refuse, got %v", err)
	}
	var after int
	_ = db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&after)
	if before != after || before == 0 {
		t.Fatalf("audit rows before=%d after=%d", before, after)
	}
}

func TestMigration000076_Postgres_DownWhenOnlyOriginalVocabulary(t *testing.T) {
	db := freshPostgresDB(t, livePostgresDSN(t))
	if err := RunMigrations(db, "postgres"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	const ins = `INSERT INTO audit_log (action, actor_type, actor_id, resource_type, resource_id, outcome)
		VALUES ('x', 'user', 'alice', 'test', $1, $2)`
	if _, err := db.Exec(ins, "r1", "success"); err != nil {
		t.Fatal(err)
	}
	if err := RollbackMigration(db, "postgres", 75); err != nil {
		t.Fatalf("rollback with only original-vocabulary rows: %v", err)
	}
	if _, err := db.Exec(ins, "r2", "skipped"); err == nil {
		t.Fatal("skipped must be rejected again after rolling back 000076")
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&n)
	if n != 1 {
		t.Fatalf("rows after rollback = %d, want 1", n)
	}
	if err := RunMigrations(db, "postgres"); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if _, err := db.Exec(ins, "r3", "pending_approval"); err != nil {
		t.Fatalf("pending_approval after re-apply: %v", err)
	}
}

func TestEnsureAuditOutcomeVocabulary_SQLite(t *testing.T) {
	db := freshSQLiteDB(t)
	if err := EnsureAuditOutcomeVocabulary(db, "sqlite"); err != nil {
		t.Fatalf("no audit_log must be a no-op: %v", err)
	}
	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	if err := RollbackMigration(db, "sqlite", 75); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(insertAuditSQLite, "a", "user", "r1", "success", ""); err != nil {
		t.Fatal(err)
	}
	if err := EnsureAuditOutcomeVocabulary(db, "sqlite"); err != nil {
		t.Fatalf("widen: %v", err)
	}
	if _, err := db.Exec(insertAuditSQLite, "a", "user", "r2", "partial", ""); err != nil {
		t.Fatalf("partial after widen: %v", err)
	}
	if err := EnsureAuditOutcomeVocabulary(db, "sqlite"); err != nil {
		t.Fatalf("second call must be a no-op: %v", err)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&n)
	if n != 2 {
		t.Fatalf("rows = %d, want 2", n)
	}
	// Migrations run afterwards must still apply cleanly on the widened table.
	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("RunMigrations after self-heal: %v", err)
	}
}
