// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package db

import "testing"

// 000387 rebuilds itsm_connections to admit kind 'plugin' with a plugin_id.
// Up keeps rows and the ticket links that reference them; down removes only
// plugin connections (and their links) and restores the two-kind CHECK.
func TestMigration000387_ITSMPluginKind_SQLite(t *testing.T) {
	db := freshSQLiteDB(t)
	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	const insConn = `INSERT INTO itsm_connections (id,kind,name,base_url,credential_ref,plugin_id,event_classes,enabled,tenant,created_at,updated_at)
		VALUES (?,?,?,?,?,?, '[]',1,'acme','2026-10-25T00:00:00Z','2026-10-25T00:00:00Z')`
	const insEvt = `INSERT INTO itsm_events (event_id,connection_id,class,payload,next_attempt_at,created_at,updated_at)
		VALUES (?,?,'renewal_failed','{}','2026-10-25T00:00:00Z','2026-10-25T00:00:00Z','2026-10-25T00:00:00Z')`
	if _, err := db.Exec(insConn, "c-jira", "jira", "J", "https://j.example", "cred", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(insConn, "c-plug", "plugin", "Z", "", "cred", "kryptkeeper.zendesk"); err != nil {
		t.Fatalf("plugin kind refused after up: %v", err)
	}
	if _, err := db.Exec(insConn, "c-bad", "carrier-pigeon", "B", "", "cred", ""); err == nil {
		t.Fatal("unknown kind accepted")
	}
	for _, args := range [][]any{{"e-jira", "c-jira"}, {"e-plug", "c-plug"}} {
		if _, err := db.Exec(insEvt, args...); err != nil {
			t.Fatal(err)
		}
	}

	if err := RollbackMigration(db, "sqlite", 386); err != nil {
		t.Fatalf("down: %v", err)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM itsm_connections WHERE kind='plugin'`); n != 0 {
		t.Errorf("plugin connections survived down: %d", n)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM itsm_events WHERE event_id='e-plug'`); n != 0 {
		t.Errorf("plugin ticket links survived down: %d", n)
	}
	var tenant string
	if err := db.QueryRow(`SELECT tenant FROM itsm_connections WHERE id='c-jira'`).Scan(&tenant); err != nil || tenant != "acme" {
		t.Errorf("jira connection lost across down: %q %v", tenant, err)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM itsm_events WHERE event_id='e-jira' AND connection_id='c-jira'`); n != 1 {
		t.Errorf("jira ticket link lost across down: %d", n)
	}

	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("re-up: %v", err)
	}
	if _, err := db.Exec(insConn, "c-plug2", "plugin", "Z", "", "cred", "kryptkeeper.freshservice"); err != nil {
		t.Errorf("plugin kind after re-up: %v", err)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM itsm_events WHERE event_id='e-jira'`); n != 1 {
		t.Errorf("jira ticket link lost across re-up: %d", n)
	}
}
