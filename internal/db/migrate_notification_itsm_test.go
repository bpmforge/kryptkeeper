// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"database/sql"
	"testing"
)

func countRows(t *testing.T, db *sql.DB, q string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(q).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

// 000302 rebuilds notification_rules and notification_deliveries to allow the
// itsm channel. Up keeps every row/column/index; down removes only itsm rows
// and restores the old CHECK.
func TestMigration000302_NotificationITSMChannel_SQLite(t *testing.T) {
	db := freshSQLiteDB(t)
	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	const insRule = `INSERT INTO notification_rules (id,name,threshold_days,channel,target,enabled,tenant) VALUES (?,?,?,?,?,1,?)`
	const insDel = `INSERT INTO notification_deliveries (id,channel,target,status,triggered_by) VALUES (?,?,?,'sent','system')`
	for _, args := range [][]any{{"r-email", "e", 30, "email", "a@b.c", "acme"}, {"r-itsm", "i", 30, "itsm", "conn-1", "acme"}} {
		if _, err := db.Exec(insRule, args...); err != nil {
			t.Fatalf("insert rule %v: %v", args[0], err)
		}
	}
	for _, args := range [][]any{{"d-email", "email", "a@b.c"}, {"d-itsm", "itsm", "conn-1"}} {
		if _, err := db.Exec(insDel, args...); err != nil {
			t.Fatalf("insert delivery %v: %v", args[0], err)
		}
	}
	// A retry row exercises the self-referencing FK across the rebuild.
	if _, err := db.Exec(`INSERT INTO notification_deliveries (id,channel,target,status,retry_of_id) VALUES ('d-retry','email','a@b.c','queued','d-email')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(insRule, "r-bad", "b", 30, "carrier-pigeon", "x", ""); err == nil {
		t.Fatal("unknown channel accepted")
	}

	if err := RollbackMigration(db, "sqlite", 301); err != nil {
		t.Fatalf("down: %v", err)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM notification_rules WHERE channel='itsm'`); n != 0 {
		t.Errorf("itsm rules survived down: %d", n)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM notification_deliveries WHERE channel='itsm'`); n != 0 {
		t.Errorf("itsm deliveries survived down: %d", n)
	}
	var tenant string
	if err := db.QueryRow(`SELECT tenant FROM notification_rules WHERE id='r-email'`).Scan(&tenant); err != nil || tenant != "acme" {
		t.Errorf("email rule lost across down: %q %v", tenant, err)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM notification_deliveries WHERE id IN ('d-email','d-retry')`); n != 2 {
		t.Errorf("non-itsm deliveries lost across down: %d", n)
	}
	if _, err := db.Exec(insRule, "r-itsm2", "i", 30, "itsm", "conn-1", ""); err == nil {
		t.Error("down must restore the old CHECK (itsm rejected)")
	}

	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("re-up: %v", err)
	}
	if _, err := db.Exec(insRule, "r-itsm3", "i", 30, "itsm", "conn-1", ""); err != nil {
		t.Errorf("itsm rule after up: %v", err)
	}
	if _, err := db.Exec(insDel, "d-itsm3", "itsm", "conn-1"); err != nil {
		t.Errorf("itsm delivery after up: %v", err)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM notification_deliveries WHERE id='d-retry' AND retry_of_id='d-email'`); n != 1 {
		t.Errorf("retry link lost: %d", n)
	}
	for _, idx := range []string{"idx_notif_rules_enabled", "idx_notif_rules_channel", "idx_notif_delivery_status", "idx_notif_delivery_channel", "idx_notif_delivery_queued", "idx_notif_delivery_policy", "idx_notif_delivery_retry"} {
		if n := countRows(t, db, `SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='`+idx+`'`); n != 1 {
			t.Errorf("index %s missing after up", idx)
		}
	}
}
