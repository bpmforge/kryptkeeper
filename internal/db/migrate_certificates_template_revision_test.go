// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package db

import "testing"

// 000126 (W23-44) adds the nullable certificates.template_revision; the
// rollback must drop it and leave the other columns alone.
func TestMigration000126_TemplateRevisionColumn(t *testing.T) {
	db := freshSQLiteDB(t)
	if err := RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	withCol := tableColumnNames(t, db, "certificates")
	has := func(cols []string) bool {
		for _, c := range cols {
			if c == "template_revision" {
				return true
			}
		}
		return false
	}
	if !has(withCol) {
		t.Fatal("template_revision missing after up")
	}
	if err := RollbackMigration(db, "sqlite", 125); err != nil {
		t.Fatalf("RollbackMigration: %v", err)
	}
	after := tableColumnNames(t, db, "certificates")
	// Rolling back to 125 also undoes later column additions (000341's
	// issuer_class); only template_revision is this migration's own.
	later := 0
	for _, c := range withCol {
		if c == "issuer_class" {
			later++
		}
	}
	if has(after) || len(after) != len(withCol)-1-later {
		t.Fatalf("down must drop only template_revision: before=%v after=%v", withCol, after)
	}
}
