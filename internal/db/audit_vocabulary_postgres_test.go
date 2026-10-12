// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package db

import "testing"

func TestEnsureAuditOutcomeVocabulary_Postgres(t *testing.T) {
	db := freshPostgresDB(t, livePostgresDSN(t))
	if err := RunMigrations(db, "postgres"); err != nil {
		t.Fatal(err)
	}
	if err := RollbackMigration(db, "postgres", 75); err != nil {
		t.Fatal(err)
	}
	const ins = `INSERT INTO audit_log (action, actor_type, actor_id, resource_type, resource_id, outcome)
		VALUES ('x', 'user', 'alice', 'test', 'r', $1)`
	if _, err := db.Exec(ins, "pending_approval"); err == nil {
		t.Fatal("test setup: the narrow table must reject pending_approval")
	}
	if err := EnsureAuditOutcomeVocabulary(db, "postgres"); err != nil {
		t.Fatalf("widen: %v", err)
	}
	if _, err := db.Exec(ins, "pending_approval"); err != nil {
		t.Fatalf("pending_approval after widen: %v", err)
	}
	if err := EnsureAuditOutcomeVocabulary(db, "postgres"); err != nil {
		t.Fatalf("second call must be a no-op: %v", err)
	}
}
