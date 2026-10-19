// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package db

import "testing"

const insertTeamPolicySQL = `INSERT INTO team_policies (tenant, team, created_at, updated_at) VALUES ($1, 'payments', 'x', 'x')`

// W33-20: 000320 creates team_policies keyed by (tenant, team).
func TestMigrationTeamPolicies_SQLite(t *testing.T) {
	db := openMigrated(t)
	ins := func(tenant string) error {
		_, err := db.Exec(`INSERT INTO team_policies (tenant, team, created_at, updated_at) VALUES (?, 'payments', 'x', 'x')`, tenant)
		return err
	}
	if err := ins("acme"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := ins("acme"); err == nil {
		t.Fatal("duplicate (tenant,team) must be rejected by the primary key")
	}
	if err := ins("beta"); err != nil {
		t.Fatalf("same team in another tenant must be allowed: %v", err)
	}
	var lists string
	var version int
	if err := db.QueryRow(`SELECT allowed_cas, version FROM team_policies WHERE tenant='acme'`).Scan(&lists, &version); err != nil || lists != "[]" || version != 1 {
		t.Fatalf("defaults = %q v%d err=%v", lists, version, err)
	}
}

func TestMigrationTeamPolicies_RollbackRemovesTable(t *testing.T) {
	db := openMigrated(t)
	if !columnExists(t, db, "team_policies", "monthly_quota") {
		t.Fatal("team_policies missing after up")
	}
	ms, err := loadMigrations("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	idx := -1
	for i, m := range ms {
		if m.name == "team_policies" {
			idx = i
		}
	}
	if idx <= 0 {
		t.Fatal("migration team_policies not found")
	}
	if err := RollbackMigration(db, "sqlite", ms[idx-1].version); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if columnExists(t, db, "team_policies", "monthly_quota") {
		t.Fatal("team_policies still present after rollback")
	}
}

func TestMigrationTeamPolicies_Postgres(t *testing.T) {
	t.Setenv(ciSeedEnvVar, "")
	db := freshPostgresDB(t, livePostgresDSN(t))
	if err := RunMigrations(db, "postgres"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	if _, err := db.Exec(insertTeamPolicySQL, "acme"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := db.Exec(insertTeamPolicySQL, "acme"); err == nil {
		t.Fatal("duplicate (tenant,team) must be rejected by the primary key")
	}
	ms, err := loadMigrations("postgres")
	if err != nil {
		t.Fatal(err)
	}
	idx := -1
	for i, m := range ms {
		if m.name == "team_policies" {
			idx = i
		}
	}
	if idx <= 0 {
		t.Fatal("migration team_policies not found")
	}
	if err := RollbackMigration(db, "postgres", ms[idx-1].version); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if _, err := db.Exec(insertTeamPolicySQL, "acme"); err == nil {
		t.Fatal("team_policies still present after rollback")
	}
}
