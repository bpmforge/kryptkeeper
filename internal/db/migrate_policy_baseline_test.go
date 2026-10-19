// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"encoding/json"
	"strings"
	"testing"
)

// W22-14: 000088 seeds the baseline issuance policy when the table is empty.
func TestMigrationSeedsBaselineIssuancePolicy(t *testing.T) {
	db := openMigrated(t)
	var name, rules, createdAt string
	var enabled int
	if err := db.QueryRow(`SELECT name, enabled, rules, created_at FROM issuance_policies WHERE id = 'pol-baseline'`).Scan(&name, &enabled, &rules, &createdAt); err != nil {
		t.Fatalf("baseline row missing: %v", err)
	}
	var r struct {
		Allowed []string `json:"allowed_algorithms"`
		MinRSA  int      `json:"min_rsa_bits"`
		MaxDays int      `json:"max_validity_days"`
		AllowCA bool     `json:"allow_ca_certs"`
	}
	if err := json.Unmarshal([]byte(rules), &r); err != nil {
		t.Fatalf("rules json: %v", err)
	}
	if name != "Baseline" || enabled != 1 || r.MinRSA != 3072 || r.MaxDays != 398 || r.AllowCA || len(r.Allowed) == 0 {
		t.Fatalf("unexpected baseline: %s enabled=%d %+v", name, enabled, r)
	}
	if !strings.HasSuffix(createdAt, "Z") {
		t.Fatalf("created_at = %q, want RFC3339 UTC", createdAt)
	}
	has3072 := false
	for _, a := range r.Allowed {
		if a == "RSA-2048" {
			t.Fatal("baseline must not allow RSA-2048")
		}
		has3072 = has3072 || a == "RSA-3072"
	}
	// 000196: min_rsa_bits 3072 must not be contradicted by the allow-list.
	if !has3072 {
		t.Fatalf("baseline allow-list %v omits RSA-3072 although min_rsa_bits is 3072", r.Allowed)
	}
}

// An operator who already defined policies is never overridden: the insert is
// guarded by NOT EXISTS, so re-running the SQL against a populated table is a no-op.
func TestBaselineMigrationSkipsPopulatedTable(t *testing.T) {
	db := openMigrated(t)
	if _, err := db.Exec(`DELETE FROM issuance_policies WHERE id = 'pol-baseline'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO issuance_policies (id,name,enabled,ca_id,rules,created_at,updated_at) VALUES ('mine','Mine',1,'','{}','x','x')`); err != nil {
		t.Fatal(err)
	}
	body, err := migrationsFS.ReadFile("migrations/sqlite/000088_issuance_policy_baseline.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(body)); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM issuance_policies`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("count = %d err=%v, want 1", n, err)
	}
}
