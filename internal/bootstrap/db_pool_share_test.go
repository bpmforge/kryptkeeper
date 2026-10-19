// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// Regression: a Postgres hub built each store (the credential store ~15x) with
// its own pool, held ~120 idle connections and exhausted max_connections=100.
func TestPostgresStoresOfOneServiceSharePool(t *testing.T) {
	t.Setenv(dbModeEnv, dbModePostgres)
	t.Setenv("DATABASE_URL", "postgres://u:p@127.0.0.1:1/db")
	pgPoolsMu.Lock()
	saved := pgPoolsByService
	pgPoolsByService = map[string]*sql.DB{}
	pgPoolsMu.Unlock()
	opens := 0
	prev := openPostgresDBFn
	openPostgresDBFn = func(string) (*sql.DB, error) {
		opens++
		return sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "x.db"))
	}
	t.Cleanup(func() {
		openPostgresDBFn = prev
		pgPoolsMu.Lock()
		pgPoolsByService = saved
		pgPoolsMu.Unlock()
	})

	open := func(service string) *sql.DB {
		st := newDBProviderState[*sql.DB](service, nil,
			func() string { return "postgres://u:p@127.0.0.1:1/db" }, nil,
			func(db *sql.DB) *sql.DB { return db }, func(db *sql.DB) *sql.DB { return db })
		if st.openErr != nil {
			t.Fatal(st.openErr)
		}
		return st.store
	}
	a, b := open("outbound-credential"), open("outbound-credential")
	if a != b || opens != 1 {
		t.Fatalf("same service opened %d pools, want 1 shared", opens)
	}
	if open("pending-action") == a || opens != 2 {
		t.Fatalf("different services must not share a pool (opens=%d)", opens)
	}
	first, second := open("compliance-attestation"), open("compliance-attestation")
	if first == second {
		t.Fatal("compliance-attestation is closed after one-shot use and must not be shared")
	}
}
