// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// freshPostgresForTest returns the DSN named by KRYPTKEEPER_TEST_POSTGRES_DSN
// after resetting its public schema, and points every DSN env the stores read
// at it with KRYPTKEEPER_DB_MODE=postgres. It skips when the env is unset and
// refuses a database whose name does not contain "test", because the reset is
// an unconditional DROP SCHEMA ... CASCADE (same guard as internal/db's
// freshPostgresDB).
func freshPostgresForTest(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("KRYPTKEEPER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("KRYPTKEEPER_TEST_POSTGRES_DSN not set — skipping live Postgres integration test")
	}
	name := ""
	if u, err := url.Parse(dsn); err == nil && u.Scheme != "" {
		name = strings.TrimPrefix(u.Path, "/")
	} else {
		for _, f := range strings.Fields(dsn) {
			if rest, ok := strings.CutPrefix(f, "dbname="); ok {
				name = rest
			}
		}
	}
	if !strings.Contains(strings.ToLower(name), "test") {
		t.Fatalf("refusing to DROP SCHEMA on database %q: KRYPTKEEPER_TEST_POSTGRES_DSN must name a disposable database with \"test\" in its name", name)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset postgres schema: %v", err)
	}

	t.Setenv(dbModeEnv, dbModePostgres)
	t.Setenv("KRYPTKEEPER_DB_DSN", dsn)
	for _, k := range []string{"APP_CORE_DB_DSN", "APP_AUDIT_DB_DSN", "DATABASE_URL"} {
		t.Setenv(k, "")
	}
	return dsn
}
