// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package tenantidor

import (
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// TestResetPostgres empties the test database before the postgres pass. Each
// run boots a hub with a fresh keystore directory, so CAs left over from an
// earlier run have no key and the hub (correctly) refuses to start. Only runs
// when run.sh asks for it, and only against a database whose name contains
// "test".
func TestResetPostgres(t *testing.T) {
	if os.Getenv("KK_IDOR_RESET_PG") != "1" {
		t.Skip("KK_IDOR_RESET_PG not set")
	}
	dsn := os.Getenv("KRYPTKEEPER_TEST_POSTGRES_DSN")
	u, err := url.Parse(dsn)
	if err != nil || !strings.Contains(strings.TrimPrefix(u.Path, "/"), "test") {
		t.Fatalf("refusing to reset: database name in KRYPTKEEPER_TEST_POSTGRES_DSN must contain \"test\"")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	for _, stmt := range []string{"DROP SCHEMA public CASCADE", "CREATE SCHEMA public"} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
}
