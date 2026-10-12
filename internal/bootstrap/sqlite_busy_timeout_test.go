// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import "testing"

// Every store opens its own pool on the shared kryptkeeper.db, so writers from
// different stores routinely meet. Without busy_timeout SQLite's default is 0:
// the loser fails at once with SQLITE_BUSY ("database is locked") instead of
// waiting out the other's short transaction. The effective pragma is checked
// on a live connection, for both places that build the default DSN.
func TestDefaultSQLiteDSNsSetBusyTimeout(t *testing.T) {
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	t.Setenv("APP_CERTS_SUMMARY_DB_DSN", "")
	generic, err := resolveSQLiteDSNFromEnv("KRYPTKEEPER_TEST_UNSET_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
	if err != nil {
		t.Fatalf("resolve dsn: %v", err)
	}
	summary, err := sqliteDSNFromEnv()
	if err != nil {
		t.Fatalf("certs summary dsn: %v", err)
	}
	for name, dsn := range map[string]string{"resolveSQLiteDSNFromEnv": generic, "sqliteDSNFromEnv": summary} {
		db, err := openConfiguredDB("sqlite", dsn, 1, 1)
		if err != nil {
			t.Fatalf("%s: open: %v", name, err)
		}
		var ms int
		if err := db.QueryRow(`PRAGMA busy_timeout`).Scan(&ms); err != nil {
			t.Fatalf("%s: read busy_timeout: %v", name, err)
		}
		var mode string
		if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
			t.Fatalf("%s: read journal_mode: %v", name, err)
		}
		_ = db.Close()
		if ms < 1000 {
			t.Errorf("%s: busy_timeout = %d ms, want at least 1000", name, ms)
		}
		if mode != "wal" {
			t.Errorf("%s: journal_mode = %q, want wal", name, mode)
		}
	}
}
