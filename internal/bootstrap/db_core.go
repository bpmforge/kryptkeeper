// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"database/sql"
	"fmt"
	"regexp"
	"strings"

	kkdb "kryptkeeper/internal/db"
)

// OpenCoreDB opens the core application database based on KRYPTKEEPER_DB_MODE,
// applying any pending versioned migrations (W10-01/G-33) before returning it
// so every caller sees an up-to-date schema, not just whatever the per-store
// EnsureSchema() idempotent CREATE TABLE IF NOT EXISTS calls happen to cover.
// Returns the DB connection, whether it is Postgres (vs SQLite), and any error.
// The caller is responsible for closing the returned *sql.DB.
func OpenCoreDB() (*sql.DB, bool, error) {
	db, isPostgres, err := OpenCoreDBNoMigrate()
	if err != nil {
		return nil, isPostgres, err
	}
	engine := "sqlite"
	if isPostgres {
		engine = "postgres"
	}
	if err := kkdb.RunMigrations(db, engine); err != nil {
		_ = db.Close()
		return nil, isPostgres, fmt.Errorf("run %s migrations: %w", engine, err)
	}
	return db, isPostgres, nil
}

// OpenCoreDBNoMigrate opens the core database exactly as OpenCoreDB does but
// leaves the schema alone. `kryptkeeper migrate status|down` needs this: it
// must report on, or roll back, a database that RunMigrations would refuse
// (newer schema) or alter (pending). The caller closes the returned *sql.DB.
func OpenCoreDBNoMigrate() (*sql.DB, bool, error) {
	mode := currentDBMode()
	switch mode {
	case dbModeSQLite:
		dsn, err := resolveSQLiteDSNFromEnv("APP_CORE_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		if err != nil {
			return nil, false, err
		}
		db, err := openConfiguredDB("sqlite", dsn, 1, 1)
		if err != nil {
			return nil, false, err
		}
		return db, false, nil
	case dbModePostgres:
		dsn := resolvePostgresDSNFromEnv("APP_CORE_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		if dsn == "" {
			return nil, true, fmt.Errorf("postgres core DB requires APP_CORE_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL")
		}
		db, err := openPostgresDB(dsn)
		if err != nil {
			return nil, true, err
		}
		return db, true, nil
	default:
		return nil, false, unsupportedDBMode(mode)
	}
}

// CoreDBStartupDecision decides what boot does when OpenCoreDB fails. With
// APP_CERTIFICATE_PROVIDER=ca the core DB is the only place the CA, its
// certificates and revocations live: continuing on an in-memory store would
// mint a root that silently vanishes at the next restart, so it is fatal.
// Other providers never open the core DB at boot, so there is nothing to veto.
func CoreDBStartupDecision(certProvider string, openErr error) error {
	if openErr == nil || !strings.EqualFold(strings.TrimSpace(certProvider), "ca") {
		return nil
	}
	hint := "check KRYPTKEEPER_DB_MODE / APP_CORE_DB_DSN / KRYPTKEEPER_DATA_DIR and that the database is reachable and writable"
	var which string
	if mig := failedMigrationName(openErr); mig != "" {
		which = fmt.Sprintf(" (migration %s failed)", mig)
		hint = "the existing schema is in a state that migration cannot apply to; back up the data directory and report this error, do not delete the database"
	}
	return fmt.Errorf("refusing to start with APP_CERTIFICATE_PROVIDER=ca: core database unavailable%s: %w; running without it would keep the CA in memory and lose it on restart. Fix: %s", which, openErr, hint)
}

var failedMigrationRe = regexp.MustCompile(`apply migration (\d{6}_[A-Za-z0-9_]+)`)

func failedMigrationName(err error) string {
	if m := failedMigrationRe.FindStringSubmatch(err.Error()); m != nil {
		return m[1]
	}
	return ""
}
