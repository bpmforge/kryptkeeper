// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"kryptkeeper/internal/logging"
)

func currentDBMode() string {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv(dbModeEnv)))
	if mode == "" {
		return dbModeSQLite
	}
	return mode
}

func unsupportedDBMode(mode string) error {
	return fmt.Errorf("unsupported %s=%q", dbModeEnv, mode)
}

func openConfiguredDB(driverName, dsn string, maxOpenConns, maxIdleConns int) (*sql.DB, error) {
	return openPool(driverName, dsn, dbPoolConfig{maxOpen: maxOpenConns, maxIdle: maxIdleConns})
}

func openPool(driverName, dsn string, cfg dbPoolConfig) (*sql.DB, error) {
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(cfg.maxOpen)
	db.SetMaxIdleConns(cfg.maxIdle)
	if cfg.maxIdleTime > 0 {
		db.SetConnMaxIdleTime(cfg.maxIdleTime)
	}
	ctx, cancel := context.WithTimeout(context.Background(), pgPingTimeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

type dbProviderState[Store any] struct {
	service string
	store   Store
	openErr error
}

// releaseFailedOpenDB closes the pool a store open made for itself when the
// store is then not used (EnsureSchema failed). The lazy stores (D-290-A)
// retry their open every storeRetryInterval, so without this each failed
// attempt leaked one held SQLite connection. A shared Postgres pool is left
// open: other holders use it and openSharedPostgresDB reuses it on retry.
func releaseFailedOpenDB(service string, db *sql.DB) {
	if db == nil || (currentDBMode() == dbModePostgres && !pgUnsharedServices[service]) {
		return
	}
	_ = db.Close()
}

func dbProviderUnavailable(service string, openErr error) error {
	if openErr == nil {
		return nil
	}
	logging.Warnf("%s db mode unavailable: %v", service, openErr)
	return openErr
}

func newDBProviderState[Store any](
	service string,
	sqliteDSN func() (string, error),
	postgresDSN func() string,
	postgresMissingErr error,
	sqliteFactory func(*sql.DB) Store,
	postgresFactory func(*sql.DB) Store,
) dbProviderState[Store] {
	mode := currentDBMode()

	switch mode {
	case dbModeSQLite:
		dsn, err := sqliteDSN()
		if err != nil {
			return dbProviderState[Store]{service: service, openErr: err}
		}
		db, err := openConfiguredDB("sqlite", dsn, 1, 1)
		if err != nil {
			return dbProviderState[Store]{service: service, openErr: err}
		}
		return dbProviderState[Store]{service: service, store: sqliteFactory(db)}
	case dbModePostgres:
		dsn := postgresDSN()
		if dsn == "" {
			return dbProviderState[Store]{service: service, openErr: postgresMissingErr}
		}
		db, err := openSharedPostgresDB(service, dsn)
		if err != nil {
			return dbProviderState[Store]{service: service, openErr: err}
		}
		return dbProviderState[Store]{service: service, store: postgresFactory(db)}
	default:
		return dbProviderState[Store]{service: service, openErr: unsupportedDBMode(mode)}
	}
}

// sqliteDSNParams are shared by every store that opens the default
// kryptkeeper.db. Each store has its own pool on the same file, so a writer
// that meets another store's write lock must wait (busy_timeout) instead of
// failing at once with SQLITE_BUSY ("database is locked").
const sqliteDSNParams = "?cache=shared&_fk=1&_journal_mode=WAL&_busy_timeout=5000"

func resolveSQLiteDSNFromEnv(serviceEnvVar, dataDirEnvVar, defaultFileName string) (string, error) {
	if dsn := strings.TrimSpace(os.Getenv(serviceEnvVar)); dsn != "" {
		return dsn, nil
	}
	dataDir := strings.TrimSpace(os.Getenv(dataDirEnvVar))
	if dataDir == "" {
		dataDir = "./var"
	}
	path := filepath.Join(dataDir, defaultFileName)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	return "file:" + path + sqliteDSNParams, nil
}

func resolvePostgresDSNFromEnv(serviceEnvVar string, fallbackEnvVars ...string) string {
	if dsn := strings.TrimSpace(os.Getenv(serviceEnvVar)); dsn != "" {
		return dsn
	}
	for _, envVar := range fallbackEnvVars {
		if dsn := strings.TrimSpace(os.Getenv(envVar)); dsn != "" {
			return dsn
		}
	}
	return ""
}
