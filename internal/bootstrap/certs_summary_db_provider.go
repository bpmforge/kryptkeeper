// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

const (
	dbModeEnv                 = "KRYPTKEEPER_DB_MODE"
	dbModeSQLite              = "sqlite"
	dbModePostgres            = "postgres"
	dbCertSummarySQLiteSource = "db-store-sqlite"
	dbCertSummaryPGSource     = "db-store-postgres"
)

var errDBCertSummaryStoreUnimplemented = errors.New("db cert summary store is unimplemented")

type dbCertSummaryStore interface {
	LoadSummary(context.Context) (CertSummarySnapshot, error)
}

func newDBCertSummaryStoreFromEnv() dbCertSummaryStore {
	mode := currentDBMode()

	switch mode {
	case dbModeSQLite:
		dsn, err := sqliteDSNFromEnv()
		if err != nil {
			return dbCertSummaryStoreError{err: err}
		}
		store, err := newSQLiteCertSummaryStore(dsn)
		if err != nil {
			return dbCertSummaryStoreError{err: err}
		}
		return store
	case dbModePostgres:
		dsn := postgresDSNFromEnv()
		if dsn == "" {
			return dbCertSummaryStoreError{err: fmt.Errorf("postgres mode requires APP_CERTS_SUMMARY_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL")}
		}
		store, err := newPostgresCertSummaryStore(dsn)
		if err != nil {
			return dbCertSummaryStoreError{err: err}
		}
		return store
	default:
		return dbCertSummaryStoreError{err: unsupportedDBMode(mode)}
	}
}

func sqliteDSNFromEnv() (string, error) {
	dsn := strings.TrimSpace(os.Getenv("APP_CERTS_SUMMARY_DB_DSN"))
	if dsn != "" {
		return dsn, nil
	}

	dataDir := strings.TrimSpace(os.Getenv("KRYPTKEEPER_DATA_DIR"))
	if dataDir == "" {
		dataDir = "./var"
	}
	path := filepath.Join(dataDir, "kryptkeeper.db")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	return "file:" + path + sqliteDSNParams, nil
}

func postgresDSNFromEnv() string {
	if dsn := strings.TrimSpace(os.Getenv("APP_CERTS_SUMMARY_DB_DSN")); dsn != "" {
		return dsn
	}
	if dsn := strings.TrimSpace(os.Getenv("KRYPTKEEPER_DB_DSN")); dsn != "" {
		return dsn
	}
	return strings.TrimSpace(os.Getenv("DATABASE_URL"))
}

type dbCertSummaryStoreError struct{ err error }

func (e dbCertSummaryStoreError) LoadSummary(context.Context) (CertSummarySnapshot, error) {
	return CertSummarySnapshot{}, e.err
}

type sqliteCertSummaryStore struct {
	db *sql.DB
}

func newSQLiteCertSummaryStore(dsn string) (*sqliteCertSummaryStore, error) {
	db, err := openConfiguredDB("sqlite", dsn, 1, 1)
	if err != nil {
		return nil, err
	}
	return &sqliteCertSummaryStore{db: db}, nil
}

type postgresCertSummaryStore struct {
	db *sql.DB
}

func newPostgresCertSummaryStore(dsn string) (*postgresCertSummaryStore, error) {
	db, err := openConfiguredDB("pgx", dsn, 5, 2)
	if err != nil {
		return nil, err
	}
	return &postgresCertSummaryStore{db: db}, nil
}

func (s *sqliteCertSummaryStore) LoadSummary(ctx context.Context) (CertSummarySnapshot, error) {
	// Served-chain intermediates/roots (is_ca) are not leaf inventory.
	const query = `
SELECT
    COALESCE(SUM(CASE WHEN ` + activeCertSQL + ` THEN 1 ELSE 0 END), 0) AS total,
    COALESCE(SUM(CASE WHEN ` + revokedCertSQL + ` THEN 1 ELSE 0 END), 0) AS revoked,
    COALESCE(SUM(CASE WHEN ` + activeCertSQL + ` AND julianday(valid_until) < julianday('now') THEN 1 ELSE 0 END), 0) AS expired,
    COALESCE(SUM(CASE WHEN ` + activeCertSQL + ` AND julianday(valid_until) >= julianday('now') AND julianday(valid_until) < julianday('now', '+30 days') THEN 1 ELSE 0 END), 0) AS expiring_30_days,
    COALESCE(SUM(CASE WHEN ` + activeCertSQL + ` AND COALESCE(management_state, 'managed') = 'managed' THEN 1 ELSE 0 END), 0) AS managed,
    COALESCE(SUM(CASE WHEN ` + activeCertSQL + ` AND management_state = 'external' THEN 1 ELSE 0 END), 0) AS external,
    COALESCE(SUM(CASE WHEN ` + activeCertSQL + ` AND management_state = 'unmanaged' THEN 1 ELSE 0 END), 0) AS unmanaged
FROM certificates
WHERE COALESCE(is_ca, 0) = 0
`
	row := s.db.QueryRowContext(ctx, query)
	var total, revoked, expired, expiring30Days, managed, external, unmanaged int
	if err := row.Scan(&total, &revoked, &expired, &expiring30Days, &managed, &external, &unmanaged); err != nil {
		return CertSummarySnapshot{}, err
	}
	return CertSummarySnapshot{Total: total, Revoked: revoked, Expiring30Days: expiring30Days, Expired: expired, Managed: managed, External: external, Unmanaged: unmanaged, Source: dbCertSummarySQLiteSource}, nil
}

func (s *postgresCertSummaryStore) LoadSummary(ctx context.Context) (CertSummarySnapshot, error) {
	const query = `
SELECT
    COALESCE(SUM(CASE WHEN ` + activeCertSQL + ` THEN 1 ELSE 0 END), 0) AS total,
    COALESCE(SUM(CASE WHEN ` + revokedCertSQL + ` THEN 1 ELSE 0 END), 0) AS revoked,
    COALESCE(SUM(CASE WHEN ` + activeCertSQL + ` AND valid_until < CURRENT_TIMESTAMP THEN 1 ELSE 0 END), 0) AS expired,
    COALESCE(SUM(CASE WHEN ` + activeCertSQL + ` AND valid_until >= CURRENT_TIMESTAMP AND valid_until < CURRENT_TIMESTAMP + INTERVAL '30 days' THEN 1 ELSE 0 END), 0) AS expiring_30_days,
    COALESCE(SUM(CASE WHEN ` + activeCertSQL + ` AND COALESCE(management_state, 'managed') = 'managed' THEN 1 ELSE 0 END), 0) AS managed,
    COALESCE(SUM(CASE WHEN ` + activeCertSQL + ` AND management_state = 'external' THEN 1 ELSE 0 END), 0) AS external,
    COALESCE(SUM(CASE WHEN ` + activeCertSQL + ` AND management_state = 'unmanaged' THEN 1 ELSE 0 END), 0) AS unmanaged
FROM certificates
WHERE NOT is_ca
`
	row := s.db.QueryRowContext(ctx, query)
	var total, revoked, expired, expiring30Days, managed, external, unmanaged int
	if err := row.Scan(&total, &revoked, &expired, &expiring30Days, &managed, &external, &unmanaged); err != nil {
		return CertSummarySnapshot{}, err
	}
	return CertSummarySnapshot{Total: total, Revoked: revoked, Expiring30Days: expiring30Days, Expired: expired, Managed: managed, External: external, Unmanaged: unmanaged, Source: dbCertSummaryPGSource}, nil
}

// certSummaryCacheTTL bounds how stale the dashboard counters may be. The
// summary is a full-table aggregate on a single-connection store, so open
// dashboards must share one query per window instead of each running their
// own (M2).
const certSummaryCacheTTL = 2 * time.Second

type dbCertSummaryProvider struct {
	store   dbCertSummaryStore
	openErr error

	// mu is held across the store read so concurrent callers coalesce onto
	// one query rather than stampeding the single connection.
	mu       sync.Mutex
	cached   CertSummarySnapshot
	cachedAt time.Time
}

func newDBCertSummaryProviderFromEnv() CertSummaryProvider {
	store := newDBCertSummaryStoreFromEnv()
	if errStore, ok := store.(dbCertSummaryStoreError); ok {
		return &dbCertSummaryProvider{openErr: errStore.err}
	}
	return newDBCertSummaryProvider(store)
}

func newDBCertSummaryProvider(store dbCertSummaryStore) CertSummaryProvider {
	return &dbCertSummaryProvider{store: store}
}

func (p *dbCertSummaryProvider) LoadSummary(ctx context.Context) (CertSummarySnapshot, error) {
	if p.openErr != nil {
		log.Printf("cert summary db mode unavailable: %v", p.openErr)
		return CertSummarySnapshot{}, p.openErr
	}
	if p.store == nil {
		return CertSummarySnapshot{}, fmt.Errorf("db cert summary store not configured")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.cachedAt.IsZero() && time.Since(p.cachedAt) < certSummaryCacheTTL {
		return p.cached, nil
	}
	snap, err := p.store.LoadSummary(ctx)
	if err != nil {
		return CertSummarySnapshot{}, err
	}
	p.cached, p.cachedAt = snap, time.Now()
	return snap, nil
}
