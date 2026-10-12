// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// PostureSnapshot is a point-in-time capture of the crypto-posture report,
// stored daily so the dashboard can chart posture trends over time. The flat
// columns make trend queries cheap; Report retains the full report for
// drill-down.
type PostureSnapshot struct {
	ID                string              `json:"id"`
	CapturedAt        string              `json:"captured_at"`
	TotalCerts        int                 `json:"total_certs"`
	PQCScorePercent   int                 `json:"pqc_score_percent"`
	AutomationPercent int                 `json:"automation_percent"`
	RiskCritical      int                 `json:"risk_critical"`
	RiskHigh          int                 `json:"risk_high"`
	RiskMedium        int                 `json:"risk_medium"`
	RiskLow           int                 `json:"risk_low"`
	Expired           int                 `json:"expired"`
	Expiring47d       int                 `json:"expiring_47d"`
	Report            CryptoPostureReport `json:"report"`
}

// snapshotFromReport flattens a CryptoPostureReport into a PostureSnapshot.
func snapshotFromReport(id, capturedAt string, r CryptoPostureReport) PostureSnapshot {
	return PostureSnapshot{
		ID:                id,
		CapturedAt:        capturedAt,
		TotalCerts:        r.TotalCerts,
		PQCScorePercent:   r.PQCReadiness.PQCScorePercent,
		AutomationPercent: r.AutomationCoverage.AutomationPercent,
		RiskCritical:      r.RiskBreakdown.Critical,
		RiskHigh:          r.RiskBreakdown.High,
		RiskMedium:        r.RiskBreakdown.Medium,
		RiskLow:           r.RiskBreakdown.Low,
		Expired:           r.ExpiryBuckets.Expired,
		Expiring47d:       r.ExpiryBuckets.Expiring47d,
		Report:            r,
	}
}

// PostureSnapshotStore persists and retrieves daily posture snapshots.
type PostureSnapshotStore interface {
	EnsureSchema(ctx context.Context) error
	Save(ctx context.Context, s PostureSnapshot) error
	List(ctx context.Context, since string, limit int) ([]PostureSnapshot, error)
	Latest(ctx context.Context) (PostureSnapshot, bool, error)
}

func newPostureSnapshotID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "psn-" + hex.EncodeToString(b), nil
}

const postureSnapshotSchema = `
CREATE TABLE IF NOT EXISTS posture_snapshots (
    id                  TEXT PRIMARY KEY,
    captured_at         TEXT NOT NULL,
    total_certs         INTEGER NOT NULL,
    pqc_score_percent   INTEGER NOT NULL,
    automation_percent  INTEGER NOT NULL,
    risk_critical       INTEGER NOT NULL,
    risk_high           INTEGER NOT NULL,
    risk_medium         INTEGER NOT NULL,
    risk_low            INTEGER NOT NULL,
    expired             INTEGER NOT NULL,
    expiring_47d        INTEGER NOT NULL,
    report_json         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_posture_snapshots_captured ON posture_snapshots(captured_at);`

// dbPostureSnapshotStore works for both SQLite and Postgres. The only dialect
// difference is the placeholder style for parameterized queries, supplied via ph.
type dbPostureSnapshotStore struct {
	db *sql.DB
	// ph builds an N-indexed placeholder ("?" for SQLite, "$N" for Postgres).
	ph func(n int) string
}

func sqlitePlaceholder(int) string     { return "?" }
func postgresPlaceholder(n int) string { return fmt.Sprintf("$%d", n) }

func (s *dbPostureSnapshotStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, postureSnapshotSchema)
	return err
}

func (s *dbPostureSnapshotStore) Save(ctx context.Context, snap PostureSnapshot) error {
	reportJSON, err := json.Marshal(snap.Report)
	if err != nil {
		return err
	}
	q := fmt.Sprintf(`
		INSERT INTO posture_snapshots
		  (id, captured_at, total_certs, pqc_score_percent, automation_percent,
		   risk_critical, risk_high, risk_medium, risk_low, expired, expiring_47d, report_json)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6),
		s.ph(7), s.ph(8), s.ph(9), s.ph(10), s.ph(11), s.ph(12))
	_, err = s.db.ExecContext(ctx, q,
		snap.ID, snap.CapturedAt, snap.TotalCerts, snap.PQCScorePercent, snap.AutomationPercent,
		snap.RiskCritical, snap.RiskHigh, snap.RiskMedium, snap.RiskLow,
		snap.Expired, snap.Expiring47d, string(reportJSON))
	return err
}

func (s *dbPostureSnapshotStore) List(ctx context.Context, since string, limit int) ([]PostureSnapshot, error) {
	if limit <= 0 {
		limit = 365
	}
	if limit > 3650 {
		limit = 3650
	}
	q := fmt.Sprintf(`
		SELECT id, captured_at, total_certs, pqc_score_percent, automation_percent,
		       risk_critical, risk_high, risk_medium, risk_low, expired, expiring_47d, report_json
		  FROM posture_snapshots
		 WHERE captured_at >= %s
		 ORDER BY captured_at ASC
		 LIMIT %s`, s.ph(1), s.ph(2))
	rows, err := s.db.QueryContext(ctx, q, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []PostureSnapshot{}
	for rows.Next() {
		snap, err := scanPostureSnapshot(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, snap)
	}
	return items, rows.Err()
}

func (s *dbPostureSnapshotStore) Latest(ctx context.Context) (PostureSnapshot, bool, error) {
	q := `
		SELECT id, captured_at, total_certs, pqc_score_percent, automation_percent,
		       risk_critical, risk_high, risk_medium, risk_low, expired, expiring_47d, report_json
		  FROM posture_snapshots
		 ORDER BY captured_at DESC
		 LIMIT 1`
	snap, err := scanPostureSnapshot(s.db.QueryRowContext(ctx, q))
	if err == sql.ErrNoRows {
		return PostureSnapshot{}, false, nil
	}
	if err != nil {
		return PostureSnapshot{}, false, err
	}
	return snap, true, nil
}

// rowScanner unifies *sql.Row and *sql.Rows for the shared scan helper.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanPostureSnapshot(row rowScanner) (PostureSnapshot, error) {
	var snap PostureSnapshot
	var reportJSON string
	err := row.Scan(&snap.ID, &snap.CapturedAt, &snap.TotalCerts, &snap.PQCScorePercent,
		&snap.AutomationPercent, &snap.RiskCritical, &snap.RiskHigh, &snap.RiskMedium,
		&snap.RiskLow, &snap.Expired, &snap.Expiring47d, &reportJSON)
	if err != nil {
		return PostureSnapshot{}, err
	}
	if reportJSON != "" {
		if err := json.Unmarshal([]byte(reportJSON), &snap.Report); err != nil {
			return PostureSnapshot{}, err
		}
	}
	return snap, nil
}

// NewPostureSnapshotStoreFromEnv opens the same SQLite/Postgres DB as the other
// providers and ensures its schema exists (idempotent), so the daily snapshot
// job works even on a DB where migration 000014 wasn't applied separately.
func NewPostureSnapshotStoreFromEnv() (PostureSnapshotStore, error) {
	state := newDBProviderState[PostureSnapshotStore](
		"posture-snapshot",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_AUDIT_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_AUDIT_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_AUDIT_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) PostureSnapshotStore {
			return &dbPostureSnapshotStore{db: db, ph: sqlitePlaceholder}
		},
		func(db *sql.DB) PostureSnapshotStore {
			return &dbPostureSnapshotStore{db: db, ph: postgresPlaceholder}
		},
	)
	if state.openErr != nil {
		return nil, state.openErr
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		return nil, err
	}
	return state.store, nil
}

// dayKey returns the UTC date portion (YYYY-MM-DD) of an RFC3339 timestamp,
// used to enforce one snapshot per day.
func dayKey(rfc3339 string) string {
	if len(rfc3339) >= 10 {
		return rfc3339[:10]
	}
	return rfc3339
}
