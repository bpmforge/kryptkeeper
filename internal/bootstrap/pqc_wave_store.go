// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

// MigrationWaveMember is a certificate assigned to a migration wave.
type MigrationWaveMember struct {
	Fingerprint string `json:"fingerprint"`
	CommonName  string `json:"common_name"`
}

// MigrationWave is a tracked PQC migration set with an owner and target date.
type MigrationWave struct {
	ID         string                `json:"id"`
	Name       string                `json:"name"`
	Owner      string                `json:"owner,omitempty"`
	TargetDate string                `json:"target_date,omitempty"`
	CreatedAt  string                `json:"created_at"`
	Status     string                `json:"status"`
	Members    []MigrationWaveMember `json:"members"`
}

// Migration wave lifecycle (W2-08/FR-R14/D-035): a wave row carries a stored
// status rather than one recomputed fresh on every read. proposed/accepted
// are only reached via an explicit accept action (there is no auto-accept);
// in_progress/done are derived from live member progress; regressed is
// sticky — once a done wave is observed with a member no longer migrated,
// it stays regressed until an explicit accept clears it, so the regression
// is a durable recorded fact, not something that silently self-heals back to
// done the moment progress recovers.
const (
	waveStatusProposed   = "proposed"
	waveStatusAccepted   = "accepted"
	waveStatusInProgress = "in_progress"
	waveStatusDone       = "done"
	waveStatusRegressed  = "regressed"
)

// advanceWaveStatus computes the next stored status for a wave given its
// current stored status and freshly observed progress. Pure function (no
// I/O) so it's directly testable; callers persist the result when it differs
// from the wave's current stored status.
func advanceWaveStatus(current string, progressPercent, total int) string {
	switch current {
	case waveStatusRegressed:
		return waveStatusRegressed
	case waveStatusDone:
		if total > 0 && progressPercent < 100 {
			return waveStatusRegressed
		}
		return waveStatusDone
	case waveStatusAccepted, waveStatusInProgress:
		switch {
		case total > 0 && progressPercent >= 100:
			return waveStatusDone
		case progressPercent > 0:
			return waveStatusInProgress
		default:
			return waveStatusAccepted
		}
	default:
		return waveStatusProposed
	}
}

// MigrationWaveStore persists PQC migration waves and their members.
type MigrationWaveStore interface {
	EnsureSchema(ctx context.Context) error
	CreateWave(ctx context.Context, w MigrationWave) (MigrationWave, error)
	ListWaves(ctx context.Context) ([]MigrationWave, error)
	DeleteWave(ctx context.Context, id string) error
	DeleteAllWaves(ctx context.Context) error
	AddMember(ctx context.Context, waveID string, m MigrationWaveMember) error
	RemoveMember(ctx context.Context, waveID, fingerprint string) error
	UpdateWaveStatus(ctx context.Context, waveID, status string) error
}

const migrationWaveSchema = `
CREATE TABLE IF NOT EXISTS migration_waves (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, owner TEXT, target_date TEXT, created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'proposed');
CREATE TABLE IF NOT EXISTS migration_wave_members (
    wave_id TEXT NOT NULL, fingerprint TEXT NOT NULL, common_name TEXT);
CREATE INDEX IF NOT EXISTS idx_wave_members_wave ON migration_wave_members(wave_id);`

// ensureWaveStatusColumn best-effort-adds the W2-08 status column to a
// migration_waves table created before this ticket (migrations never
// actually run against a live deployment — G-33 — so a table created by an
// earlier version of migrationWaveSchema, or by the real migration files up
// to 000017/000022, won't have it yet). Errors are ignored: "duplicate
// column" is the expected steady state on every table EnsureSchema itself
// just created.
func ensureWaveStatusColumn(db *sql.DB) {
	_, _ = db.Exec("ALTER TABLE migration_waves ADD COLUMN status TEXT NOT NULL DEFAULT 'proposed'") // best-effort upgrade: duplicate-column error = already migrated
}

type dbMigrationWaveStore struct {
	db *sql.DB
	ph func(n int) string
}

func newWaveID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "wave-" + hex.EncodeToString(b), nil
}

func (s *dbMigrationWaveStore) EnsureSchema(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, migrationWaveSchema); err != nil {
		return err
	}
	ensureWaveStatusColumn(s.db)
	return nil
}

func (s *dbMigrationWaveStore) CreateWave(ctx context.Context, w MigrationWave) (MigrationWave, error) {
	id, err := newWaveID()
	if err != nil {
		return MigrationWave{}, err
	}
	w.ID = id
	w.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	w.Status = waveStatusProposed
	q := fmt.Sprintf(`INSERT INTO migration_waves (id, name, owner, target_date, created_at)
		VALUES (%s, %s, %s, %s, %s)`, s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5))
	if _, err := s.db.ExecContext(ctx, q, w.ID, w.Name, w.Owner, w.TargetDate, w.CreatedAt); err != nil {
		return MigrationWave{}, err
	}
	for _, m := range w.Members {
		if err := s.AddMember(ctx, w.ID, m); err != nil {
			return MigrationWave{}, err
		}
	}
	return w, nil
}

func (s *dbMigrationWaveStore) ListWaves(ctx context.Context) ([]MigrationWave, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, name, owner, target_date, created_at, status FROM migration_waves ORDER BY created_at ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	waves := []MigrationWave{}
	index := map[string]int{}
	for rows.Next() {
		var w MigrationWave
		var owner, target sql.NullString
		if err := rows.Scan(&w.ID, &w.Name, &owner, &target, &w.CreatedAt, &w.Status); err != nil {
			return nil, err
		}
		w.Owner = owner.String
		w.TargetDate = target.String
		w.Members = []MigrationWaveMember{}
		index[w.ID] = len(waves)
		waves = append(waves, w)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	mrows, err := s.db.QueryContext(ctx,
		"SELECT wave_id, fingerprint, common_name FROM migration_wave_members")
	if err != nil {
		return nil, err
	}
	defer mrows.Close()
	for mrows.Next() {
		var waveID string
		var m MigrationWaveMember
		var cn sql.NullString
		if err := mrows.Scan(&waveID, &m.Fingerprint, &cn); err != nil {
			return nil, err
		}
		m.CommonName = cn.String
		if i, ok := index[waveID]; ok {
			waves[i].Members = append(waves[i].Members, m)
		}
	}
	return waves, mrows.Err()
}

func (s *dbMigrationWaveStore) UpdateWaveStatus(ctx context.Context, waveID, status string) error {
	_, err := s.db.ExecContext(ctx,
		fmt.Sprintf("UPDATE migration_waves SET status = %s WHERE id = %s", s.ph(1), s.ph(2)),
		status, waveID)
	return err
}

func (s *dbMigrationWaveStore) DeleteWave(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, fmt.Sprintf("DELETE FROM migration_wave_members WHERE wave_id = %s", s.ph(1)), id); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, fmt.Sprintf("DELETE FROM migration_waves WHERE id = %s", s.ph(1)), id)
	return err
}

func (s *dbMigrationWaveStore) DeleteAllWaves(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, "DELETE FROM migration_wave_members"); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, "DELETE FROM migration_waves")
	return err
}

func (s *dbMigrationWaveStore) AddMember(ctx context.Context, waveID string, m MigrationWaveMember) error {
	// Idempotent: a cert belongs to at most one wave — remove any prior assignment.
	if _, err := s.db.ExecContext(ctx,
		fmt.Sprintf("DELETE FROM migration_wave_members WHERE fingerprint = %s", s.ph(1)), m.Fingerprint); err != nil {
		return err
	}
	q := fmt.Sprintf("INSERT INTO migration_wave_members (wave_id, fingerprint, common_name) VALUES (%s, %s, %s)",
		s.ph(1), s.ph(2), s.ph(3))
	_, err := s.db.ExecContext(ctx, q, waveID, m.Fingerprint, m.CommonName)
	return err
}

func (s *dbMigrationWaveStore) RemoveMember(ctx context.Context, waveID, fingerprint string) error {
	_, err := s.db.ExecContext(ctx,
		fmt.Sprintf("DELETE FROM migration_wave_members WHERE wave_id = %s AND fingerprint = %s", s.ph(1), s.ph(2)),
		waveID, fingerprint)
	return err
}

// NewMigrationWaveStoreFromEnv opens the shared DB and ensures the schema.
// Returns nil if the DB is unavailable (callers tolerate nil).
func NewMigrationWaveStoreFromEnv() MigrationWaveStore {
	state := newDBProviderState[*dbMigrationWaveStore](
		"migration-wave",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_AUDIT_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_AUDIT_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_AUDIT_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) *dbMigrationWaveStore {
			return &dbMigrationWaveStore{db: db, ph: sqlitePlaceholder}
		},
		func(db *sql.DB) *dbMigrationWaveStore {
			return &dbMigrationWaveStore{db: db, ph: postgresPlaceholder}
		},
	)
	if state.openErr != nil || state.store == nil {
		_ = dbProviderUnavailable("migration-wave", state.openErr) // logs the outage itself; return value is the same sentinel
		return nil
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		_ = dbProviderUnavailable("migration-wave", err) // logs the outage itself; return value is the same sentinel
		return nil
	}
	return state.store
}
