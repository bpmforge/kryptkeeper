// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"
)

// W24-04: per-target discovery schedule state. One row per scheduled
// target; it exists once an interval override is set or the scheduler has
// run the target.

// discoverySchedule is one target's persisted schedule state.
type discoverySchedule struct {
	Key, ScanType, Target, LastJobID string
	Interval                         *time.Duration // nil = use the global interval
	LastRunAt                        time.Time      // zero = never
}

type discoveryScheduleStore interface {
	EnsureSchema(ctx context.Context) error
	List(ctx context.Context) (map[string]discoverySchedule, error)
	// SetInterval nil clears the override and keeps last_run.
	SetInterval(ctx context.Context, key, scanType, target string, interval *time.Duration) error
	RecordRun(ctx context.Context, key, scanType, target, jobID string, at time.Time) error
}

// discoveryScheduleSchema mirrors migration 000140 so the store self-heals
// on a database the migrations have not reached.
const discoveryScheduleSchema = `
CREATE TABLE IF NOT EXISTS discovery_target_schedules (
    target_key       TEXT PRIMARY KEY,
    scan_type        TEXT NOT NULL,
    target           TEXT NOT NULL,
    interval_seconds INTEGER CHECK (interval_seconds IS NULL OR interval_seconds >= 60),
    last_run_at      TEXT,
    last_job_id      TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);`

const discoveryScheduleTimeLayout = time.RFC3339

// ---- in-memory (scheduler default, tests) ----

type memoryDiscoveryScheduleStore struct {
	mu   sync.Mutex
	rows map[string]discoverySchedule
}

func newMemoryDiscoveryScheduleStore() *memoryDiscoveryScheduleStore {
	return &memoryDiscoveryScheduleStore{rows: map[string]discoverySchedule{}}
}

func (m *memoryDiscoveryScheduleStore) EnsureSchema(context.Context) error { return nil }

func (m *memoryDiscoveryScheduleStore) List(context.Context) (map[string]discoverySchedule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]discoverySchedule, len(m.rows))
	for k, v := range m.rows {
		out[k] = v
	}
	return out, nil
}

func (m *memoryDiscoveryScheduleStore) SetInterval(_ context.Context, key, scanType, target string, interval *time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	row := m.rows[key]
	row.Key, row.ScanType, row.Target = key, scanType, target
	row.Interval = interval
	m.rows[key] = row
	return nil
}

func (m *memoryDiscoveryScheduleStore) RecordRun(_ context.Context, key, scanType, target, jobID string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	row := m.rows[key]
	row.Key, row.ScanType, row.Target = key, scanType, target
	row.LastJobID, row.LastRunAt = jobID, at
	m.rows[key] = row
	return nil
}

// ---- SQL (sqlite + postgres) ----

type dbDiscoveryScheduleStore struct {
	db *sql.DB
	ph func(n int) string
}

func (s *dbDiscoveryScheduleStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, discoveryScheduleSchema)
	return err
}

func (s *dbDiscoveryScheduleStore) List(ctx context.Context) (map[string]discoverySchedule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT target_key, scan_type, target, interval_seconds,
		COALESCE(last_run_at, ''), COALESCE(last_job_id, '') FROM discovery_target_schedules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]discoverySchedule{}
	for rows.Next() {
		var r discoverySchedule
		var secs sql.NullInt64
		var lastRun string
		if err := rows.Scan(&r.Key, &r.ScanType, &r.Target, &secs, &lastRun, &r.LastJobID); err != nil {
			return nil, err
		}
		if secs.Valid {
			d := time.Duration(secs.Int64) * time.Second
			r.Interval = &d
		}
		if lastRun != "" {
			if t, err := time.Parse(discoveryScheduleTimeLayout, lastRun); err == nil {
				r.LastRunAt = t
			}
		}
		out[r.Key] = r
	}
	return out, rows.Err()
}

func (s *dbDiscoveryScheduleStore) SetInterval(ctx context.Context, key, scanType, target string, interval *time.Duration) error {
	var secs any
	if interval != nil {
		secs = int64(interval.Seconds())
	}
	now := time.Now().UTC().Format(discoveryScheduleTimeLayout)
	q := fmt.Sprintf(`INSERT INTO discovery_target_schedules
		(target_key, scan_type, target, interval_seconds, created_at, updated_at)
		VALUES (%s, %s, %s, %s, %s, %s)
		ON CONFLICT(target_key) DO UPDATE SET scan_type = excluded.scan_type, target = excluded.target,
		interval_seconds = excluded.interval_seconds, updated_at = excluded.updated_at`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6))
	_, err := s.db.ExecContext(ctx, q, key, scanType, target, secs, now, now)
	return err
}

func (s *dbDiscoveryScheduleStore) RecordRun(ctx context.Context, key, scanType, target, jobID string, at time.Time) error {
	now := time.Now().UTC().Format(discoveryScheduleTimeLayout)
	q := fmt.Sprintf(`INSERT INTO discovery_target_schedules
		(target_key, scan_type, target, last_run_at, last_job_id, created_at, updated_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s)
		ON CONFLICT(target_key) DO UPDATE SET scan_type = excluded.scan_type, target = excluded.target,
		last_run_at = excluded.last_run_at, last_job_id = excluded.last_job_id, updated_at = excluded.updated_at`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7))
	_, err := s.db.ExecContext(ctx, q, key, scanType, target, at.UTC().Format(discoveryScheduleTimeLayout), jobID, now, now)
	return err
}

// newDiscoveryScheduleStoreFromEnv opens the discovery database (the same
// DSNs newDBDiscoveryProviderFromEnv uses) and ensures the schema. It
// returns nil when the database is unavailable; callers tolerate nil.
func newDiscoveryScheduleStoreFromEnv() discoveryScheduleStore {
	state := newDBProviderState[discoveryScheduleStore](
		"discovery-schedule",
		discoveryDBSQLiteDSNFromEnv,
		discoveryDBPostgresDSNFromEnv,
		fmt.Errorf("postgres mode requires APP_DISCOVERY_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) discoveryScheduleStore {
			return &dbDiscoveryScheduleStore{db: db, ph: sqlitePlaceholder}
		},
		func(db *sql.DB) discoveryScheduleStore {
			return &dbDiscoveryScheduleStore{db: db, ph: postgresPlaceholder}
		},
	)
	if state.openErr != nil || state.store == nil {
		_ = dbProviderUnavailable("discovery-schedule", state.openErr) // logs the outage itself; return value is the same sentinel
		return nil
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		_ = dbProviderUnavailable("discovery-schedule", err) // logs the outage itself; return value is the same sentinel
		return nil
	}
	return state.store
}

// NewDiscoveryScheduleStoreFromEnv exposes the store to cmd/kryptkeeper.
func NewDiscoveryScheduleStoreFromEnv() discoveryScheduleStore {
	return newDiscoveryScheduleStoreFromEnv()
}
