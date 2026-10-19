// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"sync"
	"time"

	"kryptkeeper/internal/logging"
)

// renewalTriggerMaxAttempts is the retry budget for a single certificate's
// renewal-notification trigger: after this many consecutive failed attempts
// (one per scheduler poll), the fingerprint is dead-lettered instead of
// silently retrying forever with nothing but a log line to show for it.
const renewalTriggerMaxAttempts = 3

const (
	failureKindExecute      = "execute_failure"
	failureKindNotification = "notification_dead_letter"
)

// renewalFailureRecord is one row of the durable failure queue (W27-18). The
// audit-derived installState stays the source of truth for the retry decision;
// this is the operator-visible mirror that survives a hub restart.
type renewalFailureRecord struct {
	Kind, Fingerprint, TargetID, Outcome, Detail string
	Attempt, MaxAttempts                         int
	GaveUp                                       bool
	FirstFailedAt, LastFailedAt, NextAttemptAt   time.Time // NextAttemptAt zero = none
}

type renewalFailureStore interface {
	EnsureSchema(ctx context.Context) error
	// Upsert keeps first_failed_at of an existing row.
	Upsert(ctx context.Context, rec renewalFailureRecord) error
	Get(ctx context.Context, kind, fingerprint string) (renewalFailureRecord, bool, error)
	Delete(ctx context.Context, kind, fingerprint string) error
	List(ctx context.Context) ([]renewalFailureRecord, error)
}

// --- in-memory implementation (default holder; tests) ---

type memRenewalFailureStore struct {
	mu   sync.Mutex
	rows map[string]renewalFailureRecord
}

func newMemRenewalFailureStore() *memRenewalFailureStore {
	return &memRenewalFailureStore{rows: map[string]renewalFailureRecord{}}
}

func failureKey(kind, fp string) string { return kind + ":" + fp }

func (m *memRenewalFailureStore) EnsureSchema(context.Context) error { return nil }

func (m *memRenewalFailureStore) Upsert(_ context.Context, rec renewalFailureRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := failureKey(rec.Kind, rec.Fingerprint)
	if old, ok := m.rows[k]; ok {
		rec.FirstFailedAt = old.FirstFailedAt
	} else if rec.FirstFailedAt.IsZero() {
		rec.FirstFailedAt = rec.LastFailedAt
	}
	m.rows[k] = rec
	return nil
}

func (m *memRenewalFailureStore) Get(_ context.Context, kind, fp string) (renewalFailureRecord, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.rows[failureKey(kind, fp)]
	return rec, ok, nil
}

func (m *memRenewalFailureStore) Delete(_ context.Context, kind, fp string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rows, failureKey(kind, fp))
	return nil
}

func (m *memRenewalFailureStore) List(context.Context) ([]renewalFailureRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]renewalFailureRecord, 0, len(m.rows))
	for _, r := range m.rows {
		out = append(out, r)
	}
	sortFailureRecords(out)
	return out, nil
}

// sortFailureRecords orders newest failure first, then by fingerprint, so the
// report is stable across stores.
func sortFailureRecords(recs []renewalFailureRecord) {
	sort.SliceStable(recs, func(i, j int) bool {
		if !recs[i].LastFailedAt.Equal(recs[j].LastFailedAt) {
			return recs[i].LastFailedAt.After(recs[j].LastFailedAt)
		}
		if recs[i].Fingerprint != recs[j].Fingerprint {
			return recs[i].Fingerprint < recs[j].Fingerprint
		}
		return recs[i].Kind < recs[j].Kind
	})
}

// --- SQL implementations ---

const renewalFailureQueueSchema = `
CREATE TABLE IF NOT EXISTS renewal_failure_queue (
    id              TEXT PRIMARY KEY,
    kind            TEXT NOT NULL CHECK (kind IN ('execute_failure','notification_dead_letter')),
    fingerprint     TEXT NOT NULL,
    target_id       TEXT NOT NULL DEFAULT '',
    attempt         INTEGER NOT NULL DEFAULT 1,
    max_attempts    INTEGER NOT NULL DEFAULT 0,
    outcome         TEXT NOT NULL DEFAULT '',
    detail          TEXT NOT NULL DEFAULT '',
    gave_up         INTEGER NOT NULL DEFAULT 0 CHECK (gave_up IN (0, 1)),
    first_failed_at TEXT NOT NULL,
    last_failed_at  TEXT NOT NULL,
    next_attempt_at TEXT NOT NULL DEFAULT '',
    UNIQUE (kind, fingerprint)
);`

const renewalFailureQueueIndex = `CREATE INDEX IF NOT EXISTS idx_renewal_failure_queue_last ON renewal_failure_queue(last_failed_at)`

const renewalFailureColumns = `kind, fingerprint, target_id, attempt, max_attempts, outcome, detail, gave_up, first_failed_at, last_failed_at, next_attempt_at`

// sqlRenewalFailureStore serves both engines; only the placeholder style
// differs.
type sqlRenewalFailureStore struct {
	db       *sql.DB
	postgres bool
}

func (s *sqlRenewalFailureStore) ph(n int) string {
	if s.postgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

func (s *sqlRenewalFailureStore) EnsureSchema(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, renewalFailureQueueSchema); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, renewalFailureQueueIndex)
	return err
}

func fmtFailureTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func parseFailureTime(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, raw)
}

func (s *sqlRenewalFailureStore) Upsert(ctx context.Context, rec renewalFailureRecord) error {
	if rec.FirstFailedAt.IsZero() {
		rec.FirstFailedAt = rec.LastFailedAt
	}
	gaveUp := 0
	if rec.GaveUp {
		gaveUp = 1
	}
	q := fmt.Sprintf(`INSERT INTO renewal_failure_queue (id, %s) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (kind, fingerprint) DO UPDATE SET
  target_id = excluded.target_id, attempt = excluded.attempt, max_attempts = excluded.max_attempts,
  outcome = excluded.outcome, detail = excluded.detail, gave_up = excluded.gave_up,
  last_failed_at = excluded.last_failed_at, next_attempt_at = excluded.next_attempt_at`,
		renewalFailureColumns, s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7), s.ph(8), s.ph(9), s.ph(10), s.ph(11), s.ph(12))
	_, err := s.db.ExecContext(ctx, q, failureKey(rec.Kind, rec.Fingerprint), rec.Kind, rec.Fingerprint, rec.TargetID,
		rec.Attempt, rec.MaxAttempts, rec.Outcome, rec.Detail, gaveUp,
		fmtFailureTime(rec.FirstFailedAt), fmtFailureTime(rec.LastFailedAt), fmtFailureTime(rec.NextAttemptAt))
	return err
}

func scanFailureRow(sc interface{ Scan(...any) error }) (renewalFailureRecord, error) {
	var rec renewalFailureRecord
	var gaveUp int
	var first, last, next string
	if err := sc.Scan(&rec.Kind, &rec.Fingerprint, &rec.TargetID, &rec.Attempt, &rec.MaxAttempts,
		&rec.Outcome, &rec.Detail, &gaveUp, &first, &last, &next); err != nil {
		return rec, err
	}
	rec.GaveUp = gaveUp != 0
	var err error
	if rec.FirstFailedAt, err = parseFailureTime(first); err != nil {
		return rec, err
	}
	if rec.LastFailedAt, err = parseFailureTime(last); err != nil {
		return rec, err
	}
	if rec.NextAttemptAt, err = parseFailureTime(next); err != nil {
		return rec, err
	}
	return rec, nil
}

func (s *sqlRenewalFailureStore) Get(ctx context.Context, kind, fp string) (renewalFailureRecord, bool, error) {
	row := s.db.QueryRowContext(ctx, fmt.Sprintf(`SELECT %s FROM renewal_failure_queue WHERE kind = %s AND fingerprint = %s`,
		renewalFailureColumns, s.ph(1), s.ph(2)), kind, fp)
	rec, err := scanFailureRow(row)
	if err == sql.ErrNoRows {
		return renewalFailureRecord{}, false, nil
	}
	if err != nil {
		return renewalFailureRecord{}, false, err
	}
	return rec, true, nil
}

func (s *sqlRenewalFailureStore) Delete(ctx context.Context, kind, fp string) error {
	_, err := s.db.ExecContext(ctx, fmt.Sprintf(`DELETE FROM renewal_failure_queue WHERE kind = %s AND fingerprint = %s`, s.ph(1), s.ph(2)), kind, fp)
	return err
}

func (s *sqlRenewalFailureStore) List(ctx context.Context) ([]renewalFailureRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+renewalFailureColumns+` FROM renewal_failure_queue`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []renewalFailureRecord
	for rows.Next() {
		rec, err := scanFailureRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sortFailureRecords(out)
	return out, nil
}

// newRenewalFailureStoreFromEnv opens the same SQLite/Postgres DB as the other
// providers and self-heals the schema.
func newRenewalFailureStoreFromEnv() (renewalFailureStore, error) {
	state := newDBProviderState[renewalFailureStore](
		"renewal-failure-queue",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_RENEWAL_FAILURE_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_RENEWAL_FAILURE_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_RENEWAL_FAILURE_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) renewalFailureStore { return &sqlRenewalFailureStore{db: db} },
		func(db *sql.DB) renewalFailureStore { return &sqlRenewalFailureStore{db: db, postgres: true} },
	)
	if state.openErr != nil || state.store == nil {
		return nil, state.openErr
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		return nil, err
	}
	return state.store, nil
}

// newRenewalFailureStoreFromEnvLogged soft-fails: the in-memory default keeps
// the scheduler running, at the cost of losing the queue on restart.
func newRenewalFailureStoreFromEnvLogged() renewalFailureStore {
	store, err := newRenewalFailureStoreFromEnv()
	if err != nil {
		logging.Warnf("renewal scheduler: failure-queue store unavailable, queue will not survive a restart: %v", err)
		return nil
	}
	return store
}

// --- package holder ---
//
// The SLO handler is registered without the scheduler instance (main.go), so
// the store is reached through a package-level holder, like renewalStatusHolder.

var (
	renewalFailureHolderMu sync.RWMutex
	renewalFailureHolder   renewalFailureStore = newMemRenewalFailureStore()
)

// SetRenewalFailureStore installs the process-wide failure queue.
func SetRenewalFailureStore(s renewalFailureStore) {
	if s == nil {
		return
	}
	renewalFailureHolderMu.Lock()
	renewalFailureHolder = s
	renewalFailureHolderMu.Unlock()
}

func currentRenewalFailureStore() renewalFailureStore {
	renewalFailureHolderMu.RLock()
	defer renewalFailureHolderMu.RUnlock()
	return renewalFailureHolder
}

// recordRenewalTriggerFailure registers one failed renewal-notification
// attempt for fingerprint and returns the running attempt count plus whether
// the fingerprint is now past its retry budget. The row is written on every
// failure with the latest detail, so it always reflects the most recent reason.
func recordRenewalTriggerFailure(fingerprint, detail string) (attempts int, deadLettered bool) {
	if fingerprint == "" {
		return 0, false
	}
	ctx := context.Background()
	st := currentRenewalFailureStore()
	prev, ok, err := st.Get(ctx, failureKindNotification, fingerprint)
	if err != nil {
		logging.Warnf("renewal failure queue: reading %s failed: %v", fingerprint, err)
	}
	attempts = 1
	first := time.Now().UTC()
	if ok {
		attempts = prev.Attempt + 1
		first = prev.FirstFailedAt
	}
	deadLettered = attempts >= renewalTriggerMaxAttempts
	if err := st.Upsert(ctx, renewalFailureRecord{
		Kind: failureKindNotification, Fingerprint: fingerprint, Outcome: failureKindNotification, Detail: detail,
		Attempt: attempts, MaxAttempts: renewalTriggerMaxAttempts, GaveUp: deadLettered,
		FirstFailedAt: first, LastFailedAt: time.Now().UTC(),
	}); err != nil {
		logging.Warnf("renewal failure queue: recording %s failed: %v", fingerprint, err)
	}
	return attempts, deadLettered
}

// recordRenewalTriggerSuccess clears fingerprint's failure row: a later
// successful notification means the certificate is no longer stuck.
func recordRenewalTriggerSuccess(fingerprint string) {
	if fingerprint == "" {
		return
	}
	if err := currentRenewalFailureStore().Delete(context.Background(), failureKindNotification, fingerprint); err != nil {
		logging.Warnf("renewal failure queue: clearing %s failed: %v", fingerprint, err)
	}
}

// recordRenewalExecuteFailure mirrors one failed scheduled renew+install into
// the queue. next is ignored (stored as none) when gaveUp.
func recordRenewalExecuteFailure(ctx context.Context, fingerprint, targetID string, attempt, max int, outcome, detail string, next time.Time, gaveUp bool) {
	if fingerprint == "" {
		return
	}
	if gaveUp {
		next = time.Time{}
	}
	now := time.Now().UTC()
	if err := currentRenewalFailureStore().Upsert(ctx, renewalFailureRecord{
		Kind: failureKindExecute, Fingerprint: fingerprint, TargetID: targetID, Attempt: attempt, MaxAttempts: max,
		Outcome: outcome, Detail: detail, GaveUp: gaveUp, LastFailedAt: now, FirstFailedAt: now, NextAttemptAt: next,
	}); err != nil {
		logging.Warnf("renewal failure queue: recording execute failure for %s failed: %v", fingerprint, err)
	}
}

// clearRenewalExecuteFailure drops the execute-failure row after a success on
// targetID. A row owned by a different target stays: that target is still
// failing and the queue holds one row per fingerprint.
func clearRenewalExecuteFailure(ctx context.Context, fingerprint, targetID string) {
	if fingerprint == "" {
		return
	}
	st := currentRenewalFailureStore()
	rec, ok, err := st.Get(ctx, failureKindExecute, fingerprint)
	if err != nil {
		logging.Warnf("renewal failure queue: reading %s failed: %v", fingerprint, err)
		return
	}
	if !ok || (rec.TargetID != "" && targetID != "" && rec.TargetID != targetID) {
		return
	}
	if err := st.Delete(ctx, failureKindExecute, fingerprint); err != nil {
		logging.Warnf("renewal failure queue: clearing %s failed: %v", fingerprint, err)
	}
}

func failedRenewalFromRecord(r renewalFailureRecord) FailedRenewal {
	fr := FailedRenewal{
		AgentID: "renewal-scheduler", Fingerprint: r.Fingerprint, Outcome: r.Outcome, Detail: r.Detail,
		ReportedAt: fmtFailureTime(r.LastFailedAt), Type: r.Kind, TargetID: r.TargetID,
		Attempt: r.Attempt, MaxAttempts: r.MaxAttempts, GaveUp: r.GaveUp,
		NextAttemptAt: fmtFailureTime(r.NextAttemptAt),
	}
	return fr
}

// renewalFailureSnapshot returns the queue for the renewal-SLO report: every
// execute failure, and notification rows only once dead-lettered. A store
// error yields an empty list — the report must not 500 over this.
func renewalFailureSnapshot(ctx context.Context) []FailedRenewal {
	recs, err := currentRenewalFailureStore().List(ctx)
	if err != nil {
		logging.Warnf("renewal failure queue: list failed: %v", err)
		return []FailedRenewal{}
	}
	out := make([]FailedRenewal, 0, len(recs))
	for _, r := range recs {
		if r.Kind == failureKindNotification && !r.GaveUp {
			continue
		}
		out = append(out, failedRenewalFromRecord(r))
	}
	return out
}

// renewalDeadLetterSnapshot returns only the notification rows that exhausted
// their retry budget.
func renewalDeadLetterSnapshot() []FailedRenewal {
	recs, err := currentRenewalFailureStore().List(context.Background())
	if err != nil {
		logging.Warnf("renewal failure queue: list failed: %v", err)
		return []FailedRenewal{}
	}
	out := make([]FailedRenewal, 0)
	for _, r := range recs {
		if r.Kind == failureKindNotification && r.GaveUp {
			out = append(out, failedRenewalFromRecord(r))
		}
	}
	return out
}

// resetRenewalRetryStateForTest installs a fresh in-memory queue. Package-level
// state must not leak between tests.
func resetRenewalRetryStateForTest() {
	SetRenewalFailureStore(newMemRenewalFailureStore())
}
