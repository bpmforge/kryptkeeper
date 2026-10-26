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
	"strings"
	"time"
)

// EvidenceSchedule is a recurring evidence-pack email delivery.
type EvidenceSchedule struct {
	ID         string   `json:"id"`
	Framework  string   `json:"framework"`  // pci | soc2 | nist | all
	Cadence    string   `json:"cadence"`    // weekly | monthly
	Recipients []string `json:"recipients"` // email addresses
	Enabled    bool     `json:"enabled"`
	LastSentAt string   `json:"last_sent_at,omitempty"`
	CreatedAt  string   `json:"created_at"`
}

// cadenceInterval returns the delivery period for a cadence.
func cadenceInterval(cadence string) time.Duration {
	switch strings.ToLower(cadence) {
	case "daily":
		return 24 * time.Hour
	case "weekly":
		return 7 * 24 * time.Hour
	case "monthly":
		return 30 * 24 * time.Hour
	default:
		return 7 * 24 * time.Hour
	}
}

// isDue reports whether a schedule should send at now.
func (s EvidenceSchedule) isDue(now time.Time) bool {
	if !s.Enabled || len(s.Recipients) == 0 {
		return false
	}
	if s.LastSentAt == "" {
		return true
	}
	last, err := time.Parse(time.RFC3339, s.LastSentAt)
	if err != nil {
		return true
	}
	return now.Sub(last) >= cadenceInterval(s.Cadence)
}

// EvidenceScheduleStore persists recurring evidence-delivery schedules.
type EvidenceScheduleStore interface {
	EnsureSchema(ctx context.Context) error
	Create(ctx context.Context, s EvidenceSchedule) (EvidenceSchedule, error)
	List(ctx context.Context) ([]EvidenceSchedule, error)
	Delete(ctx context.Context, id string) error
	MarkSent(ctx context.Context, id, when string) error
}

const evidenceScheduleSchema = `
CREATE TABLE IF NOT EXISTS evidence_schedules (
    id TEXT PRIMARY KEY, framework TEXT NOT NULL, cadence TEXT NOT NULL,
    recipients TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
    last_sent_at TEXT, created_at TEXT NOT NULL);`

type dbEvidenceScheduleStore struct {
	db *sql.DB
	ph func(n int) string
}

func newEvidenceScheduleID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "esc-" + hex.EncodeToString(b), nil
}

func (s *dbEvidenceScheduleStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, evidenceScheduleSchema)
	return err
}

func (s *dbEvidenceScheduleStore) Create(ctx context.Context, sched EvidenceSchedule) (EvidenceSchedule, error) {
	id, err := newEvidenceScheduleID()
	if err != nil {
		return EvidenceSchedule{}, err
	}
	sched.ID = id
	sched.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	q := fmt.Sprintf(`INSERT INTO evidence_schedules
		(id, framework, cadence, recipients, enabled, created_at)
		VALUES (%s, %s, %s, %s, %s, %s)`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6))
	if _, err := s.db.ExecContext(ctx, q, sched.ID, sched.Framework, sched.Cadence,
		strings.Join(sched.Recipients, ","), boolToInt(sched.Enabled), sched.CreatedAt); err != nil {
		return EvidenceSchedule{}, err
	}
	return sched, nil
}

func (s *dbEvidenceScheduleStore) List(ctx context.Context) ([]EvidenceSchedule, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, framework, cadence, recipients, enabled, last_sent_at, created_at FROM evidence_schedules ORDER BY created_at ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EvidenceSchedule{}
	for rows.Next() {
		var sched EvidenceSchedule
		var recipients string
		var enabled int
		var lastSent sql.NullString
		if err := rows.Scan(&sched.ID, &sched.Framework, &sched.Cadence, &recipients,
			&enabled, &lastSent, &sched.CreatedAt); err != nil {
			return nil, err
		}
		sched.Recipients = splitRecipients(recipients)
		sched.Enabled = enabled != 0
		sched.LastSentAt = lastSent.String
		out = append(out, sched)
	}
	return out, rows.Err()
}

func (s *dbEvidenceScheduleStore) Delete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, fmt.Sprintf("DELETE FROM evidence_schedules WHERE id = %s", s.ph(1)), id)
	return err
}

func (s *dbEvidenceScheduleStore) MarkSent(ctx context.Context, id, when string) error {
	_, err := s.db.ExecContext(ctx,
		fmt.Sprintf("UPDATE evidence_schedules SET last_sent_at = %s WHERE id = %s", s.ph(1), s.ph(2)), when, id)
	return err
}

// splitRecipients parses a comma-separated recipient list, trimming blanks.
func splitRecipients(s string) []string {
	var out []string
	for _, r := range strings.Split(s, ",") {
		if t := strings.TrimSpace(r); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// NewEvidenceScheduleStoreFromEnv opens the same DB as the other providers and
// ensures the schema. Returns nil if the DB is unavailable (callers tolerate nil).
func NewEvidenceScheduleStoreFromEnv() EvidenceScheduleStore {
	state := newDBProviderState[*dbEvidenceScheduleStore](
		"evidence-schedule",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_AUDIT_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_AUDIT_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_AUDIT_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) *dbEvidenceScheduleStore {
			return &dbEvidenceScheduleStore{db: db, ph: sqlitePlaceholder}
		},
		func(db *sql.DB) *dbEvidenceScheduleStore {
			return &dbEvidenceScheduleStore{db: db, ph: postgresPlaceholder}
		},
	)
	if state.openErr != nil || state.store == nil {
		_ = dbProviderUnavailable("evidence-schedule", state.openErr) // logs the outage itself; return value is the same sentinel
		return nil
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		_ = dbProviderUnavailable("evidence-schedule", err) // logs the outage itself; return value is the same sentinel
		return nil
	}
	return state.store
}
