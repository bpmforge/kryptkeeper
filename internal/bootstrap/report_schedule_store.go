// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"
)

const (
	reportExecutiveSummary = "executive-summary"
	reportInventory        = "inventory"
	reportFindings         = "findings"

	maxReportScheduleRecipients = 20
)

// reportScheduleFormats is the allowed report/format matrix: the PDF layout
// exists only for the executive summary and the tabular exports only as
// CSV/XLSX.
var reportScheduleFormats = map[string][]string{
	reportExecutiveSummary: {"pdf"},
	reportInventory:        {"csv", "xlsx"},
	reportFindings:         {"csv", "xlsx"},
}

// errReportScheduleNotFound is returned by Delete when no row matched.
var errReportScheduleNotFound = errors.New("report schedule not found")

// ReportSchedule is a recurring delivery of one named report in one format.
type ReportSchedule struct {
	ID         string   `json:"id"`
	Report     string   `json:"report"`  // executive-summary | inventory | findings
	Format     string   `json:"format"`  // csv | xlsx | pdf
	Cadence    string   `json:"cadence"` // weekly | monthly (default monthly)
	Recipients []string `json:"recipients"`
	Enabled    bool     `json:"enabled"`
	LastSentAt string   `json:"last_sent_at,omitempty"`
	CreatedAt  string   `json:"created_at"`
}

// validateReportSchedule normalizes defaults (cadence) and rejects anything
// outside the report/format matrix, cadence set or recipient limits. Error
// text never echoes recipient addresses.
func validateReportSchedule(s *ReportSchedule) error {
	if s.Cadence == "" {
		s.Cadence = "monthly"
	}
	formats, ok := reportScheduleFormats[s.Report]
	if !ok {
		return fmt.Errorf("report must be one of executive-summary, inventory, findings")
	}
	allowed := false
	for _, f := range formats {
		if f == s.Format {
			allowed = true
		}
	}
	if !allowed {
		return fmt.Errorf("format %q is not available for report %q (allowed: %s)", s.Format, s.Report, strings.Join(formats, ", "))
	}
	if s.Cadence != "weekly" && s.Cadence != "monthly" {
		return fmt.Errorf("cadence must be weekly or monthly")
	}
	if n := len(s.Recipients); n < 1 || n > maxReportScheduleRecipients {
		return fmt.Errorf("recipients must contain 1 to %d addresses", maxReportScheduleRecipients)
	}
	for i, r := range s.Recipients {
		a, err := mail.ParseAddress(r)
		if err != nil || a.Address == "" {
			return fmt.Errorf("recipient %d is not a valid email address", i+1)
		}
		s.Recipients[i] = a.Address
	}
	return nil
}

// isDue applies the same rule as EvidenceSchedule.isDue.
func (s ReportSchedule) isDue(now time.Time) bool {
	return EvidenceSchedule{
		Cadence: s.Cadence, Recipients: s.Recipients, Enabled: s.Enabled, LastSentAt: s.LastSentAt,
	}.isDue(now)
}

// ReportScheduleStore persists recurring report-delivery schedules.
type ReportScheduleStore interface {
	EnsureSchema(ctx context.Context) error
	Create(ctx context.Context, s ReportSchedule) (ReportSchedule, error)
	List(ctx context.Context) ([]ReportSchedule, error)
	Delete(ctx context.Context, id string) error
	MarkSent(ctx context.Context, id, when string) error
}

const reportScheduleSchema = `
CREATE TABLE IF NOT EXISTS report_schedules (
    id TEXT PRIMARY KEY, report TEXT NOT NULL, format TEXT NOT NULL, cadence TEXT NOT NULL,
    recipients TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
    last_sent_at TEXT, created_at TEXT NOT NULL);`

type dbReportScheduleStore struct {
	db *sql.DB
	ph func(n int) string
}

func newReportScheduleID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "rsc-" + hex.EncodeToString(b), nil
}

func (s *dbReportScheduleStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, reportScheduleSchema)
	return err
}

func (s *dbReportScheduleStore) Create(ctx context.Context, sched ReportSchedule) (ReportSchedule, error) {
	id, err := newReportScheduleID()
	if err != nil {
		return ReportSchedule{}, err
	}
	sched.ID = id
	sched.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	q := fmt.Sprintf(`INSERT INTO report_schedules
		(id, report, format, cadence, recipients, enabled, created_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s)`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7))
	if _, err := s.db.ExecContext(ctx, q, sched.ID, sched.Report, sched.Format, sched.Cadence,
		strings.Join(sched.Recipients, ","), boolToInt(sched.Enabled), sched.CreatedAt); err != nil {
		return ReportSchedule{}, err
	}
	return sched, nil
}

func (s *dbReportScheduleStore) List(ctx context.Context) ([]ReportSchedule, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, report, format, cadence, recipients, enabled, last_sent_at, created_at FROM report_schedules ORDER BY created_at ASC, id ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ReportSchedule{}
	for rows.Next() {
		var sched ReportSchedule
		var recipients string
		var enabled int
		var lastSent sql.NullString
		if err := rows.Scan(&sched.ID, &sched.Report, &sched.Format, &sched.Cadence, &recipients,
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

func (s *dbReportScheduleStore) Delete(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, fmt.Sprintf("DELETE FROM report_schedules WHERE id = %s", s.ph(1)), id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return errReportScheduleNotFound
	}
	return nil
}

func (s *dbReportScheduleStore) MarkSent(ctx context.Context, id, when string) error {
	_, err := s.db.ExecContext(ctx,
		fmt.Sprintf("UPDATE report_schedules SET last_sent_at = %s WHERE id = %s", s.ph(1), s.ph(2)), when, id)
	return err
}

// NewReportScheduleStoreFromEnv opens the same DB as the other providers and
// ensures the schema. Returns nil if the DB is unavailable (callers tolerate nil).
func NewReportScheduleStoreFromEnv() ReportScheduleStore {
	state := newDBProviderState[*dbReportScheduleStore](
		"report-schedule",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_AUDIT_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_AUDIT_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_AUDIT_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) *dbReportScheduleStore {
			return &dbReportScheduleStore{db: db, ph: sqlitePlaceholder}
		},
		func(db *sql.DB) *dbReportScheduleStore {
			return &dbReportScheduleStore{db: db, ph: postgresPlaceholder}
		},
	)
	if state.openErr != nil || state.store == nil {
		_ = dbProviderUnavailable("report-schedule", state.openErr) // logs the outage itself
		return nil
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		_ = dbProviderUnavailable("report-schedule", err) // logs the outage itself
		return nil
	}
	return state.store
}
