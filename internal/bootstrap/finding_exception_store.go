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
	"time"
)

var errFindingExceptionNotFound = errors.New("finding exception not found")

// Fixed-enum justification codes for an accepted-risk exception — see
// docs/design/FINDING_ECONOMICS.md. Cribbed from VEX-style justification
// vocabularies, adapted for accepted-risk (a real, present finding being
// risk-accepted) rather than pure not-affected/affected disputes.
const (
	JustificationRiskAccepted        = "risk_accepted"
	JustificationCompensatingControl = "compensating_control"
	JustificationFalsePositive       = "false_positive"
	JustificationPlannedRemediation  = "planned_remediation"
	JustificationNotApplicable       = "not_applicable"
)

// FindingExceptionTargetCertificate/CA are the fixed target_type values — an
// exception is filed against a specific certificate (by fingerprint) or a
// specific CA (by ID), per D-031/R-D1's "per cert/CA" scope.
const (
	FindingExceptionTargetCertificate = "certificate"
	FindingExceptionTargetCA          = "ca"
)

// FindingException is an accepted-risk exception: a human decision that a
// specific finding, on a specific target, is accepted risk for a bounded
// period. See docs/design/FINDING_ECONOMICS.md for the full design,
// including why cert-scoped exceptions auto-reopen on re-issuance without
// any reconciliation code (fingerprint identity does it structurally) and
// why only expiry needs a runtime check.
type FindingException struct {
	ID                string `json:"id"`
	TargetType        string `json:"target_type"` // certificate | ca
	TargetID          string `json:"target_id"`
	FindingCode       string `json:"finding_code"`
	JustificationCode string `json:"justification_code"`
	JustificationNote string `json:"justification_note,omitempty"`
	CreatedBy         string `json:"created_by"`
	CreatedAt         string `json:"created_at"`
	ExpiresAt         string `json:"expires_at"`
}

// IsActive reports whether the exception is still in effect at now — the
// only runtime check the "auto-reopen" requirement needs (see the design
// doc's "Auto-reopen" section). An unparseable ExpiresAt is treated as
// already lapsed rather than permanently active — an exception must not
// fail open.
func (e FindingException) IsActive(now time.Time) bool {
	expires, err := time.Parse(time.RFC3339, e.ExpiresAt)
	if err != nil {
		return false
	}
	return now.Before(expires)
}

// findingExceptionKey builds the lookup key an active-exception index uses:
// exact (target_type, target_id, finding_code) match, matching the schema's
// own identity — there is no fuzzy or prefix matching.
func findingExceptionKey(targetType, targetID, findingCode string) string {
	return targetType + "\x00" + targetID + "\x00" + findingCode
}

// findingExceptionIndex turns a bulk ListActive read into an O(1)-lookup set
// keyed by findingExceptionKey, so a report can check thousands of raw
// findings against the active exception set without a query per finding.
func findingExceptionIndex(active []FindingException) map[string]bool {
	idx := make(map[string]bool, len(active))
	for _, e := range active {
		idx[findingExceptionKey(e.TargetType, e.TargetID, e.FindingCode)] = true
	}
	return idx
}

// FindingExceptionStore persists accepted-risk exceptions.
// Intentionally unwired until v0.10: no handler creates exceptions yet, so reads always return an empty set (FB-09).
type FindingExceptionStore interface {
	EnsureSchema(ctx context.Context) error
	Create(ctx context.Context, exc FindingException) error
	Get(ctx context.Context, id string) (FindingException, error)
	ListForTarget(ctx context.Context, targetType, targetID string) ([]FindingException, error)
	// ListActive returns every exception across every target that is still
	// in effect at now (IsActive), in a single bulk read. W2-11's finding
	// funnel (raw/effective/suppressed on posture and discovery reports)
	// needs to check every raw finding on every certificate/CA against the
	// active exception set; ListForTarget would require one round-trip per
	// target, which doesn't scale to a 10,000-certificate report. Expiry is
	// applied in Go via FindingException.IsActive, matching the design
	// doc's "expiry is computed, not stored" rule rather than duplicating
	// the RFC3339 comparison in SQL.
	ListActive(ctx context.Context, now time.Time) ([]FindingException, error)
	Delete(ctx context.Context, id string) error
}

// findingExceptionSchema mirrors migration 000022_finding_exceptions — see
// G-33: a migration existing is not sufficient, every DB-backed store in
// this codebase must self-heal its own schema since migrations are never
// actually run against a live deployment.
const findingExceptionSchema = `
CREATE TABLE IF NOT EXISTS finding_exceptions (
    id                  TEXT PRIMARY KEY,
    target_type         TEXT NOT NULL
                          CHECK (target_type IN ('certificate', 'ca')),
    target_id           TEXT NOT NULL,
    finding_code        TEXT NOT NULL,
    justification_code  TEXT NOT NULL
                          CHECK (justification_code IN (
                              'risk_accepted', 'compensating_control',
                              'false_positive', 'planned_remediation', 'not_applicable'
                          )),
    justification_note  TEXT,
    created_by          TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    expires_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_finding_exceptions_target ON finding_exceptions(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_finding_exceptions_expires ON finding_exceptions(expires_at);`

func newFindingExceptionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "exc-" + hex.EncodeToString(b), nil
}

// --- SQLite implementation ---

type sqliteFindingExceptionStore struct{ db *sql.DB }

func (s *sqliteFindingExceptionStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, findingExceptionSchema)
	return err
}

func (s *sqliteFindingExceptionStore) Create(ctx context.Context, exc FindingException) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO finding_exceptions
		  (id, target_type, target_id, finding_code, justification_code, justification_note, created_by, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		exc.ID, exc.TargetType, exc.TargetID, exc.FindingCode, exc.JustificationCode,
		nullString(exc.JustificationNote), exc.CreatedBy, exc.CreatedAt, exc.ExpiresAt)
	return err
}

func (s *sqliteFindingExceptionStore) Get(ctx context.Context, id string) (FindingException, error) {
	return scanFindingException(s.db.QueryRowContext(ctx, `
		SELECT id, target_type, target_id, finding_code, justification_code, justification_note, created_by, created_at, expires_at
		FROM finding_exceptions WHERE id = ?`, id))
}

func (s *sqliteFindingExceptionStore) ListForTarget(ctx context.Context, targetType, targetID string) ([]FindingException, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, target_type, target_id, finding_code, justification_code, justification_note, created_by, created_at, expires_at
		FROM finding_exceptions WHERE target_type = ? AND target_id = ?
		ORDER BY created_at DESC`, targetType, targetID)
	if err != nil {
		return nil, err
	}
	return scanFindingExceptionRows(rows)
}

func (s *sqliteFindingExceptionStore) ListActive(ctx context.Context, now time.Time) ([]FindingException, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, target_type, target_id, finding_code, justification_code, justification_note, created_by, created_at, expires_at
		FROM finding_exceptions
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	all, err := scanFindingExceptionRows(rows)
	if err != nil {
		return nil, err
	}
	return filterActiveFindingExceptions(all, now), nil
}

func (s *sqliteFindingExceptionStore) Delete(ctx context.Context, id string) error {
	return deleteFindingExceptionRow(ctx, s.db, "DELETE FROM finding_exceptions WHERE id = ?", id)
}

// --- Postgres implementation ---

type postgresFindingExceptionStore struct{ db *sql.DB }

func (s *postgresFindingExceptionStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, findingExceptionSchema)
	return err
}

func (s *postgresFindingExceptionStore) Create(ctx context.Context, exc FindingException) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO finding_exceptions
		  (id, target_type, target_id, finding_code, justification_code, justification_note, created_by, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		exc.ID, exc.TargetType, exc.TargetID, exc.FindingCode, exc.JustificationCode,
		nullString(exc.JustificationNote), exc.CreatedBy, exc.CreatedAt, exc.ExpiresAt)
	return err
}

func (s *postgresFindingExceptionStore) Get(ctx context.Context, id string) (FindingException, error) {
	return scanFindingException(s.db.QueryRowContext(ctx, `
		SELECT id, target_type, target_id, finding_code, justification_code, justification_note, created_by, created_at, expires_at
		FROM finding_exceptions WHERE id = $1`, id))
}

func (s *postgresFindingExceptionStore) ListForTarget(ctx context.Context, targetType, targetID string) ([]FindingException, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, target_type, target_id, finding_code, justification_code, justification_note, created_by, created_at, expires_at
		FROM finding_exceptions WHERE target_type = $1 AND target_id = $2
		ORDER BY created_at DESC`, targetType, targetID)
	if err != nil {
		return nil, err
	}
	return scanFindingExceptionRows(rows)
}

func (s *postgresFindingExceptionStore) ListActive(ctx context.Context, now time.Time) ([]FindingException, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, target_type, target_id, finding_code, justification_code, justification_note, created_by, created_at, expires_at
		FROM finding_exceptions
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	all, err := scanFindingExceptionRows(rows)
	if err != nil {
		return nil, err
	}
	return filterActiveFindingExceptions(all, now), nil
}

func (s *postgresFindingExceptionStore) Delete(ctx context.Context, id string) error {
	return deleteFindingExceptionRow(ctx, s.db, "DELETE FROM finding_exceptions WHERE id = $1", id)
}

// --- shared helpers ---

func scanFindingException(row *sql.Row) (FindingException, error) {
	var e FindingException
	var note sql.NullString
	err := row.Scan(&e.ID, &e.TargetType, &e.TargetID, &e.FindingCode, &e.JustificationCode,
		&note, &e.CreatedBy, &e.CreatedAt, &e.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return FindingException{}, errFindingExceptionNotFound
	}
	if err != nil {
		return FindingException{}, err
	}
	e.JustificationNote = note.String
	return e, nil
}

func scanFindingExceptionRows(rows *sql.Rows) ([]FindingException, error) {
	defer rows.Close()
	items := []FindingException{}
	for rows.Next() {
		var e FindingException
		var note sql.NullString
		if err := rows.Scan(&e.ID, &e.TargetType, &e.TargetID, &e.FindingCode, &e.JustificationCode,
			&note, &e.CreatedBy, &e.CreatedAt, &e.ExpiresAt); err != nil {
			return nil, err
		}
		e.JustificationNote = note.String
		items = append(items, e)
	}
	return items, rows.Err()
}

// filterActiveFindingExceptions keeps only the exceptions still in effect at
// now, per FindingException.IsActive's fail-closed-on-unparseable rule.
func filterActiveFindingExceptions(all []FindingException, now time.Time) []FindingException {
	active := make([]FindingException, 0, len(all))
	for _, e := range all {
		if e.IsActive(now) {
			active = append(active, e)
		}
	}
	return active
}

func deleteFindingExceptionRow(ctx context.Context, db *sql.DB, query, id string) error {
	res, err := db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errFindingExceptionNotFound
	}
	return nil
}

// newFindingExceptionStoreFromEnv opens the same SQLite/Postgres DB as
// other providers and ensures the finding_exceptions schema exists (G-33:
// migration 000022 alone cannot be assumed to have run). Constructed by
// every finding-funnel surface (crypto-posture, executive summary, PQC
// countdown, posture-snapshot capture — see docs/design/FINDING_ECONOMICS.md)
// via its own call to this function, each degrading independently to
// raw==effective on a nil store or read error rather than failing the report.
func newFindingExceptionStoreFromEnv() (FindingExceptionStore, error) {
	state := newDBProviderState[FindingExceptionStore](
		"finding-exception",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_FINDINGS_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_FINDINGS_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_FINDINGS_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) FindingExceptionStore { return &sqliteFindingExceptionStore{db: db} },
		func(db *sql.DB) FindingExceptionStore { return &postgresFindingExceptionStore{db: db} },
	)
	if state.openErr != nil || state.store == nil {
		return nil, state.openErr
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		return nil, err
	}
	return state.store, nil
}
