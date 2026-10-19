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
	"strings"
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
	// FindingExceptionTargetFile files an exception against one discovered
	// file (install posture findings such as SERVICE_RUNS_AS_ROOT); target_id
	// is discovered_files.id and finding_code the bare code.
	FindingExceptionTargetFile = "target_file"
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
	// Tenant is the creating tenant, filled by activeFindingExceptions from
	// the finding_exception_tenants stamp (not a column of this row; "" = the
	// default tenant). Tenant-aware funnels match on it (W22-28/29).
	Tenant string `json:"-"`
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
                          CHECK (target_type IN ('certificate', 'ca', 'target_file')),
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

// --- tenant stamp (W22-28) ---
//
// An exception is created by one tenant's principal and must stay hidden from
// every other tenant. The stamp lives in a side table so the exception row
// itself (and every query above) is unchanged; a row with no stamp predates
// tenancy and belongs to DefaultTenant. Migration 000095 declares the table;
// EnsureTenantSchema self-heals it like every other store here (G-33).

const findingExceptionTenantSchema = `
CREATE TABLE IF NOT EXISTS finding_exception_tenants (
    exception_id TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL
);`

// findingExceptionTenantStore is the optional tenant-stamping surface of a
// FindingExceptionStore. The exceptions API refuses to run against a store
// that lacks it, because an unstamped exception could not be tenant-scoped.
type findingExceptionTenantStore interface {
	EnsureTenantSchema(ctx context.Context) error
	// CreateWithTenant inserts the exception and its tenant stamp atomically.
	CreateWithTenant(ctx context.Context, exc FindingException, tenant string) error
	// TenantsByID returns exception id -> tenant for every stamped exception.
	TenantsByID(ctx context.Context) (map[string]string, error)
	// ForgetTenant removes an exception's stamp (after the exception is deleted).
	ForgetTenant(ctx context.Context, id string) error
}

func (s *sqliteFindingExceptionStore) EnsureTenantSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, findingExceptionTenantSchema)
	return err
}

func (s *sqliteFindingExceptionStore) CreateWithTenant(ctx context.Context, exc FindingException, tenant string) error {
	return createFindingExceptionWithTenant(ctx, s.db, exc, tenant,
		`INSERT INTO finding_exceptions
		  (id, target_type, target_id, finding_code, justification_code, justification_note, created_by, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		`INSERT INTO finding_exception_tenants (exception_id, tenant_id) VALUES (?, ?)`)
}

func (s *sqliteFindingExceptionStore) TenantsByID(ctx context.Context) (map[string]string, error) {
	return findingExceptionTenants(ctx, s.db)
}

func (s *sqliteFindingExceptionStore) ForgetTenant(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM finding_exception_tenants WHERE exception_id = ?`, id)
	return err
}

func (s *postgresFindingExceptionStore) EnsureTenantSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, findingExceptionTenantSchema)
	return err
}

func (s *postgresFindingExceptionStore) CreateWithTenant(ctx context.Context, exc FindingException, tenant string) error {
	return createFindingExceptionWithTenant(ctx, s.db, exc, tenant,
		`INSERT INTO finding_exceptions
		  (id, target_type, target_id, finding_code, justification_code, justification_note, created_by, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		`INSERT INTO finding_exception_tenants (exception_id, tenant_id) VALUES ($1, $2)`)
}

func (s *postgresFindingExceptionStore) TenantsByID(ctx context.Context) (map[string]string, error) {
	return findingExceptionTenants(ctx, s.db)
}

func (s *postgresFindingExceptionStore) ForgetTenant(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM finding_exception_tenants WHERE exception_id = $1`, id)
	return err
}

func createFindingExceptionWithTenant(ctx context.Context, db *sql.DB, exc FindingException, tenant, insertExc, insertTenant string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }() // no-op once committed
	if _, err := tx.ExecContext(ctx, insertExc,
		exc.ID, exc.TargetType, exc.TargetID, exc.FindingCode, exc.JustificationCode,
		nullString(exc.JustificationNote), exc.CreatedBy, exc.CreatedAt, exc.ExpiresAt); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, insertTenant, exc.ID, tenant); err != nil {
		return err
	}
	return tx.Commit()
}

func findingExceptionTenants(ctx context.Context, db *sql.DB) (map[string]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT exception_id, tenant_id FROM finding_exception_tenants`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, tenant string
		if err := rows.Scan(&id, &tenant); err != nil {
			return nil, err
		}
		out[id] = tenant
	}
	return out, rows.Err()
}

// --- lifecycle events (W22-31) ---
//
// The expiry scanner must warn once and audit a lapse once, across restarts
// and replicas, so each (exception, kind) is claimed by an insert that only
// the first caller wins. Migration 000096 declares the table; the claim path
// self-heals it (G-33).

const findingExceptionEventSchema = `
CREATE TABLE IF NOT EXISTS finding_exception_events (
    exception_id TEXT NOT NULL,
    kind         TEXT NOT NULL CHECK (kind IN ('expiring', 'expired')),
    at           TEXT NOT NULL,
    PRIMARY KEY (exception_id, kind)
);`

func (s *sqliteFindingExceptionStore) EnsureLifecycleSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, findingExceptionEventSchema)
	return err
}

// ListAll returns every exception including lapsed ones (ListActive hides
// them); the evidence trail and the expiry scanner both need the lapsed rows.
func (s *sqliteFindingExceptionStore) ListAll(ctx context.Context) ([]FindingException, error) {
	return listAllFindingExceptions(ctx, s.db)
}

func (s *sqliteFindingExceptionStore) ClaimEvent(ctx context.Context, exceptionID, kind string, at time.Time) (bool, error) {
	return claimFindingExceptionEvent(ctx, s.db,
		`INSERT INTO finding_exception_events (exception_id, kind, at) VALUES (?, ?, ?)
		 ON CONFLICT (exception_id, kind) DO NOTHING`, exceptionID, kind, at)
}

func (s *postgresFindingExceptionStore) EnsureLifecycleSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, findingExceptionEventSchema)
	return err
}

func (s *postgresFindingExceptionStore) ListAll(ctx context.Context) ([]FindingException, error) {
	return listAllFindingExceptions(ctx, s.db)
}

func (s *postgresFindingExceptionStore) ClaimEvent(ctx context.Context, exceptionID, kind string, at time.Time) (bool, error) {
	return claimFindingExceptionEvent(ctx, s.db,
		`INSERT INTO finding_exception_events (exception_id, kind, at) VALUES ($1, $2, $3)
		 ON CONFLICT (exception_id, kind) DO NOTHING`, exceptionID, kind, at)
}

func listAllFindingExceptions(ctx context.Context, db *sql.DB) ([]FindingException, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, target_type, target_id, finding_code, justification_code, justification_note, created_by, created_at, expires_at
		FROM finding_exceptions
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	return scanFindingExceptionRows(rows)
}

func claimFindingExceptionEvent(ctx context.Context, db *sql.DB, query, exceptionID, kind string, at time.Time) (bool, error) {
	res, err := db.ExecContext(ctx, query, exceptionID, kind, at.UTC().Format(time.RFC3339))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// exceptionTenantKey folds the default tenant to "" so exception stamps
// ("default") and discovery endpoint tenants ("" = default) compare equal.
func exceptionTenantKey(t string) string {
	if t == DefaultTenant {
		return ""
	}
	return t
}

// findingExceptionIndexForTenant is findingExceptionIndex restricted to the
// exceptions created in tenant, so one tenant's exception never suppresses
// another tenant's finding on the same fingerprint.
func findingExceptionIndexForTenant(active []FindingException, tenant string) map[string]bool {
	want := exceptionTenantKey(tenant)
	idx := make(map[string]bool)
	for _, e := range active {
		if exceptionTenantKey(e.Tenant) == want {
			idx[findingExceptionKey(e.TargetType, e.TargetID, e.FindingCode)] = true
		}
	}
	return idx
}

// DiscoveredFileRef is what an exception needs to know about its target file:
// who owns it (tenant), how to name it, and which certificates live in it.
type DiscoveredFileRef struct {
	ID, Tenant, Host, Path string
	Fingerprints           []string
}

// discoveredFileLookup resolves a discovered_files row for exception handling.
// found=false covers both "no such row" and "this database has no posture
// tables": either way there is nothing to file an exception against.
type discoveredFileLookup interface {
	LookupDiscoveredFile(ctx context.Context, id string) (ref DiscoveredFileRef, found bool, err error)
}

func lookupDiscoveredFile(ctx context.Context, db *sql.DB, postgres bool, id string) (DiscoveredFileRef, bool, error) {
	ref := DiscoveredFileRef{ID: id}
	err := db.QueryRowContext(ctx, dialectQuery(postgres, `SELECT tenant, host, path FROM discovered_files WHERE id = ?`), id).
		Scan(&ref.Tenant, &ref.Host, &ref.Path)
	if errors.Is(err, sql.ErrNoRows) {
		return DiscoveredFileRef{}, false, nil
	}
	if err != nil {
		if strings.Contains(err.Error(), "no such table") || strings.Contains(err.Error(), "does not exist") {
			return DiscoveredFileRef{}, false, nil
		}
		return DiscoveredFileRef{}, false, err
	}
	rows, err := db.QueryContext(ctx, dialectQuery(postgres, `SELECT certificate_fingerprint FROM certificate_files WHERE file_id = ?`), id)
	if err != nil {
		return DiscoveredFileRef{}, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return DiscoveredFileRef{}, false, err
		}
		ref.Fingerprints = append(ref.Fingerprints, fp)
	}
	return ref, true, rows.Err()
}

func (s *sqliteFindingExceptionStore) LookupDiscoveredFile(ctx context.Context, id string) (DiscoveredFileRef, bool, error) {
	return lookupDiscoveredFile(ctx, s.db, false, id)
}

func (s *postgresFindingExceptionStore) LookupDiscoveredFile(ctx context.Context, id string) (DiscoveredFileRef, bool, error) {
	return lookupDiscoveredFile(ctx, s.db, true, id)
}
