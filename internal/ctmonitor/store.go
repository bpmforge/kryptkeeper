// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ctmonitor

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// W6-06: persisted CT findings. The table is EnsureSchema-owned (the
// pending-actions store precedent). W24-19 adds migration 000143 so a
// migrations-only hub also gets the table with the triage columns; EnsureSchema
// stays authoritative for databases that predate it (best-effort ALTER).

// ErrFindingNotFound is returned by Get and Resolve for an unknown id.
var ErrFindingNotFound = errors.New("ct finding not found")

// Resolution values: how an acknowledged finding was triaged. The stored
// status stays open|acknowledged (SQLite cannot alter a CHECK in place).
const (
	ResolutionAcknowledged = "acknowledged"
	ResolutionKnownIssuer  = "known_issuer"
)

// DefaultTenant stamps findings whose caller did not set Finding.Tenant.
const DefaultTenant = "default"

// Finding is one rogue/shadow certificate observed in CT for an owned
// domain and absent from the inventory.
type Finding struct {
	ID         string    `json:"id"` // source:entry-id — the dedup key
	Domain     string    `json:"domain"`
	CommonName string    `json:"common_name"`
	DNSNames   []string  `json:"dns_names"`
	Issuer     string    `json:"issuer"`
	Serial     string    `json:"serial"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	Source     string    `json:"source"` // "crtsh"
	Status     string    `json:"status"` // open | acknowledged
	CreatedAt  time.Time `json:"created_at"`
	// W24-19 triage columns.
	Tenant     string    `json:"tenant"`
	Resolution string    `json:"resolution"` // "" | acknowledged | known_issuer
	ResolvedBy string    `json:"resolved_by"`
	ResolvedAt time.Time `json:"resolved_at"`
}

const ctFindingsSchema = `
CREATE TABLE IF NOT EXISTS ct_findings (
    id          TEXT PRIMARY KEY,
    domain      TEXT NOT NULL,
    common_name TEXT NOT NULL DEFAULT '',
    dns_names   TEXT NOT NULL DEFAULT '[]',
    issuer      TEXT NOT NULL DEFAULT '',
    serial      TEXT NOT NULL DEFAULT '',
    not_before  TEXT NOT NULL DEFAULT '',
    not_after   TEXT NOT NULL DEFAULT '',
    source      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open'
                CHECK (status IN ('open', 'acknowledged')),
    created_at  TEXT NOT NULL,
    resolution  TEXT NOT NULL DEFAULT '',
    resolved_by TEXT NOT NULL DEFAULT '',
    resolved_at TEXT NOT NULL DEFAULT '',
    tenant      TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_ct_findings_domain ON ct_findings(domain, status);`

// Store persists findings. sqlite and postgres share the SQL; only the
// placeholder dialect differs.
type Store struct {
	db       *sql.DB
	postgres bool
}

func NewStore(db *sql.DB, postgres bool) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("ct monitor store requires a database")
	}
	s := &Store{db: db, postgres: postgres}
	// No migration owns ct_findings; without this a "ca" hub (migrations only)
	// had no table and every Record failed with "relation does not exist".
	if err := s.EnsureSchema(context.Background()); err != nil {
		return nil, fmt.Errorf("ct monitor store: ensure schema: %w", err)
	}
	return s, nil
}

func (s *Store) rebind(q string) string {
	if !s.postgres {
		return q
	}
	out := make([]byte, 0, len(q)+8)
	n := 0
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			n++
			out = append(out, fmt.Sprintf("$%d", n)...)
			continue
		}
		out = append(out, q[i])
	}
	return string(out)
}

// ctFindingsUpgrade adds the W24-19 columns to a table created before them.
// One statement per Exec: ADD COLUMN ... NOT NULL DEFAULT is valid on both
// engines, and a duplicate-column error just means the column is present.
var ctFindingsUpgrade = []string{
	`ALTER TABLE ct_findings ADD COLUMN resolution TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE ct_findings ADD COLUMN resolved_by TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE ct_findings ADD COLUMN resolved_at TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE ct_findings ADD COLUMN tenant TEXT NOT NULL DEFAULT 'default'`,
}

// EnsureSchema creates the findings table and upgrades an older one.
func (s *Store) EnsureSchema(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, ctFindingsSchema); err != nil {
		return err
	}
	for _, stmt := range ctFindingsUpgrade {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil && !isDuplicateColumn(err) {
			return fmt.Errorf("ct findings: upgrade schema: %w", err)
		}
	}
	return nil
}

func isDuplicateColumn(err error) bool {
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "duplicate column") || strings.Contains(m, "already exists")
}

// Record persists a finding once; a duplicate id reports created=false
// so callers alert only on NEW findings.
func (s *Store) Record(ctx context.Context, f Finding) (created bool, err error) {
	if f.ID == "" || f.Domain == "" || f.Source == "" {
		return false, fmt.Errorf("ct finding: id, domain and source are required")
	}
	dns, err := json.Marshal(f.DNSNames)
	if err != nil {
		return false, fmt.Errorf("ct finding: dns marshal: %w", err)
	}
	tenant := strings.TrimSpace(f.Tenant)
	if tenant == "" {
		tenant = DefaultTenant
	}
	res, err := s.db.ExecContext(ctx, s.rebind(`
		INSERT INTO ct_findings (id, domain, common_name, dns_names, issuer, serial,
			not_before, not_after, source, status, created_at, tenant)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)
		ON CONFLICT (id) DO NOTHING`),
		f.ID, f.Domain, f.CommonName, string(dns), f.Issuer, f.Serial,
		f.NotBefore.UTC().Format(time.RFC3339), f.NotAfter.UTC().Format(time.RFC3339),
		f.Source, time.Now().UTC().Format(time.RFC3339), tenant)
	if err != nil {
		return false, fmt.Errorf("ct finding: persist: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

const findingColumns = `id, domain, common_name, dns_names, issuer, serial,
		not_before, not_after, source, status, created_at,
		resolution, resolved_by, resolved_at, tenant`

type rowScanner interface{ Scan(dest ...any) error }

func scanFinding(row rowScanner) (Finding, error) {
	var f Finding
	var dns, notBefore, notAfter, createdAt, resolvedAt string
	if err := row.Scan(&f.ID, &f.Domain, &f.CommonName, &dns, &f.Issuer, &f.Serial,
		&notBefore, &notAfter, &f.Source, &f.Status, &createdAt,
		&f.Resolution, &f.ResolvedBy, &resolvedAt, &f.Tenant); err != nil {
		return Finding{}, err
	}
	if err := json.Unmarshal([]byte(dns), &f.DNSNames); err != nil {
		return Finding{}, fmt.Errorf("ct finding %s: dns parse: %w", f.ID, err)
	}
	f.NotBefore, _ = time.Parse(time.RFC3339, notBefore)
	f.NotAfter, _ = time.Parse(time.RFC3339, notAfter)
	f.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	f.ResolvedAt, _ = time.Parse(time.RFC3339, resolvedAt)
	return f, nil
}

// List returns findings, optionally filtered by stored status ("" = all).
func (s *Store) List(ctx context.Context, status string) ([]Finding, error) {
	query := `SELECT ` + findingColumns + ` FROM ct_findings`
	var args []any
	if status != "" {
		query += s.rebind(` WHERE status = ?`)
		args = append(args, status)
	}
	query += ` ORDER BY created_at DESC, id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("ct findings: list: %w", err)
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// Get returns one finding or ErrFindingNotFound.
func (s *Store) Get(ctx context.Context, id string) (Finding, error) {
	f, err := scanFinding(s.db.QueryRowContext(ctx,
		s.rebind(`SELECT `+findingColumns+` FROM ct_findings WHERE id = ?`), id))
	if errors.Is(err, sql.ErrNoRows) {
		return Finding{}, ErrFindingNotFound
	}
	if err != nil {
		return Finding{}, fmt.Errorf("ct findings: get: %w", err)
	}
	return f, nil
}

// Resolve triages a finding: status becomes acknowledged and resolution,
// resolved_by and resolved_at record how. Re-resolving is allowed (the later
// call wins); an unknown id is ErrFindingNotFound.
func (s *Store) Resolve(ctx context.Context, id, resolution, by string, at time.Time) error {
	if resolution != ResolutionAcknowledged && resolution != ResolutionKnownIssuer {
		return fmt.Errorf("ct finding: invalid resolution %q", resolution)
	}
	res, err := s.db.ExecContext(ctx, s.rebind(`UPDATE ct_findings
		SET status = 'acknowledged', resolution = ?, resolved_by = ?, resolved_at = ?
		WHERE id = ?`), resolution, by, at.UTC().Format(time.RFC3339), id)
	if err != nil {
		return fmt.Errorf("ct findings: resolve: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrFindingNotFound
	}
	return nil
}

// Acknowledge marks a finding acknowledged.
func (s *Store) Acknowledge(ctx context.Context, id string) error {
	return s.Resolve(ctx, id, ResolutionAcknowledged, "", time.Now())
}
