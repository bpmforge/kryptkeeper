// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ctmonitor

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// W6-06: persisted CT findings. The table is EnsureSchema-owned (the
// pending-actions store precedent) — no migration number consumed.

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
    created_at  TEXT NOT NULL
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

// EnsureSchema creates the findings table.
func (s *Store) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, ctFindingsSchema)
	return err
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
	res, err := s.db.ExecContext(ctx, s.rebind(`
		INSERT INTO ct_findings (id, domain, common_name, dns_names, issuer, serial,
			not_before, not_after, source, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
		ON CONFLICT (id) DO NOTHING`),
		f.ID, f.Domain, f.CommonName, string(dns), f.Issuer, f.Serial,
		f.NotBefore.UTC().Format(time.RFC3339), f.NotAfter.UTC().Format(time.RFC3339),
		f.Source, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return false, fmt.Errorf("ct finding: persist: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// List returns findings, optionally filtered by status ("" = all).
func (s *Store) List(ctx context.Context, status string) ([]Finding, error) {
	query := `SELECT id, domain, common_name, dns_names, issuer, serial,
		not_before, not_after, source, status, created_at
		FROM ct_findings`
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
		var f Finding
		var dns, notBefore, notAfter, createdAt string
		if err := rows.Scan(&f.ID, &f.Domain, &f.CommonName, &dns, &f.Issuer, &f.Serial,
			&notBefore, &notAfter, &f.Source, &f.Status, &createdAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(dns), &f.DNSNames); err != nil {
			return nil, fmt.Errorf("ct finding %s: dns parse: %w", f.ID, err)
		}
		f.NotBefore, _ = time.Parse(time.RFC3339, notBefore)
		f.NotAfter, _ = time.Parse(time.RFC3339, notAfter)
		f.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		out = append(out, f)
	}
	return out, rows.Err()
}

// Acknowledge marks a finding acknowledged.
func (s *Store) Acknowledge(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, s.rebind(
		`UPDATE ct_findings SET status = 'acknowledged' WHERE id = ?`), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("ct finding %s not found", id)
	}
	return nil
}
