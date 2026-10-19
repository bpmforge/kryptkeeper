// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package migration

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// schemaDDL must stay identical to migrations 000144_migration_batches and
// 000325_migration_item_snapshots and
// 000326_migration_item_supersedes: the
// store creates its own tables because migrations never run against a live
// deployment's side databases (managed-target precedent).
var schemaDDL = []string{
	`CREATE TABLE IF NOT EXISTS migration_batches (
  id TEXT PRIMARY KEY, source TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'applied' CHECK (status IN ('applied','rolled_back')),
  created_by TEXT NOT NULL, created_at TEXT NOT NULL,
  rolled_back_at TEXT NOT NULL DEFAULT '', rolled_back_by TEXT NOT NULL DEFAULT '',
  report_json TEXT NOT NULL DEFAULT '{}')`,
	`CREATE TABLE IF NOT EXISTS migration_batch_items (
  batch_id TEXT NOT NULL REFERENCES migration_batches(id), source_key TEXT NOT NULL,
  template_id TEXT NOT NULL, name TEXT NOT NULL, content_hash TEXT NOT NULL,
  owner_hint TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
  disabled_at TEXT NOT NULL DEFAULT '', keep_reason TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (batch_id, source_key))`,
	`CREATE INDEX IF NOT EXISTS idx_migration_items_source_key ON migration_batch_items(source_key)`,
	`CREATE INDEX IF NOT EXISTS idx_migration_items_template_id ON migration_batch_items(template_id)`,
	`CREATE TABLE IF NOT EXISTS migration_item_snapshots (
  batch_id TEXT NOT NULL, source_key TEXT NOT NULL, prior_json TEXT NOT NULL,
  PRIMARY KEY (batch_id, source_key),
  FOREIGN KEY (batch_id, source_key) REFERENCES migration_batch_items(batch_id, source_key))`,
	`CREATE TABLE IF NOT EXISTS migration_item_supersedes (
  batch_id TEXT NOT NULL, source_key TEXT NOT NULL, supersedes_batch_id TEXT NOT NULL,
  PRIMARY KEY (batch_id, source_key),
  FOREIGN KEY (batch_id, source_key) REFERENCES migration_batch_items(batch_id, source_key))`,
}

// SQLStore is the SQLite/Postgres Store.
type SQLStore struct {
	db       *sql.DB
	postgres bool
}

// NewSQLStore wraps db. Queries are written with ? and rebound for Postgres.
func NewSQLStore(db *sql.DB, postgres bool) *SQLStore {
	return &SQLStore{db: db, postgres: postgres}
}

func (s *SQLStore) q(query string) string {
	if !s.postgres {
		return query
	}
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			fmt.Fprintf(&b, "$%d", n)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (s *SQLStore) EnsureSchema(ctx context.Context) error {
	for _, stmt := range schemaDDL {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migration schema: %w", err)
		}
	}
	return nil
}

func (s *SQLStore) SaveBatch(ctx context.Context, b Batch, items []BatchItem) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback() // the original error is the one worth returning
		}
	}()
	if _, err = tx.ExecContext(ctx, s.q(`INSERT INTO migration_batches (id, source, status, created_by, created_at, report_json) VALUES (?, ?, ?, ?, ?, ?)`),
		b.ID, b.Source, b.Status, b.CreatedBy, b.CreatedAt, b.ReportJSON); err != nil {
		return err
	}
	for _, it := range items {
		if it.SupersedesBatchID != "" {
			// The new batch owns the template now: retire the superseded item
			// so FindActiveItem finds the new one and rolling back the old
			// batch leaves the template alone.
			if _, err = tx.ExecContext(ctx, s.q(`UPDATE migration_batch_items SET disabled_at = ?, keep_reason = '' WHERE batch_id = ? AND source_key = ? AND disabled_at = ''`),
				b.CreatedAt, it.SupersedesBatchID, it.SourceKey); err != nil {
				return err
			}
		}
		if _, err = tx.ExecContext(ctx, s.q(`INSERT INTO migration_batch_items (batch_id, source_key, template_id, name, content_hash, owner_hint, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`),
			b.ID, it.SourceKey, it.TemplateID, it.Name, it.ContentHash, it.OwnerHint, it.CreatedAt); err != nil {
			return err
		}
		if it.SupersedesBatchID != "" {
			// Kept so rolling this batch back can reactivate the item it retired.
			if _, err = tx.ExecContext(ctx, s.q(`INSERT INTO migration_item_supersedes (batch_id, source_key, supersedes_batch_id) VALUES (?, ?, ?)`),
				b.ID, it.SourceKey, it.SupersedesBatchID); err != nil {
				return err
			}
		}
		if it.PriorJSON == "" {
			continue
		}
		if _, err = tx.ExecContext(ctx, s.q(`INSERT INTO migration_item_snapshots (batch_id, source_key, prior_json) VALUES (?, ?, ?)`),
			b.ID, it.SourceKey, it.PriorJSON); err != nil {
			return err
		}
	}
	return tx.Commit()
}

const itemColumns = `batch_id, source_key, template_id, name, content_hash, owner_hint, created_at, disabled_at, keep_reason`

func scanItem(sc interface{ Scan(...any) error }) (BatchItem, error) {
	var it BatchItem
	err := sc.Scan(&it.BatchID, &it.SourceKey, &it.TemplateID, &it.Name, &it.ContentHash, &it.OwnerHint, &it.CreatedAt, &it.DisabledAt, &it.KeepReason)
	return it, err
}

func (s *SQLStore) FindActiveItem(ctx context.Context, source, sourceKey string) (BatchItem, bool, error) {
	row := s.db.QueryRowContext(ctx, s.q(`SELECT i.batch_id, i.source_key, i.template_id, i.name, i.content_hash, i.owner_hint, i.created_at, i.disabled_at, i.keep_reason
FROM migration_batch_items i JOIN migration_batches b ON b.id = i.batch_id
WHERE b.source = ? AND i.source_key = ? AND i.disabled_at = ''
ORDER BY i.created_at DESC, i.batch_id DESC LIMIT 1`), source, sourceKey)
	it, err := scanItem(row)
	if err == sql.ErrNoRows {
		return BatchItem{}, false, nil
	}
	return it, err == nil, err
}

// FindItemByTemplate returns the active batch item that recorded templateID,
// else the newest retired one: proof a migration made the template. Active
// wins because a rollback can reactivate an older item under a newer retired one.
func (s *SQLStore) FindItemByTemplate(ctx context.Context, templateID string) (BatchItem, bool, error) {
	row := s.db.QueryRowContext(ctx, s.q(`SELECT `+itemColumns+` FROM migration_batch_items
WHERE template_id = ? ORDER BY (disabled_at = '') DESC, created_at DESC, batch_id DESC LIMIT 1`), templateID)
	it, err := scanItem(row)
	if err == sql.ErrNoRows {
		return BatchItem{}, false, nil
	}
	return it, err == nil, err
}

const batchColumns = `id, source, status, created_by, created_at, rolled_back_at, rolled_back_by, report_json`

func scanBatch(sc interface{ Scan(...any) error }) (Batch, error) {
	var b Batch
	err := sc.Scan(&b.ID, &b.Source, &b.Status, &b.CreatedBy, &b.CreatedAt, &b.RolledBackAt, &b.RolledBackBy, &b.ReportJSON)
	return b, err
}

func (s *SQLStore) GetBatch(ctx context.Context, id string) (Batch, []BatchItem, bool, error) {
	b, err := scanBatch(s.db.QueryRowContext(ctx, s.q(`SELECT `+batchColumns+` FROM migration_batches WHERE id = ?`), id))
	if err == sql.ErrNoRows {
		return Batch{}, nil, false, nil
	}
	if err != nil {
		return Batch{}, nil, false, err
	}
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT i.batch_id, i.source_key, i.template_id, i.name, i.content_hash, i.owner_hint, i.created_at, i.disabled_at, i.keep_reason, COALESCE(s.prior_json, ''), COALESCE(u.supersedes_batch_id, '')
FROM migration_batch_items i LEFT JOIN migration_item_snapshots s ON s.batch_id = i.batch_id AND s.source_key = i.source_key
LEFT JOIN migration_item_supersedes u ON u.batch_id = i.batch_id AND u.source_key = i.source_key
WHERE i.batch_id = ? ORDER BY i.name, i.source_key`), id)
	if err != nil {
		return Batch{}, nil, false, err
	}
	defer func() { _ = rows.Close() }()
	items := []BatchItem{}
	for rows.Next() {
		var it BatchItem
		if err := rows.Scan(&it.BatchID, &it.SourceKey, &it.TemplateID, &it.Name, &it.ContentHash, &it.OwnerHint, &it.CreatedAt, &it.DisabledAt, &it.KeepReason, &it.PriorJSON, &it.SupersedesBatchID); err != nil {
			return Batch{}, nil, false, err
		}
		items = append(items, it)
	}
	b.Items = len(items)
	return b, items, true, rows.Err()
}

func (s *SQLStore) ListBatches(ctx context.Context, limit int) ([]Batch, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT b.id, b.source, b.status, b.created_by, b.created_at, b.rolled_back_at, b.rolled_back_by, '',
(SELECT COUNT(*) FROM migration_batch_items i WHERE i.batch_id = b.id)
FROM migration_batches b ORDER BY b.created_at DESC, b.id DESC LIMIT ?`), limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []Batch{}
	for rows.Next() {
		var b Batch
		if err := rows.Scan(&b.ID, &b.Source, &b.Status, &b.CreatedBy, &b.CreatedAt, &b.RolledBackAt, &b.RolledBackBy, &b.ReportJSON, &b.Items); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
