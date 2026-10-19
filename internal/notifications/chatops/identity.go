// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package chatops

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Identity.Platform values.
const (
	PlatformSlack = "slack"
	PlatformTeams = "teams"
)

// Identity names a person on a chat platform.
type Identity struct {
	Platform   string `json:"platform"`
	Workspace  string `json:"workspace"`
	ExternalID string `json:"external_id"`
}

// Mapping binds a chat identity to a Kryptkeeper user inside one tenant.
type Mapping struct {
	Identity
	KryptkeeperUser string `json:"kryptkeeper_user"`
	Tenant          string `json:"tenant"`
	CreatedAt       string `json:"created_at"`
}

// IdentityStore persists chat-identity to user mappings.
type IdentityStore interface {
	Lookup(ctx context.Context, id Identity) (Mapping, bool, error)
	Upsert(ctx context.Context, m Mapping) error
	Delete(ctx context.Context, id Identity) error
	List(ctx context.Context, tenant string) ([]Mapping, error)
}

const identitySchema = `
CREATE TABLE IF NOT EXISTS chatops_identity_map (
    platform TEXT NOT NULL, workspace TEXT NOT NULL, external_id TEXT NOT NULL,
    kryptkeeper_user TEXT NOT NULL, tenant TEXT NOT NULL, created_at TEXT NOT NULL,
    PRIMARY KEY (platform, workspace, external_id));`

// SQLIdentityStore is a self-healing sidecar table (no migration file).
type SQLIdentityStore struct {
	db *sql.DB
	ph func(int) string
}

// NewSQLIdentityStore wraps db; ph renders the nth placeholder ("?" or "$n").
func NewSQLIdentityStore(db *sql.DB, ph func(int) string) *SQLIdentityStore {
	return &SQLIdentityStore{db: db, ph: ph}
}

func (s *SQLIdentityStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, identitySchema)
	return err
}

func (s *SQLIdentityStore) Lookup(ctx context.Context, id Identity) (Mapping, bool, error) {
	var m Mapping
	err := s.db.QueryRowContext(ctx, fmt.Sprintf(
		`SELECT platform, workspace, external_id, kryptkeeper_user, tenant, created_at FROM chatops_identity_map
		 WHERE platform = %s AND workspace = %s AND external_id = %s`, s.ph(1), s.ph(2), s.ph(3)),
		id.Platform, id.Workspace, id.ExternalID).
		Scan(&m.Platform, &m.Workspace, &m.ExternalID, &m.KryptkeeperUser, &m.Tenant, &m.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Mapping{}, false, nil
	}
	if err != nil {
		return Mapping{}, false, err
	}
	return m, true, nil
}

func (s *SQLIdentityStore) Upsert(ctx context.Context, m Mapping) error {
	q := fmt.Sprintf(`INSERT INTO chatops_identity_map (platform, workspace, external_id, kryptkeeper_user, tenant, created_at)
		VALUES (%s, %s, %s, %s, %s, %s)
		ON CONFLICT (platform, workspace, external_id) DO UPDATE SET kryptkeeper_user = excluded.kryptkeeper_user,
		tenant = excluded.tenant, created_at = excluded.created_at`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6))
	_, err := s.db.ExecContext(ctx, q, m.Platform, m.Workspace, m.ExternalID, m.KryptkeeperUser, m.Tenant, m.CreatedAt)
	return err
}

func (s *SQLIdentityStore) Delete(ctx context.Context, id Identity) error {
	_, err := s.db.ExecContext(ctx, fmt.Sprintf(
		`DELETE FROM chatops_identity_map WHERE platform = %s AND workspace = %s AND external_id = %s`,
		s.ph(1), s.ph(2), s.ph(3)), id.Platform, id.Workspace, id.ExternalID)
	return err
}

func (s *SQLIdentityStore) List(ctx context.Context, tenant string) ([]Mapping, error) {
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(
		`SELECT platform, workspace, external_id, kryptkeeper_user, tenant, created_at FROM chatops_identity_map
		 WHERE tenant = %s ORDER BY platform, workspace, external_id`, s.ph(1)), tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Mapping{}
	for rows.Next() {
		var m Mapping
		if err := rows.Scan(&m.Platform, &m.Workspace, &m.ExternalID, &m.KryptkeeperUser, &m.Tenant, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
