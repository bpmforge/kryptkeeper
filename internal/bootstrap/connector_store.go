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

// W11-03: persisted issuer-connector config. Secrets never live in
// config_json — they are credential_ref pointers into the W5-10 encrypted
// store, same discipline as managed targets.

var (
	errConnectorNotFound = errors.New("connector not found")
	errConnectorInvalid  = errors.New("connector name and a type of internal|acme|digicert|scep|est|wstep are required")
	validConnectorTypes  = map[string]bool{"internal": true, "acme": true, "digicert": true, "scep": true, "est": true, "wstep": true}
)

type ConnectorRecord struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	ConfigJSON    string `json:"config_json"`
	CredentialRef string `json:"credential_ref,omitempty"`
	Tenant        string `json:"tenant"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

type ConnectorStore interface {
	EnsureSchema(ctx context.Context) error
	Create(ctx context.Context, rec ConnectorRecord) (ConnectorRecord, error)
	Get(ctx context.Context, id string) (ConnectorRecord, error)
	List(ctx context.Context) ([]ConnectorRecord, error)
	Delete(ctx context.Context, id string) error
}

// connectorSchema mirrors migration 000044 as widened by 000205 — every DB-backed store
// self-heals its schema (G-33 discipline).
const connectorSchema = `
CREATE TABLE IF NOT EXISTS connectors (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    type           TEXT NOT NULL CHECK (type IN ('internal', 'acme', 'digicert', 'scep', 'est', 'wstep')),
    config_json    TEXT NOT NULL DEFAULT '{}',
    credential_ref TEXT,
    tenant         TEXT NOT NULL DEFAULT 'default',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_connectors_tenant ON connectors(tenant);`

func newConnectorID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "conn-" + hex.EncodeToString(buf), nil
}

func validateConnectorRecord(rec ConnectorRecord) error {
	if strings.TrimSpace(rec.Name) == "" || !validConnectorTypes[rec.Type] {
		return errConnectorInvalid
	}
	if rec.Type == "acme" {
		return validateACMEConnectorConfig(rec.ConfigJSON)
	}
	if upstreamConnectorTypes[rec.Type] {
		return validateUpstreamConnector(rec)
	}
	return nil
}

type dbConnectorStore struct {
	db       *sql.DB
	postgres bool
}

func newConnectorStore(db *sql.DB, postgres bool) ConnectorStore {
	return &dbConnectorStore{db: db, postgres: postgres}
}

func (s *dbConnectorStore) ph(n int) string {
	if s.postgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

func (s *dbConnectorStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, connectorSchema)
	return err
}

func (s *dbConnectorStore) Create(ctx context.Context, rec ConnectorRecord) (ConnectorRecord, error) {
	if err := validateConnectorRecord(rec); err != nil {
		return ConnectorRecord{}, err
	}
	if rec.ConfigJSON == "" {
		rec.ConfigJSON = "{}"
	}
	if rec.Tenant == "" {
		rec.Tenant = DefaultTenant
	}
	now := time.Now().UTC().Format(time.RFC3339)
	rec.CreatedAt, rec.UpdatedAt = now, now
	q := fmt.Sprintf(`INSERT INTO connectors (id, name, type, config_json, credential_ref, tenant, created_at, updated_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s)`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7), s.ph(8))
	_, err := s.db.ExecContext(ctx, q,
		rec.ID, rec.Name, rec.Type, rec.ConfigJSON, nullString(rec.CredentialRef), rec.Tenant, rec.CreatedAt, rec.UpdatedAt)
	if err != nil {
		return ConnectorRecord{}, err
	}
	return rec, nil
}

func (s *dbConnectorStore) Get(ctx context.Context, id string) (ConnectorRecord, error) {
	q := fmt.Sprintf(`SELECT id, name, type, config_json, credential_ref, tenant, created_at, updated_at
		FROM connectors WHERE id = %s`, s.ph(1))
	return scanConnector(s.db.QueryRowContext(ctx, q, id))
}

func (s *dbConnectorStore) List(ctx context.Context) ([]ConnectorRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, type, config_json, credential_ref, tenant, created_at, updated_at
		FROM connectors ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ConnectorRecord{}
	for rows.Next() {
		var rec ConnectorRecord
		var credRef sql.NullString
		if err := rows.Scan(&rec.ID, &rec.Name, &rec.Type, &rec.ConfigJSON, &credRef, &rec.Tenant, &rec.CreatedAt, &rec.UpdatedAt); err != nil {
			return nil, err
		}
		rec.CredentialRef = credRef.String
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *dbConnectorStore) Delete(ctx context.Context, id string) error {
	q := fmt.Sprintf(`DELETE FROM connectors WHERE id = %s`, s.ph(1))
	res, err := s.db.ExecContext(ctx, q, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errConnectorNotFound
	}
	return nil
}

func scanConnector(row *sql.Row) (ConnectorRecord, error) {
	var rec ConnectorRecord
	var credRef sql.NullString
	err := row.Scan(&rec.ID, &rec.Name, &rec.Type, &rec.ConfigJSON, &credRef, &rec.Tenant, &rec.CreatedAt, &rec.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ConnectorRecord{}, errConnectorNotFound
	}
	if err != nil {
		return ConnectorRecord{}, err
	}
	rec.CredentialRef = credRef.String
	return rec, nil
}

func newConnectorStoreFromEnv() ConnectorStore {
	state := newDBProviderState[ConnectorStore](
		"connector",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_CONNECTORS_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_CONNECTORS_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_CONNECTORS_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) ConnectorStore { return newConnectorStore(db, false) },
		func(db *sql.DB) ConnectorStore { return newConnectorStore(db, true) },
	)
	if state.openErr != nil || state.store == nil {
		_ = dbProviderUnavailable("connector", state.openErr) // logs the outage itself; return value is the same sentinel
		return nil
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		_ = dbProviderUnavailable("connector", err) // logs the outage itself; return value is the same sentinel
		return nil
	}
	return state.store
}
