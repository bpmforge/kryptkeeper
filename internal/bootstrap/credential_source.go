// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

// Credential sources (W38-07, D-324): where a target credential's secret is
// fetched from at use time instead of being stored in the hub. A source is a
// tenant-owned row that says how to reach a secret manager (HashiCorp Vault or
// OpenBao KV v2 natively, or a `credentials` plugin for CyberArk, Delinea and
// the like) and names a LOCAL api_token credential that logs in to it. An
// external credential then carries only a reference (path, version), never a
// secret.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Where a credential's secret lives.
const (
	CredentialSourceLocal    = "local"
	CredentialSourceExternal = "external"
)

// Kinds of credential source.
const (
	CredentialSourceVaultKV2 = "vault_kv2"
	CredentialSourcePlugin   = "plugin"
)

var (
	errCredentialSourceNotFound = errors.New("credential source not found")
	errCredentialSourceInUse    = errors.New("credential source is used by credentials")
	errCredentialSourceInvalid  = errors.New("invalid credential source")
)

// MaxCredentialCacheTTLSeconds caps the optional cache: the point of an
// external source is that the hub does not keep the secret, so even an opted-in
// cache is minutes, never hours.
const MaxCredentialCacheTTLSeconds = 300

// CredentialSourceConfig is everything about a source that is not secret. The
// login (Vault token, AppRole, or a plugin's own credential fields) is in the
// local credential named by CredentialSource.CredentialRef.
type CredentialSourceConfig struct {
	// BaseURL is the Vault or OpenBao address (vault_kv2 only).
	BaseURL string `json:"base_url,omitempty"`
	// Namespace is the Vault Enterprise / HCP namespace, sent as
	// X-Vault-Namespace; OpenBao accepts it too.
	Namespace string `json:"namespace,omitempty"`
	// Mount is the KV v2 mount path, default "secret".
	Mount string `json:"mount,omitempty"`
	// AppRoleMount is the AppRole auth mount, default "approle".
	AppRoleMount string `json:"approle_mount,omitempty"`
	// CACertPEM pins a private server CA. A certificate is public material.
	CACertPEM string `json:"ca_cert_pem,omitempty"`
	// PluginID names the enabled credentials plugin (plugin only).
	PluginID string `json:"plugin_id,omitempty"`
	// CacheTTLSeconds keeps a fetched credential in memory this long; 0, the
	// default, means every use fetches again.
	CacheTTLSeconds int `json:"cache_ttl_seconds,omitempty"`
}

// CredentialSource is a stored source. Nothing in it is a secret.
type CredentialSource struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Tenant string `json:"tenant"`
	// CredentialRef is the local api_token credential that logs in to the
	// manager: {"token"} or {"role_id","secret_id"} for Vault, the plugin's
	// credential fields for a plugin.
	CredentialRef string                 `json:"credential_ref"`
	Config        CredentialSourceConfig `json:"config"`
	CreatedAt     string                 `json:"created_at"`
	UpdatedAt     string                 `json:"updated_at"`
}

// Validate checks a source's own consistency; the credential it points at is
// checked by the caller, which has the store.
func (s CredentialSource) Validate() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", errCredentialSourceInvalid, fmt.Sprintf(format, a...))
	}
	c := s.Config
	switch {
	case strings.TrimSpace(s.Name) == "":
		return bad("name is required")
	case strings.TrimSpace(s.CredentialRef) == "":
		return bad("credential_ref is required: the local credential that logs in to the manager")
	case c.CacheTTLSeconds < 0 || c.CacheTTLSeconds > MaxCredentialCacheTTLSeconds:
		return bad("cache_ttl_seconds must be 0 (no cache) to %d", MaxCredentialCacheTTLSeconds)
	}
	switch s.Kind {
	case CredentialSourceVaultKV2:
		u, err := url.Parse(c.BaseURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil {
			return bad("config.base_url must be an http(s) URL of the Vault or OpenBao server, without credentials")
		}
		if c.PluginID != "" {
			return bad("config.plugin_id is for plugin sources")
		}
	case CredentialSourcePlugin:
		if strings.TrimSpace(c.PluginID) == "" {
			return bad("config.plugin_id is required for a plugin source")
		}
		if c.BaseURL != "" || c.Namespace != "" || c.Mount != "" || c.AppRoleMount != "" || c.CACertPEM != "" {
			return bad("a plugin source takes its address from the plugin's credential, not from config")
		}
	default:
		return bad("kind must be %s or %s", CredentialSourceVaultKV2, CredentialSourcePlugin)
	}
	return nil
}

// CredentialSourceStore persists sources.
type CredentialSourceStore interface {
	EnsureSchema(ctx context.Context) error
	Create(ctx context.Context, s CredentialSource) (CredentialSource, error)
	Get(ctx context.Context, id string) (CredentialSource, error)
	List(ctx context.Context) ([]CredentialSource, error)
	// Delete refuses a source that credentials still reference.
	Delete(ctx context.Context, id string) error
}

// credentialSourceSchema mirrors migration 000386.
const credentialSourceSchema = `
CREATE TABLE IF NOT EXISTS credential_sources (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    kind           TEXT NOT NULL CHECK (kind IN ('vault_kv2', 'plugin')),
    tenant         TEXT NOT NULL DEFAULT 'default',
    config         TEXT NOT NULL,
    credential_ref TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_credential_sources_tenant ON credential_sources(tenant);`

// dbCredentialSourceStore serves both engines: the SQL is the same apart from
// placeholders.
type dbCredentialSourceStore struct {
	db       *sql.DB
	postgres bool
}

func (s *dbCredentialSourceStore) q(query string) string {
	if s.postgres {
		return rebindPostgres(query)
	}
	return query
}

func (s *dbCredentialSourceStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, credentialSourceSchema)
	return err
}

const credentialSourceCols = `id, name, kind, tenant, config, credential_ref, created_at, updated_at`

func (s *dbCredentialSourceStore) Create(ctx context.Context, src CredentialSource) (CredentialSource, error) {
	if src.Tenant == "" {
		src.Tenant = DefaultTenant
	}
	src.Name = strings.TrimSpace(src.Name)
	if err := src.Validate(); err != nil {
		return CredentialSource{}, err
	}
	cfg, err := json.Marshal(src.Config)
	if err != nil {
		return CredentialSource{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	src.CreatedAt, src.UpdatedAt = now, now
	_, err = s.db.ExecContext(ctx, s.q(`INSERT INTO credential_sources (`+credentialSourceCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
		src.ID, src.Name, src.Kind, src.Tenant, string(cfg), src.CredentialRef, now, now)
	if err != nil {
		return CredentialSource{}, err
	}
	return src, nil
}

func scanCredentialSource(r rowScanner) (CredentialSource, error) {
	var src CredentialSource
	var cfg string
	if err := r.Scan(&src.ID, &src.Name, &src.Kind, &src.Tenant, &cfg, &src.CredentialRef, &src.CreatedAt, &src.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CredentialSource{}, errCredentialSourceNotFound
		}
		return CredentialSource{}, err
	}
	if err := json.Unmarshal([]byte(cfg), &src.Config); err != nil {
		return CredentialSource{}, fmt.Errorf("credential source %s: stored config is not valid JSON", src.ID)
	}
	return src, nil
}

func (s *dbCredentialSourceStore) Get(ctx context.Context, id string) (CredentialSource, error) {
	return scanCredentialSource(s.db.QueryRowContext(ctx, s.q(`SELECT `+credentialSourceCols+` FROM credential_sources WHERE id = ?`), id))
}

func (s *dbCredentialSourceStore) List(ctx context.Context) ([]CredentialSource, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+credentialSourceCols+` FROM credential_sources ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CredentialSource{}
	for rows.Next() {
		src, err := scanCredentialSource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, src)
	}
	return out, rows.Err()
}

func (s *dbCredentialSourceStore) Delete(ctx context.Context, id string) error {
	var n int
	// The column may be absent on a store that predates it and never saw an
	// external credential; that reads as "not in use".
	if err := s.db.QueryRowContext(ctx, s.q(`SELECT COUNT(*) FROM outbound_credentials WHERE source_id = ?`), id).Scan(&n); err == nil && n > 0 {
		return fmt.Errorf("%w (%d)", errCredentialSourceInUse, n)
	}
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM credential_sources WHERE id = ?`), id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return errCredentialSourceNotFound
	}
	return nil
}

// newCredentialSourceStoreFromEnv opens the hub database and ensures the
// table, nil-tolerant like the other stores: a hub without a database has no
// external sources.
func newCredentialSourceStoreFromEnv() CredentialSourceStore {
	state := newDBProviderState[CredentialSourceStore](
		"credential-source",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_TARGETS_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_TARGETS_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_TARGETS_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) CredentialSourceStore { return &dbCredentialSourceStore{db: db} },
		func(db *sql.DB) CredentialSourceStore { return &dbCredentialSourceStore{db: db, postgres: true} },
	)
	if state.openErr != nil || state.store == nil {
		_ = dbProviderUnavailable("credential-source", state.openErr) // logs the outage itself; return value is the same sentinel
		return nil
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		_ = dbProviderUnavailable("credential-source", err) // logs the outage itself; return value is the same sentinel
		return nil
	}
	return state.store
}
