// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"
)

// DefaultTenant is the tenant every resource and principal falls back to —
// existing single-tenant data, and everyone when MULTI_TENANCY is off.
const DefaultTenant = "default"

// multiTenancyEnabled reports whether tenant isolation is enforced. Off by
// default: when off, every principal is super-admin in the "default" tenant, so
// behavior is identical to single-tenant.
func multiTenancyEnabled() bool {
	return tenancyFlagOn(os.Getenv("MULTI_TENANCY"))
}

// Tenant is an isolation boundary (a policy folder).
type Tenant struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}

// TenantStore persists tenants and the CA→tenant mapping.
type TenantStore interface {
	EnsureSchema(ctx context.Context) error
	CreateTenant(ctx context.Context, id, name string) (Tenant, error)
	ListTenants(ctx context.Context) ([]Tenant, error)
	// TenantExists reports whether id names a real tenant. DefaultTenant
	// always exists (it's the implicit fallback every unmapped resource and
	// tenancy-off principal resolves to — never a row in the tenants table).
	TenantExists(ctx context.Context, id string) (bool, error)
	// SetCATenant maps a CA to a tenant.
	SetCATenant(ctx context.Context, caID, tenantID string) error
	// CATenant returns the tenant a CA belongs to (DefaultTenant if unmapped).
	CATenant(ctx context.Context, caID string) (string, error)
	// CAIDsForTenant returns the CA ids mapped to a tenant.
	CAIDsForTenant(ctx context.Context, tenantID string) (map[string]bool, error)
	// SetTemplateTenant maps a template to a tenant.
	SetTemplateTenant(ctx context.Context, templateID, tenantID string) error
	// TemplateTenant returns the tenant a template belongs to (DefaultTenant if unmapped).
	TemplateTenant(ctx context.Context, templateID string) (string, error)
}

// tenantSchema declares FK references from ca_tenants/template_tenants to
// tenants (W3-01 acceptance #3). This only takes effect on a genuinely fresh
// table: SQLite can't ALTER TABLE ADD CONSTRAINT, so a table created before
// W3-01 keeps running FK-free (same limitation as every other inline-healed
// schema in this package — see G-33). Enforced on sqlite via the shared DSN's
// _fk=1 (resolveSQLiteDSNFromEnv); Postgres enforces FKs unconditionally.
const tenantSchema = `
CREATE TABLE IF NOT EXISTS tenants (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ca_tenants (ca_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id));
CREATE INDEX IF NOT EXISTS idx_ca_tenants_tenant ON ca_tenants(tenant_id);
CREATE TABLE IF NOT EXISTS template_tenants (template_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id));
CREATE INDEX IF NOT EXISTS idx_template_tenants_tenant ON template_tenants(tenant_id);`

type dbTenantStore struct {
	db *sql.DB
	ph func(n int) string
}

func (s *dbTenantStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, tenantSchema)
	return err
}

func (s *dbTenantStore) CreateTenant(ctx context.Context, id, name string) (Tenant, error) {
	t := Tenant{ID: id, Name: name, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	q := fmt.Sprintf("INSERT INTO tenants (id, name, created_at) VALUES (%s, %s, %s)", s.ph(1), s.ph(2), s.ph(3))
	if _, err := s.db.ExecContext(ctx, q, t.ID, t.Name, t.CreatedAt); err != nil {
		return Tenant{}, err
	}
	return t, nil
}

func (s *dbTenantStore) ListTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, name, created_at FROM tenants ORDER BY created_at ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Tenant{}
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *dbTenantStore) TenantExists(ctx context.Context, id string) (bool, error) {
	if id == DefaultTenant {
		return true, nil
	}
	var found string
	err := s.db.QueryRowContext(ctx, fmt.Sprintf("SELECT id FROM tenants WHERE id = %s", s.ph(1)), id).Scan(&found)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *dbTenantStore) SetCATenant(ctx context.Context, caID, tenantID string) error {
	if _, err := s.db.ExecContext(ctx, fmt.Sprintf("DELETE FROM ca_tenants WHERE ca_id = %s", s.ph(1)), caID); err != nil {
		return err
	}
	q := fmt.Sprintf("INSERT INTO ca_tenants (ca_id, tenant_id) VALUES (%s, %s)", s.ph(1), s.ph(2))
	_, err := s.db.ExecContext(ctx, q, caID, tenantID)
	return err
}

func (s *dbTenantStore) CATenant(ctx context.Context, caID string) (string, error) {
	var tid string
	err := s.db.QueryRowContext(ctx, fmt.Sprintf("SELECT tenant_id FROM ca_tenants WHERE ca_id = %s", s.ph(1)), caID).Scan(&tid)
	if err == sql.ErrNoRows {
		return DefaultTenant, nil
	}
	if err != nil {
		return "", err
	}
	return tid, nil
}

func (s *dbTenantStore) CAIDsForTenant(ctx context.Context, tenantID string) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf("SELECT ca_id FROM ca_tenants WHERE tenant_id = %s", s.ph(1)), tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

func (s *dbTenantStore) SetTemplateTenant(ctx context.Context, templateID, tenantID string) error {
	if _, err := s.db.ExecContext(ctx, fmt.Sprintf("DELETE FROM template_tenants WHERE template_id = %s", s.ph(1)), templateID); err != nil {
		return err
	}
	q := fmt.Sprintf("INSERT INTO template_tenants (template_id, tenant_id) VALUES (%s, %s)", s.ph(1), s.ph(2))
	_, err := s.db.ExecContext(ctx, q, templateID, tenantID)
	return err
}

func (s *dbTenantStore) TemplateTenant(ctx context.Context, templateID string) (string, error) {
	var tid string
	err := s.db.QueryRowContext(ctx, fmt.Sprintf("SELECT tenant_id FROM template_tenants WHERE template_id = %s", s.ph(1)), templateID).Scan(&tid)
	if err == sql.ErrNoRows {
		return DefaultTenant, nil
	}
	if err != nil {
		return "", err
	}
	return tid, nil
}

// NewTenantStoreFromEnv opens the shared DB and ensures the schema. Returns nil
// if the DB is unavailable (callers tolerate nil → single-tenant).
func NewTenantStoreFromEnv() TenantStore {
	state := newDBProviderState[*dbTenantStore](
		"tenant",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_AUDIT_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_AUDIT_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_AUDIT_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) *dbTenantStore { return &dbTenantStore{db: db, ph: sqlitePlaceholder} },
		func(db *sql.DB) *dbTenantStore { return &dbTenantStore{db: db, ph: postgresPlaceholder} },
	)
	if state.openErr != nil || state.store == nil {
		_ = dbProviderUnavailable("tenant", state.openErr) // logs the outage itself; return value is the same sentinel
		return nil
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		_ = dbProviderUnavailable("tenant", err) // logs the outage itself; return value is the same sentinel
		return nil
	}
	return state.store
}
