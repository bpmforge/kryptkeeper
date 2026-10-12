// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

type stubCertSummaryForAudit struct{}

func (stubCertSummaryForAudit) LoadSummary(context.Context) (CertSummarySnapshot, error) {
	return CertSummarySnapshot{Total: 0, Expiring30Days: 0, Expired: 0, Source: "file-store-default"}, nil
}

type stubCAProviderForAudit struct{}

func (stubCAProviderForAudit) ListCAs(context.Context, CAListQuery) (CAListResult, error) {
	return CAListResult{Items: []CAListItem{}, Total: 0, Limit: 25}, nil
}

func (stubCAProviderForAudit) GetCA(context.Context, string) (CAListItem, bool, error) {
	return CAListItem{}, false, nil
}

func (stubCAProviderForAudit) GetCAChain(context.Context, string) ([]CAListItem, bool, error) {
	return nil, false, nil
}

func (stubCAProviderForAudit) UpdateCA(context.Context, string, CAUpdateRequest) (CAListItem, error) {
	return CAListItem{}, errCANotFound
}

func (stubCAProviderForAudit) DeleteCA(context.Context, string) error {
	return errCANotFound
}

type stubTemplateProviderForAudit struct{}

func (stubTemplateProviderForAudit) ListTemplates(context.Context, TemplateListQuery) (TemplateListResult, error) {
	return TemplateListResult{Items: []TemplateItem{}, Total: 0, Limit: 25}, nil
}

func (stubTemplateProviderForAudit) GetTemplate(context.Context, string) (TemplateItem, bool, error) {
	return TemplateItem{}, false, nil
}

func (stubTemplateProviderForAudit) CreateTemplate(context.Context, TemplateUpsertRequest) (TemplateItem, error) {
	return TemplateItem{}, errTemplateInvalidCreate
}

func (stubTemplateProviderForAudit) ReplaceTemplate(context.Context, string, TemplateUpsertRequest, int) (TemplateItem, error) {
	return TemplateItem{}, errTemplateNotFound
}

func (stubTemplateProviderForAudit) CloneTemplate(context.Context, string, TemplateCloneRequest) (TemplateItem, error) {
	return TemplateItem{}, errTemplateNotFound
}

func (stubTemplateProviderForAudit) PatchTemplate(context.Context, string, TemplatePatchRequest) (TemplateItem, error) {
	return TemplateItem{}, errTemplateNotFound
}

func (stubTemplateProviderForAudit) DeleteTemplate(context.Context, string) error {
	return errTemplateNotFound
}

func (stubCAProviderForAudit) SuspendCA(context.Context, string) (CAStatusChange, error) {
	return CAStatusChange{}, errCANotFound
}

func (stubCAProviderForAudit) ActivateCA(context.Context, string) (CAStatusChange, error) {
	return CAStatusChange{}, errCANotFound
}

func (stubCAProviderForAudit) CreateCA(context.Context, CACreateRequest) (CAListItem, error) {
	return CAListItem{}, errCACreateUnsupported
}

type failingAuditProvider struct{}

func (failingAuditProvider) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{}, os.ErrNotExist
}

func (failingAuditProvider) AppendEntry(context.Context, AuditEntry) error {
	return os.ErrNotExist
}

func TestFileAuditProviderLoadsEntries(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "audit.json")
	body := []byte(`[{"id":1,"timestamp":"2026-04-07T00:00:00Z","action":"certificate.issue","actor_type":"system","actor_id":"system","resource_type":"certificate","resource_id":"abc","outcome":"success"}]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write audit fixture: %v", err)
	}
	t.Setenv("APP_AUDIT_FILE", filePath)

	provider := mustFileAudit(t)
	result, err := provider.ListEntries(context.Background(), AuditListQuery{Limit: 25})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 1 || len(result.Entries) != 1 {
		t.Fatalf("unexpected audit result: %+v", result)
	}
	if result.Entries[0].Action != "certificate.issue" {
		t.Fatalf("expected action certificate.issue, got %q", result.Entries[0].Action)
	}
}

func TestFileAuditProviderFiltersAndPagination(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "audit-filter.json")
	body := []byte(`[
{"id":3,"timestamp":"2026-04-07T00:00:03Z","action":"protected.ping.read","actor_type":"system","actor_id":"bootstrap","resource_type":"protected_resource","resource_id":"ping","trace_id":"trace-3","outcome":"success"},
{"id":2,"timestamp":"2026-04-07T00:00:02Z","action":"authz.check","actor_type":"system","actor_id":"bootstrap","resource_type":"auth","resource_id":"authz-check","trace_id":"trace-2","outcome":"success"},
{"id":1,"timestamp":"2026-04-07T00:00:01Z","action":"protected.ping.read","actor_type":"user","actor_id":"u-1","resource_type":"protected_resource","resource_id":"ping","trace_id":"trace-1","outcome":"denied"}
]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write audit fixture: %v", err)
	}
	t.Setenv("APP_AUDIT_FILE", filePath)

	provider := mustFileAudit(t)
	result, err := provider.ListEntries(context.Background(), AuditListQuery{Limit: 1, Offset: 1, Order: "desc", Action: "protected.ping.read"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 2 || len(result.Entries) != 1 {
		t.Fatalf("unexpected filtered/paged result: %+v", result)
	}
	if result.Entries[0].ID != 1 {
		t.Fatalf("expected second filtered row id=1, got %d", result.Entries[0].ID)
	}

	strictResult, err := provider.ListEntries(context.Background(), AuditListQuery{
		Limit:        10,
		Order:        "desc",
		Action:       "protected.ping.read",
		ActorType:    "system",
		ActorID:      "bootstrap",
		ResourceType: "protected_resource",
		ResourceID:   "ping",
		TraceID:      "trace-3",
		After:        "2026-04-07T00:00:02Z",
		Before:       "2026-04-07T00:00:04Z",
	})
	if err != nil {
		t.Fatalf("unexpected strict filter error: %v", err)
	}
	if strictResult.Total != 1 || len(strictResult.Entries) != 1 || strictResult.Entries[0].ID != 3 {
		t.Fatalf("unexpected strict filter result: %+v", strictResult)
	}
}

func TestDBAuditStoreLoadsEntriesFromSQLite(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "audit.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open temp db: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE audit_log (
id INTEGER PRIMARY KEY AUTOINCREMENT,
timestamp TEXT NOT NULL,
action TEXT NOT NULL,
actor_type TEXT NOT NULL,
actor_id TEXT NOT NULL,
resource_type TEXT NOT NULL,
resource_id TEXT NOT NULL,
trace_id TEXT,
outcome TEXT NOT NULL,
source_ip TEXT,
user_agent TEXT,
session_id TEXT,
change_summary TEXT,
tenant TEXT NOT NULL DEFAULT 'default'
)`); err != nil {
		t.Fatalf("failed to create audit_log table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO audit_log(timestamp,action,actor_type,actor_id,resource_type,resource_id,trace_id,outcome) VALUES
		(datetime('now'), 'certificate.issue', 'system', 'system', 'certificate', 'fp-1', 'trace-1', 'success'),
		(datetime('now', '-1 minute'), 'certificate.revoke', 'user', 'u-1', 'certificate', 'fp-2', 'trace-2', 'denied')`); err != nil {
		t.Fatalf("failed to seed audit_log table: %v", err)
	}

	store := &sqliteAuditStore{db: db}
	result, err := store.ListEntries(context.Background(), AuditListQuery{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 2 || len(result.Entries) != 2 {
		t.Fatalf("unexpected audit result: %+v", result)
	}
}

func TestDBAuditStoreAppendsEntryToSQLite(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "audit-append.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open temp db: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE audit_log (
id INTEGER PRIMARY KEY AUTOINCREMENT,
timestamp TEXT NOT NULL,
action TEXT NOT NULL,
actor_type TEXT NOT NULL,
actor_id TEXT NOT NULL,
resource_type TEXT NOT NULL,
resource_id TEXT NOT NULL,
trace_id TEXT,
outcome TEXT NOT NULL,
source_ip TEXT,
user_agent TEXT,
session_id TEXT,
change_summary TEXT,
tenant TEXT NOT NULL DEFAULT 'default'
)`); err != nil {
		t.Fatalf("failed to create audit_log table: %v", err)
	}

	store := &sqliteAuditStore{db: db}
	if err := store.AppendEntry(context.Background(), AuditEntry{
		Action:       "protected.ping.read",
		ActorType:    "system",
		ActorID:      "bootstrap",
		ResourceType: "protected_resource",
		ResourceID:   "ping",
		Outcome:      "success",
	}); err != nil {
		t.Fatalf("unexpected append error: %v", err)
	}

	result, err := store.ListEntries(context.Background(), AuditListQuery{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected list error: %v", err)
	}
	if result.Total != 1 || len(result.Entries) != 1 {
		t.Fatalf("unexpected result after append: %+v", result)
	}
	if result.Entries[0].Tenant != DefaultTenant {
		t.Fatalf("expected an entry with no Tenant set to default to %q, got %q", DefaultTenant, result.Entries[0].Tenant)
	}
}

// TestDBAuditStoreRoundTripsTenant is the W2-04 regression: AppendEntry
// stores a non-default Tenant faithfully, and ListEntries reads it back.
func TestDBAuditStoreRoundTripsTenant(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "audit-tenant.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open temp db: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE audit_log (
id INTEGER PRIMARY KEY AUTOINCREMENT,
timestamp TEXT NOT NULL,
action TEXT NOT NULL,
actor_type TEXT NOT NULL,
actor_id TEXT NOT NULL,
resource_type TEXT NOT NULL,
resource_id TEXT NOT NULL,
trace_id TEXT,
outcome TEXT NOT NULL,
source_ip TEXT,
user_agent TEXT,
session_id TEXT,
change_summary TEXT,
tenant TEXT NOT NULL DEFAULT 'default'
)`); err != nil {
		t.Fatalf("failed to create audit_log table: %v", err)
	}

	store := &sqliteAuditStore{db: db}
	if err := store.AppendEntry(context.Background(), AuditEntry{
		Action: "ca.suspend", ActorType: "user", ActorID: "svc-principal",
		ResourceType: "ca", ResourceID: "ca-acme", Outcome: "success", Tenant: "acme",
	}); err != nil {
		t.Fatalf("unexpected append error: %v", err)
	}

	result, err := store.ListEntries(context.Background(), AuditListQuery{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected list error: %v", err)
	}
	if len(result.Entries) != 1 || result.Entries[0].Tenant != "acme" {
		t.Fatalf("expected tenant %q to round-trip, got %+v", "acme", result.Entries)
	}
}

// TestEnsureAuditTenantColumnUpgradesExistingTable is the W2-04 upgrade
// regression: an audit_log table created before this ticket (no tenant
// column, matching migration 000004/000011's original shape) still works
// once ensureAuditTenantColumn runs, without a manual migration step.
func TestEnsureAuditTenantColumnUpgradesExistingTable(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "audit-upgrade.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open temp db: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE audit_log (
id INTEGER PRIMARY KEY AUTOINCREMENT,
timestamp TEXT NOT NULL,
action TEXT NOT NULL,
actor_type TEXT NOT NULL,
actor_id TEXT NOT NULL,
resource_type TEXT NOT NULL,
resource_id TEXT NOT NULL,
trace_id TEXT,
outcome TEXT NOT NULL,
source_ip TEXT,
user_agent TEXT,
session_id TEXT,
change_summary TEXT
)`); err != nil {
		t.Fatalf("failed to create pre-W2-04 audit_log table: %v", err)
	}

	ensureAuditTenantColumn(db)

	store := &sqliteAuditStore{db: db}
	if err := store.AppendEntry(context.Background(), AuditEntry{
		Action: "ca.suspend", ActorType: "user", ActorID: "svc-principal",
		ResourceType: "ca", ResourceID: "ca-acme", Outcome: "success", Tenant: "acme",
	}); err != nil {
		t.Fatalf("append after upgrade: %v", err)
	}
	result, err := store.ListEntries(context.Background(), AuditListQuery{Limit: 10})
	if err != nil {
		t.Fatalf("list after upgrade: %v", err)
	}
	if len(result.Entries) != 1 || result.Entries[0].Tenant != "acme" {
		t.Fatalf("expected tenant to round-trip after upgrade, got %+v", result.Entries)
	}

	// Calling it again (the normal case on every process restart) must not error.
	ensureAuditTenantColumn(db)
}

// TestSQLiteAuditStoreEnsureSchemaOnFreshDB is the S-07/G-48 regression: a
// brand-new sqlite DB with no pre-existing audit_log table (unlike every
// other test in this file, which manually CREATE TABLEs before use) must
// self-heal via EnsureSchema alone, with no manual migration step, and the
// append-only trigger must actually be in effect afterward.
func TestSQLiteAuditStoreEnsureSchemaOnFreshDB(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "audit-fresh.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open temp db: %v", err)
	}
	defer db.Close()

	store := &sqliteAuditStore{db: db}
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("EnsureSchema on fresh db: %v", err)
	}

	if err := store.AppendEntry(context.Background(), AuditEntry{
		Action: "ca.create", ActorType: "user", ActorID: "svc-principal",
		ResourceType: "ca", ResourceID: "ca-acme", Outcome: "success", Tenant: "acme",
	}); err != nil {
		t.Fatalf("append on fresh db: %v", err)
	}
	result, err := store.ListEntries(context.Background(), AuditListQuery{Limit: 10})
	if err != nil {
		t.Fatalf("list on fresh db: %v", err)
	}
	if len(result.Entries) != 1 || result.Entries[0].Tenant != "acme" {
		t.Fatalf("expected the freshly-created row to round-trip, got %+v", result.Entries)
	}

	// EnsureSchema must be safe to run again (the normal case on every
	// process restart) — every statement is IF NOT EXISTS.
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("EnsureSchema re-run on already-initialized db: %v", err)
	}

	// The append-only trigger (created by EnsureSchema, not a manual test
	// fixture) must actually reject mutation.
	if _, err := db.Exec("UPDATE audit_log SET outcome = 'failure' WHERE id = 1"); err == nil {
		t.Fatal("expected UPDATE to be rejected by the append-only trigger")
	}
	if _, err := db.Exec("DELETE FROM audit_log WHERE id = 1"); err == nil {
		t.Fatal("expected DELETE to be rejected by the append-only trigger")
	}
}

// TestNewDBAuditStoreFromEnvSelfHealsFreshSQLiteDB proves the actual
// production entrypoint (not just the raw store struct) self-heals: a fresh
// KRYPTKEEPER_DATA_DIR with no audit_log table at all still works end to end.
func TestNewDBAuditStoreFromEnvSelfHealsFreshSQLiteDB(t *testing.T) {
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())

	store, err := newDBAuditStoreFromEnv()
	if err != nil {
		t.Fatalf("newDBAuditStoreFromEnv: %v", err)
	}
	if store == nil {
		t.Fatal("expected a non-nil store")
	}

	if err := store.AppendEntry(context.Background(), AuditEntry{
		Action: "ca.create", ActorType: "user", ActorID: "svc-principal",
		ResourceType: "ca", ResourceID: "ca-acme", Outcome: "success",
	}); err != nil {
		t.Fatalf("append via fresh env-constructed store: %v", err)
	}
	result, err := store.ListEntries(context.Background(), AuditListQuery{Limit: 10})
	if err != nil {
		t.Fatalf("list via fresh env-constructed store: %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %+v", result.Entries)
	}
}

// TestPostgresAuditStoreEnsureSchemaOnFreshDB is the Postgres half of the
// S-07/G-48 regression. No local Postgres is reachable in this dev
// environment (and CI has never run against one — see HANDOFF.md), so this
// skips rather than claiming coverage it can't exercise; it runs for real the
// moment APP_AUDIT_DB_DSN/KRYPTKEEPER_DB_DSN/DATABASE_URL points at one.
func TestPostgresAuditStoreEnsureSchemaOnFreshDB(t *testing.T) {
	dsn := auditPostgresDSNFromEnv()
	if dsn == "" {
		t.Skip("no Postgres DSN configured (APP_AUDIT_DB_DSN/KRYPTKEEPER_DB_DSN/DATABASE_URL) — skipping")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("failed to open postgres db: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec("DROP TABLE IF EXISTS audit_log CASCADE"); err != nil {
		t.Fatalf("failed to reset audit_log for test: %v", err)
	}

	store := &postgresAuditStore{db: db}
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("EnsureSchema on fresh postgres db: %v", err)
	}
	// Must be safe to run again (the normal case on every process restart).
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("EnsureSchema re-run on already-initialized postgres db: %v", err)
	}

	if err := store.AppendEntry(context.Background(), AuditEntry{
		Action: "ca.create", ActorType: "user", ActorID: "svc-principal",
		ResourceType: "ca", ResourceID: "ca-acme", Outcome: "success", Tenant: "acme",
	}); err != nil {
		t.Fatalf("append on fresh postgres db: %v", err)
	}
	result, err := store.ListEntries(context.Background(), AuditListQuery{Limit: 10})
	if err != nil {
		t.Fatalf("list on fresh postgres db: %v", err)
	}
	if len(result.Entries) != 1 || result.Entries[0].Tenant != "acme" {
		t.Fatalf("expected the freshly-created row to round-trip, got %+v", result.Entries)
	}

	if _, err := db.Exec("UPDATE audit_log SET outcome = 'failure'"); err == nil {
		t.Fatal("expected UPDATE to be rejected by the append-only trigger")
	}
	if _, err := db.Exec("DELETE FROM audit_log"); err == nil {
		t.Fatal("expected DELETE to be rejected by the append-only trigger")
	}
}

func TestFileAuditProviderAppendEntry(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "audit.json")
	t.Setenv("APP_AUDIT_FILE", filePath)

	provider := mustFileAudit(t)
	if err := provider.AppendEntry(context.Background(), AuditEntry{
		Action:       "audit.list",
		ActorType:    "system",
		ActorID:      "bootstrap",
		ResourceType: "audit_log",
		ResourceID:   "audit",
		Outcome:      "success",
	}); err != nil {
		t.Fatalf("unexpected append error: %v", err)
	}

	result, err := provider.ListEntries(context.Background(), AuditListQuery{Limit: 25})
	if err != nil {
		t.Fatalf("unexpected list error: %v", err)
	}
	if result.Total != 1 || len(result.Entries) != 1 {
		t.Fatalf("unexpected result after append: %+v", result)
	}
}

func TestAuditHandlerReturnsAuditPayload(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_AUDIT_FILE", filepath.Join(t.TempDir(), "audit.json"))

	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	auditProvider := mustFileAudit(t)
	RegisterHandlers(mux, auth, stubCertSummaryForAudit{}, auditProvider, stubCAProviderForAudit{}, stubTemplateProviderForAudit{}, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 status, got %d", rec.Code)
	}

	var payload struct {
		Data      []AuditEntry `json:"data"`
		Principal string       `json:"principal"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response payload: %v", err)
	}
	if payload.Principal != "bootstrap" {
		t.Fatalf("expected bootstrap principal, got %q", payload.Principal)
	}
}

func TestAuditHandlerFailsClosedWhenProviderUnavailable(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")

	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryForAudit{}, failingAuditProvider{}, stubCAProviderForAudit{}, stubTemplateProviderForAudit{}, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 status, got %d", rec.Code)
	}
}

func TestAuditHandlerSupportsFiltersAndCursor(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "audit-handler.json")
	body := []byte(`[
{"id":3,"timestamp":"2026-04-07T00:00:03Z","action":"protected.ping.read","actor_type":"system","actor_id":"bootstrap","resource_type":"protected_resource","resource_id":"ping","outcome":"success"},
{"id":2,"timestamp":"2026-04-07T00:00:02Z","action":"authz.check","actor_type":"system","actor_id":"bootstrap","resource_type":"auth","resource_id":"authz-check","outcome":"success"},
{"id":1,"timestamp":"2026-04-07T00:00:01Z","action":"protected.ping.read","actor_type":"system","actor_id":"bootstrap","resource_type":"protected_resource","resource_id":"ping","outcome":"denied"}
]`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write audit fixture: %v", err)
	}
	t.Setenv("APP_AUDIT_FILE", filePath)

	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	auditProvider := mustFileAudit(t)
	RegisterHandlers(mux, auth, stubCertSummaryForAudit{}, auditProvider, stubCAProviderForAudit{}, stubTemplateProviderForAudit{}, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit?action=protected.ping.read&limit=1&cursor=1&order=desc", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 status, got %d", rec.Code)
	}

	var payload struct {
		Data []AuditEntry `json:"data"`
		Meta struct {
			Total      int     `json:"total"`
			Limit      int     `json:"limit"`
			NextCursor *string `json:"next_cursor"`
			PrevCursor *string `json:"prev_cursor"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response payload: %v", err)
	}
	if payload.Meta.Total < 2 || payload.Meta.Limit != 1 || len(payload.Data) != 1 {
		t.Fatalf("unexpected filtered payload: %+v", payload)
	}
	if payload.Meta.PrevCursor == nil {
		t.Fatalf("expected prev_cursor when cursor > 0")
	}
}

func TestDBAuditStoreFiltersForSQLite(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "audit-filter-sqlite.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open temp db: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE audit_log (
id INTEGER PRIMARY KEY AUTOINCREMENT,
timestamp TEXT NOT NULL,
action TEXT NOT NULL,
actor_type TEXT NOT NULL,
actor_id TEXT NOT NULL,
resource_type TEXT NOT NULL,
resource_id TEXT NOT NULL,
trace_id TEXT,
outcome TEXT NOT NULL,
source_ip TEXT,
user_agent TEXT,
session_id TEXT,
change_summary TEXT,
tenant TEXT NOT NULL DEFAULT 'default'
)`); err != nil {
		t.Fatalf("failed to create audit_log table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO audit_log(timestamp,action,actor_type,actor_id,resource_type,resource_id,trace_id,outcome) VALUES
		('2026-04-07T00:00:03Z','protected.ping.read','system','bootstrap','protected_resource','ping','trace-3','success'),
		('2026-04-07T00:00:02Z','authz.check','system','bootstrap','auth','authz-check','trace-2','success'),
		('2026-04-07T00:00:01Z','protected.ping.read','user','u-1','protected_resource','ping','trace-1','denied')`); err != nil {
		t.Fatalf("failed to seed audit_log table: %v", err)
	}

	store := &sqliteAuditStore{db: db}
	result, err := store.ListEntries(context.Background(), AuditListQuery{
		Limit:        10,
		Order:        "desc",
		Action:       "protected.ping.read",
		ActorType:    "system",
		ActorID:      "bootstrap",
		ResourceType: "protected_resource",
		ResourceID:   "ping",
		TraceID:      "trace-3",
		After:        "2026-04-07T00:00:02Z",
		Before:       "2026-04-07T00:00:04Z",
	})
	if err != nil {
		t.Fatalf("unexpected sqlite filter error: %v", err)
	}
	if result.Total != 1 || len(result.Entries) != 1 || result.Entries[0].TraceID != "trace-3" {
		t.Fatalf("unexpected sqlite filtered result: %+v", result)
	}
}
