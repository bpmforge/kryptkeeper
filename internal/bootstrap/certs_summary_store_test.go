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

type stubCertSummaryProvider struct {
	snapshot CertSummarySnapshot
}

func (s stubCertSummaryProvider) LoadSummary(context.Context) (CertSummarySnapshot, error) {
	return s.snapshot, nil
}

type failingCertSummaryStore struct{}

func (failingCertSummaryStore) LoadSummary(context.Context) (CertSummarySnapshot, error) {
	return CertSummarySnapshot{}, errDBCertSummaryStoreUnimplemented
}

type stubAuditProvider struct{}

func (stubAuditProvider) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{Entries: []AuditEntry{}, Total: 0, Limit: 25}, nil
}

func (stubAuditProvider) AppendEntry(context.Context, AuditEntry) error {
	return nil
}

type stubCAProvider struct{}

func (stubCAProvider) ListCAs(context.Context, CAListQuery) (CAListResult, error) {
	return CAListResult{Items: []CAListItem{}, Total: 0, Limit: 25}, nil
}

func (stubCAProvider) GetCA(context.Context, string) (CAListItem, bool, error) {
	return CAListItem{}, false, nil
}

func (stubCAProvider) GetCAChain(context.Context, string) ([]CAListItem, bool, error) {
	return nil, false, nil
}

func (stubCAProvider) UpdateCA(context.Context, string, CAUpdateRequest) (CAListItem, error) {
	return CAListItem{}, errCANotFound
}

func (stubCAProvider) DeleteCA(context.Context, string) error {
	return errCANotFound
}

func (stubCAProvider) SuspendCA(context.Context, string) (CAStatusChange, error) {
	return CAStatusChange{}, errCANotFound
}

func (stubCAProvider) ActivateCA(context.Context, string) (CAStatusChange, error) {
	return CAStatusChange{}, errCANotFound
}

func (stubCAProvider) CreateCA(context.Context, CACreateRequest) (CAListItem, error) {
	return CAListItem{}, errCACreateUnsupported
}

type stubTemplateProvider struct{}

func (stubTemplateProvider) ListTemplates(context.Context, TemplateListQuery) (TemplateListResult, error) {
	return TemplateListResult{Items: []TemplateItem{}, Total: 0, Limit: 25}, nil
}

func (stubTemplateProvider) GetTemplate(context.Context, string) (TemplateItem, bool, error) {
	return TemplateItem{}, false, nil
}

func (stubTemplateProvider) CreateTemplate(context.Context, TemplateUpsertRequest) (TemplateItem, error) {
	return TemplateItem{}, errTemplateInvalidCreate
}

func (stubTemplateProvider) ReplaceTemplate(context.Context, string, TemplateUpsertRequest, int) (TemplateItem, error) {
	return TemplateItem{}, errTemplateNotFound
}

func (stubTemplateProvider) CloneTemplate(context.Context, string, TemplateCloneRequest) (TemplateItem, error) {
	return TemplateItem{}, errTemplateNotFound
}

func (stubTemplateProvider) PatchTemplate(context.Context, string, TemplatePatchRequest) (TemplateItem, error) {
	return TemplateItem{}, errTemplateNotFound
}

func (stubTemplateProvider) DeleteTemplate(context.Context, string) error {
	return errTemplateNotFound
}

func TestDBCertSummaryStoreLoadsSummaryFromSQLite(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "summary.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open temp db: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE certificates (valid_until TEXT NOT NULL, management_state TEXT, revoked_at TEXT, renewal_status TEXT, owner_team TEXT, is_ca INTEGER NOT NULL DEFAULT 0)`); err != nil {
		t.Fatalf("failed to create certificates table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO certificates(valid_until) VALUES
		(datetime('now', '-1 day')),
		(datetime('now', '+5 day')),
		(datetime('now', '+20 day')),
		(datetime('now', '+45 day'))`); err != nil {
		t.Fatalf("failed to seed certificates: %v", err)
	}

	store := &sqliteCertSummaryStore{db: db}
	summary, err := store.LoadSummary(context.Background())
	if err != nil {
		t.Fatalf("expected summary query to succeed: %v", err)
	}

	if summary.Total != 4 || summary.Expiring30Days != 2 || summary.Expired != 1 {
		t.Fatalf("unexpected db summary: %+v", summary)
	}
	if summary.Source != dbCertSummarySQLiteSource {
		t.Fatalf("expected source %q, got %q", dbCertSummarySQLiteSource, summary.Source)
	}
}

func TestFileCertSummaryProviderFromEnvUsesDefaultPathFallback(t *testing.T) {
	t.Setenv("APP_CERTS_SUMMARY_FILE", "")
	t.Setenv(certSummaryProviderEnv, "")

	provider := NewFileCertSummaryProviderFromEnv()
	summary, err := provider.LoadSummary(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary.Total != 0 || summary.Expiring30Days != 0 || summary.Expired != 0 {
		t.Fatalf("expected zeroed fallback summary, got %+v", summary)
	}
	if summary.Source != "file-store-default" {
		t.Fatalf("expected fallback source file-store-default, got %q", summary.Source)
	}
}

func TestFileCertSummaryProviderFromEnvLoadsValidSummary(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "summary.json")
	body := []byte(`{"total":5,"expiring_30_days":2,"expired":1}`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write temp summary file: %v", err)
	}
	t.Setenv("APP_CERTS_SUMMARY_FILE", filePath)
	t.Setenv(certSummaryProviderEnv, "file")

	provider := NewFileCertSummaryProviderFromEnv()
	summary, err := provider.LoadSummary(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary.Total != 5 || summary.Expiring30Days != 2 || summary.Expired != 1 {
		t.Fatalf("expected parsed summary values, got %+v", summary)
	}
	if summary.Source != "file-store" {
		t.Fatalf("expected source file-store, got %q", summary.Source)
	}
}

func TestFileCertSummaryProviderFromEnvTrimsWhitespaceAroundPath(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "summary.json")
	body := []byte(`{"total":7,"expiring_30_days":1,"expired":0}`)
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("failed to write temp summary file: %v", err)
	}
	t.Setenv("APP_CERTS_SUMMARY_FILE", "  "+filePath+"  ")

	provider := NewFileCertSummaryProviderFromEnv()
	summary, err := provider.LoadSummary(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary.Total != 7 || summary.Expiring30Days != 1 || summary.Expired != 0 {
		t.Fatalf("expected trimmed-path summary values, got %+v", summary)
	}
	if summary.Source != "file-store" {
		t.Fatalf("expected source file-store, got %q", summary.Source)
	}
}

func TestCertSummaryProviderFromEnvDefaultsToFileProvider(t *testing.T) {
	t.Setenv(certSummaryProviderEnv, "")
	t.Setenv(certificateProviderEnv, "")

	provider := NewCertSummaryProviderFromEnv()
	summary, err := provider.LoadSummary(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary.Source != "file-store-default" {
		t.Fatalf("expected default file-backed source, got %q", summary.Source)
	}
}

// S-68: with APP_CERTIFICATE_PROVIDER=ca certificates persist to the core DB,
// so an unset summary provider must count that DB, not the file store the
// dashboard was born reading — every deploy surface sets the former and none
// set APP_CERTS_SUMMARY_PROVIDER, which made the dashboard report 0 forever.
func TestCertSummaryProviderFromEnvFollowsCACertificateProvider(t *testing.T) {
	t.Setenv(certSummaryProviderEnv, "")
	t.Setenv(certificateProviderEnv, "ca")
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "summary.db")
	t.Setenv("APP_CERTS_SUMMARY_DB_DSN", "file:"+dbPath+"?cache=shared&_fk=1&_journal_mode=WAL")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open temp db: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE certificates (valid_until TEXT NOT NULL, management_state TEXT, revoked_at TEXT, renewal_status TEXT, owner_team TEXT, is_ca INTEGER NOT NULL DEFAULT 0)`); err != nil {
		t.Fatalf("failed to create certificates table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO certificates(valid_until) VALUES (datetime('now', '+45 day'))`); err != nil {
		t.Fatalf("failed to seed certificate: %v", err)
	}
	_ = db.Close()

	provider := NewCertSummaryProviderFromEnv()
	summary, err := provider.LoadSummary(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary.Total != 1 {
		t.Fatalf("expected the issued certificate to be counted, got %+v", summary)
	}
	if summary.Source != dbCertSummarySQLiteSource {
		t.Fatalf("expected db source %q, got %q", dbCertSummarySQLiteSource, summary.Source)
	}
}

// An explicit file selection wins even in ca mode: the operator said file.
func TestCertSummaryProviderFromEnvExplicitFileWinsOverCAMode(t *testing.T) {
	t.Setenv(certSummaryProviderEnv, "file")
	t.Setenv(certificateProviderEnv, "ca")
	t.Setenv("APP_CERTS_SUMMARY_FILE", "")

	provider := NewCertSummaryProviderFromEnv()
	summary, err := provider.LoadSummary(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summary.Source != "file-store-default" {
		t.Fatalf("expected explicit file source, got %q", summary.Source)
	}
}

func TestCertSummaryProviderFromEnvSelectsSQLiteDBStore(t *testing.T) {
	t.Setenv(certSummaryProviderEnv, "db")
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "summary.db")
	t.Setenv("APP_CERTS_SUMMARY_DB_DSN", "file:"+dbPath+"?cache=shared&_fk=1&_journal_mode=WAL")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open temp db: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE certificates (valid_until TEXT NOT NULL, management_state TEXT, revoked_at TEXT, renewal_status TEXT, owner_team TEXT, is_ca INTEGER NOT NULL DEFAULT 0)`); err != nil {
		t.Fatalf("failed to create certificates table: %v", err)
	}
	_ = db.Close()

	provider := NewCertSummaryProviderFromEnv()
	summary, err := provider.LoadSummary(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary.Total != 0 || summary.Expiring30Days != 0 || summary.Expired != 0 {
		t.Fatalf("expected zeroed db summary, got %+v", summary)
	}
	if summary.Source != dbCertSummarySQLiteSource {
		t.Fatalf("expected db source %q, got %q", dbCertSummarySQLiteSource, summary.Source)
	}
}

func TestDBCertSummaryProviderReadsFromConfiguredSQLiteDSN(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "summary.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open temp db: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE certificates (valid_until TEXT NOT NULL, management_state TEXT, revoked_at TEXT, renewal_status TEXT, owner_team TEXT, is_ca INTEGER NOT NULL DEFAULT 0)`); err != nil {
		t.Fatalf("failed to create certificates table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO certificates(valid_until) VALUES
		(datetime('now', '-2 day')),
		(datetime('now', '+2 day')),
		(datetime('now', '+12 day'))`); err != nil {
		t.Fatalf("failed to seed certs: %v", err)
	}

	provider := newDBCertSummaryProvider(&sqliteCertSummaryStore{db: db})
	summary, err := provider.LoadSummary(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary.Total != 3 || summary.Expiring30Days != 2 || summary.Expired != 1 {
		t.Fatalf("unexpected db provider summary: %+v", summary)
	}
	if summary.Source != dbCertSummarySQLiteSource {
		t.Fatalf("expected db source %q, got %q", dbCertSummarySQLiteSource, summary.Source)
	}
}

func TestCertSummaryProviderFromEnvPostgresModeWithoutDSNFailsClosed(t *testing.T) {
	t.Setenv(certSummaryProviderEnv, "db")
	t.Setenv(dbModeEnv, dbModePostgres)
	t.Setenv("APP_CERTS_SUMMARY_DB_DSN", "")
	t.Setenv("KRYPTKEEPER_DB_DSN", "")
	t.Setenv("DATABASE_URL", "")

	provider := NewCertSummaryProviderFromEnv()
	if _, err := provider.LoadSummary(context.Background()); err == nil {
		t.Fatalf("expected postgres mode without dsn to fail closed")
	}
}

func TestCertSummaryProviderFromEnvUnsupportedDBModeFailsClosed(t *testing.T) {
	t.Setenv(certSummaryProviderEnv, "db")
	t.Setenv(dbModeEnv, "oracle")

	provider := NewCertSummaryProviderFromEnv()
	if _, err := provider.LoadSummary(context.Background()); err == nil {
		t.Fatalf("expected unsupported db mode to fail closed")
	}
}

func TestDBCertSummaryProviderFailsClosedWhenStoreUnimplemented(t *testing.T) {
	provider := newDBCertSummaryProvider(failingCertSummaryStore{})

	if _, err := provider.LoadSummary(context.Background()); err == nil {
		t.Fatalf("expected db provider to fail closed")
	}
}

func TestCertSummaryProviderFromEnvFallsBackToFileForUnknownMode(t *testing.T) {
	t.Setenv(certSummaryProviderEnv, "unknown")
	var warnings []string
	prevWarnf := certSummaryProviderWarnf
	certSummaryProviderWarnf = func(format string, args ...any) {
		warnings = append(warnings, format)
	}
	defer func() { certSummaryProviderWarnf = prevWarnf }()

	provider := NewCertSummaryProviderFromEnv()
	summary, err := provider.LoadSummary(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary.Source != "file-store-default" {
		t.Fatalf("expected unknown mode to fall back to file provider, got %q", summary.Source)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected one unknown-mode warning, got %d", len(warnings))
	}
}

func TestProtectedCertSummaryHandlerUsesInjectedProvider(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")

	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, stubCertSummaryProvider{snapshot: CertSummarySnapshot{
		Total:          11,
		Expiring30Days: 3,
		Expired:        4,
		Source:         "file-store",
	}}, stubAuditProvider{}, stubCAProvider{}, stubTemplateProvider{}, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/protected/certs/summary", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 status, got %d", rec.Code)
	}

	var payload struct {
		Source  string `json:"source"`
		Summary struct {
			Total          int `json:"total"`
			Expiring30Days int `json:"expiring_30_days"`
			Expired        int `json:"expired"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response payload: %v", err)
	}

	if payload.Source != "file-store" {
		t.Fatalf("expected source file-store, got %q", payload.Source)
	}
	if payload.Summary.Total != 11 || payload.Summary.Expiring30Days != 3 || payload.Summary.Expired != 4 {
		t.Fatalf("unexpected summary payload: %+v", payload.Summary)
	}
}

func TestProtectedCertSummaryHandlerReturns503WhenDBUnavailable(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")

	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	RegisterHandlers(mux, auth, failingCertSummaryStore{}, stubAuditProvider{}, stubCAProvider{}, stubTemplateProvider{}, NewFileCertificateProviderFromEnv(), NewProtocolProviderFromEnv(), NewDiscoveryProviderFromEnv(), NewNotificationProviderFromEnv(), NewDashboardActionProviderFromEnv(), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/protected/certs/summary", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 status, got %d", rec.Code)
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response payload: %v", err)
	}
	if payload["error"] != "service_unavailable" {
		t.Fatalf("expected service_unavailable payload, got %+v", payload)
	}
}
