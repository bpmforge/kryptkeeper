// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"kryptkeeper/internal/connectors"
)

// W11-03: the internal engine satisfies the issuer interface (a registry-
// routed issue lands in real inventory with origin=internal), connector
// rows round-trip with live health in the listing, and takeover flips an
// imported cert to managed with its renewal path recorded.

func TestInternalConnectorIssuesThroughTheInterface(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()
	caID := getFirstCAID(t, engine)

	registry := connectors.NewRegistry()
	registry.Register(NewInternalIssuerConnector("conn-int-1", provider, caID))

	res, err := registry.Issue(ctx, "conn-int-1", connectors.IssueRequest{
		CSRPEM:     generateTestCSRPEM(t, "conn.example.com", "conn.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-conn",
	})
	if err != nil {
		t.Fatalf("registry issue: %v", err)
	}
	if res.FingerprintSHA256 == "" || !bytes.Contains([]byte(res.CertificatePEM), []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("connector issue result incomplete: %+v", res)
	}

	// The cert is real inventory with the connector's origin.
	item, ok, err := provider.GetCertificate(ctx, res.FingerprintSHA256)
	if err != nil || !ok {
		t.Fatalf("issued cert not in inventory: ok=%v err=%v", ok, err)
	}
	if item.Origin != "internal" || item.ManagementState != "managed" {
		t.Fatalf("connector-issued cert estate wrong: %+v", item.CertificateItem)
	}

	if h := registry.List()[0].Health(ctx); h.Status != "healthy" {
		t.Fatalf("internal connector health = %+v", h)
	}
}

func newConnectorTestStore(t *testing.T) ConnectorStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "connectors.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	store := newConnectorStore(db, false)
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return store
}

func TestConnectorStoreRoundTrip(t *testing.T) {
	store := newConnectorTestStore(t)
	ctx := context.Background()

	created, err := store.Create(ctx, ConnectorRecord{
		ID: "conn-a", Name: "Internal Root", Type: "internal",
		ConfigJSON: `{"ca_id":"ca-1"}`,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := store.Get(ctx, created.ID)
	if err != nil || got.Name != "Internal Root" || got.ConfigJSON != `{"ca_id":"ca-1"}` {
		t.Fatalf("round-trip wrong: %+v %v", got, err)
	}
	if _, err := store.Create(ctx, ConnectorRecord{ID: "conn-b", Name: "x", Type: "not-a-type"}); err == nil {
		t.Fatal("invalid type accepted")
	}
	if err := store.Delete(ctx, "conn-a"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := store.Delete(ctx, "conn-a"); err == nil {
		t.Fatal("double delete should 404")
	}
}

func newEstateTestMux(t *testing.T) (*http.ServeMux, CertificateProvider, ConnectorStore, string) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()

	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	caID := getFirstCAID(t, engine)
	store := newConnectorTestStore(t)

	mux := http.NewServeMux()
	RegisterConnectorHandlers(mux, auth, store, provider, nil, stubAuditProvider{})
	RegisterEstateHandlers(mux, auth, provider, store, stubAuditProvider{})
	return mux, provider, store, caID
}

func doJSON(t *testing.T, mux *http.ServeMux, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestConnectorListingCarriesLiveHealth(t *testing.T) {
	mux, _, store, caID := newEstateTestMux(t)
	ctx := context.Background()

	if _, err := store.Create(ctx, ConnectorRecord{ID: "conn-int", Name: "Internal", Type: "internal", ConfigJSON: `{"ca_id":"` + caID + `"}`}); err != nil {
		t.Fatalf("create internal: %v", err)
	}
	if _, err := store.Create(ctx, ConnectorRecord{ID: "conn-acme", Name: "LE", Type: "acme"}); err != nil {
		t.Fatalf("create acme: %v", err)
	}

	rec := doJSON(t, mux, http.MethodGet, "/api/v1/connectors", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data []connectorListEntry `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	byID := map[string]connectorListEntry{}
	for _, e := range resp.Data {
		byID[e.ID] = e
	}
	if byID["conn-int"].Health.Status != "healthy" {
		t.Fatalf("internal connector should probe healthy: %+v", byID["conn-int"].Health)
	}
	// W11-04: acme now has a runtime implementation; an unconfigured row is
	// a VISIBLE degraded state (missing directory_url), not a dropped row.
	if byID["conn-acme"].Health.Status != "degraded" || byID["conn-acme"].Health.Detail == "" {
		t.Fatalf("unconfigured acme connector should report degraded+reason: %+v", byID["conn-acme"].Health)
	}
}

func TestTakeoverFlipsImportedCertToManaged(t *testing.T) {
	mux, provider, store, _ := newEstateTestMux(t)
	ctx := context.Background()

	imported, err := provider.ImportCertificate(ctx, CertificateImportRequest{
		CertificatePEM: estateTestCertPEM(t),
		TeamID:         "team-takeover",
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	fp := imported.CertificateItem.FingerprintSHA256

	if _, err := store.Create(ctx, ConnectorRecord{ID: "conn-up", Name: "Upstream", Type: "acme"}); err != nil {
		t.Fatalf("create connector: %v", err)
	}

	rec := doJSON(t, mux, http.MethodPost, "/api/v1/estate/takeover", takeoverRequest{
		Fingerprint: fp,
		OwnerEmail:  "owner@example.com",
		OwnerTeam:   "platform",
		RenewalPath: takeoverRenewalPath{Mode: "connector", ConnectorID: "conn-up"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("takeover: %d %s", rec.Code, rec.Body.String())
	}

	after, _, err := provider.GetCertificate(ctx, fp)
	if err != nil {
		t.Fatalf("get after takeover: %v", err)
	}
	if after.ManagementState != "managed" || after.OwnerEmail != "owner@example.com" || after.RenewalMethod != "acme" {
		t.Fatalf("takeover did not stick: state=%q owner=%q method=%q",
			after.ManagementState, after.OwnerEmail, after.RenewalMethod)
	}
	// And it persisted: the DB row carries the connector id.
	var connID string
	dbc := providerDB(t, provider)
	if err := dbc.QueryRow(`SELECT COALESCE(renewal_connector_id,'') FROM certificates WHERE fingerprint_sha256 = ?`, fp).Scan(&connID); err != nil {
		t.Fatalf("select connector id: %v", err)
	}
	if connID != "conn-up" {
		t.Fatalf("renewal_connector_id = %q, want conn-up", connID)
	}
}

func TestTakeoverRejectsUnknownConnectorBeforeMutating(t *testing.T) {
	mux, provider, _, _ := newEstateTestMux(t)
	ctx := context.Background()

	imported, err := provider.ImportCertificate(ctx, CertificateImportRequest{
		CertificatePEM: estateTestCertPEM(t),
		TeamID:         "team-takeover-2",
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	fp := imported.CertificateItem.FingerprintSHA256

	rec := doJSON(t, mux, http.MethodPost, "/api/v1/estate/takeover", takeoverRequest{
		Fingerprint: fp,
		OwnerEmail:  "owner@example.com",
		RenewalPath: takeoverRenewalPath{Mode: "connector", ConnectorID: "conn-missing"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown connector, got %d", rec.Code)
	}
	// Nothing mutated — still unmanaged, ownership untouched.
	after, _, err := provider.GetCertificate(ctx, fp)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if after.ManagementState != "unmanaged" || after.OwnerEmail != "" {
		t.Fatalf("failed takeover mutated state: %+v", after.CertificateItem)
	}
}

// providerDB digs the *sql.DB out of the ca provider for row assertions.
func providerDB(t *testing.T, provider CertificateProvider) *sql.DB {
	t.Helper()
	ca, ok := provider.(*caCertificateProvider)
	if !ok || ca.db == nil {
		t.Fatal("provider has no DB")
	}
	return ca.db
}
