// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	kkdb "kryptkeeper/internal/db"
	"kryptkeeper/internal/keystore"
)

// W11-01 estate model: origin + management_state through the PRODUCTION
// writer/reader (S-66 lesson), surviving a provider restart, with filters
// and the summary split observing the same rows.

// estateTestCertPEM generates a throwaway self-signed cert for import tests.
func estateTestCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "estate-import.example.com"},
		DNSNames:     []string{"estate-import.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestEstateModelPersistsAcrossRestart(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	ctx := context.Background()

	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       getFirstCAID(t, engine),
		CSRPEM:     generateTestCSRPEM(t, "estate.example.com", "estate.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-estate",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if issued.CertificateItem.Origin != "internal" || issued.CertificateItem.ManagementState != "managed" {
		t.Fatalf("issued cert estate fields wrong: %+v", issued.CertificateItem)
	}

	imported, err := provider.ImportCertificate(ctx, CertificateImportRequest{
		CertificatePEM: estateTestCertPEM(t),
		TeamID:         "team-estate",
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if imported.CertificateItem.Origin != "imported" || imported.CertificateItem.ManagementState != "unmanaged" {
		t.Fatalf("imported cert estate fields wrong: origin=%q state=%q",
			imported.CertificateItem.Origin, imported.CertificateItem.ManagementState)
	}

	// Restart: a second provider on the same DB must load the same estate
	// fields — this is what fails if the writer or the loader drops them.
	provider2 := NewCACertificateProvider(engine, ca.NewDBRevocationStore(db, false), db, false)
	after, ok, err := provider2.GetCertificate(ctx, imported.CertificateItem.FingerprintSHA256)
	if err != nil || !ok {
		t.Fatalf("reload imported cert: ok=%v err=%v", ok, err)
	}
	if after.Origin != "imported" || after.ManagementState != "unmanaged" {
		t.Fatalf("estate fields lost across restart: origin=%q state=%q", after.Origin, after.ManagementState)
	}

	// Filters see the split.
	unmanaged, err := provider2.ListCertificates(ctx, CertificateListQuery{ManagementState: "unmanaged", Limit: 50})
	if err != nil {
		t.Fatalf("list unmanaged: %v", err)
	}
	if unmanaged.Total != 1 || unmanaged.Items[0].Origin != "imported" {
		t.Fatalf("management_state filter wrong: %+v", unmanaged)
	}
	internalOnly, err := provider2.ListCertificates(ctx, CertificateListQuery{Origin: "internal", Limit: 50})
	if err != nil {
		t.Fatalf("list internal: %v", err)
	}
	if internalOnly.Total != 1 || internalOnly.Items[0].FingerprintSHA256 != issued.CertificateItem.FingerprintSHA256 {
		t.Fatalf("origin filter wrong: %+v", internalOnly)
	}

	// The DB summary provider splits the same rows.
	store, err := newSQLiteCertSummaryStore("file:" + dbPathOf(t, db) + "?cache=shared&_fk=1")
	if err != nil {
		t.Fatalf("summary store: %v", err)
	}
	summary, err := store.LoadSummary(ctx)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if summary.Total != 2 || summary.Managed != 1 || summary.Unmanaged != 1 || summary.External != 0 {
		t.Fatalf("summary split wrong: %+v", summary)
	}
}

// dbPathOf digs the sqlite file path back out of the test DB (the summary
// store opens its own connection to the same file).
func dbPathOf(t *testing.T, db *sql.DB) string {
	t.Helper()
	var _, file string
	rows, err := db.Query("PRAGMA database_list")
	if err != nil {
		t.Fatalf("pragma: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var seq int
		var name string
		if err := rows.Scan(&seq, &name, &file); err != nil {
			t.Fatalf("scan pragma: %v", err)
		}
		if name == "main" {
			return file
		}
	}
	t.Fatal("main database not found")
	return ""
}

func TestEstateModelPersists_Postgres(t *testing.T) {
	dsn := os.Getenv("KRYPTKEEPER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("KRYPTKEEPER_TEST_POSTGRES_DSN not set — skipping live Postgres estate test")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := kkdb.RunMigrations(db, "postgres"); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("integration-passphrase-32bytes!!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewDBStore(db, true))
	rootCA, err := engine.CreateRootCA("W11-01 Estate Root", pkix.Name{CommonName: "W11-01 Estate Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM certificate_authorities WHERE id = $1`, rootCA.ID) })

	provider := NewCACertificateProvider(engine, ca.NewDBRevocationStore(db, true), db, true)
	ctx := context.Background()

	issued, err := provider.IssueCertificate(ctx, CertificateIssueRequest{
		CAID:       rootCA.ID,
		CSRPEM:     generateTestCSRPEM(t, "estate-pg.example.com", "estate-pg.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-estate-pg",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	fp := issued.CertificateItem.FingerprintSHA256
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM certificates WHERE fingerprint_sha256 = $1`, fp) })

	// The row the production writer persisted carries the estate columns.
	var origin, state string
	if err := db.QueryRow(`SELECT origin, management_state FROM certificates WHERE fingerprint_sha256 = $1`, fp).
		Scan(&origin, &state); err != nil {
		t.Fatalf("select estate columns: %v", err)
	}
	if origin != "internal" || state != "managed" {
		t.Fatalf("postgres estate columns wrong: origin=%q state=%q", origin, state)
	}
}

// W27-12: bulk takeover is all-or-nothing on request validity, skips rows it
// must not touch, and exposes read-only owner suggestions.

func estateNamedCertPEM(t *testing.T, cn string, sans ...string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(func() []byte { b := make([]byte, 12); _, _ = rand.Read(b); return b }()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     sans,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func importNamedEstateCert(t *testing.T, provider CertificateProvider, cn string, sans ...string) string {
	t.Helper()
	imp, err := provider.ImportCertificate(context.Background(), CertificateImportRequest{
		CertificatePEM: estateNamedCertPEM(t, cn, sans...), TeamID: "t-w27",
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	return imp.CertificateItem.FingerprintSHA256
}

func TestBulkTakeoverUnknownConnectorFailsWholeCall(t *testing.T) {
	mux, provider, _, audit := newEstateAuditMux(t)
	a, b, c := importEstateCert(t, provider, "t-uc"), importEstateCert(t, provider, "t-uc"), importEstateCert(t, provider, "t-uc")
	items := []takeoverRequest{
		internalItem(a),
		{Fingerprint: b, OwnerEmail: "must-not-stick@example.com", RenewalPath: takeoverRenewalPath{Mode: "connector", ConnectorID: "conn-missing"}},
		internalItem(c),
	}
	rec := doJSON(t, mux, http.MethodPost, "/api/v1/estate/takeover/bulk", bulkTakeoverRequest{Items: items})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d %s", rec.Code, rec.Body.String())
	}
	for _, fp := range []string{a, b, c} {
		got, _, _ := provider.GetCertificate(context.Background(), fp)
		if got.ManagementState != "unmanaged" || got.OwnerEmail != "" {
			t.Fatalf("%s mutated: %+v", fp, got.CertificateItem)
		}
	}
	if n := audit.count("estate.takeover", AuditOutcomeSuccess); n != 0 {
		t.Fatalf("success audits=%d", n)
	}
	if n := audit.count("estate.takeover.bulk", AuditOutcomeFailure); n != 1 {
		t.Fatalf("bulk failure audits=%d", n)
	}
}

func TestBulkTakeoverCap500(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	mux, provider, _, _ := newEstateAuditMux(t)
	items := make([]takeoverRequest, 0, 500)
	for i := 0; i < 500; i++ {
		items = append(items, internalItem(importEstateCert(t, provider, "t-cap")))
	}
	rec := doJSON(t, mux, http.MethodPost, "/api/v1/estate/takeover/bulk", bulkTakeoverRequest{Items: items})
	if rec.Code != http.StatusOK {
		t.Fatalf("500 items: %d %s", rec.Code, rec.Body.String())
	}
	if r := decodeBulk(t, rec.Body.Bytes()); r.Data.Succeeded != 500 {
		t.Fatalf("succeeded=%d", r.Data.Succeeded)
	}
	over := append(items, internalItem("fp-501"))
	if rec := doJSON(t, mux, http.MethodPost, "/api/v1/estate/takeover/bulk", bulkTakeoverRequest{Items: over}); rec.Code != http.StatusBadRequest {
		t.Fatalf("501 items: %d", rec.Code)
	}
}

// caStampProvider overrides the CA of chosen fingerprints so tenant scoping
// (which keys off the issuing CA) can be exercised on imported certificates.
type caStampProvider struct {
	CertificateProvider
	caByFP map[string]string
}

func (p caStampProvider) GetCertificate(ctx context.Context, fp string) (CertificateDetail, bool, error) {
	d, ok, err := p.CertificateProvider.GetCertificate(ctx, fp)
	if ca, stamped := p.caByFP[fp]; stamped && ok && err == nil {
		d.CAID = ca
	}
	return d, ok, err
}

func TestBulkTakeoverSkipsAlreadyManagedAndOtherTenant(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("MULTI_TENANCY", "on")
	auth := NewAuthenticatorFromEnv()
	base, _ := newIntegrationCAProvider(t, setupIntegrationDB(t))
	ctx := context.Background()
	managed, other, free := importEstateCert(t, base, "t-sk"), importEstateCert(t, base, "t-sk"), importEstateCert(t, base, "t-sk")
	provider := caStampProvider{CertificateProvider: base, caByFP: map[string]string{managed: "ca-acme", other: "ca-globex", free: "ca-acme"}}
	ts := newTestTenantStore(t)
	_ = ts.SetCATenant(ctx, "ca-acme", "acme")
	_ = ts.SetCATenant(ctx, "ca-globex", "globex")
	prev := activeTenantStore
	setActiveTenantStore(ts)
	t.Cleanup(func() { setActiveTenantStore(prev) })
	_, tok, err := auth.CreateAPIKey("acme-admin", "acme-admin", "pki-admin", []string{"*"}, "", "acme", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	audit := &estateAuditRecorder{}
	mux := http.NewServeMux()
	RegisterEstateHandlers(mux, auth, provider, newConnectorTestStore(t), audit)

	if _, err := base.UpdateEstate(ctx, managed, EstateUpdate{ManagementState: "managed", RenewalMethod: "api"}); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(bulkTakeoverRequest{Items: []takeoverRequest{internalItem(managed), internalItem(other), internalItem(free)}})
	req := tenantReq(tok, "acme", http.MethodPost, "/api/v1/estate/takeover/bulk", body)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bulk: %d %s", rec.Code, rec.Body.String())
	}
	r := decodeBulk(t, rec.Body.Bytes())
	if r.Data.Total != 3 || r.Data.Succeeded != 1 || r.Data.Skipped != 2 || r.Data.Failed != 0 {
		t.Fatalf("summary: %+v", r.Data)
	}
	if got := r.Data.Results[0]; got.Status != "skipped" || got.Reason != "already_managed" {
		t.Fatalf("managed row: %+v", got)
	}
	if got := r.Data.Results[1]; got.Status != "skipped" || got.Reason != "other_tenant" {
		t.Fatalf("other row: %+v", got)
	}
	if got := r.Data.Results[2]; got.Status != "ok" {
		t.Fatalf("free row: %+v", got)
	}
	if n := audit.count("estate.takeover", AuditOutcomeSuccess); n != 1 {
		t.Fatalf("success audits=%d", n)
	}
	if n := audit.count("estate.takeover", AuditOutcomeDenied); n != 1 {
		t.Fatalf("denied audits=%d", n)
	}
	if g, _, _ := base.GetCertificate(ctx, other); g.ManagementState != "unmanaged" || g.OwnerEmail != "" {
		t.Fatalf("other-tenant cert mutated: %+v", g.CertificateItem)
	}
}

func TestBulkTakeoverAuditOneRowPerSuccess(t *testing.T) {
	mux, provider, _, audit := newEstateAuditMux(t)
	items := []takeoverRequest{
		internalItem(importEstateCert(t, provider, "t-one")),
		internalItem(importEstateCert(t, provider, "t-one")),
		internalItem(importEstateCert(t, provider, "t-one")),
	}
	if rec := doJSON(t, mux, http.MethodPost, "/api/v1/estate/takeover/bulk", bulkTakeoverRequest{Items: items}); rec.Code != http.StatusOK {
		t.Fatalf("bulk: %d", rec.Code)
	}
	if n := audit.count("estate.takeover", AuditOutcomeSuccess); n != 3 {
		t.Fatalf("per-cert success audits=%d", n)
	}
	if n := audit.count("estate.takeover.bulk", AuditOutcomeSuccess); n != 1 {
		t.Fatalf("summary audits=%d", n)
	}
}

func TestTakeoverSuggestionsFromOwnershipAndSiblings(t *testing.T) {
	mux, provider, _, audit := newEstateAuditMux(t)
	ctx := context.Background()
	own := func(fp, email, team, svc string) {
		t.Helper()
		if _, err := provider.UpdateOwnership(ctx, fp, CertificateOwnershipRequest{OwnerEmail: email, OwnerTeam: team, ServiceName: svc}); err != nil {
			t.Fatal(err)
		}
	}
	a := importNamedEstateCert(t, provider, "a.example.com")
	own(a, "a@example.com", "team-a", "svc-a")
	b := importNamedEstateCert(t, provider, "b.example.com", "shared.example.com")
	c := importNamedEstateCert(t, provider, "c.example.com", "shared.example.com")
	d := importNamedEstateCert(t, provider, "d.example.com", "shared.example.com")
	own(c, "ops@example.com", "team-ops", "svc-shared")
	own(d, "ops@example.com", "team-ops", "svc-shared")
	e := importNamedEstateCert(t, provider, "lonely.example.com")

	q := url.Values{"fingerprint": {a, b, e, "deadbeef-unknown"}}
	rec := doJSON(t, mux, http.MethodGet, "/api/v1/estate/takeover/suggestions?"+q.Encode(), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("suggestions: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data []takeoverSuggestion `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || len(resp.Data) != 4 {
		t.Fatalf("decode: %v %s", err, rec.Body.String())
	}
	want := []struct{ fp, source, conf, email string }{
		{a, "existing_ownership", "high", "a@example.com"},
		{b, "sibling_certificate", "medium", "ops@example.com"},
		{e, "none", "none", ""},
		{"deadbeef-unknown", "unavailable", "none", ""},
	}
	for i, w := range want {
		g := resp.Data[i]
		if g.Fingerprint != w.fp || g.Source != w.source || g.Confidence != w.conf || g.OwnerEmail != w.email {
			t.Fatalf("row %d: %+v want %+v", i, g, w)
		}
	}
	if g, _, _ := provider.GetCertificate(ctx, b); g.OwnerEmail != "" {
		t.Fatalf("suggestions mutated ownership: %+v", g.CertificateItem)
	}
	if n := audit.count("estate.takeover.suggest", AuditOutcomeSuccess); n != 1 {
		t.Fatalf("suggest audits=%d", n)
	}
	if rec := doJSON(t, mux, http.MethodGet, "/api/v1/estate/takeover/suggestions", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("no fingerprints: %d", rec.Code)
	}
	if rec := doJSON(t, mux, http.MethodPost, "/api/v1/estate/takeover/suggestions?fingerprint="+a, nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", rec.Code)
	}
	unauth := httptest.NewRecorder()
	mux.ServeHTTP(unauth, httptest.NewRequest(http.MethodGet, "/api/v1/estate/takeover/suggestions?fingerprint="+a, nil))
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("unauth: %d", unauth.Code)
	}
	many := url.Values{}
	for i := 0; i < 501; i++ {
		many.Add("fingerprint", fmt.Sprintf("fp-%d", i))
	}
	if rec := doJSON(t, mux, http.MethodGet, "/api/v1/estate/takeover/suggestions?"+many.Encode(), nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("501 fingerprints: %d", rec.Code)
	}
}
