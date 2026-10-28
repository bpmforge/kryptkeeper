// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

type caMetaAudit struct {
	mu      sync.Mutex
	entries []AuditEntry
}

func (a *caMetaAudit) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{}, nil
}

func (a *caMetaAudit) AppendEntry(_ context.Context, e AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
	return nil
}

func (a *caMetaAudit) last(action string) (AuditEntry, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := len(a.entries) - 1; i >= 0; i-- {
		if a.entries[i].Action == action {
			return a.entries[i], true
		}
	}
	return AuditEntry{}, false
}

type caMetaEnv struct {
	mux    *http.ServeMux
	store  ca.Store
	keys   keystore.Store
	engine *ca.Engine
	audit  *caMetaAudit
}

func newCAMetaEnv(t *testing.T, seed ...*ca.CA) *caMetaEnv {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("test-ca-passphrase-32chars-min!!"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	store := ca.NewMemStore()
	for _, c := range seed {
		if err := store.Save(c); err != nil {
			t.Fatal(err)
		}
	}
	engine := ca.NewEngine(keys, store)
	env := &caMetaEnv{store: store, keys: keys, engine: engine, audit: &caMetaAudit{}}
	env.mux = http.NewServeMux()
	registerCAHandlers(env.mux, NewAuthenticatorFromEnv(), NewEngineCAProvider(engine), NewTenantStoreFromEnv(), env.audit)
	return env
}

func (e *caMetaEnv) do(method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func (e *caMetaEnv) newRoot(t *testing.T) *ca.CA {
	t.Helper()
	root, err := e.engine.CreateRootCA("Meta Root", pkix.Name{CommonName: "Meta Root"}, keystore.ECDSAP256, 24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	return root
}

func decodeCAItem(t *testing.T, rec *httptest.ResponseRecorder) CAListItem {
	t.Helper()
	var resp struct {
		Data CAListItem `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return resp.Data
}

func TestCAPatchPersistsAndSurvivesProviderRebuild(t *testing.T) {
	env := newCAMetaEnv(t)
	root := env.newRoot(t)
	path := "/api/v1/cas/" + root.ID

	rec := env.do(http.MethodPatch, path, `{"display_name":"  Prod Root ","crl_distribution_points":["http://crl.example/a.crl","http://crl.example/a.crl","ldap://dir.example/cn=ca"],"ocsp_service_url":"https://ocsp.example"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body.String())
	}
	check := func(label string, item CAListItem) {
		t.Helper()
		if item.DisplayName != "Prod Root" || item.Name != "Meta Root" ||
			len(item.CRLDistributionPoints) != 2 || item.CRLDistributionPoints[1] != "ldap://dir.example/cn=ca" ||
			item.OCSPServiceURL == nil || *item.OCSPServiceURL != "https://ocsp.example" {
			t.Fatalf("%s: unexpected item %+v", label, item)
		}
	}
	check("patch response", decodeCAItem(t, rec))
	check("GET after patch", decodeCAItem(t, env.do(http.MethodGet, path, "")))

	// A fresh engine + provider over the same store is a restart.
	item, found, err := NewEngineCAProvider(ca.NewEngine(env.keys, env.store)).GetCA(context.Background(), root.ID)
	if err != nil || !found {
		t.Fatalf("GetCA after rebuild: found=%v err=%v", found, err)
	}
	check("after provider rebuild", item)

	// The pointers the issuing path reads (cmd/kryptkeeper main.go) come from GetCA.
	if rec := env.do(http.MethodPatch, path, `{"ocsp_service_url":""}`); rec.Code != http.StatusOK {
		t.Fatalf("clear ocsp: %d %s", rec.Code, rec.Body.String())
	}
	item, _, _ = NewEngineCAProvider(ca.NewEngine(env.keys, env.store)).GetCA(context.Background(), root.ID)
	if item.OCSPServiceURL != nil || item.DisplayName != "Prod Root" {
		t.Fatalf("clear ocsp / partial update wrong: %+v", item)
	}
}

func TestCAPatchRejectsInvalidValues(t *testing.T) {
	env := newCAMetaEnv(t)
	root := env.newRoot(t)
	path := "/api/v1/cas/" + root.ID
	tooMany := `["http://a/1","http://a/2","http://a/3","http://a/4","http://a/5","http://a/6","http://a/7","http://a/8","http://a/9"]`
	for name, body := range map[string]string{
		"blank display name": `{"display_name":"   "}`,
		"long display name":  `{"display_name":"` + strings.Repeat("x", 256) + `"}`,
		"crl not a url":      `{"crl_distribution_points":["not a url"]}`,
		"crl bad scheme":     `{"crl_distribution_points":["ftp://crl.example/x"]}`,
		"crl no host":        `{"crl_distribution_points":["http:///x"]}`,
		"crl empty entry":    `{"crl_distribution_points":[""]}`,
		"crl too many":       `{"crl_distribution_points":` + tooMany + `}`,
		"ocsp ldap":          `{"ocsp_service_url":"ldap://x.example"}`,
		"ocsp relative":      `{"ocsp_service_url":"/ocsp"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if rec := env.do(http.MethodPatch, path, body); rec.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d %s", rec.Code, rec.Body.String())
			}
		})
	}
	got, _ := env.engine.GetCA(root.ID)
	if got.DisplayName != "" || len(got.CRLDistributionPoints) != 0 || got.OCSPServiceURL != "" {
		t.Fatalf("a rejected patch changed the CA: %+v", got)
	}
	if rec := env.do(http.MethodPatch, "/api/v1/cas/missing", `{"display_name":"x"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown CA: want 404, got %d", rec.Code)
	}
}

func TestCAPatchExternalCARefusesRevocationPointers(t *testing.T) {
	env := newCAMetaEnv(t, &ca.CA{ID: "ext-1", Name: "Ext", Type: ca.CATypeExternal, Status: "active", ConnectorID: "c1"})

	for _, body := range []string{
		`{"crl_distribution_points":["http://crl.example/x"]}`,
		`{"ocsp_service_url":"http://ocsp.example"}`,
	} {
		rec := env.do(http.MethodPatch, "/api/v1/cas/ext-1", body)
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "upstream") {
			t.Fatalf("%s: want 422 naming the upstream, got %d %s", body, rec.Code, rec.Body.String())
		}
	}
	if e, ok := env.audit.last("ca.update"); !ok || e.Outcome != AuditOutcomeFailure {
		t.Fatalf("refusal must be audited as a failure: %+v", e)
	}
	rec := env.do(http.MethodPatch, "/api/v1/cas/ext-1", `{"display_name":"Vault upstream"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("display name on an external CA: %d %s", rec.Code, rec.Body.String())
	}
	if item := decodeCAItem(t, rec); item.DisplayName != "Vault upstream" || len(item.CRLDistributionPoints) != 0 || item.OCSPServiceURL != nil {
		t.Fatalf("external CA must never carry hub pointers: %+v", item)
	}
}

func TestCAPatchAuditCarriesChangeSummary(t *testing.T) {
	env := newCAMetaEnv(t)
	root := env.newRoot(t)

	rec := env.do(http.MethodPatch, "/api/v1/cas/"+root.ID, `{"display_name":"Renamed","ocsp_service_url":"http://ocsp.example","crl_distribution_points":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body.String())
	}
	e, ok := env.audit.last("ca.update")
	if !ok || e.Outcome != AuditOutcomeSuccess {
		t.Fatalf("no success audit entry: %+v", e)
	}
	for _, want := range []string{`display_name: "Meta Root" -> "Renamed"`, `ocsp_service_url: "" -> "http://ocsp.example"`} {
		if !strings.Contains(e.ChangeSummary, want) {
			t.Errorf("summary %q lacks %q", e.ChangeSummary, want)
		}
	}
	if strings.Contains(e.ChangeSummary, "crl_distribution_points") {
		t.Errorf("unchanged field listed: %q", e.ChangeSummary)
	}
}

func TestCAMetadata_Postgres_RoundTrip(t *testing.T) {
	freshPostgresForTest(t)
	db, isPG, err := OpenCoreDB()
	if err != nil || !isPG {
		t.Fatalf("OpenCoreDB: isPG=%v err=%v", isPG, err)
	}
	store := ca.NewDBStore(db, true)
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("test-ca-passphrase-32chars-min!!"))
	if err != nil {
		t.Fatal(err)
	}
	e := ca.NewEngine(keys, store)
	root, err := e.CreateRootCA("PG Root", pkix.Name{CommonName: "PG Root"}, keystore.ECDSAP256, 24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	crl := []string{"http://crl.example/z.crl", "http://crl.example/a.crl", "ldap://dir.example/cn=x"}
	ocsp, name := "http://ocsp.example", "PG Pretty"
	if _, err := e.UpdateCAMetadata(root.ID, &name, &crl, &ocsp); err != nil {
		t.Fatalf("UpdateCAMetadata: %v", err)
	}
	got, err := ca.NewEngine(keys, store).GetCA(root.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "PG Root" || got.DisplayName != name || got.OCSPServiceURL != ocsp ||
		strings.Join(got.CRLDistributionPoints, "|") != strings.Join(crl, "|") {
		t.Fatalf("round trip lost data (order matters): %+v", got)
	}
	empty := []string{}
	noOCSP := ""
	if _, err := e.UpdateCAMetadata(root.ID, nil, &empty, &noOCSP); err != nil {
		t.Fatal(err)
	}
	got, _ = ca.NewEngine(keys, store).GetCA(root.ID)
	if len(got.CRLDistributionPoints) != 0 || got.OCSPServiceURL != "" {
		t.Fatalf("clear failed: %+v", got)
	}
}
