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
	"path/filepath"
	"sync"
	"testing"
	"time"

	"kryptkeeper/internal/ctmonitor"

	_ "modernc.org/sqlite"
)

type ctRecordingAudit struct {
	mu      sync.Mutex
	entries []AuditEntry
}

func (a *ctRecordingAudit) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{}, nil
}

func (a *ctRecordingAudit) AppendEntry(_ context.Context, e AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
	return nil
}

func (a *ctRecordingAudit) find(action string, outcome AuditOutcome) (AuditEntry, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.entries {
		if e.Action == action && e.Outcome == outcome {
			return e, true
		}
	}
	return AuditEntry{}, false
}

// ctFakeCAProvider serves ListCAs only; every other (mutating) method counts
// as a call the CT API must never make.
type ctFakeCAProvider struct {
	CAProvider
	items []CAListItem
	other int
}

func (p *ctFakeCAProvider) ListCAs(context.Context, CAListQuery) (CAListResult, error) {
	return CAListResult{Items: p.items, Total: len(p.items)}, nil
}
func (p *ctFakeCAProvider) UpdateCA(context.Context, string, CAUpdateRequest) (CAListItem, error) {
	p.other++
	return CAListItem{}, nil
}
func (p *ctFakeCAProvider) DeleteCA(context.Context, string) error { p.other++; return nil }
func (p *ctFakeCAProvider) SuspendCA(context.Context, string) (CAStatusChange, error) {
	p.other++
	return CAStatusChange{}, nil
}
func (p *ctFakeCAProvider) ActivateCA(context.Context, string) (CAStatusChange, error) {
	p.other++
	return CAStatusChange{}, nil
}
func (p *ctFakeCAProvider) CreateCA(context.Context, CACreateRequest) (CAListItem, error) {
	p.other++
	return CAListItem{}, nil
}

func ctOurCA() CAListItem {
	ca := CAListItem{ID: "ca-1", Name: "internal-issuing", DisplayName: "Acme Issuing CA"}
	ca.Certificate = &struct {
		FingerprintSHA256 string `json:"fingerprint_sha256"`
		SubjectDN         string `json:"subject_dn"`
		ValidFrom         string `json:"valid_from"`
		ValidUntil        string `json:"valid_until"`
		PublicKeyAlg      string `json:"public_key_algorithm"`
		KeySizeBits       int    `json:"key_size_bits"`
	}{SubjectDN: "CN=Acme Issuing CA,O=Acme"}
	return ca
}

type ctHarness struct {
	mux   *http.ServeMux
	auth  *Authenticator
	store *ctmonitor.Store
	audit *ctRecordingAudit
	cas   *ctFakeCAProvider
}

func newCTHarness(t *testing.T) *ctHarness {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "ct.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := ctmonitor.NewStore(db, false)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	h := &ctHarness{auth: auth, store: store, audit: &ctRecordingAudit{}, cas: &ctFakeCAProvider{items: []CAListItem{ctOurCA()}}}
	h.mux = http.NewServeMux()
	RegisterCTFindingsHandlers(h.mux, auth, store, h.cas, h.audit)
	return h
}

func (h *ctHarness) do(method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec
}

func (h *ctHarness) record(t *testing.T, id, issuer, serial, tenant string) {
	t.Helper()
	_, err := h.store.Record(context.Background(), ctmonitor.Finding{
		ID: id, Domain: "example.com", CommonName: "rogue.example.com",
		DNSNames: []string{"rogue.example.com"}, Issuer: issuer, Serial: serial,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		Source: "crtsh", Tenant: tenant,
	})
	if err != nil {
		t.Fatalf("record: %v", err)
	}
}

type ctListResp struct {
	Data struct {
		Findings []ctFindingView `json:"findings"`
		Total    int             `json:"total"`
	} `json:"data"`
}

func (h *ctHarness) list(t *testing.T, token, query string) ctListResp {
	t.Helper()
	rec := h.do(http.MethodGet, "/api/v1/ct/findings"+query, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d body = %s", rec.Code, rec.Body.String())
	}
	var out ctListResp
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

func TestCTFindingsList_ReturnsFields(t *testing.T) {
	h := newCTHarness(t)
	h.record(t, "crtsh:1", "C=XX, O=Shady CA", "0abc", "")
	out := h.list(t, "test-token", "")
	if out.Data.Total != 1 || len(out.Data.Findings) != 1 {
		t.Fatalf("unexpected list: %+v", out.Data)
	}
	f := out.Data.Findings[0]
	if f.ID != "crtsh:1" || f.LogID != "crtsh:1" || f.Source != "crtsh" || f.CA != "C=XX, O=Shady CA" ||
		f.Serial != "0abc" || f.Status != "open" || f.NotBefore.IsZero() || f.Ours || f.RevokeURL != "" {
		t.Fatalf("bad finding fields: %+v", f)
	}
	if rec := h.do(http.MethodGet, "/api/v1/ct/findings?status=bogus", "test-token"); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid status = %d, want 400", rec.Code)
	}
	if rec := h.do(http.MethodGet, "/api/v1/ct/findings", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token = %d, want 401", rec.Code)
	}
}

func TestCTFindingsAcknowledgeOneCall(t *testing.T) {
	h := newCTHarness(t)
	h.record(t, "crtsh:1", "C=XX, O=Shady CA", "0abc", "")
	rec := h.do(http.MethodPost, "/api/v1/ct/findings/crtsh:1/acknowledge", "test-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("ack = %d body = %s", rec.Code, rec.Body.String())
	}
	if got := h.list(t, "test-token", "").Data.Findings[0]; got.Status != "acknowledged" || got.ResolvedBy == "" || got.ResolvedAt == nil {
		t.Fatalf("after ack: %+v", got)
	}
	if rec := h.do(http.MethodPost, "/api/v1/ct/findings/crtsh:1/acknowledge", "test-token"); rec.Code != http.StatusOK {
		t.Fatalf("second ack must be idempotent 200, got %d", rec.Code)
	}
	// A re-scan of an acknowledged finding neither re-creates nor reopens it.
	h.record(t, "crtsh:1", "C=XX, O=Shady CA", "0abc", "")
	if got := h.list(t, "test-token", "?status=open"); got.Data.Total != 0 {
		t.Fatalf("re-scan reopened the finding: %+v", got.Data)
	}
}

func TestCTFindingsKnownIssuerOneCall(t *testing.T) {
	h := newCTHarness(t)
	h.record(t, "crtsh:1", "C=XX, O=A", "01", "")
	h.record(t, "crtsh:2", "C=XX, O=B", "02", "")
	if rec := h.do(http.MethodPost, "/api/v1/ct/findings/crtsh:1/known-issuer", "test-token"); rec.Code != http.StatusOK {
		t.Fatalf("known-issuer = %d body = %s", rec.Code, rec.Body.String())
	}
	if rec := h.do(http.MethodPost, "/api/v1/ct/findings/crtsh:2/acknowledge", "test-token"); rec.Code != http.StatusOK {
		t.Fatalf("ack = %d", rec.Code)
	}
	ki := h.list(t, "test-token", "?status=known_issuer")
	if ki.Data.Total != 1 || ki.Data.Findings[0].ID != "crtsh:1" || ki.Data.Findings[0].Status != "known_issuer" {
		t.Fatalf("known_issuer filter: %+v", ki.Data)
	}
	ack := h.list(t, "test-token", "?status=acknowledged")
	if ack.Data.Total != 1 || ack.Data.Findings[0].ID != "crtsh:2" {
		t.Fatalf("acknowledged filter must exclude known_issuer: %+v", ack.Data)
	}
}

func TestCTFindingsAuditActions(t *testing.T) {
	h := newCTHarness(t)
	h.record(t, "crtsh:1", "C=XX, O=A", "01", "")
	h.list(t, "test-token", "")
	h.do(http.MethodPost, "/api/v1/ct/findings/crtsh:1/acknowledge", "test-token")
	h.do(http.MethodPost, "/api/v1/ct/findings/crtsh:1/known-issuer", "test-token")
	h.do(http.MethodPost, "/api/v1/ct/findings/crtsh:missing/acknowledge", "test-token")
	for _, action := range []string{"ct.finding.list", "ct.finding.acknowledge", "ct.finding.known_issuer"} {
		e, ok := h.audit.find(action, AuditOutcomeSuccess)
		if !ok || e.ResourceType != "ct_finding" {
			t.Fatalf("no success audit row for %s (%+v)", action, h.audit.entries)
		}
	}
	if e, ok := h.audit.find("ct.finding.acknowledge", AuditOutcomeSuccess); !ok || e.ResourceID != "crtsh:1" {
		t.Fatalf("ack audit resource id = %+v", e)
	}
	if _, ok := h.audit.find("ct.finding.acknowledge", AuditOutcomeFailure); !ok {
		t.Fatal("unknown-id acknowledge must be audited as failure")
	}
}

func TestCTFindingsTenantIsolation(t *testing.T) {
	h := newCTHarness(t)
	t.Setenv("MULTI_TENANCY", "on")
	_, tokenA, err := h.auth.CreateAPIKey("user-a", "user-a", "pki-admin", []string{"*"}, "", "tenant-a", time.Now())
	if err != nil {
		t.Fatalf("key a: %v", err)
	}
	_, tokenB, err := h.auth.CreateAPIKey("user-b", "user-b", "pki-admin", []string{"*"}, "", "tenant-b", time.Now())
	if err != nil {
		t.Fatalf("key b: %v", err)
	}
	h.record(t, "crtsh:a1", "C=XX, O=A", "0a", "tenant-a")

	if got := h.list(t, tokenA, ""); got.Data.Total != 1 {
		t.Fatalf("tenant-a must see own finding: %+v", got.Data)
	}
	if got := h.list(t, tokenB, ""); got.Data.Total != 0 || len(got.Data.Findings) != 0 {
		t.Fatalf("tenant-b must not see tenant-a finding: %+v", got.Data)
	}
	for _, verb := range []string{"acknowledge", "known-issuer"} {
		if rec := h.do(http.MethodPost, "/api/v1/ct/findings/crtsh:a1/"+verb, tokenB); rec.Code != http.StatusNotFound {
			t.Fatalf("cross-tenant %s = %d, want 404", verb, rec.Code)
		}
	}
	f, _ := h.store.Get(context.Background(), "crtsh:a1")
	if f.Status != "open" {
		t.Fatalf("cross-tenant call mutated the finding: %+v", f)
	}
	if rec := h.do(http.MethodPost, "/api/v1/ct/findings/crtsh:a1/acknowledge", tokenA); rec.Code != http.StatusOK {
		t.Fatalf("owner ack = %d", rec.Code)
	}
}

func TestCTFindingsOursCarriesRevokeURL(t *testing.T) {
	h := newCTHarness(t)
	h.record(t, "crtsh:ours", "CN=Acme Issuing CA, O=Acme", "0a:b1", "")
	h.record(t, "crtsh:lookalike", "CN=Acme Issuing CA Fake, O=Evil", "02", "")
	h.record(t, "crtsh:foreign", "C=US, O=Let's Encrypt, CN=R11", "03", "")
	byID := map[string]ctFindingView{}
	for _, f := range h.list(t, "test-token", "").Data.Findings {
		byID[f.ID] = f
	}
	ours := byID["crtsh:ours"]
	if !ours.Ours || ours.RevokeURL != "/certificates?q=0a%3Ab1" {
		t.Fatalf("ours finding: %+v", ours)
	}
	for _, id := range []string{"crtsh:lookalike", "crtsh:foreign"} {
		if f := byID[id]; f.Ours || f.RevokeURL != "" {
			t.Fatalf("%s must not carry a revoke link: %+v", id, f)
		}
	}
}

func TestCTFindingsNeverRevokes(t *testing.T) {
	h := newCTHarness(t)
	h.record(t, "crtsh:ours", "CN=Acme Issuing CA", "0a", "")
	h.list(t, "test-token", "")
	h.do(http.MethodPost, "/api/v1/ct/findings/crtsh:ours/acknowledge", "test-token")
	h.do(http.MethodPost, "/api/v1/ct/findings/crtsh:ours/known-issuer", "test-token")
	if h.cas.other != 0 {
		t.Fatalf("CT API invoked %d mutating CA operations; it must never revoke or change a CA", h.cas.other)
	}
}

func TestCTFindings503WhenStoreNil(t *testing.T) {
	h := newCTHarness(t)
	mux := http.NewServeMux()
	RegisterCTFindingsHandlers(mux, h.auth, nil, h.cas, h.audit)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/ct/findings"},
		{http.MethodPost, "/api/v1/ct/findings/crtsh:1/acknowledge"},
		{http.MethodPost, "/api/v1/ct/findings/crtsh:1/known-issuer"},
	} {
		req := httptest.NewRequest(c.method, c.path, nil)
		req.Header.Set("Authorization", "Bearer test-token")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s %s = %d, want 503", c.method, c.path, rec.Code)
		}
	}
}

func TestCTFindingsForbiddenRole(t *testing.T) {
	h := newCTHarness(t)
	h.record(t, "crtsh:1", "C=XX, O=A", "01", "")
	_, token, err := h.auth.CreateAPIKey("aud", "aud", "pki-auditor", []string{"ops:read"}, "", "default", time.Now())
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	if got := h.list(t, token, ""); got.Data.Total != 1 {
		t.Fatalf("auditor must read: %+v", got.Data)
	}
	if rec := h.do(http.MethodPost, "/api/v1/ct/findings/crtsh:1/acknowledge", token); rec.Code != http.StatusForbidden {
		t.Fatalf("auditor ack = %d, want 403", rec.Code)
	}
	if _, ok := h.audit.find("ct.finding.acknowledge", AuditOutcomeDenied); !ok {
		t.Fatal("denied ack must be audited")
	}
	f, _ := h.store.Get(context.Background(), "crtsh:1")
	if f.Status != "open" {
		t.Fatalf("forbidden call mutated the finding: %+v", f)
	}
}
