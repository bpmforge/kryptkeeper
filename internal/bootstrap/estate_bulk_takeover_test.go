// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// W24-31: bulk takeover + managed->unmanaged revert.

type estateAuditRecorder struct {
	mu      sync.Mutex
	entries []AuditEntry
}

func (a *estateAuditRecorder) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{}, nil
}

func (a *estateAuditRecorder) AppendEntry(_ context.Context, e AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
	return nil
}

func (a *estateAuditRecorder) count(action string, outcome AuditOutcome) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, e := range a.entries {
		if e.Action == action && e.Outcome == outcome {
			n++
		}
	}
	return n
}

// newEstateAuditMux mirrors newEstateTestMux but wires a recording audit.
func newEstateAuditMux(t *testing.T) (*http.ServeMux, CertificateProvider, ConnectorStore, *estateAuditRecorder) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()
	db := setupIntegrationDB(t)
	provider, _ := newIntegrationCAProvider(t, db)
	store := newConnectorTestStore(t)
	rec := &estateAuditRecorder{}
	mux := http.NewServeMux()
	RegisterEstateHandlers(mux, auth, provider, store, rec)
	return mux, provider, store, rec
}

func importEstateCert(t *testing.T, provider CertificateProvider, team string) string {
	t.Helper()
	imp, err := provider.ImportCertificate(context.Background(), CertificateImportRequest{
		CertificatePEM: estateTestCertPEM(t), TeamID: team,
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	return imp.CertificateItem.FingerprintSHA256
}

type bulkTakeoverResp struct {
	Data struct {
		Total     int               `json:"total"`
		Succeeded int               `json:"succeeded"`
		Failed    int               `json:"failed"`
		Skipped   int               `json:"skipped"`
		Results   []bulkTakeoverRow `json:"results"`
	} `json:"data"`
}

func decodeBulk(t *testing.T, body []byte) bulkTakeoverResp {
	t.Helper()
	var r bulkTakeoverResp
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	return r
}

func internalItem(fp string) takeoverRequest {
	return takeoverRequest{Fingerprint: fp, OwnerEmail: "o@example.com", RenewalPath: takeoverRenewalPath{Mode: "internal"}}
}

func TestBulkTakeoverMixedRows(t *testing.T) {
	mux, provider, store, _ := newEstateAuditMux(t)
	ctx := context.Background()
	if _, err := store.Create(ctx, ConnectorRecord{ID: "conn-up", Name: "Up", Type: "acme"}); err != nil {
		t.Fatalf("connector: %v", err)
	}
	a, b, c := importEstateCert(t, provider, "t1"), importEstateCert(t, provider, "t1"), importEstateCert(t, provider, "t1")
	items := []takeoverRequest{
		internalItem(a),
		{Fingerprint: b, RenewalPath: takeoverRenewalPath{Mode: "connector", ConnectorID: "conn-up"}},
		internalItem("deadbeef-unknown"),
		{Fingerprint: "", RenewalPath: takeoverRenewalPath{Mode: "internal"}},
		internalItem(c),
	}
	rec := doJSON(t, mux, http.MethodPost, "/api/v1/estate/takeover/bulk", bulkTakeoverRequest{Items: items})
	if rec.Code != http.StatusOK {
		t.Fatalf("bulk: %d %s", rec.Code, rec.Body.String())
	}
	r := decodeBulk(t, rec.Body.Bytes())
	if r.Data.Total != 5 || r.Data.Succeeded != 3 || r.Data.Failed != 2 || r.Data.Skipped != 0 {
		t.Fatalf("summary: %+v", r.Data)
	}
	wantCodes := []string{"", "", "not_found", "bad_request", ""}
	for i, row := range r.Data.Results {
		if row.Fingerprint != items[i].Fingerprint {
			t.Fatalf("row %d order: %q", i, row.Fingerprint)
		}
		if row.Code != wantCodes[i] {
			t.Fatalf("row %d code %q want %q (%+v)", i, row.Code, wantCodes[i], row)
		}
	}
	for _, fp := range []string{a, b, c} {
		got, _, _ := provider.GetCertificate(ctx, fp)
		if got.ManagementState != "managed" {
			t.Fatalf("%s not managed: %q", fp, got.ManagementState)
		}
	}
}

func TestBulkTakeoverLimits(t *testing.T) {
	mux, provider, _, _ := newEstateAuditMux(t)
	over := make([]takeoverRequest, 501)
	for i := range over {
		over[i] = internalItem(fmt.Sprintf("fp-%d", i))
	}
	if rec := doJSON(t, mux, http.MethodPost, "/api/v1/estate/takeover/bulk", bulkTakeoverRequest{Items: over}); rec.Code != http.StatusBadRequest {
		t.Fatalf("501 items: %d", rec.Code)
	}
	if rec := doJSON(t, mux, http.MethodPost, "/api/v1/estate/takeover/bulk", bulkTakeoverRequest{Items: []takeoverRequest{}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty: %d", rec.Code)
	}
	fp := importEstateCert(t, provider, "t-dup")
	rec := doJSON(t, mux, http.MethodPost, "/api/v1/estate/takeover/bulk", bulkTakeoverRequest{Items: []takeoverRequest{internalItem(fp), internalItem(fp), internalItem(" ")}})
	if rec.Code != http.StatusOK {
		t.Fatalf("dup: %d %s", rec.Code, rec.Body.String())
	}
	r := decodeBulk(t, rec.Body.Bytes())
	if r.Data.Results[0].Status != "ok" || r.Data.Results[1].Status != "error" || r.Data.Results[1].Code != "bad_request" || r.Data.Results[2].Status != "error" {
		t.Fatalf("rows: %+v", r.Data.Results)
	}
}

func TestBulkTakeoverAuditsPerRowAndSummary(t *testing.T) {
	mux, provider, _, audit := newEstateAuditMux(t)
	a, b := importEstateCert(t, provider, "t-au"), importEstateCert(t, provider, "t-au")
	rec := doJSON(t, mux, http.MethodPost, "/api/v1/estate/takeover/bulk", bulkTakeoverRequest{Items: []takeoverRequest{internalItem(a), internalItem(b), internalItem("nope")}})
	if rec.Code != http.StatusOK {
		t.Fatalf("bulk: %d", rec.Code)
	}
	if n := audit.count("estate.takeover", AuditOutcomeSuccess); n != 2 {
		t.Fatalf("per-row success audits=%d", n)
	}
	if n := audit.count("estate.takeover", AuditOutcomeFailure); n != 1 {
		t.Fatalf("per-row failure audits=%d", n)
	}
	if n := audit.count("estate.takeover.bulk", AuditOutcomeSuccess); n != 1 {
		t.Fatalf("summary audits=%d", n)
	}
}

func TestBulkTakeoverRequiresAuth(t *testing.T) {
	mux, _, _, audit := newEstateAuditMux(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/estate/takeover/bulk", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no auth: %d", rec.Code)
	}
	if audit.count("estate.takeover.bulk", AuditOutcomeDenied) != 1 {
		t.Fatal("denied audit missing")
	}
}

// NoApprovalGate documents the inherited behaviour: bulk takeover, like
// single takeover, is audit-only; a plain principal succeeds without any
// approval request.
func TestBulkTakeoverNoApprovalGate(t *testing.T) {
	mux, provider, _, _ := newEstateAuditMux(t)
	fp := importEstateCert(t, provider, "t-noapp")
	rec := doJSON(t, mux, http.MethodPost, "/api/v1/estate/takeover/bulk", bulkTakeoverRequest{Items: []takeoverRequest{internalItem(fp)}})
	if rec.Code != http.StatusOK || decodeBulk(t, rec.Body.Bytes()).Data.Succeeded != 1 {
		t.Fatalf("expected immediate success: %d %s", rec.Code, rec.Body.String())
	}
}

func TestRevertReturnsManagedToUnmanaged(t *testing.T) {
	mux, provider, _, audit := newEstateAuditMux(t)
	ctx := context.Background()
	fp := importEstateCert(t, provider, "t-rev")

	// Not managed yet -> 409.
	if rec := doJSON(t, mux, http.MethodPost, "/api/v1/estate/revert", revertRequest{Fingerprint: fp}); rec.Code != http.StatusConflict {
		t.Fatalf("revert unmanaged: %d", rec.Code)
	}
	if rec := doJSON(t, mux, http.MethodPost, "/api/v1/estate/takeover", internalItem(fp)); rec.Code != http.StatusOK {
		t.Fatalf("takeover: %d %s", rec.Code, rec.Body.String())
	}
	rec := doJSON(t, mux, http.MethodPost, "/api/v1/estate/revert", revertRequest{Fingerprint: fp})
	if rec.Code != http.StatusOK {
		t.Fatalf("revert: %d %s", rec.Code, rec.Body.String())
	}
	got, _, _ := provider.GetCertificate(ctx, fp)
	if got.ManagementState != "unmanaged" {
		t.Fatalf("state after revert: %q", got.ManagementState)
	}
	if audit.count("estate.takeover.revert", AuditOutcomeSuccess) != 1 {
		t.Fatal("revert success audit missing")
	}
	if rec := doJSON(t, mux, http.MethodPost, "/api/v1/estate/revert", revertRequest{Fingerprint: fp}); rec.Code != http.StatusConflict {
		t.Fatalf("second revert: %d", rec.Code)
	}
	if rec := doJSON(t, mux, http.MethodPost, "/api/v1/estate/revert", revertRequest{Fingerprint: "unknown-fp"}); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown revert: %d", rec.Code)
	}
	if rec := doJSON(t, mux, http.MethodPost, "/api/v1/estate/revert", revertRequest{}); rec.Code != http.StatusBadRequest {
		t.Fatalf("blank revert: %d", rec.Code)
	}
}

func TestBulkTakeoverAuditsRejectedRequests(t *testing.T) {
	over := make([]takeoverRequest, 501)
	for i := range over {
		over[i] = internalItem(fmt.Sprintf("fp-%d", i))
	}
	for name, body := range map[string]any{
		"empty body":  nil,
		"empty items": bulkTakeoverRequest{Items: []takeoverRequest{}},
		"too many":    bulkTakeoverRequest{Items: over},
	} {
		mux, _, _, audit := newEstateAuditMux(t)
		if rec := doJSON(t, mux, http.MethodPost, "/api/v1/estate/takeover/bulk", body); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: want 400, got %d", name, rec.Code)
		}
		if n := audit.count("estate.takeover.bulk", AuditOutcomeFailure); n != 1 {
			t.Fatalf("%s: want 1 failure audit row, got %d", name, n)
		}
	}
}

// B4 (ADCS cutover rehearsal): revert restores the state the certificate had
// before takeover. One synced from an inventory source goes back to external;
// one imported by hand goes back to unmanaged. The audit row says from/to.
func TestRevertRestoresPreTakeoverState(t *testing.T) {
	for _, tc := range []struct {
		name, origin, before string
	}{
		{"inventory source", "synced", "external"},
		{"manual import", "imported", "unmanaged"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux, provider, _, audit := newEstateAuditMux(t)
			ctx := context.Background()
			fp := importEstateCert(t, provider, "t-rev")
			if _, err := provider.UpdateEstate(ctx, fp, EstateUpdate{Origin: tc.origin, ManagementState: tc.before}); err != nil {
				t.Fatalf("stamp: %v", err)
			}
			if rec := doJSON(t, mux, http.MethodPost, "/api/v1/estate/takeover", internalItem(fp)); rec.Code != http.StatusOK {
				t.Fatalf("takeover: %d %s", rec.Code, rec.Body.String())
			}
			rec := doJSON(t, mux, http.MethodPost, "/api/v1/estate/revert", revertRequest{Fingerprint: fp})
			if rec.Code != http.StatusOK {
				t.Fatalf("revert: %d %s", rec.Code, rec.Body.String())
			}
			got, _, _ := provider.GetCertificate(ctx, fp)
			if got.ManagementState != tc.before {
				t.Fatalf("state after revert: %q, want %q", got.ManagementState, tc.before)
			}
			want := `{"from":"managed","to":"` + tc.before + `","renewal_method":{"from":"api","to":"manual"},"renewal_connector_id":{"from":"","to":""}}`
			found := false
			for _, e := range audit.entries {
				if e.Action == "estate.takeover.revert" && e.Outcome == AuditOutcomeSuccess && e.ChangeSummary == want {
					found = true
				}
			}
			if !found {
				t.Fatalf("revert audit row with %s missing: %+v", want, audit.entries)
			}
		})
	}
}

// Takeover onto an ACME connector sets the renewal method and connector;
// revert must put both back, not just the management state, so a reverted
// certificate is not left renewing through a connector nobody manages.
func TestRevertRestoresPreTakeoverRenewalPath(t *testing.T) {
	mux, provider, store, audit := newEstateAuditMux(t)
	ctx := context.Background()
	if _, err := store.Create(ctx, ConnectorRecord{ID: "conn-acme", Name: "Up", Type: "acme"}); err != nil {
		t.Fatalf("connector: %v", err)
	}
	fp := importEstateCert(t, provider, "t-renew")
	if _, err := provider.UpdateEstate(ctx, fp, EstateUpdate{Origin: "synced", ManagementState: "external"}); err != nil {
		t.Fatalf("stamp: %v", err)
	}
	before, _, _ := provider.GetCertificate(ctx, fp)

	rec := doJSON(t, mux, http.MethodPost, "/api/v1/estate/takeover", takeoverRequest{
		Fingerprint: fp, RenewalPath: takeoverRenewalPath{Mode: "connector", ConnectorID: "conn-acme"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("takeover: %d %s", rec.Code, rec.Body.String())
	}
	taken, _, _ := provider.GetCertificate(ctx, fp)
	if taken.RenewalMethod != "acme" || taken.RenewalConnectorID != "conn-acme" {
		t.Fatalf("takeover did not set the connector: %+v", taken.CertificateItem)
	}
	if rec := doJSON(t, mux, http.MethodPost, "/api/v1/estate/revert", revertRequest{Fingerprint: fp}); rec.Code != http.StatusOK {
		t.Fatalf("revert: %d %s", rec.Code, rec.Body.String())
	}
	got, _, _ := provider.GetCertificate(ctx, fp)
	if got.ManagementState != before.ManagementState || got.Origin != before.Origin ||
		got.RenewalMethod != before.RenewalMethod || got.RenewalConnectorID != before.RenewalConnectorID {
		t.Fatalf("revert != pre-takeover snapshot:\n got %+v\nwant %+v", got.CertificateItem, before.CertificateItem)
	}
	want := `{"from":"managed","to":"external","renewal_method":{"from":"acme","to":"manual"},"renewal_connector_id":{"from":"conn-acme","to":""}}`
	found := false
	for _, e := range audit.entries {
		found = found || (e.Action == "estate.takeover.revert" && e.Outcome == AuditOutcomeSuccess && e.ChangeSummary == want)
	}
	if !found {
		t.Fatalf("revert audit row %s missing: %+v", want, audit.entries)
	}
}
