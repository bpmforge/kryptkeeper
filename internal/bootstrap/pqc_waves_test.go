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
	"testing"

	_ "modernc.org/sqlite"
)

// --- derive logic ---

func TestDerivePQCWaves_Classifies(t *testing.T) {
	certs := []CertificateItem{
		{FingerprintSHA256: "t1", CommonName: "api.staging.example.com", PQCReadiness: "vulnerable"},
		{FingerprintSHA256: "c1", CommonName: "shop.example.com", SubjectAltNames: []string{"shop.example.com"}, PQCReadiness: "vulnerable", OwnerTeam: "payments"},
		{FingerprintSHA256: "i1", CommonName: "db", SubjectAltNames: []string{"db.corp.local"}, PQCReadiness: "vulnerable"},
		{FingerprintSHA256: "safe", CommonName: "pqc", PQCReadiness: "quantum_safe"}, // skipped
	}
	waves := derivePQCWaves(certs)

	got := map[string][]string{}
	for _, w := range waves {
		for _, m := range w.Members {
			got[w.Name] = append(got[w.Name], m.Fingerprint)
		}
	}
	if len(got["Test"]) != 1 || got["Test"][0] != "t1" {
		t.Errorf("Test wave wrong: %v", got["Test"])
	}
	if len(got["Customer-Facing"]) != 1 || got["Customer-Facing"][0] != "c1" {
		t.Errorf("Customer-Facing wave wrong: %v", got["Customer-Facing"])
	}
	if len(got["Internal"]) != 1 || got["Internal"][0] != "i1" {
		t.Errorf("Internal wave wrong: %v", got["Internal"])
	}
	// quantum-safe cert must not appear anywhere.
	for _, w := range waves {
		for _, m := range w.Members {
			if m.Fingerprint == "safe" {
				t.Error("quantum-safe cert should not be in any wave")
			}
		}
	}
	// Owner inferred from the dominant team in the Customer-Facing wave.
	for _, w := range waves {
		if w.Name == "Customer-Facing" && w.Owner != "payments" {
			t.Errorf("expected owner=payments, got %q", w.Owner)
		}
	}
}

// --- store ---

func newTestWaveStore(t *testing.T) *dbMigrationWaveStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "waves.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := &dbMigrationWaveStore{db: db, ph: sqlitePlaceholder}
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return s
}

func TestMigrationWaveStore_CRUDAndMembers(t *testing.T) {
	s := newTestWaveStore(t)
	ctx := context.Background()

	w, err := s.CreateWave(ctx, MigrationWave{
		Name: "Internal", Owner: "infra",
		Members: []MigrationWaveMember{{Fingerprint: "fp1", CommonName: "a"}},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	waves, _ := s.ListWaves(ctx)
	if len(waves) != 1 || len(waves[0].Members) != 1 {
		t.Fatalf("list wrong: %+v", waves)
	}

	// AddMember is unique-per-fingerprint (acts as a move).
	w2, _ := s.CreateWave(ctx, MigrationWave{Name: "Test"})
	if err := s.AddMember(ctx, w2.ID, MigrationWaveMember{Fingerprint: "fp1", CommonName: "a"}); err != nil {
		t.Fatalf("add member: %v", err)
	}
	waves, _ = s.ListWaves(ctx)
	total := 0
	for _, wv := range waves {
		total += len(wv.Members)
	}
	if total != 1 {
		t.Fatalf("expected fp1 in exactly one wave after move, got %d total members", total)
	}

	if err := s.DeleteWave(ctx, w.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := s.DeleteAllWaves(ctx); err != nil {
		t.Fatalf("delete all: %v", err)
	}
	if waves, _ := s.ListWaves(ctx); len(waves) != 0 {
		t.Fatalf("expected empty, got %d", len(waves))
	}
}

// --- handlers ---

func waveTestMux(t *testing.T, certs *reportCertProvider) (*http.ServeMux, MigrationWaveStore) {
	t.Helper()
	auth := newReportsTestAuth(t)
	store := newTestWaveStore(t)
	mux := http.NewServeMux()
	registerPQCWaveHandlers(mux, auth, certs, stubTemplateProvider{}, store, nil, stubAuditProvider{})
	return mux, store
}

func TestPQCWaveHandlers_AutoDeriveListProgress(t *testing.T) {
	certs := &reportCertProvider{items: []CertificateItem{
		{FingerprintSHA256: "t1", CommonName: "x.staging.example.com", PQCReadiness: "vulnerable"},
		{FingerprintSHA256: "c1", CommonName: "shop.example.com", SubjectAltNames: []string{"shop.example.com"}, PQCReadiness: "vulnerable"},
	}}
	mux, _ := waveTestMux(t, certs)

	// Auto-derive.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/reports/pqc-waves/auto-derive", []byte("{}")))
	if rec.Code != http.StatusOK {
		t.Fatalf("auto-derive: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// List with progress (nothing migrated yet → 0%).
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, authedReq(http.MethodGet, "/api/v1/reports/pqc-waves", nil))
	var resp struct {
		Data []WaveProgress `json:"data"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Data) != 2 {
		t.Fatalf("expected 2 waves, got %d", len(resp.Data))
	}
	for _, wp := range resp.Data {
		if wp.Total != 1 || wp.Migrated != 0 || wp.ProgressPercent != 0 {
			t.Errorf("expected 0%% progress, got %+v", wp)
		}
	}
}

func TestPQCWaveHandlers_ProgressReflectsMigration(t *testing.T) {
	// c1 vulnerable, t1 already migrated (quantum_safe) — wave member t1 counts done.
	certs := &reportCertProvider{items: []CertificateItem{
		{FingerprintSHA256: "c1", CommonName: "shop.example.com", SubjectAltNames: []string{"shop.example.com"}, PQCReadiness: "vulnerable"},
	}}
	mux, store := waveTestMux(t, certs)
	ctx := context.Background()
	_, _ = store.CreateWave(ctx, MigrationWave{
		Name: "W", Members: []MigrationWaveMember{
			{Fingerprint: "c1"},   // still vulnerable
			{Fingerprint: "gone"}, // not in inventory → treated as migrated
		},
	})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/reports/pqc-waves", nil))
	var resp struct {
		Data []WaveProgress `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Data) != 1 {
		t.Fatalf("expected 1 wave, got %d", len(resp.Data))
	}
	wp := resp.Data[0]
	if wp.Total != 2 || wp.Migrated != 1 || wp.ProgressPercent != 50 {
		t.Fatalf("expected 1/2 migrated (50%%), got %+v", wp)
	}
}

// --- lifecycle status (W2-08) ---

func TestAdvanceWaveStatus(t *testing.T) {
	cases := []struct {
		name            string
		current         string
		progressPercent int
		total           int
		want            string
	}{
		{"proposed stays proposed even at 100%", waveStatusProposed, 100, 2, waveStatusProposed},
		{"accepted at 0% stays accepted", waveStatusAccepted, 0, 2, waveStatusAccepted},
		{"accepted partial becomes in_progress", waveStatusAccepted, 50, 2, waveStatusInProgress},
		{"accepted full becomes done", waveStatusAccepted, 100, 2, waveStatusDone},
		{"in_progress full becomes done", waveStatusInProgress, 100, 2, waveStatusDone},
		{"in_progress back to 0% becomes accepted", waveStatusInProgress, 0, 2, waveStatusAccepted},
		{"empty wave (total=0) accepted stays accepted, not done", waveStatusAccepted, 0, 0, waveStatusAccepted},
		{"done stays done at 100%", waveStatusDone, 100, 2, waveStatusDone},
		{"done regresses below 100%", waveStatusDone, 50, 2, waveStatusRegressed},
		{"done with all members removed (total=0) stays done, not regressed", waveStatusDone, 0, 0, waveStatusDone},
		{"regressed is sticky even back at 100%", waveStatusRegressed, 100, 2, waveStatusRegressed},
		{"regressed is sticky at 0%", waveStatusRegressed, 0, 2, waveStatusRegressed},
		{"unknown/empty current defaults to proposed", "", 0, 2, waveStatusProposed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := advanceWaveStatus(c.current, c.progressPercent, c.total)
			if got != c.want {
				t.Errorf("advanceWaveStatus(%q, %d, %d) = %q, want %q", c.current, c.progressPercent, c.total, got, c.want)
			}
		})
	}
}

// TestPQCWaveHandlers_StatusLifecyclePersistsAndRegressionSticks mutates
// certs.items between requests (reportCertProvider.ListCertificates reads
// the field live, not a snapshot) to simulate a wave member's PQC readiness
// changing over time: migrated, then regressed, then recovered.
func TestPQCWaveHandlers_StatusLifecyclePersistsAndRegressionSticks(t *testing.T) {
	certs := &reportCertProvider{items: []CertificateItem{
		{FingerprintSHA256: "c1", CommonName: "shop.example.com", PQCReadiness: "vulnerable"},
	}}
	mux, store := waveTestMux(t, certs)
	ctx := context.Background()

	created, err := store.CreateWave(ctx, MigrationWave{
		Name: "W", Members: []MigrationWaveMember{{Fingerprint: "c1"}},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Status != waveStatusProposed {
		t.Fatalf("expected new wave to start proposed, got %q", created.Status)
	}

	// A freshly created (not yet accepted) wave stays "proposed" even though
	// nothing about its progress has changed — no auto-accept.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/reports/pqc-waves", nil))
	var listResp struct {
		Data []WaveProgress `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &listResp)
	if listResp.Data[0].Status != waveStatusProposed {
		t.Fatalf("expected proposed before accept, got %q", listResp.Data[0].Status)
	}

	// Explicitly accept.
	acceptRec := httptest.NewRecorder()
	mux.ServeHTTP(acceptRec, authedReq(http.MethodPost, "/api/v1/reports/pqc-waves/"+created.ID+"/accept", []byte("{}")))
	if acceptRec.Code != http.StatusOK {
		t.Fatalf("accept: expected 200, got %d: %s", acceptRec.Code, acceptRec.Body.String())
	}
	waves, _ := store.ListWaves(ctx)
	if waves[0].Status != waveStatusAccepted {
		t.Fatalf("expected accepted after accept action, got %q", waves[0].Status)
	}

	// Member migrates (no longer vulnerable) → GET must persist done, not
	// just report it in the response.
	certs.items = []CertificateItem{
		{FingerprintSHA256: "c1", CommonName: "shop.example.com", PQCReadiness: "quantum_safe"},
	}
	mux.ServeHTTP(httptest.NewRecorder(), authedReq(http.MethodGet, "/api/v1/reports/pqc-waves", nil))
	waves, _ = store.ListWaves(ctx)
	if waves[0].Status != waveStatusDone {
		t.Fatalf("expected done persisted in store after migration, got %q", waves[0].Status)
	}

	// Member regresses (vulnerable again, e.g. re-issued with a classical
	// key) → GET must persist regressed, queried directly from the store,
	// not just recomputed in the response.
	certs.items = []CertificateItem{
		{FingerprintSHA256: "c1", CommonName: "shop.example.com", PQCReadiness: "vulnerable"},
	}
	mux.ServeHTTP(httptest.NewRecorder(), authedReq(http.MethodGet, "/api/v1/reports/pqc-waves", nil))
	waves, _ = store.ListWaves(ctx)
	if waves[0].Status != waveStatusRegressed {
		t.Fatalf("expected regressed persisted in store after regression, got %q", waves[0].Status)
	}

	// Member recovers again (migrated once more) — the regression must
	// remain a recorded fact, NOT silently self-heal back to done.
	certs.items = []CertificateItem{
		{FingerprintSHA256: "c1", CommonName: "shop.example.com", PQCReadiness: "quantum_safe"},
	}
	mux.ServeHTTP(httptest.NewRecorder(), authedReq(http.MethodGet, "/api/v1/reports/pqc-waves", nil))
	waves, _ = store.ListWaves(ctx)
	if waves[0].Status != waveStatusRegressed {
		t.Fatalf("expected regressed to stay sticky after recovery, got %q — a regression must not auto-heal", waves[0].Status)
	}

	// Only an explicit accept clears it.
	mux.ServeHTTP(httptest.NewRecorder(), authedReq(http.MethodPost, "/api/v1/reports/pqc-waves/"+created.ID+"/accept", []byte("{}")))
	waves, _ = store.ListWaves(ctx)
	if waves[0].Status != waveStatusAccepted {
		t.Fatalf("expected accept to clear a sticky regression, got %q", waves[0].Status)
	}
}

func TestPQCWaveHandlers_CreateAndDelete(t *testing.T) {
	mux, _ := waveTestMux(t, &reportCertProvider{})
	body, _ := json.Marshal(MigrationWave{Name: "Manual wave", Owner: "sec"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/reports/pqc-waves", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d", rec.Code)
	}
	var created struct {
		Data MigrationWave `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, authedReq(http.MethodDelete, "/api/v1/reports/pqc-waves/"+created.Data.ID, nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("delete: expected 200, got %d", rec2.Code)
	}
}
