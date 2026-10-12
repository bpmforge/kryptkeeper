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
	"testing"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// fakeTemplateProvider is a minimal TemplateProvider whose GetTemplate result
// is set directly per test, for exercising W4-03's algorithm-allowlist gate.
type fakeTemplateProvider struct {
	templates map[string]TemplateItem
}

func (p *fakeTemplateProvider) ListTemplates(context.Context, TemplateListQuery) (TemplateListResult, error) {
	return TemplateListResult{}, nil
}
func (p *fakeTemplateProvider) GetTemplate(_ context.Context, id string) (TemplateItem, bool, error) {
	tpl, ok := p.templates[id]
	return tpl, ok, nil
}
func (p *fakeTemplateProvider) CreateTemplate(context.Context, TemplateUpsertRequest) (TemplateItem, error) {
	return TemplateItem{}, errTemplateInvalidCreate
}
func (p *fakeTemplateProvider) ReplaceTemplate(context.Context, string, TemplateUpsertRequest, int) (TemplateItem, error) {
	return TemplateItem{}, errTemplateNotFound
}
func (p *fakeTemplateProvider) CloneTemplate(context.Context, string, TemplateCloneRequest) (TemplateItem, error) {
	return TemplateItem{}, errTemplateNotFound
}
func (p *fakeTemplateProvider) PatchTemplate(context.Context, string, TemplatePatchRequest) (TemplateItem, error) {
	return TemplateItem{}, errTemplateNotFound
}
func (p *fakeTemplateProvider) DeleteTemplate(context.Context, string) error {
	return errTemplateNotFound
}

// waveExecuteTestFixture wires a real CA-backed CertificateProvider (not a
// stub) plus a real sqlite-backed MigrationWaveStore, since W4-03's whole
// point is proving the migration loop actually calls real issuance -- a
// stub CertificateProvider whose IssueCertificate is a no-op would prove
// nothing.
type waveExecuteTestFixture struct {
	mux       *http.ServeMux
	auth      *Authenticator
	certs     CertificateProvider
	engine    *ca.Engine
	waveStore MigrationWaveStore
	templates *fakeTemplateProvider
	keys      keystore.Store
}

func newWaveExecuteTestFixture(t *testing.T) *waveExecuteTestFixture {
	t.Helper()
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := newReportsTestAuth(t)
	dir := t.TempDir()
	keys, err := keystore.NewSoftwareStore(dir, []byte("test-passphrase-for-wave-execute!"))
	if err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	engine := ca.NewEngine(keys, ca.NewMemStore())
	if _, err := engine.CreateRootCA("Wave Execute Test Root", pkix.Name{CommonName: "Wave Execute Test Root CA"}, keystore.ECDSAP256, 10*365*24*time.Hour); err != nil {
		t.Fatalf("create root CA: %v", err)
	}
	templates := &fakeTemplateProvider{templates: map[string]TemplateItem{
		// Long-lived (365d, > the 100d migration_ready threshold) so an
		// original cert issued against it is genuinely "vulnerable", the
		// realistic migrate-wave target -- not the provider's 90d default,
		// which would misleadingly read migration_ready regardless of what
		// migrate-wave does to it.
		"tpl-classical": {ID: "tpl-classical", Active: true, ValidityPeriod: "8760h", AllowedAlgorithms: []string{"ECDSA"}},
		"tpl-pqc":       {ID: "tpl-pqc", Active: true, ValidityPeriod: "8760h", AllowedAlgorithms: []string{"ECDSA", "ML-DSA-65"}},
	}}
	certs := WithTemplateProvider(NewCACertificateProvider(engine, ca.NewMemRevocationStore(), nil, false), templates)
	waveStore := newTestWaveStore(t)

	mux := http.NewServeMux()
	registerPQCWaveHandlers(mux, auth, certs, templates, waveStore, keys, stubAuditProvider{})
	return &waveExecuteTestFixture{mux: mux, auth: auth, certs: certs, engine: engine, waveStore: waveStore, templates: templates, keys: keys}
}

func waveExecuteToken(t *testing.T, auth *Authenticator, principalID, role string) string {
	t.Helper()
	_, token, err := auth.CreateAPIKey(principalID+"-key", principalID, role, []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatalf("create api key for %s: %v", principalID, err)
	}
	return token
}

func waveExecuteReq(method, path, token string, body any) *http.Request {
	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest(method, path, bytes.NewReader(b))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func TestPQCWaveExecute_ProposeRejectsNonPQCTemplate(t *testing.T) {
	fx := newWaveExecuteTestFixture(t)
	wave, err := fx.waveStore.CreateWave(context.Background(), MigrationWave{Name: "wave-1"})
	if err != nil {
		t.Fatalf("create wave: %v", err)
	}
	token := waveExecuteToken(t, fx.auth, "proposer", "pki-admin")

	rec := httptest.NewRecorder()
	fx.mux.ServeHTTP(rec, waveExecuteReq(http.MethodPost, "/api/v1/reports/pqc-waves/"+wave.ID+"/execute", token, migrateWaveExecutionParams{TemplateID: "tpl-classical"}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("propose with non-PQC template: status = %d, want 400. body: %s", rec.Code, rec.Body.String())
	}
}

func TestPQCWaveExecute_ProposeSucceeds(t *testing.T) {
	fx := newWaveExecuteTestFixture(t)
	wave, err := fx.waveStore.CreateWave(context.Background(), MigrationWave{Name: "wave-1"})
	if err != nil {
		t.Fatalf("create wave: %v", err)
	}
	token := waveExecuteToken(t, fx.auth, "proposer", "pki-admin")

	rec := httptest.NewRecorder()
	fx.mux.ServeHTTP(rec, waveExecuteReq(http.MethodPost, "/api/v1/reports/pqc-waves/"+wave.ID+"/execute", token, migrateWaveExecutionParams{TemplateID: "tpl-pqc"}))
	if rec.Code != http.StatusCreated {
		t.Fatalf("propose: status = %d, want 201. body: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data PendingAction `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Data.Status != "pending" {
		t.Errorf("action status = %q, want pending", resp.Data.Status)
	}
	if resp.Data.ActionType != "pqc_migrate_wave" {
		t.Errorf("action_type = %q, want pqc_migrate_wave", resp.Data.ActionType)
	}
}

func proposeWaveExecute(t *testing.T, fx *waveExecuteTestFixture, waveID, proposerToken string) PendingAction {
	t.Helper()
	rec := httptest.NewRecorder()
	fx.mux.ServeHTTP(rec, waveExecuteReq(http.MethodPost, "/api/v1/reports/pqc-waves/"+waveID+"/execute", proposerToken, migrateWaveExecutionParams{TemplateID: "tpl-pqc"}))
	if rec.Code != http.StatusCreated {
		t.Fatalf("propose: status = %d, want 201. body: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data PendingAction `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp.Data
}

func TestPQCWaveExecute_ApproveAsProposerForbidden(t *testing.T) {
	fx := newWaveExecuteTestFixture(t)
	wave, err := fx.waveStore.CreateWave(context.Background(), MigrationWave{Name: "wave-1"})
	if err != nil {
		t.Fatalf("create wave: %v", err)
	}
	proposerToken := waveExecuteToken(t, fx.auth, "proposer", "pki-admin")
	action := proposeWaveExecute(t, fx, wave.ID, proposerToken)

	rec := httptest.NewRecorder()
	fx.mux.ServeHTTP(rec, waveExecuteReq(http.MethodPost, "/api/v1/reports/pqc-waves/"+wave.ID+"/execute/"+action.ID+"/approve", proposerToken, nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("approve as proposer: status = %d, want 403. body: %s", rec.Code, rec.Body.String())
	}
}

func TestPQCWaveExecute_ApproveAsNonApproverForbidden(t *testing.T) {
	fx := newWaveExecuteTestFixture(t)
	wave, err := fx.waveStore.CreateWave(context.Background(), MigrationWave{Name: "wave-1"})
	if err != nil {
		t.Fatalf("create wave: %v", err)
	}
	proposerToken := waveExecuteToken(t, fx.auth, "proposer", "pki-admin")
	action := proposeWaveExecute(t, fx, wave.ID, proposerToken)
	nonApproverToken := waveExecuteToken(t, fx.auth, "auditor", "pki-auditor")

	rec := httptest.NewRecorder()
	fx.mux.ServeHTTP(rec, waveExecuteReq(http.MethodPost, "/api/v1/reports/pqc-waves/"+wave.ID+"/execute/"+action.ID+"/approve", nonApproverToken, nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("approve as non-approver role: status = %d, want 403. body: %s", rec.Code, rec.Body.String())
	}
}

// TestPQCWaveExecute_ApproveRunsMigrationWithPartialFailure is the core
// acceptance-criteria proof: real classical-CA-issued certs are re-issued
// to ML-DSA via the real certificate-issuance path (acceptance #1), a
// member whose fingerprint no longer resolves is recorded failed rather
// than aborting the whole run (acceptance #2), and the response is a
// successful 200 with a mixed result set, not an error.
func TestPQCWaveExecute_ApproveRunsMigrationWithPartialFailure(t *testing.T) {
	fx := newWaveExecuteTestFixture(t)
	ctx := context.Background()

	caID := getFirstCAID(t, fx.engine)
	csr1 := generateTestCSRPEM(t, "migrate-1.example.com")
	issued1, err := fx.certs.IssueCertificate(ctx, CertificateIssueRequest{CAID: caID, TemplateID: "tpl-classical", CSRPEM: csr1, TeamID: "team-1"})
	if err != nil {
		t.Fatalf("issue cert 1: %v", err)
	}
	csr2 := generateTestCSRPEM(t, "migrate-2.example.com")
	issued2, err := fx.certs.IssueCertificate(ctx, CertificateIssueRequest{CAID: caID, TemplateID: "tpl-classical", CSRPEM: csr2, TeamID: "team-1"})
	if err != nil {
		t.Fatalf("issue cert 2: %v", err)
	}

	wave, err := fx.waveStore.CreateWave(ctx, MigrationWave{Name: "wave-partial"})
	if err != nil {
		t.Fatalf("create wave: %v", err)
	}
	for _, fp := range []string{issued1.FingerprintSHA256, issued2.FingerprintSHA256, "does-not-exist"} {
		if err := fx.waveStore.AddMember(ctx, wave.ID, MigrationWaveMember{Fingerprint: fp}); err != nil {
			t.Fatalf("add member %s: %v", fp, err)
		}
	}

	proposerToken := waveExecuteToken(t, fx.auth, "proposer", "pki-admin")
	action := proposeWaveExecute(t, fx, wave.ID, proposerToken)
	approverToken := waveExecuteToken(t, fx.auth, "approver", "pki-operator")

	rec := httptest.NewRecorder()
	fx.mux.ServeHTTP(rec, waveExecuteReq(http.MethodPost, "/api/v1/reports/pqc-waves/"+wave.ID+"/execute/"+action.ID+"/approve", approverToken, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: status = %d, want 200. body: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data migrateWaveExecutionResult `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Data.Migrated != 2 {
		t.Errorf("migrated = %d, want 2", resp.Data.Migrated)
	}
	if resp.Data.Failed != 1 {
		t.Errorf("failed = %d, want 1", resp.Data.Failed)
	}
	if len(resp.Data.Results) != 3 {
		t.Fatalf("results length = %d, want 3 (never silently dropped)", len(resp.Data.Results))
	}

	// Independently verify: the migrated members' new certs are real,
	// ML-DSA-keyed, and re-parsing shows the correct PQCReadiness.
	migratedCount := 0
	for _, r := range resp.Data.Results {
		if r.Status != "migrated" {
			continue
		}
		migratedCount++
		detail, ok, err := fx.certs.GetCertificate(ctx, r.NewFingerprint)
		if err != nil || !ok {
			t.Fatalf("new cert %s not found: ok=%v err=%v", r.NewFingerprint, ok, err)
		}
		if detail.PublicKeyAlgorithm == "" || detail.PublicKeyAlgorithm == "ECDSA" {
			t.Errorf("migrated cert %s PublicKeyAlgorithm = %q, want ML-DSA", r.NewFingerprint, detail.PublicKeyAlgorithm)
		}
	}
	if migratedCount != 2 {
		t.Fatalf("expected 2 results with status=migrated, got %d", migratedCount)
	}

	// Re-approving an already-decided action must not silently succeed again.
	rec2 := httptest.NewRecorder()
	fx.mux.ServeHTTP(rec2, waveExecuteReq(http.MethodPost, "/api/v1/reports/pqc-waves/"+wave.ID+"/execute/"+action.ID+"/approve", approverToken, nil))
	if rec2.Code != http.StatusConflict {
		t.Errorf("re-approve already-decided action: status = %d, want 409", rec2.Code)
	}
}

// TestPQCWaveExecute_ProgressAdvancesAfterMigration proves the other half
// of acceptance #1 ("advances tracked progress", not just "re-issues"):
// caught by advisor before close -- runWaveMigration's first draft called
// IssueCertificate, which creates a wholly independent new cert with no
// link back to the wave member's original fingerprint, so a subsequent GET
// showed 0% progress even after every member was successfully migrated
// (confirmed empirically with a real long-lived classical cert before
// fixing). Fixed by switching to CertificateProvider.RenewCertificate --
// the same PredecessorFP/SuccessorFP chaining every other renewal in the
// product already uses -- and excluding superseded certs from
// vulnerableFingerprints's count.
func TestPQCWaveExecute_ProgressAdvancesAfterMigration(t *testing.T) {
	fx := newWaveExecuteTestFixture(t)
	ctx := context.Background()
	caID := getFirstCAID(t, fx.engine)

	// A genuinely long-lived (365d) classical cert -- the realistic
	// migrate-wave target, PQCReadiness=="vulnerable" (validity exceeds the
	// 100-day migration_ready threshold), not the provider's short default.
	csr := generateTestCSRPEM(t, "progress-check.example.com")
	issued, err := fx.certs.IssueCertificate(ctx, CertificateIssueRequest{CAID: caID, TemplateID: "tpl-classical", CSRPEM: csr, TeamID: "team-1"})
	if err != nil {
		t.Fatalf("issue original cert: %v", err)
	}
	if issued.PQCReadiness != "vulnerable" {
		t.Fatalf("precondition failed: original cert PQCReadiness = %q, want vulnerable", issued.PQCReadiness)
	}

	wave, err := fx.waveStore.CreateWave(ctx, MigrationWave{Name: "progress-wave"})
	if err != nil {
		t.Fatalf("create wave: %v", err)
	}
	if err := fx.waveStore.AddMember(ctx, wave.ID, MigrationWaveMember{Fingerprint: issued.FingerprintSHA256}); err != nil {
		t.Fatalf("add member: %v", err)
	}

	// Confirm the precondition: progress is 0% before EXECUTE.
	getToken := waveExecuteToken(t, fx.auth, "reader", "pki-admin")
	before := listWavesForTest(t, fx.mux, getToken)
	if len(before) != 1 || before[0].Migrated != 0 || before[0].ProgressPercent != 0 {
		t.Fatalf("precondition failed: wave progress before EXECUTE = %+v, want 0/0%%", before)
	}

	proposerToken := waveExecuteToken(t, fx.auth, "proposer", "pki-admin")
	action := proposeWaveExecute(t, fx, wave.ID, proposerToken)
	approverToken := waveExecuteToken(t, fx.auth, "approver", "pki-operator")
	rec := httptest.NewRecorder()
	fx.mux.ServeHTTP(rec, waveExecuteReq(http.MethodPost, "/api/v1/reports/pqc-waves/"+wave.ID+"/execute/"+action.ID+"/approve", approverToken, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: status = %d, want 200. body: %s", rec.Code, rec.Body.String())
	}

	after := listWavesForTest(t, fx.mux, getToken)
	if len(after) != 1 || after[0].Migrated != 1 || after[0].ProgressPercent != 100 {
		t.Fatalf("wave progress after EXECUTE = %+v, want migrated=1 progress_percent=100", after)
	}

	// Independently verify the predecessor/successor chain was actually
	// set, not just that progress happens to read 100% by coincidence.
	predecessorDetail, ok, err := fx.certs.GetCertificate(ctx, issued.FingerprintSHA256)
	if err != nil || !ok {
		t.Fatalf("get predecessor: ok=%v err=%v", ok, err)
	}
	if predecessorDetail.SuccessorFP == nil {
		t.Fatal("predecessor cert has no SuccessorFP set after migration")
	}
	if predecessorDetail.RenewalStatus != "renewed" {
		t.Errorf("predecessor RenewalStatus = %q, want renewed", predecessorDetail.RenewalStatus)
	}
	successorDetail, ok, err := fx.certs.GetCertificate(ctx, *predecessorDetail.SuccessorFP)
	if err != nil || !ok {
		t.Fatalf("get successor: ok=%v err=%v", ok, err)
	}
	if successorDetail.PublicKeyAlgorithm == "" || successorDetail.PublicKeyAlgorithm == "ECDSA" {
		t.Errorf("successor PublicKeyAlgorithm = %q, want ML-DSA", successorDetail.PublicKeyAlgorithm)
	}
}

func listWavesForTest(t *testing.T, mux *http.ServeMux, token string) []WaveProgress {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, waveExecuteReq(http.MethodGet, "/api/v1/reports/pqc-waves", token, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list waves: status = %d, body: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data []WaveProgress `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode list waves response: %v", err)
	}
	return resp.Data
}
