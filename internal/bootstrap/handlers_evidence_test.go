// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"strings"
	"testing"
	"time"
)

func evidenceTestMux(t *testing.T, mailer *EvidenceMailer) (*http.ServeMux, *Authenticator) {
	t.Helper()
	auth := newReportsTestAuth(t)
	store := newTestScheduleStore(t)
	mux := http.NewServeMux()
	registerEvidenceHandlers(mux, auth,
		&reportCertProvider{items: buildTestCerts()}, &reportCAProvider{}, store, mailer, stubAuditProvider{})
	return mux, auth
}

func authedReq(method, url string, body []byte) *http.Request {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, url, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, url, nil)
	}
	r.Header.Set("Authorization", "Bearer reports-test-token")
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestEvidenceSchedules_CreateListDelete(t *testing.T) {
	mux, _ := evidenceTestMux(t, NewEvidenceMailerFromEnv())

	// Create.
	body, _ := json.Marshal(EvidenceSchedule{Framework: "pci", Cadence: "monthly", Recipients: []string{"a@x.com"}, Enabled: true})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/reports/evidence/schedules", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Data EvidenceSchedule `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created.Data.ID == "" {
		t.Fatal("expected schedule id")
	}

	// List.
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, authedReq(http.MethodGet, "/api/v1/reports/evidence/schedules", nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", rec2.Code)
	}
	var list struct {
		Data []EvidenceSchedule `json:"data"`
	}
	_ = json.Unmarshal(rec2.Body.Bytes(), &list)
	if len(list.Data) != 1 {
		t.Fatalf("expected 1 schedule, got %d", len(list.Data))
	}

	// Delete.
	rec3 := httptest.NewRecorder()
	mux.ServeHTTP(rec3, authedReq(http.MethodDelete, "/api/v1/reports/evidence/schedules/"+created.Data.ID, nil))
	if rec3.Code != http.StatusOK {
		t.Fatalf("delete: expected 200, got %d", rec3.Code)
	}
}

func TestEvidenceSchedules_CreateRequiresRecipients(t *testing.T) {
	mux, _ := evidenceTestMux(t, NewEvidenceMailerFromEnv())
	body, _ := json.Marshal(EvidenceSchedule{Framework: "pci"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/reports/evidence/schedules", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without recipients, got %d", rec.Code)
	}
}

func TestEvidenceSend_SMTPNotConfigured(t *testing.T) {
	mux, _ := evidenceTestMux(t, NewEvidenceMailerFromEnv()) // no SMTP env → disabled
	body, _ := json.Marshal(map[string]any{"framework": "pci", "recipients": []string{"a@x.com"}})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/reports/evidence/send", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when SMTP unconfigured, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestEvidenceSend_RendersAndMails(t *testing.T) {
	var sentMsg []byte
	mailer := &EvidenceMailer{host: "smtp.x", from: "noreply@x", send: func(_ string, _ smtp.Auth, _ string, _ []string, msg []byte) error {
		sentMsg = msg
		return nil
	}}
	mux, _ := evidenceTestMux(t, mailer)

	body, _ := json.Marshal(map[string]any{"framework": "pci", "recipients": []string{"a@x.com"}})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/reports/evidence/send", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	// The email must carry a PDF attachment.
	if !bytes.Contains(sentMsg, []byte("application/pdf")) {
		t.Error("sent email missing PDF attachment")
	}
}

// seedAcceptedRiskStore opens the env-configured exception store (the one the
// reports handler self-constructs) on a temp DB and seeds two active and one
// lapsed exception.
func seedAcceptedRiskStore(t *testing.T) FindingExceptionStore {
	t.Helper()
	t.Setenv("APP_FINDINGS_DB_DSN", "file:"+t.TempDir()+"/accepted-risk.db?cache=shared&_fk=1&_journal_mode=WAL")
	store, err := newFindingExceptionStoreFromEnv()
	if err != nil {
		t.Fatalf("exception store: %v", err)
	}
	now := time.Now().UTC()
	for _, e := range []FindingException{
		{ID: "exc-late", TargetType: FindingExceptionTargetCertificate, TargetID: "fp-owned", FindingCode: "WEAK_RSA_KEY",
			JustificationCode: JustificationCompensatingControl, JustificationNote: "behind WAF", CreatedBy: "alice",
			CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(60 * 24 * time.Hour).Format(time.RFC3339)},
		{ID: "exc-soon", TargetType: FindingExceptionTargetCA, TargetID: "ca-1", FindingCode: "CA_ALGO",
			JustificationCode: JustificationRiskAccepted, CreatedBy: "bob",
			CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(10 * 24 * time.Hour).Format(time.RFC3339)},
		{ID: "exc-lapsed", TargetType: FindingExceptionTargetCertificate, TargetID: "fp-owned", FindingCode: "OLD",
			JustificationCode: JustificationRiskAccepted, CreatedBy: "carol",
			CreatedAt: now.Add(-48 * time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(-time.Hour).Format(time.RFC3339)},
		{ID: "exc-foreign", TargetType: FindingExceptionTargetCertificate, TargetID: "fp-other-tenant", FindingCode: "WEAK_RSA_KEY",
			JustificationCode: JustificationRiskAccepted, CreatedBy: "mallory",
			CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339)},
	} {
		if err := store.Create(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	return store
}

func acceptedRiskReportMux(t *testing.T) *http.ServeMux {
	t.Helper()
	auth := newReportsTestAuth(t)
	mux := http.NewServeMux()
	certs := &reportCertProvider{items: []CertificateItem{
		{FingerprintSHA256: "fp-owned", CommonName: "pay.example.com", OwnerTeam: "payments", OwnerEmail: "pay@example.com"},
	}}
	// fp-other-tenant is deliberately absent from the visible inventory.
	registerReportsHandlers(mux, auth, certs, exceptionCAs{ids: map[string]bool{"ca-1": true}}, stubTemplateProvider{}, nil, stubAuditProvider{})
	return mux
}

type acceptedRiskPack struct {
	Data struct {
		AcceptedRisks json.RawMessage `json:"accepted_risks"`
	} `json:"data"`
}

func TestAcceptedRisksInPackJSON(t *testing.T) {
	seedAcceptedRiskStore(t)
	mux := acceptedRiskReportMux(t)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/reports/compliance-evidence?framework=all", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var pack acceptedRiskPack
	if err := json.Unmarshal(rec.Body.Bytes(), &pack); err != nil {
		t.Fatal(err)
	}
	var risks []AcceptedRisk
	if err := json.Unmarshal(pack.Data.AcceptedRisks, &risks); err != nil {
		t.Fatalf("accepted_risks: %v (%s)", err, pack.Data.AcceptedRisks)
	}
	// Exactly the two active, in-scope exceptions, soonest expiry first; the
	// lapsed one and the one on a certificate outside the visible set are out.
	if len(risks) != 2 || risks[0].ID != "exc-soon" || risks[1].ID != "exc-late" {
		t.Fatalf("risks = %+v", risks)
	}
	late := risks[1]
	if late.OwnerTeam != "payments" || late.OwnerEmail != "pay@example.com" || late.JustificationCode != JustificationCompensatingControl ||
		late.ExpiresAt == "" || late.CreatedBy != "alice" || late.JustificationNote != "behind WAF" {
		t.Fatalf("late = %+v", late)
	}
	if risks[0].OwnerTeam != "" || risks[0].TargetType != FindingExceptionTargetCA {
		t.Fatalf("CA-target risk must be unowned: %+v", risks[0])
	}
}

func TestAcceptedRisksEmptyIsArray(t *testing.T) {
	t.Setenv("APP_FINDINGS_DB_DSN", "file:"+t.TempDir()+"/empty.db?cache=shared&_fk=1&_journal_mode=WAL")
	mux := acceptedRiskReportMux(t)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/reports/compliance-evidence", nil))
	var pack acceptedRiskPack
	if err := json.Unmarshal(rec.Body.Bytes(), &pack); err != nil || string(pack.Data.AcceptedRisks) != "[]" {
		t.Fatalf("accepted_risks = %s (err %v)", pack.Data.AcceptedRisks, err)
	}
}

func TestAcceptedRisksTenantScoped(t *testing.T) {
	store := seedAcceptedRiskStore(t)
	// A tenant whose visible inventory is just fp-owned must not see the
	// exception on fp-other-tenant, nor a CA it cannot see.
	risks := buildAcceptedRisks(context.Background(), store,
		[]CertificateItem{{FingerprintSHA256: "fp-owned"}}, nil, time.Now())
	if len(risks) != 1 || risks[0].ID != "exc-late" {
		t.Fatalf("risks = %+v", risks)
	}
	if got := buildAcceptedRisks(context.Background(), nil, nil, nil, time.Now()); got == nil || len(got) != 0 {
		t.Fatalf("nil store must give an empty non-nil slice: %#v", got)
	}
}

func TestRenderEvidencePackWithExceptions(t *testing.T) {
	store := seedAcceptedRiskStore(t)
	prev := pdfCompression
	pdfCompression = false
	t.Cleanup(func() { pdfCompression = prev })
	certs := &reportCertProvider{items: []CertificateItem{{FingerprintSHA256: "fp-owned", CommonName: "pay.example.com", OwnerTeam: "payments"}}}
	b, name, err := renderEvidencePackWithExceptions(context.Background(), certs, exceptionCAs{ids: map[string]bool{"ca-1": true}}, store, "all", time.Now().UTC())
	if err != nil || !strings.HasSuffix(name, ".pdf") {
		t.Fatalf("render: %v %s", err, name)
	}
	text := pdfText(b)
	for _, want := range []string{"Accepted risks (2)", "WEAK_RSA_KEY", "CA_ALGO", "payments"} {
		if !strings.Contains(text, want) {
			t.Errorf("pack PDF lacks %q", want)
		}
	}
	if strings.Contains(text, "mallory") || strings.Contains(text, "OLD") {
		t.Error("pack PDF lists an out-of-scope or lapsed exception")
	}
}

func TestEvidenceSchedules_CreateDefaultsEnabled(t *testing.T) {
	mux, _ := evidenceTestMux(t, NewEvidenceMailerFromEnv())
	body := []byte(`{"framework":"soc2","cadence":"weekly","recipients":["grc@x.com"]}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/reports/evidence/schedules", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Data EvidenceSchedule `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if !created.Data.Enabled {
		t.Fatal("schedule created without an enabled field must default to enabled")
	}

	body = []byte(`{"framework":"soc2","cadence":"weekly","recipients":["grc@x.com"],"enabled":false}`)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/reports/evidence/schedules", body))
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created.Data.Enabled {
		t.Fatal("explicit enabled=false must be kept")
	}
}
