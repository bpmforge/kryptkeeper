// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"testing"
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
