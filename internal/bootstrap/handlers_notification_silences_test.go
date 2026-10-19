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
	"time"

	_ "modernc.org/sqlite"
)

// newNotifSilencesTestMux wires the full silence CRUD surface against a real
// (temp-dir) sqlite DB — KRYPTKEEPER_DATA_DIR must be set to a temp dir or
// newNotificationSilenceStoreFromEnv would default to ./var/kryptkeeper.db in
// the repo's actual working directory.
func newNotifSilencesTestMux(t *testing.T) *http.ServeMux {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	provider := newFileNotificationProvider()
	registerNotificationHandlers(mux, auth, provider, stubAuditProvider{}, nil)
	return mux
}

func silencesAuthedReq(method, url string, body []byte) *http.Request {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, url, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, url, nil)
	}
	r.Header.Set("Authorization", "Bearer test-token")
	r.Header.Set("Content-Type", "application/json")
	return r
}

// TestNotificationSilences_CreateListDelete is the W1-10/G-60 acceptance
// regression: an operator can create, list, and delete a silence via the
// HTTP surface — the part W1-06 shipped without.
func TestNotificationSilences_CreateListDelete(t *testing.T) {
	mux := newNotifSilencesTestMux(t)

	createBody, _ := json.Marshal(map[string]string{
		"target_type": SilenceTargetCertificate,
		"target_id":   "fp-legacy",
	})
	createRec := httptest.NewRecorder()
	mux.ServeHTTP(createRec, silencesAuthedReq(http.MethodPost, "/api/v1/notifications/silences", createBody))
	if createRec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", createRec.Code, createRec.Body.String())
	}
	var createResp struct {
		Data NotificationSilence `json:"data"`
	}
	if err := json.Unmarshal(createRec.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if createResp.Data.ID == "" || createResp.Data.TargetType != SilenceTargetCertificate || createResp.Data.TargetID != "fp-legacy" {
		t.Fatalf("unexpected create response: %+v", createResp.Data)
	}
	if createResp.Data.CreatedBy == "" {
		t.Error("expected created_by to be stamped from the authenticated principal")
	}

	listRec := httptest.NewRecorder()
	mux.ServeHTTP(listRec, silencesAuthedReq(http.MethodGet, "/api/v1/notifications/silences?target_type=certificate&target_id=fp-legacy", nil))
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", listRec.Code, listRec.Body.String())
	}
	var listResp struct {
		Data struct {
			Items []NotificationSilence `json:"items"`
		} `json:"data"`
		Meta struct {
			Total int `json:"total"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if listResp.Meta.Total != 1 || len(listResp.Data.Items) != 1 {
		t.Fatalf("expected 1 silence listed, got %+v", listResp)
	}

	deleteRec := httptest.NewRecorder()
	mux.ServeHTTP(deleteRec, silencesAuthedReq(http.MethodDelete, "/api/v1/notifications/silences/"+createResp.Data.ID, nil))
	if deleteRec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", deleteRec.Code, deleteRec.Body.String())
	}

	listAfterDeleteRec := httptest.NewRecorder()
	mux.ServeHTTP(listAfterDeleteRec, silencesAuthedReq(http.MethodGet, "/api/v1/notifications/silences?target_type=certificate&target_id=fp-legacy", nil))
	var listAfterDeleteResp struct {
		Meta struct {
			Total int `json:"total"`
		} `json:"meta"`
	}
	_ = json.Unmarshal(listAfterDeleteRec.Body.Bytes(), &listAfterDeleteResp)
	if listAfterDeleteResp.Meta.Total != 0 {
		t.Fatalf("expected 0 silences after delete, got %d", listAfterDeleteResp.Meta.Total)
	}
}

// TestNotificationSilences_CreateRejectsInvalidTargetType proves the
// endpoint validates target_type before hitting the store.
func TestNotificationSilences_CreateRejectsInvalidTargetType(t *testing.T) {
	mux := newNotifSilencesTestMux(t)

	body, _ := json.Marshal(map[string]string{"target_type": "endpoint", "target_id": "x"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, silencesAuthedReq(http.MethodPost, "/api/v1/notifications/silences", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an invalid target_type, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestNotificationSilences_ReadOnlyRoleCannotMutate is the discriminating
// authz regression: the silence endpoints are deliberately gated MORE
// strictly than their neighboring /notifications/rules endpoints (which
// have no role check at all beyond authentication — see G-61). Every other
// test in this file authenticates as the bootstrap super-admin, which
// passes every gate regardless of which helper (or whether an inverted one)
// is actually wired in — this test mints a pki-auditor key (passes
// canReadOperationalSummaries, does NOT pass canManageNotifications) and
// proves GET succeeds while POST/DELETE are denied.
func TestNotificationSilences_ReadOnlyRoleCannotMutate(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	registerNotificationHandlers(mux, auth, newFileNotificationProvider(), stubAuditProvider{}, nil)

	_, auditorKey, err := auth.CreateAPIKey("auditor-integration", "auditor-svc", "pki-auditor", nil, "", "", time.Now())
	if err != nil {
		t.Fatalf("create pki-auditor api key: %v", err)
	}
	auditorReq := func(method, url string, body []byte) *http.Request {
		var r *http.Request
		if body != nil {
			r = httptest.NewRequest(method, url, bytes.NewReader(body))
		} else {
			r = httptest.NewRequest(method, url, nil)
		}
		r.Header.Set("Authorization", "Bearer "+auditorKey)
		return r
	}

	getRec := httptest.NewRecorder()
	mux.ServeHTTP(getRec, auditorReq(http.MethodGet, "/api/v1/notifications/silences?target_type=certificate&target_id=fp-1", nil))
	if getRec.Code != http.StatusOK {
		t.Fatalf("expected pki-auditor GET to succeed (200), got %d: %s", getRec.Code, getRec.Body.String())
	}

	createBody, _ := json.Marshal(map[string]string{"target_type": SilenceTargetCertificate, "target_id": "fp-1"})
	postRec := httptest.NewRecorder()
	mux.ServeHTTP(postRec, auditorReq(http.MethodPost, "/api/v1/notifications/silences", createBody))
	if postRec.Code != http.StatusForbidden {
		t.Fatalf("expected pki-auditor POST to be denied (403), got %d: %s", postRec.Code, postRec.Body.String())
	}

	deleteRec := httptest.NewRecorder()
	mux.ServeHTTP(deleteRec, auditorReq(http.MethodDelete, "/api/v1/notifications/silences/sil-whatever", nil))
	if deleteRec.Code != http.StatusForbidden {
		t.Fatalf("expected pki-auditor DELETE to be denied (403), got %d: %s", deleteRec.Code, deleteRec.Body.String())
	}
}

// TestNotificationSilences_RequiresAuth proves the endpoint isn't reachable
// without authentication.
func TestNotificationSilences_RequiresAuth(t *testing.T) {
	mux := newNotifSilencesTestMux(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/notifications/silences?target_type=certificate&target_id=fp-1", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// TestNotificationSilences_EndpointTakesEffectOnNextSchedulerScan is the
// second half of W1-10's acceptance criterion: a silence created through the
// HTTP endpoint must be visible to a SEPARATE renewal-scheduler instance
// reading the same underlying DB — proving the endpoint and the scheduler
// share the real store, not two independent ones.
func TestNotificationSilences_EndpointTakesEffectOnNextSchedulerScan(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("KRYPTKEEPER_DATA_DIR", dataDir)
	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	registerNotificationHandlers(mux, auth, newFileNotificationProvider(), stubAuditProvider{}, nil)

	body, _ := json.Marshal(map[string]string{
		"target_type": SilenceTargetCertificate,
		"target_id":   "fp-silenced-via-api",
	})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, silencesAuthedReq(http.MethodPost, "/api/v1/notifications/silences", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// A fresh sqlite handle onto the SAME data dir's DB file, exactly what
	// the scheduler's own env-based constructor would open.
	db, err := sql.Open("sqlite", filepath.Join(dataDir, "kryptkeeper.db")+"?cache=shared&_fk=1&_journal_mode=WAL")
	if err != nil {
		t.Fatalf("open shared db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	silenceStore := &sqliteNotificationSilenceStore{db: db}
	if err := silenceStore.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	soon := time.Now().UTC().Add(10 * 24 * time.Hour).Format(time.RFC3339)
	s := &RenewalScheduler{
		certProvider: &reportCertProvider{items: []CertificateItem{
			{FingerprintSHA256: "fp-silenced-via-api", CommonName: "s", ValidUntil: soon, OwnerEmail: "o@example.com"},
		}},
		notifProvider: succeedingTestDeliveryNotificationProvider{},
		auditProvider: stubAuditProvider{},
		thresholdDays: 30, pollInterval: 24 * time.Hour,
		silenceStore: silenceStore,
	}
	s.runScan()
	if st := s.Status(); st.LastNotifications != 0 {
		t.Fatalf("expected the API-created silence to suppress the notification, got %d", st.LastNotifications)
	}
}
