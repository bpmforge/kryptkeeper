// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// W9-06: the ceremony API — approver identity comes from authentication,
// never from the request body.

const ceremonyHandlerTestSchema = `
CREATE TABLE IF NOT EXISTS key_ceremonies (
    id            TEXT PRIMARY KEY,
    ca_id         TEXT NOT NULL,
    ca_name       TEXT NOT NULL,
    common_name   TEXT NOT NULL,
    algorithm     TEXT NOT NULL,
    validity_days INTEGER NOT NULL CHECK (validity_days > 0),
    initiator     TEXT NOT NULL,
    approvers     TEXT NOT NULL,
    quorum        INTEGER NOT NULL CHECK (quorum >= 2),
    approvals     TEXT NOT NULL DEFAULT '[]',
    status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending', 'completed', 'aborted')),
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);`

func newCeremonyHandlerMux(t *testing.T) (*http.ServeMux, *ca.CeremonyManager) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()

	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "cer.db"))
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(ceremonyHandlerTestSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	keys, err := keystore.NewSoftwareStore(t.TempDir(), []byte("ceremony-http-test-passphrase-32"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	t.Cleanup(func() { keys.Close() })
	engine := ca.NewEngine(keys, ca.NewMemStore())
	mgr, err := ca.NewCeremonyManager(db, false, engine)
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	mux := http.NewServeMux()
	RegisterCeremonyHandlers(mux, auth, mgr, stubAuditProvider{})
	return mux, mgr
}

func doCeremonyReq(t *testing.T, mux *http.ServeMux, method, path string, body any) *httptest.ResponseRecorder {
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

func TestCeremonyStartEndpointCreatesPendingCeremony(t *testing.T) {
	mux, _ := newCeremonyHandlerMux(t)
	rec := doCeremonyReq(t, mux, http.MethodPost, "/api/v1/ceremonies", map[string]any{
		"name": "API Root", "common_name": "API Root CA",
		"algorithm": "ECDSA-P256", "validity_days": 3650,
		"approvers": []string{"bootstrap", "alice"}, "quorum": 2,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("start: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct{ Data ca.Ceremony }
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.Data.Status != ca.CeremonyPending || resp.Data.CAID == "" {
		t.Fatalf("malformed ceremony: %+v", resp.Data)
	}
	if resp.Data.Initiator != "bootstrap" {
		t.Fatalf("initiator must be the authenticated principal, got %q", resp.Data.Initiator)
	}
}

func TestCeremonyApproveUsesAuthenticatedPrincipalOnly(t *testing.T) {
	mux, mgr := newCeremonyHandlerMux(t)
	rec := doCeremonyReq(t, mux, http.MethodPost, "/api/v1/ceremonies", map[string]any{
		"name": "R", "common_name": "R CA", "algorithm": "ECDSA-P256",
		"validity_days": 365,
		"approvers":     []string{"bootstrap", "alice"}, "quorum": 2,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("start: %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct{ Data ca.Ceremony }
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	id := resp.Data.ID

	// A body-supplied approver name must be ignored: the recorded approval
	// is the authenticated principal ("bootstrap"), not "alice".
	rec = doCeremonyReq(t, mux, http.MethodPost, "/api/v1/ceremonies/"+id+"/approve", map[string]any{
		"approver": "alice",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: %d: %s", rec.Code, rec.Body.String())
	}
	got, _, err := mgr.Get(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.Approvals) != 1 || got.Approvals[0] != "bootstrap" {
		t.Fatalf("approval must be the authenticated principal, got %v", got.Approvals)
	}

	// The same principal cannot approve twice — quorum is unreachable
	// through one identity, which is the whole point of M-of-N.
	rec = doCeremonyReq(t, mux, http.MethodPost, "/api/v1/ceremonies/"+id+"/approve", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("second approval by the same principal must 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "already approved") {
		t.Fatalf("refusal must explain distinct identities, got: %s", rec.Body.String())
	}
	got, _, _ = mgr.Get(id)
	if got.Status != ca.CeremonyPending {
		t.Fatalf("ceremony must still be pending, got %q", got.Status)
	}
}

func TestCeremonyEndpointsRequireAuth(t *testing.T) {
	mux, _ := newCeremonyHandlerMux(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ceremonies", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", rec.Code)
	}
}

func TestCeremonyAbortEndpoint(t *testing.T) {
	mux, mgr := newCeremonyHandlerMux(t)
	rec := doCeremonyReq(t, mux, http.MethodPost, "/api/v1/ceremonies", map[string]any{
		"name": "A", "common_name": "A CA", "algorithm": "ECDSA-P256",
		"validity_days": 365,
		"approvers":     []string{"bootstrap", "alice"}, "quorum": 2,
	})
	var resp struct{ Data ca.Ceremony }
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)

	rec = doCeremonyReq(t, mux, http.MethodPost, "/api/v1/ceremonies/"+resp.Data.ID+"/abort", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("abort: %d: %s", rec.Code, rec.Body.String())
	}
	got, _, _ := mgr.Get(resp.Data.ID)
	if got.Status != ca.CeremonyAborted {
		t.Fatalf("expected aborted, got %q", got.Status)
	}
}
