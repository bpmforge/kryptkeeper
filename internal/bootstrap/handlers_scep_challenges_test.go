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
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	kkdb "kryptkeeper/internal/db"
	"kryptkeeper/internal/scep"
)

type scepRecordingAudit struct{ entries []AuditEntry }

func (r *scepRecordingAudit) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{}, nil
}
func (r *scepRecordingAudit) AppendEntry(_ context.Context, e AuditEntry) error {
	r.entries = append(r.entries, e)
	return nil
}

func newSCEPChallengeMux(t *testing.T) (*http.ServeMux, *Authenticator, *scep.DBChallengeStore, *scepRecordingAudit) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "scep.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := scep.NewDBChallengeStore(db, false)
	audit := &scepRecordingAudit{}
	mux := http.NewServeMux()
	RegisterSCEPChallengeHandlers(mux, auth, store, "ca-scep", audit)
	return mux, auth, store, audit
}

func scepAPI(t *testing.T, mux *http.ServeMux, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// W20-16: an issuer mints a challenge bound to names; the secret appears in
// that one response and never in the list, the store or the audit log.
func TestSCEPChallengeAPIMintListDelete(t *testing.T) {
	mux, _, store, audit := newSCEPChallengeMux(t)

	rec := scepAPI(t, mux, http.MethodPost, "/api/v1/scep/challenges", "test-token",
		map[string]any{"common_name": "Printer-7.Example.com", "dns_names": []string{"printer-7.example.com"}, "ttl": "30m"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Data struct {
			ID         string    `json:"id"`
			Challenge  string    `json:"challenge"`
			CAID       string    `json:"ca_id"`
			CommonName string    `json:"common_name"`
			ExpiresAt  time.Time `json:"expires_at"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	d := created.Data
	if len(d.Challenge) != 64 || d.CAID != "ca-scep" || d.CommonName != "printer-7.example.com" {
		t.Fatalf("created %+v", d)
	}
	if left := time.Until(d.ExpiresAt); left < 29*time.Minute || left > 31*time.Minute {
		t.Errorf("expires in %s, want 30m", left)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("the response carrying the secret must not be cached")
	}

	list := scepAPI(t, mux, http.MethodGet, "/api/v1/scep/challenges", "test-token", nil)
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), d.Challenge) || !strings.Contains(list.Body.String(), d.ID) {
		t.Fatalf("list must show the challenge but never its secret: %d %s", list.Code, list.Body.String())
	}
	for _, e := range audit.entries {
		if strings.Contains(e.ChangeSummary, d.Challenge) {
			t.Fatal("the secret reached the audit log")
		}
	}

	// The minted secret really enrolls (store side), so it was not mangled.
	if _, err := store.Consume(context.Background(), d.Challenge, time.Now()); err != nil {
		t.Fatalf("minted secret does not consume: %v", err)
	}
	if del := scepAPI(t, mux, http.MethodDelete, "/api/v1/scep/challenges/"+d.ID, "test-token", nil); del.Code != http.StatusNotFound {
		t.Errorf("deleting a used challenge: %d, want 404", del.Code)
	}

	rec = scepAPI(t, mux, http.MethodPost, "/api/v1/scep/challenges", "test-token", map[string]any{"common_name": "spare.example.com"})
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if del := scepAPI(t, mux, http.MethodDelete, "/api/v1/scep/challenges/"+created.Data.ID, "test-token", nil); del.Code != http.StatusNoContent {
		t.Errorf("deleting an unused challenge: %d", del.Code)
	}
}

func TestSCEPChallengeAPIRefusals(t *testing.T) {
	mux, auth, _, _ := newSCEPChallengeMux(t)
	_, auditorKey, err := auth.CreateAPIKey("auditor", "auditor-svc", "pki-auditor", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, operatorKey, err := auth.CreateAPIKey("operator", "operator-svc", "pki-operator", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	good := map[string]any{"common_name": "dev.example.com"}

	for _, tc := range []struct {
		name  string
		token string
		body  map[string]any
		want  int
	}{
		{"anonymous", "", good, http.StatusUnauthorized},
		{"auditor", auditorKey, good, http.StatusForbidden},
		{"operator", operatorKey, good, http.StatusCreated},
		{"wildcard CN", "test-token", map[string]any{"common_name": "*.example.com"}, http.StatusBadRequest},
		{"bad SAN", "test-token", map[string]any{"common_name": "a.example.com", "dns_names": []string{"evil example"}}, http.StatusBadRequest},
		{"ttl over cap", "test-token", map[string]any{"common_name": "a.example.com", "ttl": "25h"}, http.StatusBadRequest},
		{"no CN", "test-token", map[string]any{}, http.StatusBadRequest},
	} {
		if rec := scepAPI(t, mux, http.MethodPost, "/api/v1/scep/challenges", tc.token, tc.body); rec.Code != tc.want {
			t.Errorf("%s: %d, want %d (%s)", tc.name, rec.Code, tc.want, rec.Body.String())
		}
	}
}
