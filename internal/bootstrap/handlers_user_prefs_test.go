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
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

type prefsAudit struct {
	mu   sync.Mutex
	rows []AuditEntry
}

func (a *prefsAudit) ListEntries(_ context.Context, _ AuditListQuery) (AuditListResult, error) {
	return AuditListResult{}, nil
}
func (a *prefsAudit) AppendEntry(_ context.Context, e AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rows = append(a.rows, e)
	return nil
}

func newPrefsTestMux(t *testing.T, withStore bool) (*http.ServeMux, *Authenticator, *prefsAudit) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()
	var store UserPrefsStore
	if withStore {
		db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "prefs.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		s := &dbUserPrefsStore{db: db, ph: sqlitePlaceholder, schema: userPrefsSchemaSQLite}
		if err := s.EnsureSchema(t.Context()); err != nil {
			t.Fatal(err)
		}
		store = s
	}
	audit := &prefsAudit{}
	mux := http.NewServeMux()
	registerUserPrefsHandlers(mux, auth, store, audit)
	return mux, auth, audit
}

func prefsReq(mux *http.ServeMux, method, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/api/v1/users/me/prefs", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func prefsDismissed(t *testing.T, rec *httptest.ResponseRecorder) bool {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Data UserPrefs `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Data.OnboardingDismissed
}

func newPrefsKey(t *testing.T, auth *Authenticator, name string) string {
	t.Helper()
	_, tok, err := auth.CreateAPIKey(name, name, "viewer", []string{}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestUserPrefs_RequiresAuth(t *testing.T) {
	mux, _, _ := newPrefsTestMux(t, true)
	for _, m := range []string{http.MethodGet, http.MethodPut} {
		if rec := prefsReq(mux, m, "", `{"onboarding_dismissed":true}`); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: got %d, want 401", m, rec.Code)
		}
	}
}

func TestUserPrefs_DefaultsFalse(t *testing.T) {
	mux, _, _ := newPrefsTestMux(t, true)
	if prefsDismissed(t, prefsReq(mux, http.MethodGet, "test-token", "")) {
		t.Fatal("default must be false")
	}
}

func TestUserPrefs_PutThenGet_PerPrincipal(t *testing.T) {
	mux, auth, _ := newPrefsTestMux(t, true)
	a, b := newPrefsKey(t, auth, "prefs-a"), newPrefsKey(t, auth, "prefs-b")
	if !prefsDismissed(t, prefsReq(mux, http.MethodPut, a, `{"onboarding_dismissed":true}`)) {
		t.Fatal("PUT must echo stored prefs")
	}
	if !prefsDismissed(t, prefsReq(mux, http.MethodGet, a, "")) {
		t.Fatal("A should be dismissed")
	}
	if prefsDismissed(t, prefsReq(mux, http.MethodGet, b, "")) {
		t.Fatal("B must not inherit A's prefs")
	}
}

// A second browser is a new session/token for the same principal.
func TestUserPrefs_SecondSessionSameUser(t *testing.T) {
	mux, _, _ := newPrefsTestMux(t, true)
	prefsReq(mux, http.MethodPut, "test-token", `{"onboarding_dismissed":true}`)
	if !prefsDismissed(t, prefsReq(mux, http.MethodGet, "test-token", "")) {
		t.Fatal("same principal must see the stored pref")
	}
}

func TestUserPrefs_RejectsUnknownField(t *testing.T) {
	mux, _, audit := newPrefsTestMux(t, true)
	for _, body := range []string{`{"onboarding_dismissed":true,"principal_id":"x"}`, `{}`, `nope`} {
		if rec := prefsReq(mux, http.MethodPut, "test-token", body); rec.Code != http.StatusBadRequest {
			t.Fatalf("%q: got %d, want 400", body, rec.Code)
		}
	}
	if len(audit.rows) != 3 || audit.rows[0].Outcome != AuditOutcomeFailure {
		t.Fatalf("validation failures must be audited, got %d rows", len(audit.rows))
	}
	big := `{"onboarding_dismissed":true,"x":"` + strings.Repeat("a", 5000) + `"}`
	if rec := prefsReq(mux, http.MethodPut, "test-token", big); rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body: got %d, want 400", rec.Code)
	}
}

func TestUserPrefs_StoreNil503(t *testing.T) {
	mux, _, audit := newPrefsTestMux(t, false)
	if rec := prefsReq(mux, http.MethodGet, "test-token", ""); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET: got %d", rec.Code)
	}
	if rec := prefsReq(mux, http.MethodPut, "test-token", `{"onboarding_dismissed":true}`); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("PUT: got %d", rec.Code)
	}
	if len(audit.rows) != 1 {
		t.Fatalf("PUT 503 must be audited, got %d rows", len(audit.rows))
	}
}

func TestUserPrefs_AuditsSet(t *testing.T) {
	mux, _, audit := newPrefsTestMux(t, true)
	prefsReq(mux, http.MethodPut, "test-token", `{"onboarding_dismissed":true}`)
	prefsReq(mux, http.MethodGet, "test-token", "")
	if len(audit.rows) != 1 {
		t.Fatalf("want exactly 1 audit row (no audit on GET), got %d", len(audit.rows))
	}
	if e := audit.rows[0]; e.Action != "user.prefs.set" || e.Outcome != AuditOutcomeSuccess || e.ResourceType != "user_prefs" {
		t.Fatalf("unexpected audit row %+v", e)
	}
}
