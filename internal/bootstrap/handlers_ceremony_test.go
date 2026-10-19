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
                  CHECK (status IN ('pending', 'completed', 'aborted', 'expired')),
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    reminder_sent_at TEXT
);`

func newCeremonyHandlerMux(t *testing.T) (*http.ServeMux, *ca.CeremonyManager) {
	t.Helper()
	mux, mgr, _ := newCeremonyHandlerMuxEngine(t)
	return mux, mgr
}

func newCeremonyHandlerMuxEngine(t *testing.T) (*http.ServeMux, *ca.CeremonyManager, *ca.Engine) {
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
	return mux, mgr, engine
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

func TestCeremonyStartRejectsQuorumBelowTwo(t *testing.T) {
	mux, _, engine := newCeremonyHandlerMuxEngine(t)
	for _, q := range []int{1, 0} {
		rec := doCeremonyReq(t, mux, http.MethodPost, "/api/v1/ceremonies", map[string]any{
			"name": "Q", "common_name": "Q CA", "algorithm": "ECDSA-P256",
			"validity_days": 365,
			"approvers":     []string{"bootstrap", "alice"}, "quorum": q,
		})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("quorum %d: want 400, got %d: %s", q, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "at least 2") {
			t.Fatalf("quorum %d: message must mention 'at least 2': %s", q, rec.Body.String())
		}
	}
	cas, err := engine.ListCAs()
	if err != nil || len(cas) != 0 {
		t.Fatalf("no CA may be created for a rejected ceremony: %d %v", len(cas), err)
	}
}

func TestCeremonyEndpointsShowExpiresAt(t *testing.T) {
	mux, _ := newCeremonyHandlerMux(t)
	rec := doCeremonyReq(t, mux, http.MethodPost, "/api/v1/ceremonies", map[string]any{
		"name": "E", "common_name": "E CA", "algorithm": "ECDSA-P256",
		"validity_days": 365,
		"approvers":     []string{"bootstrap", "alice"}, "quorum": 2,
	})
	var created struct{ Data ca.Ceremony }
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if want := created.Data.CreatedAt.Add(72 * time.Hour); !created.Data.ExpiresAt.Equal(want) {
		t.Fatalf("start expires_at = %v, want created_at+72h = %v", created.Data.ExpiresAt, want)
	}
	rec = doCeremonyReq(t, mux, http.MethodGet, "/api/v1/ceremonies/"+created.Data.ID, nil)
	var got struct{ Data ca.Ceremony }
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Data.ExpiresAt.IsZero() || !got.Data.ExpiresAt.Equal(created.Data.ExpiresAt) {
		t.Fatalf("get expires_at = %v, want %v", got.Data.ExpiresAt, created.Data.ExpiresAt)
	}
	rec = doCeremonyReq(t, mux, http.MethodGet, "/api/v1/ceremonies", nil)
	var list struct{ Data []ca.Ceremony }
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Data) != 1 || list.Data[0].ExpiresAt.IsZero() {
		t.Fatalf("list must include expires_at: %s", rec.Body.String())
	}
}

type captureAudit struct {
	stubAuditProvider
	entries []AuditEntry
}

func (c *captureAudit) AppendEntry(_ context.Context, e AuditEntry) error {
	c.entries = append(c.entries, e)
	return nil
}

func TestSweepCeremoniesAuditsExpiry(t *testing.T) {
	_, mgr := newCeremonyHandlerMux(t)
	start := func(name string) ca.Ceremony {
		c, err := mgr.StartRootCACeremony(ca.RootCACeremonyParams{
			Name: name, CommonName: name + " CA", Algorithm: keystore.ECDSAP256,
			ValidityDays: 365, Initiator: "ops", Approvers: []string{"alice", "bob"}, Quorum: 2,
		})
		if err != nil {
			t.Fatalf("start %s: %v", name, err)
		}
		return c
	}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := t0
	mgr.SetClock(func() time.Time { return now })
	stale := start("stale")
	done := start("done")
	aborted := start("aborted")
	if _, err := mgr.Approve(done.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Approve(done.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Abort(aborted.ID); err != nil {
		t.Fatal(err)
	}
	now = t0.Add(73 * time.Hour)
	fresh := start("fresh")

	audit := &captureAudit{}
	SweepCeremonies(context.Background(), mgr, audit)
	if len(audit.entries) != 1 {
		t.Fatalf("want exactly 1 ceremony.expire entry, got %+v", audit.entries)
	}
	e := audit.entries[0]
	if e.Action != "ceremony.expire" || e.ResourceID != stale.ID || e.ActorType != "system" || e.Outcome != AuditOutcomeSuccess {
		t.Fatalf("unexpected audit entry: %+v", e)
	}
	SweepCeremonies(context.Background(), mgr, audit)
	if len(audit.entries) != 1 {
		t.Fatalf("a second sweep must not re-audit, got %d entries", len(audit.entries))
	}
	for id, want := range map[string]string{
		stale.ID: ca.CeremonyExpired, done.ID: ca.CeremonyCompleted,
		aborted.ID: ca.CeremonyAborted, fresh.ID: ca.CeremonyPending,
	} {
		if c, _, _ := mgr.Get(id); c.Status != want {
			t.Fatalf("ceremony %s status = %q, want %q", id, c.Status, want)
		}
	}
}
