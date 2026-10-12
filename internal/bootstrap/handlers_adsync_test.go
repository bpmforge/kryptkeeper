// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"kryptkeeper/internal/adsync"
)

// W17-10: AD sync reachable. Writing into AD's Configuration naming
// context is high blast radius, so the gate and the honesty of the
// result are what these pin.

type fakeDirectory struct {
	added   []string
	addErr  error
	entries []adsync.LDAPEntry
}

func (f *fakeDirectory) Search(string, string, []string) ([]adsync.LDAPEntry, error) {
	return f.entries, nil
}
func (f *fakeDirectory) Add(dn string, _ map[string][]string) error {
	if f.addErr != nil {
		return f.addErr
	}
	f.added = append(f.added, dn)
	return nil
}
func (f *fakeDirectory) Modify(string, []adsync.LDAPChange) error { return nil }
func (f *fakeDirectory) Delete(string) error                      { return nil }
func (f *fakeDirectory) Close() error                             { return nil }

func adsyncMux(t *testing.T, dir *fakeDirectory) *http.ServeMux {
	t.Helper()
	prev := newADSyncClient
	newADSyncClient = func(adsyncRequest, string) (adsync.LDAPClient, error) { return dir, nil }
	t.Cleanup(func() { newADSyncClient = prev })

	mux := http.NewServeMux()
	registerADSyncHandlers(mux, newReportsTestAuth(t),
		&renewalFakeCredStore{meta: OutboundCredentialMeta{ID: "cred-ad", CredentialType: CredentialTypeAPIToken},
			payload: []byte("s3cret")}, stubAuditProvider{})
	return mux
}

func adsyncBody(templates int) []byte {
	tpls := make([]map[string]any, 0, templates)
	for i := 0; i < templates; i++ {
		tpls = append(tpls, map[string]any{"name": "WebServer"})
	}
	raw, _ := json.Marshal(map[string]any{
		"ldap_url": "ldaps://dc.example.com", "bind_dn": "CN=svc",
		"credential_ref": "cred-ad", "config_dn": "CN=Configuration,DC=corp",
		"templates": tpls,
	})
	return raw
}

func TestADSyncPublishesTemplates(t *testing.T) {
	dir := &fakeDirectory{}
	rec := httptest.NewRecorder()
	adsyncMux(t, dir).ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/adsync/templates", adsyncBody(2)))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(dir.added) == 0 {
		t.Fatal("templates must actually reach the directory")
	}
}

// A partially-applied sync must not read as a clean success.
func TestADSyncReportsPerTemplateErrors(t *testing.T) {
	dir := &fakeDirectory{addErr: errors.New("insufficient access rights")}
	rec := httptest.NewRecorder()
	adsyncMux(t, dir).ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/adsync/templates", adsyncBody(1)))
	var resp struct {
		Data adsync.SyncResult `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Data.Errors) == 0 {
		t.Fatalf("a failed template add must surface in errors: %+v", resp.Data)
	}
	if resp.Data.Created != 0 {
		t.Fatalf("nothing was created, so created must be 0: %+v", resp.Data)
	}
}

func TestADSyncValidatesAndRequiresAuth(t *testing.T) {
	mux := adsyncMux(t, &fakeDirectory{})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/adsync/templates", []byte(`{"ldap_url":"ldaps://x"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing config_dn/credential_ref must be refused, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/adsync/templates", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestADSyncGPOCheckIsAdvisory(t *testing.T) {
	rec := httptest.NewRecorder()
	adsyncMux(t, &fakeDirectory{}).ServeHTTP(rec,
		authedReq(http.MethodPost, "/api/v1/adsync/gpo-check", []byte(`{}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Checks     []adsync.GPOCheckResult `json:"checks"`
			AllPassing bool                    `json:"all_passing"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Data.Checks) == 0 {
		t.Fatal("the validator must return checks")
	}
	// An empty config must not claim to be passing.
	if resp.Data.AllPassing {
		t.Fatal("an empty GPO config must not report all_passing")
	}
}

var _ = context.Background
