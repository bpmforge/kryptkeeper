// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// W7-02: NHI issuance — propose → approve (distinct principal) →
// join token → short-lived SVID; policy refusals; self-approval refused.

func newTestNHIStore(t *testing.T) NHIStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "nhi.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := &dbNHIStore{db: db, ph: sqlitePlaceholder}
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return s
}

func TestValidateNHIRequestPolicy(t *testing.T) {
	if err := validateNHIRequest("checkout-agent", "ai_agent", []string{"certificate.read"}); err != nil {
		t.Fatalf("valid request refused: %v", err)
	}
	cases := map[string]struct {
		name, kind string
		scopes     []string
	}{
		"bad kind":     {"a", "robot", []string{"certificate.read"}},
		"bad scope":    {"a", "ai_agent", []string{"certificate.readd"}},
		"empty scopes": {"a", "ai_agent", nil},
		"bad name":     {"Not_A_Label!", "ai_agent", []string{"certificate.read"}},
		"path chars":   {"x/../y", "ai_agent", []string{"certificate.read"}},
	}
	for label, c := range cases {
		if err := validateNHIRequest(c.name, c.kind, c.scopes); err == nil {
			t.Errorf("%s: expected refusal", label)
		}
	}
}

// nhiTestSetup wires SPIFFE + workload + NHI handlers over one registry.
// It also returns the Authenticator so tests can mint named admins: the
// bootstrap token (the fixture's default credential) can propose but never
// approve (RC1-B-01).
func nhiTestSetup(t *testing.T) (*http.ServeMux, NHIStore, *Authenticator) {
	t.Helper()
	mux := spiffeTestSetup(t)
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := newReportsTestAuth(t)
	reg := NewWorkloadRegistry()
	registerSPIFFEWorkloadHandlers(mux, auth, reg, stubAuditProvider{})
	store := newTestNHIStore(t)
	registerNHIHandlers(mux, auth, store, reg, stubAuditProvider{})
	return mux, store, auth
}

func proposeNHI(t *testing.T, mux *http.ServeMux, name string) NHIIdentity {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"name": name, "kind": "ai_agent",
		"scopes": []string{"certificate.read", "action.propose"},
	})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/nhi/identities", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("propose: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data NHIIdentity `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp.Data
}

func TestNHIProposeIsPendingAndScoped(t *testing.T) {
	mux, _, _ := nhiTestSetup(t)
	created := proposeNHI(t, mux, "checkout-agent")
	if created.Status != "pending" {
		t.Fatalf("proposal must land pending, got %q", created.Status)
	}
	if created.SPIFFEID != "spiffe://example.org/nhi/ai_agent/checkout-agent" {
		t.Fatalf("spiffe id %q", created.SPIFFEID)
	}
	if len(created.Scopes) != 2 {
		t.Fatalf("scopes not recorded: %v", created.Scopes)
	}

	// Policy refusal at filing time: out-of-vocabulary scope.
	bad, _ := json.Marshal(map[string]any{
		"name": "rogue", "kind": "ai_agent", "scopes": []string{"root.everything"},
	})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/nhi/identities", bad))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("out-of-vocabulary scope: expected 400, got %d", rec.Code)
	}
}

func TestNHISelfApprovalRefused(t *testing.T) {
	mux, store, _ := nhiTestSetup(t)
	created := proposeNHI(t, mux, "self-serve")

	// The same principal (same test token = same principal ID) tries to
	// approve its own proposal — structurally refused.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/nhi/identities/"+created.ID+"/approve", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("self-approval: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	got, _, _ := store.Get(context.Background(), created.ID)
	if got.Status != "pending" {
		t.Fatalf("identity must stay pending after refused self-approval, got %q", got.Status)
	}
}

func TestNHIApproveByDistinctPrincipalYieldsWorkingJoinToken(t *testing.T) {
	mux, store, auth := nhiTestSetup(t)
	approver := mintAdminToken(t, auth, "nhi-approver", "")
	created := proposeNHI(t, mux, "billing-agent")

	// Approve as a DIFFERENT principal: rewrite the stored creator so the
	// approver's principal differs (the fixture auth has one token).
	if err := seedNHICreator(store, created.ID, "someone-else"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, bearerReq(approver, http.MethodPost, "/api/v1/nhi/identities/"+created.ID+"/approve", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			JoinToken string `json:"join_token"`
			SPIFFEID  string `json:"spiffe_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.JoinToken == "" {
		t.Fatal("approval must return the join token once")
	}
	got, _, _ := store.Get(context.Background(), created.ID)
	if got.Status != "approved" {
		t.Fatalf("status %q after approval", got.Status)
	}

	// The agent (no principal credential) redeems the token for its SVID.
	body, _ := json.Marshal(map[string]string{"join_token": resp.Data.JoinToken})
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/api/v1/spiffe/workload-svid", bytes.NewReader(body)))
	if rec2.Code != http.StatusCreated {
		t.Fatalf("svid redeem: expected 201, got %d: %s", rec2.Code, rec2.Body.String())
	}
	var svid struct {
		Data struct {
			SPIFFEID string `json:"spiffe_id"`
			SVIDPEM  string `json:"svid_pem"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &svid); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if svid.Data.SPIFFEID != created.SPIFFEID {
		t.Fatalf("SVID identity %q, want %q", svid.Data.SPIFFEID, created.SPIFFEID)
	}
	block, _ := pem.Decode([]byte(svid.Data.SVIDPEM))
	if block == nil {
		t.Fatal("svid not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cert.URIs) != 1 || !strings.HasPrefix(cert.URIs[0].String(), "spiffe://example.org/nhi/ai_agent/") {
		t.Fatalf("SVID must carry the NHI URI SAN: %v", cert.URIs)
	}
	if until := time.Until(cert.NotAfter); until > 2*time.Hour {
		t.Fatalf("NHI SVID not short-lived: %v", cert.NotAfter)
	}
}

func TestNHIRejectAndRevoke(t *testing.T) {
	mux, store, auth := nhiTestSetup(t)
	approver := mintAdminToken(t, auth, "nhi-approver", "")
	created := proposeNHI(t, mux, "doomed-agent")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/nhi/identities/"+created.ID+"/reject", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("reject: expected 204, got %d", rec.Code)
	}
	got, _, _ := store.Get(context.Background(), created.ID)
	if got.Status != "rejected" {
		t.Fatalf("status %q", got.Status)
	}

	// Approving a non-pending identity is refused.
	_ = seedNHICreator(store, created.ID, "someone-else")
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, bearerReq(approver, http.MethodPost, "/api/v1/nhi/identities/"+created.ID+"/approve", nil))
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("approve after reject: expected 400, got %d", rec2.Code)
	}

	// Revoke works from any state (kill switch).
	rec3 := httptest.NewRecorder()
	mux.ServeHTTP(rec3, authedReq(http.MethodPost, "/api/v1/nhi/identities/"+created.ID+"/revoke", nil))
	if rec3.Code != http.StatusNoContent {
		t.Fatalf("revoke: expected 204, got %d", rec3.Code)
	}
}

// seedNHICreator rewrites created_by so approval comes from a distinct
// principal (the test auth fixture issues a single principal).
func seedNHICreator(store NHIStore, id, creator string) error {
	s, ok := store.(*dbNHIStore)
	if !ok {
		return nil
	}
	_, err := s.db.Exec("UPDATE nhi_identities SET created_by = ? WHERE id = ?", creator, id)
	return err
}
