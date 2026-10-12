// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newTestPendingStore(t *testing.T) *dbPendingActionStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "pa.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := &dbPendingActionStore{db: db, ph: sqlitePlaceholder}
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return s
}

func TestPendingActionStore_CreateListDecide(t *testing.T) {
	s := newTestPendingStore(t)
	ctx := context.Background()
	a, err := s.Create(ctx, PendingAction{
		ActionType: "revoke", Params: json.RawMessage(`{"fingerprint":"fp1"}`),
		ProposedBy: "mcp:agent", Rationale: "compromised",
	})
	if err != nil || a.ID == "" {
		t.Fatalf("create: %v", err)
	}
	if a.Status != "pending" {
		t.Errorf("expected pending, got %s", a.Status)
	}
	pending, _ := s.List(ctx, "pending")
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}
	if err := s.Decide(ctx, a.ID, "approved", "admin", json.RawMessage(`{"revoked":1}`)); err != nil {
		t.Fatalf("decide: %v", err)
	}
	// Second decide must fail (already decided).
	if err := s.Decide(ctx, a.ID, "rejected", "admin", nil); err == nil {
		t.Error("expected error deciding an already-decided action")
	}
	got, ok, _ := s.Get(ctx, a.ID)
	if !ok || got.Status != "approved" || got.ApprovedBy != "admin" {
		t.Errorf("unexpected after decide: %+v", got)
	}
}

func TestExecutePendingAction_Revoke(t *testing.T) {
	certs := &recordingCertProvider{reportCertProvider: &reportCertProvider{}}
	a := PendingAction{ActionType: "revoke", Params: json.RawMessage(`{"fingerprint":"fp1","reason_code":4}`)}
	res, err := executePendingAction(context.Background(), certs, a)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if certs.revoked != 1 {
		t.Errorf("expected 1 revoke call, got %d", certs.revoked)
	}
	if !json.Valid(res) {
		t.Error("result not valid JSON")
	}
}

func TestExecutePendingAction_BulkRevoke(t *testing.T) {
	certs := &recordingCertProvider{reportCertProvider: &reportCertProvider{items: []CertificateItem{
		{FingerprintSHA256: "a"}, {FingerprintSHA256: "b"},
	}}}
	a := PendingAction{ActionType: "bulk_revoke", Params: json.RawMessage(`{"ca_id":"ca-7","reason_code":4}`)}
	res, err := executePendingAction(context.Background(), certs, a)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if certs.revoked != 2 {
		t.Errorf("expected 2 revokes, got %d", certs.revoked)
	}
	var m map[string]any
	_ = json.Unmarshal(res, &m)
	if m["revoked"].(float64) != 2 {
		t.Errorf("result revoked count wrong: %v", m)
	}
}

func TestExecutePendingAction_UnknownType(t *testing.T) {
	_, err := executePendingAction(context.Background(), &reportCertProvider{}, PendingAction{ActionType: "nuke"})
	if err == nil {
		t.Fatal("expected error for unknown action type")
	}
}

// --- handler RBAC ---

func pendingMux(t *testing.T, certs CertificateProvider) (*http.ServeMux, *Authenticator, PendingActionStore) {
	t.Helper()
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := newReportsTestAuth(t) // bootstrap token → role pki-admin, id "admin" (subject)
	store := newTestPendingStore(t)
	mux := http.NewServeMux()
	registerPendingActionHandlers(mux, auth, certs, store, stubAuditProvider{}, nil)
	return mux, auth, store
}

func TestPendingActions_ProposerCannotSelfApprove(t *testing.T) {
	certs := &recordingCertProvider{reportCertProvider: &reportCertProvider{}}
	mux, _, store := pendingMux(t, certs)

	// Seed an action proposed by the same principal the bootstrap token resolves to.
	pd := bootstrapPrincipalID(t)
	created, _ := store.Create(context.Background(), PendingAction{
		ActionType: "revoke", Params: json.RawMessage(`{"fingerprint":"fp1"}`), ProposedBy: pd,
	})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/pending-actions/"+created.ID+"/approve", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 self-approval, got %d: %s", rec.Code, rec.Body.String())
	}
	if certs.revoked != 0 {
		t.Error("self-approval must not execute")
	}
}

func TestPendingActions_ApproveExecutes(t *testing.T) {
	certs := &recordingCertProvider{reportCertProvider: &reportCertProvider{}}
	mux, auth, store := pendingMux(t, certs)
	// Proposed by the AI (different principal than the approving admin).
	created, _ := store.Create(context.Background(), PendingAction{
		ActionType: "revoke", Params: json.RawMessage(`{"fingerprint":"fp1","reason_code":1}`), ProposedBy: "mcp:agent",
	})

	// The bootstrap token can never approve (FG-2); a named admin does.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, bearerReq(mintAdminToken(t, auth, "approver-one", ""), http.MethodPost, "/api/v1/pending-actions/"+created.ID+"/approve", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if certs.revoked != 1 {
		t.Errorf("expected execution (1 revoke), got %d", certs.revoked)
	}
	got, _, _ := store.Get(context.Background(), created.ID)
	if got.Status != "approved" {
		t.Errorf("expected approved, got %s", got.Status)
	}
}

// TestCanApproveActions_MCPAgentRoleRejected is the direct unit-level
// version of the W1-04/D-029 guarantee: RoleMCPAgent is denied by
// canApproveActions itself, independent of any handler wiring.
func TestCanApproveActions_MCPAgentRoleRejected(t *testing.T) {
	if canApproveActions(RoleMCPAgent) {
		t.Fatal("expected RoleMCPAgent to be rejected by canApproveActions")
	}
	// Sanity: the existing approver roles are unaffected by this change.
	if !canApproveActions("pki-admin") || !canApproveActions("pki-operator") {
		t.Fatal("expected pki-admin/pki-operator to remain approver-capable")
	}
}

// TestPendingActions_MCPAgentRoleCannotApproveOrReject is the W1-04/D-029
// regression: an API-key principal provisioned with RoleMCPAgent must be
// structurally unable to approve OR reject a pending action proposed by a
// DIFFERENT principal (i.e. this is not the pre-existing self-approval
// check — that's already covered by TestPendingActions_ProposerCannotSelfApprove).
// Full max scope ("*") on the key proves the block is role-based, not a
// scope gap that a broader grant would bypass.
func TestPendingActions_MCPAgentRoleCannotApproveOrReject(t *testing.T) {
	certs := &recordingCertProvider{reportCertProvider: &reportCertProvider{}}
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "reports-test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()
	store := newTestPendingStore(t)
	mux := http.NewServeMux()
	registerPendingActionHandlers(mux, auth, certs, store, stubAuditProvider{}, nil)

	_, rawKey, err := auth.CreateAPIKey("mcp-integration", "mcp-server", RoleMCPAgent, []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatalf("create mcp-agent api key: %v", err)
	}

	// Proposed by a human admin — not the mcp-agent — so this is not a
	// self-approval case.
	created, _ := store.Create(context.Background(), PendingAction{
		ActionType: "revoke", Params: json.RawMessage(`{"fingerprint":"fp1"}`), ProposedBy: bootstrapPrincipalID(t),
	})

	mcpReq := func(verb string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/pending-actions/"+created.ID+"/"+verb, nil)
		r.Header.Set("Authorization", "Bearer "+rawKey)
		return r
	}

	approveRec := httptest.NewRecorder()
	mux.ServeHTTP(approveRec, mcpReq("approve"))
	if approveRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 approving as mcp-agent, got %d: %s", approveRec.Code, approveRec.Body.String())
	}
	if certs.revoked != 0 {
		t.Error("mcp-agent approval must not execute the action")
	}

	rejectRec := httptest.NewRecorder()
	mux.ServeHTTP(rejectRec, mcpReq("reject"))
	if rejectRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 rejecting as mcp-agent, got %d: %s", rejectRec.Code, rejectRec.Body.String())
	}

	got, _, _ := store.Get(context.Background(), created.ID)
	if got.Status != "pending" {
		t.Errorf("expected the action to remain pending after both denied attempts, got %s", got.Status)
	}
}

func TestPendingActions_CreateRejectsBadType(t *testing.T) {
	mux, _, _ := pendingMux(t, &reportCertProvider{})
	body, _ := json.Marshal(map[string]any{"action_type": "delete_everything"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/pending-actions", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

// recordingCertProvider counts RevokeCertificate calls.
type recordingCertProvider struct {
	*reportCertProvider
	revoked int
}

func (p *recordingCertProvider) RevokeCertificate(_ context.Context, fp string, _ CertificateRevokeRequest) (CertificateRevokeResult, error) {
	p.revoked++
	return CertificateRevokeResult{FingerprintSHA256: fp}, nil
}

// bootstrapPrincipalID returns the subject the bootstrap token resolves to.
func bootstrapPrincipalID(t *testing.T) string {
	t.Helper()
	auth := newReportsTestAuth(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer reports-test-token")
	pd, err := auth.AuthenticatePrincipalDetails(req, time.Now())
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	return pd.ID
}

// S-63: when an approved action's execution fails AND recording the
// failure also fails, the caller must be told both — never "failed" while
// the queue still shows pending.
type decideFailingStore struct {
	PendingActionStore
	inner    PendingActionStore
	failured bool
}

func (s *decideFailingStore) Get(ctx context.Context, id string) (PendingAction, bool, error) {
	return s.inner.Get(ctx, id)
}
func (s *decideFailingStore) List(ctx context.Context, status string) ([]PendingAction, error) {
	return s.inner.List(ctx, status)
}
func (s *decideFailingStore) Create(ctx context.Context, a PendingAction) (PendingAction, error) {
	return s.inner.Create(ctx, a)
}
func (s *decideFailingStore) Decide(ctx context.Context, id, status, by string, result json.RawMessage) error {
	if status == "failed" {
		s.failured = true
		return fmt.Errorf("simulated decide outage")
	}
	return s.inner.Decide(ctx, id, status, by, result)
}

func TestFailedDecideAfterFailedActionIsSurfaced(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "pa-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()
	approverToken := mintAdminToken(t, auth, "approver-two", "")

	inner := newTestPendingStore(t)
	// An action whose execution will fail: unknown fingerprint revoke via
	// the file provider (no certs configured).
	created, err := inner.Create(context.Background(), PendingAction{
		ActionType: "revoke", Params: json.RawMessage(`{"fingerprint":"no-such"}`),
		ProposedBy: "someone-else",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	store := &decideFailingStore{inner: inner}

	mux := http.NewServeMux()
	registerPendingActionHandlers(mux, auth, NewFileCertificateProviderFromEnv(), store, stubAuditProvider{}, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/pending-actions/"+created.ID+"/approve", nil)
	req.Header.Set("Authorization", "Bearer "+approverToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", rec.Code, rec.Body.String())
	}
	if !store.failured {
		t.Fatal("test setup: Decide(failed) was never attempted")
	}
	if !strings.Contains(rec.Body.String(), "recording the failure also failed") {
		t.Fatalf("caller must be told the failure could not be recorded, got: %s", rec.Body.String())
	}
}
