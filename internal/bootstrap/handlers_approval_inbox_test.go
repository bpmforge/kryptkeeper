// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type inboxEnv struct {
	mux       *http.ServeMux
	auth      *Authenticator
	actions   *dbPendingActionStore
	approvals *sqliteApprovalStore
	tenants   *dbTenantStore
	ran       *atomic.Int32
}

func newInboxEnv(t *testing.T, multiTenant bool) inboxEnv {
	t.Helper()
	if multiTenant {
		t.Setenv("MULTI_TENANCY", "on")
	}
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := newReportsTestAuth(t)
	actions := newTestPendingStore(t)
	approvals := newTestApprovalStore(t)
	tenants := newTestTenantStore(t)
	ctx := context.Background()
	for _, tn := range []string{"acme", "globex"} {
		if _, err := tenants.CreateTenant(ctx, tn, tn); err != nil {
			t.Fatal(err)
		}
		if err := tenants.SetCATenant(ctx, "ca-"+tn, tn); err != nil {
			t.Fatal(err)
		}
	}
	setActiveTenantStore(tenants)
	t.Cleanup(func() { setActiveTenantStore(nil) })
	var ran atomic.Int32
	execs := map[string]ActionExecutor{"revoke": func(context.Context, PendingAction, AuthPrincipal) (json.RawMessage, error) {
		ran.Add(1)
		return json.RawMessage(`{}`), nil
	}}
	mux := http.NewServeMux()
	registerPendingActionHandlers(mux, auth, &reportCertProvider{}, actions, stubAuditProvider{}, execs)
	registerApprovalHandlers(mux, auth, approvals, &reportCertProvider{}, foundTemplateProvider{}, stubAuditProvider{})
	registerApprovalInboxHandlers(mux, auth, approvals, actions, tenants, stubAuditProvider{}, nil)
	return inboxEnv{mux, auth, actions, approvals, tenants, &ran}
}

func (e inboxEnv) do(token, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, bearerReq(token, method, path, nil))
	return rec
}

func (e inboxEnv) seedAction(t *testing.T, proposer, tenant string) PendingAction {
	t.Helper()
	a, err := e.actions.Create(context.Background(), PendingAction{ActionType: "revoke", Params: json.RawMessage(`{"fingerprint":"fp"}`), ProposedBy: proposer, Tenant: tenant})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (e inboxEnv) seedCert(t *testing.T, id, ca, requester string) {
	t.Helper()
	if err := e.approvals.Create(context.Background(), ApprovalRequest{ID: id, TemplateID: "tpl", CAID: ca, Requester: requester, RequestedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
}

type inboxResp struct {
	Data []inboxItem `json:"data"`
	Meta struct{ Total, Limit, Offset int }
}

func decodeInbox(t *testing.T, rec *httptest.ResponseRecorder) inboxResp {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("inbox status %d: %s", rec.Code, rec.Body.String())
	}
	var out inboxResp
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

const bootstrapTok = "reports-test-token"

func TestInboxMergesBothStores(t *testing.T) {
	e := newInboxEnv(t, false)
	e.seedCert(t, "apr-1", "ca-acme", "req-cert")
	e.seedAction(t, "agent-1", "")
	e.seedAction(t, "agent-2", "")
	got := decodeInbox(t, e.do(mintAdminToken(t, e.auth, "appr-a", ""), http.MethodGet, "/api/v1/approvals/inbox"))
	if len(got.Data) != 3 || got.Meta.Total != 3 {
		t.Fatalf("items = %+v", got)
	}
	types := map[string]int{}
	for _, it := range got.Data {
		types[it.Type]++
		if it.AgeSeconds < 0 || it.Requester == "" || it.Tenant == "" || it.CreatedAt == "" {
			t.Fatalf("incomplete item: %+v", it)
		}
	}
	if types[inboxTypeCert] != 1 || types[inboxTypeAction] != 2 {
		t.Fatalf("types = %v", types)
	}
}

func TestInboxFilters(t *testing.T) {
	e := newInboxEnv(t, true)
	e.seedCert(t, "apr-g", "ca-globex", "req-cert")
	e.seedAction(t, "agent-1", "acme")
	old := e.seedAction(t, "agent-2", "acme")
	if _, err := e.actions.db.Exec(`UPDATE pending_actions SET created_at = ? WHERE id = ?`, time.Now().UTC().Add(-3*time.Hour).Format(time.RFC3339), old.ID); err != nil {
		t.Fatal(err)
	}
	if n := len(decodeInbox(t, e.do(bootstrapTok, http.MethodGet, "/api/v1/approvals/inbox?type=pending_action")).Data); n != 2 {
		t.Fatalf("type filter: %d", n)
	}
	aged := decodeInbox(t, e.do(bootstrapTok, http.MethodGet, "/api/v1/approvals/inbox?min_age=1h"))
	if len(aged.Data) != 1 || aged.Data[0].ID != old.ID {
		t.Fatalf("min_age: %+v", aged.Data)
	}
	gx := decodeInbox(t, e.do(bootstrapTok, http.MethodGet, "/api/v1/approvals/inbox?tenant=globex"))
	if len(gx.Data) != 1 || gx.Data[0].Type != inboxTypeCert || gx.Data[0].Tenant != "globex" {
		t.Fatalf("tenant filter: %+v", gx.Data)
	}
	if rec := e.do(bootstrapTok, http.MethodGet, "/api/v1/approvals/inbox?type=bogus"); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad type: %d", rec.Code)
	}
	if rec := e.do(bootstrapTok, http.MethodGet, "/api/v1/approvals/inbox?min_age=soon"); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad min_age: %d", rec.Code)
	}
	oldest := decodeInbox(t, e.do(bootstrapTok, http.MethodGet, "/api/v1/approvals/inbox"))
	if oldest.Data[0].ID != old.ID {
		t.Fatalf("not oldest-first: %+v", oldest.Data)
	}
	if rec := e.do("", http.MethodGet, "/api/v1/approvals/inbox"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d", rec.Code)
	}
}

func TestInboxTenantPrincipalSeesOnlyOwnTenant(t *testing.T) {
	e := newInboxEnv(t, true)
	mk := func(principal, tenant string) string {
		_, tok, err := e.auth.CreateAPIKeyAs("", principal, principal, "pki-admin", []string{"*"}, "", tenant, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	acme, globex := mk("acme-admin", "acme"), mk("globex-admin", "globex")
	e.seedCert(t, "apr-a", "ca-acme", "r1")
	e.seedCert(t, "apr-g", "ca-globex", "r2")
	e.seedAction(t, "agent", "acme")
	e.seedAction(t, "agent", "globex")
	e.seedAction(t, "agent", "globex")
	for _, q := range []string{"", "?tenant=globex"} {
		got := decodeInbox(t, e.do(acme, http.MethodGet, "/api/v1/approvals/inbox"+q))
		if got.Meta.Total != 2 || len(got.Data) != 2 {
			t.Fatalf("acme%s: %+v", q, got)
		}
		for _, it := range got.Data {
			if it.Tenant != "acme" {
				t.Fatalf("leaked %+v", it)
			}
		}
	}
	if got := decodeInbox(t, e.do(globex, http.MethodGet, "/api/v1/approvals/inbox")); got.Meta.Total != 3 {
		t.Fatalf("globex: %+v", got)
	}
	// Cross-tenant decisions stay hidden behind the source handlers.
	gAction := e.actions
	list, _ := gAction.List(context.Background(), "pending")
	for _, a := range list {
		if a.Tenant == "globex" {
			if rec := e.do(acme, http.MethodPost, "/api/v1/approvals/inbox/pending_action/"+a.ID+"/approve"); rec.Code != http.StatusNotFound {
				t.Fatalf("cross-tenant action approve: %d %s", rec.Code, rec.Body.String())
			}
		}
	}
	if rec := e.do(acme, http.MethodPost, "/api/v1/approvals/inbox/certificate_approval/apr-g/approve"); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant cert approve: %d %s", rec.Code, rec.Body.String())
	}
	if e.ran.Load() != 0 {
		t.Fatal("cross-tenant action executed")
	}
}

func TestInboxApproveDelegatesAndKeepsRefusals(t *testing.T) {
	e := newInboxEnv(t, false)
	tokA := mintAdminToken(t, e.auth, "appr-a", "")
	tokB := mintAdminToken(t, e.auth, "appr-b", "")
	_, mcpTok, err := e.auth.CreateAPIKey("mcp-int", "mcp-server", RoleMCPAgent, []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	path := func(id, verb string) string { return "/api/v1/approvals/inbox/pending_action/" + id + "/" + verb }

	own := e.seedAction(t, "appr-a", "")
	if rec := e.do(tokA, http.MethodPost, path(own.ID, "approve")); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), msgSelfApproval) {
		t.Fatalf("self: %d %s", rec.Code, rec.Body.String())
	}
	if rec := e.do(bootstrapTok, http.MethodPost, path(own.ID, "approve")); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), msgBootstrapCannotApprove) {
		t.Fatalf("bootstrap: %d %s", rec.Code, rec.Body.String())
	}
	if rec := e.do(mcpTok, http.MethodPost, path(own.ID, "approve")); rec.Code != http.StatusForbidden {
		t.Fatalf("mcp: %d", rec.Code)
	}
	if e.ran.Load() != 0 {
		t.Fatal("refused approvals executed")
	}
	if rec := e.do(tokB, http.MethodPost, path(own.ID, "approve")); rec.Code != http.StatusOK || e.ran.Load() != 1 {
		t.Fatalf("approve: %d %s ran=%d", rec.Code, rec.Body.String(), e.ran.Load())
	}
	if rec := e.do(tokB, http.MethodPost, path(own.ID, "approve")); rec.Code != http.StatusConflict {
		t.Fatalf("decided: %d", rec.Code)
	}
	rej := e.seedAction(t, "agent", "")
	if rec := e.do(tokB, http.MethodPost, path(rej.ID, "reject")); rec.Code != http.StatusOK {
		t.Fatalf("reject: %d %s", rec.Code, rec.Body.String())
	}
	e.seedCert(t, "apr-1", "ca-acme", "requester")
	if rec := e.do(tokB, http.MethodPost, "/api/v1/approvals/inbox/certificate_approval/apr-1/approve"); rec.Code != http.StatusCreated {
		t.Fatalf("cert approve: %d %s", rec.Code, rec.Body.String())
	}
	for _, bad := range []string{"/api/v1/approvals/inbox/other/x/approve", "/api/v1/approvals/inbox/pending_action/a%2Fb/approve", "/api/v1/approvals/inbox/pending_action/x/delete"} {
		if rec := e.do(tokB, http.MethodPost, bad); rec.Code != http.StatusNotFound {
			t.Fatalf("%s: %d", bad, rec.Code)
		}
	}
}
