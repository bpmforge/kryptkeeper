// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	kkdb "kryptkeeper/internal/db"
	"kryptkeeper/internal/notifications/itsm"
)

type itsmActorEnv struct {
	actor *itsmApprovalActor
	store ApprovalStore
	audit *expiryAudit
}

func newITSMActorEnv(t *testing.T) itsmActorEnv {
	t.Helper()
	mux, auth, store, audit, _ := certApprovalEnv(t)
	users := &stubUserProvider{users: []UserRecord{
		{ID: "u-approver", Role: "pki-admin", Status: "active", Tenant: "acme"},
		{ID: "u-other", Role: "pki-admin", Status: "active", Tenant: "globex"},
		{ID: "u-viewer", Role: "pki-viewer", Status: "active", Tenant: "acme"},
		{ID: "u-gone", Role: "pki-admin", Status: "deactivated", Tenant: "acme"},
		{ID: "bootstrap", Role: "pki-admin", Status: "active", Tenant: "acme"},
	}}
	auth.userProvider = users
	return itsmActorEnv{&itsmApprovalActor{mux: mux, auth: auth, users: users}, store, audit}
}

func (e itsmActorEnv) status(t *testing.T, id string) string {
	t.Helper()
	apr, err := e.store.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return apr.Status
}

func TestActor_UsesHandleApproveGates(t *testing.T) {
	e := newITSMActorEnv(t)
	seedApproval(t, e.store, "apr-x", "someone-else")
	// A user of another tenant reaches the real route and is refused by its tenant gate.
	out, err := e.actor.Approve(context.Background(), "apr-x", "u-other", ChannelITSM, "acct-1")
	if err != nil || out != itsm.OutcomeRefused || e.status(t, "apr-x") != "pending" {
		t.Fatalf("cross-tenant: out=%s err=%v status=%s", out, err, e.status(t, "apr-x"))
	}
	if rows := rowsFor(e.audit, "approval.approve"); len(rows) != 1 || rows[0].Outcome != AuditOutcomeDenied ||
		!strings.Contains(rows[0].ChangeSummary, `"channel":"itsm"`) {
		t.Fatalf("refusal not audited by the real route: %+v", rows)
	}
}

func TestBridge_ProposerMappedPrincipalRefused_ZeroStateChange(t *testing.T) {
	e := newITSMActorEnv(t)
	seedApproval(t, e.store, "apr-self", "u-approver")
	out, err := e.actor.Approve(context.Background(), "apr-self", "u-approver", ChannelITSM, "acct-1")
	if err != nil || out != itsm.OutcomeRefused || e.status(t, "apr-self") != "pending" {
		t.Fatalf("out=%s err=%v status=%s", out, err, e.status(t, "apr-self"))
	}
	if rows := rowsFor(e.audit, "approval.approve"); len(rows) != 1 || rows[0].Outcome != AuditOutcomeDenied {
		t.Fatalf("rows %+v", rows)
	}
}

func TestBridge_NoApproveCapabilityRefused(t *testing.T) {
	e := newITSMActorEnv(t)
	seedApproval(t, e.store, "apr-v", "someone-else")
	for _, u := range []string{"u-viewer", "u-gone", "no-such-user"} {
		out, err := e.actor.Approve(context.Background(), "apr-v", u, ChannelITSM, "acct-1")
		if err != nil || out != itsm.OutcomeRefused || e.status(t, "apr-v") != "pending" {
			t.Fatalf("%s: out=%s err=%v", u, out, err)
		}
	}
	if rows := rowsFor(e.audit, "approval.approve"); len(rows) != 0 {
		t.Fatalf("refused before the route, yet it ran: %+v", rows)
	}
}

func TestBridge_BootstrapPrincipalCannotBeMapped(t *testing.T) {
	e := newITSMActorEnv(t)
	seedApproval(t, e.store, "apr-b", "someone-else")
	out, err := e.actor.Approve(context.Background(), "apr-b", "bootstrap", ChannelITSM, "acct-1")
	if err != nil || out != itsm.OutcomeRefused || e.status(t, "apr-b") != "pending" {
		t.Fatalf("out=%s err=%v status=%s", out, err, e.status(t, "apr-b"))
	}
}

func TestActor_ApprovesThroughRealRouteWithChannelAudit(t *testing.T) {
	e := newITSMActorEnv(t)
	seedApproval(t, e.store, "apr-ok", "someone-else")
	// Issuance is not wired in this harness, so the route may answer 5xx after it
	// decided; the decision and its audit are what matter.
	_, _ = e.actor.Approve(context.Background(), "apr-ok", "u-approver", ChannelITSM, "jira:acct-1")
	if e.status(t, "apr-ok") != "approved" {
		t.Fatalf("status %s", e.status(t, "apr-ok"))
	}
	rows := rowsFor(e.audit, "approval.approve")
	if len(rows) == 0 || rows[0].ActorID != "u-approver" || !strings.Contains(rows[0].ChangeSummary, `"channel":"itsm"`) ||
		!strings.Contains(rows[0].ChangeSummary, `"external_id":"jira:acct-1"`) {
		t.Fatalf("rows %+v", rows)
	}
	out, err := e.actor.Approve(context.Background(), "apr-ok", "u-approver", ChannelITSM, "jira:acct-1")
	if err != nil || out != itsm.OutcomeAlreadyDecided {
		t.Fatalf("second: out=%s err=%v", out, err)
	}
	out, _ = e.actor.Approve(context.Background(), "apr-missing", "u-approver", ChannelITSM, "jira:acct-1")
	if out != itsm.OutcomeNotFound {
		t.Fatalf("missing: %s", out)
	}
	out, _ = e.actor.Approve(context.Background(), "../pending-actions/x", "u-approver", ChannelITSM, "jira:acct-1")
	if out != itsm.OutcomeRefused {
		t.Fatalf("path injection: %s", out)
	}
	out, _ = e.actor.Approve(context.Background(), "apr-ok", "u-approver", ChannelChatOps, "x")
	if out != itsm.OutcomeRefused {
		t.Fatalf("wrong channel: %s", out)
	}
}

type itsmMapEnv struct {
	mux   *http.ServeMux
	store *itsm.Store
	audit *expiryAudit
	admin string
}

func newITSMMapEnv(t *testing.T) itsmMapEnv {
	t.Helper()
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := newReportsTestAuth(t)
	auth.userProvider = &stubUserProvider{users: []UserRecord{
		{ID: "u-1", Role: "pki-admin", Status: "active"},
		{ID: "u-off", Role: "pki-admin", Status: "deactivated"},
		{ID: "u-acme", Role: "pki-admin", Status: "active", Tenant: "acme"},
	}}
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	store := itsm.NewStore(db, false)
	svc := itsm.NewService(itsm.Config{Store: store})
	audit := &expiryAudit{}
	mux := http.NewServeMux()
	registerITSMApprovalHandlers(mux, auth, svc, audit)
	return itsmMapEnv{mux, store, audit, mintAdminToken(t, auth, "admin-a", "")}
}

func (e itsmMapEnv) do(token, method, path, body string) *httptest.ResponseRecorder {
	var b []byte
	if body != "" {
		b = []byte(body)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, bearerReq(token, method, path, b))
	return rec
}

func TestPrincipalMap_AdminOnlyAndAudited(t *testing.T) {
	e := newITSMMapEnv(t)
	const p = "/api/v1/itsm/principal-map"
	if rec := e.do("bad-token", http.MethodGet, p, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth %d", rec.Code)
	}
	if rec := e.do(e.admin, http.MethodPost, p, `{"kind":"x","external_id":"a","user_id":"u-1"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad kind %d", rec.Code)
	}
	for _, bad := range []string{"u-off", "u-acme", "nobody"} {
		if rec := e.do(e.admin, http.MethodPost, p, `{"kind":"jira","external_id":"acct-1","user_id":"`+bad+`"}`); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d", bad, rec.Code)
		}
	}
	if rec := e.do(e.admin, http.MethodPost, p, `{"kind":"jira","external_id":"acct-1","user_id":"u-1"}`); rec.Code != http.StatusCreated {
		t.Fatalf("create %d %s", rec.Code, rec.Body.String())
	}
	if m, ok, _ := e.store.LookupMapping(context.Background(), "jira", "acct-1"); !ok || m.UserID != "u-1" || m.Tenant != DefaultTenant {
		t.Fatalf("mapping %+v %v", m, ok)
	}
	if rec := e.do(e.admin, http.MethodGet, p, ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "acct-1") {
		t.Fatalf("list %d %s", rec.Code, rec.Body.String())
	}
	if rec := e.do(e.admin, http.MethodDelete, p+"?kind=jira&external_id=acct-1", ""); rec.Code != http.StatusOK {
		t.Fatalf("delete %d", rec.Code)
	}
	if rec := e.do(e.admin, http.MethodDelete, p+"?kind=jira&external_id=acct-1", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("delete again %d", rec.Code)
	}
	if len(rowsFor(e.audit, "itsm.principal_map.create")) < 5 || len(rowsFor(e.audit, "itsm.principal_map.delete")) != 2 {
		t.Fatalf("audit create=%d delete=%d", len(rowsFor(e.audit, "itsm.principal_map.create")), len(rowsFor(e.audit, "itsm.principal_map.delete")))
	}
}

func TestPrincipalMap_CrossTenantMappingNotTouchable(t *testing.T) {
	e := newITSMMapEnv(t)
	if err := e.store.UpsertMapping(context.Background(), itsm.Mapping{Kind: "jira", ExternalID: "acct-z", UserID: "u-acme", Tenant: "acme"}); err != nil {
		t.Fatal(err)
	}
	const p = "/api/v1/itsm/principal-map"
	if rec := e.do(e.admin, http.MethodPost, p, `{"kind":"jira","external_id":"acct-z","user_id":"u-1"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("overwrite %d", rec.Code)
	}
	if rec := e.do(e.admin, http.MethodDelete, p+"?kind=jira&external_id=acct-z", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("delete %d", rec.Code)
	}
	if m, _, _ := e.store.LookupMapping(context.Background(), "jira", "acct-z"); m.UserID != "u-acme" {
		t.Fatalf("changed: %+v", m)
	}
}

func TestPrincipalMap_NoServiceIs503(t *testing.T) {
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := newReportsTestAuth(t)
	mux := http.NewServeMux()
	registerITSMApprovalHandlers(mux, auth, nil, &expiryAudit{})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, bearerReq(mintAdminToken(t, auth, "a", ""), http.MethodGet, "/api/v1/itsm/principal-map", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("%d", rec.Code)
	}
}

func TestITSMPrincipalMap_TenantMovedUserNotResolved(t *testing.T) {
	e := newITSMMapEnv(t)
	ctx := context.Background()
	users := &stubUserProvider{users: []UserRecord{{ID: "u-1", Role: "pki-admin", Status: "active", Tenant: "acme"}}}
	pm := &itsmPrincipalMap{store: e.store, users: users}
	_ = e.store.UpsertMapping(ctx, itsm.Mapping{Kind: "jira", ExternalID: "a", UserID: "u-1", Tenant: DefaultTenant})
	if _, ok, _ := pm.Lookup(ctx, "jira", "a"); ok {
		t.Fatal("user moved to another tenant must not resolve")
	}
	_ = e.store.UpsertMapping(ctx, itsm.Mapping{Kind: "jira", ExternalID: "a", UserID: "u-1", Tenant: "acme"})
	if id, ok, _ := pm.Lookup(ctx, "jira", "a"); !ok || id != "u-1" {
		t.Fatalf("%s %v", id, ok)
	}
}
