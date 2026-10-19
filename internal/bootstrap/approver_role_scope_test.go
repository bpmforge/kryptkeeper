// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// approverTemplates names roles per template: tpl-appr lists approver,
// tpl-ops lists only pki-operator, anything else lists nobody.
type approverTemplates struct{ stubTemplateProvider }

func (approverTemplates) GetTemplate(_ context.Context, id string) (TemplateItem, bool, error) {
	switch id {
	case "tpl-appr":
		return TemplateItem{ID: id, ApprovalRoles: []string{"approver", "pki-operator"}}, true, nil
	case "tpl-ops":
		return TemplateItem{ID: id, ApprovalRoles: []string{"pki-operator"}}, true, nil
	}
	return TemplateItem{ID: id}, true, nil
}

func newApproverEnv(t *testing.T, multiTenant bool) (inboxEnv, string, *expiryAudit) {
	t.Helper()
	e := newInboxEnv(t, multiTenant)
	audit := &expiryAudit{}
	mux := http.NewServeMux()
	registerPendingActionHandlers(mux, e.auth, &reportCertProvider{}, e.actions, audit, map[string]ActionExecutor{})
	registerApprovalHandlers(mux, e.auth, e.approvals, &reportCertProvider{}, approverTemplates{}, audit)
	registerApprovalInboxHandlers(mux, e.auth, e.approvals, e.actions, e.tenants, audit, approverTemplates{})
	e.mux = mux
	tenant := ""
	if multiTenant {
		tenant = "acme"
	}
	_, tok, err := e.auth.CreateAPIKeyAs("", "appr-1", "appr-1", "approver", []string{"*"}, "", tenant, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return e, tok, audit
}

func (e inboxEnv) seedCertTpl(t *testing.T, id, tpl, ca, requester string) {
	t.Helper()
	if err := e.approvals.Create(context.Background(), ApprovalRequest{ID: id, TemplateID: tpl, CAID: ca, Requester: requester,
		RequestedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
}

func TestApproverRole_DecidesOnlyTemplatesNamingIt(t *testing.T) {
	e, tok, audit := newApproverEnv(t, false)
	e.seedCertTpl(t, "ok", "tpl-appr", "ca-acme", "req-1")
	e.seedCertTpl(t, "no", "tpl-ops", "ca-acme", "req-1")
	e.seedCertTpl(t, "none", "tpl-none", "ca-acme", "req-1")
	for _, id := range []string{"no", "none"} {
		if rec := e.do(tok, http.MethodPost, "/api/v1/approvals/"+id+"/approve"); rec.Code != http.StatusForbidden {
			t.Fatalf("approve %s: %d %s", id, rec.Code, rec.Body.String())
		}
		if got, _ := e.approvals.Get(context.Background(), id); got.Status != "pending" {
			t.Fatalf("%s status %s", id, got.Status)
		}
	}
	if len(audit.all("approval.approve", AuditOutcomeDenied)) != 2 {
		t.Fatalf("denied audit rows: %+v", audit.entries)
	}
	if rec := e.do(tok, http.MethodPost, "/api/v1/approvals/ok/approve"); rec.Code != http.StatusCreated {
		t.Fatalf("approve ok: %d %s", rec.Code, rec.Body.String())
	}
	if got, _ := e.approvals.Get(context.Background(), "ok"); got.Status != "approved" || got.DecidedBy == nil || *got.DecidedBy != "appr-1" {
		t.Fatalf("ok row: %+v", got)
	}
	if len(audit.all("approval.approve", AuditOutcomeSuccess)) != 1 {
		t.Fatalf("success audit rows: %+v", audit.entries)
	}
	e.seedCertTpl(t, "rej", "tpl-appr", "ca-acme", "req-1")
	if rec := e.do(tok, http.MethodPost, "/api/v1/approvals/rej/reject"); rec.Code == http.StatusForbidden {
		t.Fatalf("reject on a naming template refused: %s", rec.Body.String())
	}
}

func TestApproverRole_CannotApproveOwnRequest(t *testing.T) {
	e, tok, audit := newApproverEnv(t, false)
	e.seedCertTpl(t, "mine", "tpl-appr", "ca-acme", "appr-1")
	rec := e.do(tok, http.MethodPost, "/api/v1/approvals/mine/approve")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), msgSelfApproval) {
		t.Fatalf("self approve: %d %s", rec.Code, rec.Body.String())
	}
	if got, _ := e.approvals.Get(context.Background(), "mine"); got.Status != "pending" {
		t.Fatalf("status %s", got.Status)
	}
	if len(audit.all("approval.approve", AuditOutcomeDenied)) != 1 {
		t.Fatalf("audit: %+v", audit.entries)
	}
}

func TestApproverRole_ListAndInboxShowOnlyActionableItems(t *testing.T) {
	e, tok, _ := newApproverEnv(t, false)
	e.seedCertTpl(t, "ok", "tpl-appr", "ca-acme", "req-1")
	e.seedCertTpl(t, "no", "tpl-ops", "ca-acme", "req-1")
	e.seedCertTpl(t, "mine", "tpl-ops", "ca-acme", "appr-1")
	e.seedAction(t, "agent", "")
	ownAction := e.seedAction(t, "appr-1", "")

	var list struct {
		Data []ApprovalRequest `json:"data"`
	}
	rec := e.do(tok, http.MethodGet, "/api/v1/approvals?status=pending")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, a := range list.Data {
		got[a.ID] = true
	}
	if len(got) != 2 || !got["ok"] || !got["mine"] {
		t.Fatalf("list ids: %v", got)
	}
	if rec := e.do(tok, http.MethodGet, "/api/v1/approvals/ok"); rec.Code != http.StatusOK {
		t.Fatalf("get ok: %d", rec.Code)
	}
	if rec := e.do(tok, http.MethodGet, "/api/v1/approvals/no"); rec.Code != http.StatusForbidden {
		t.Fatalf("get no: %d", rec.Code)
	}

	in := decodeInbox(t, e.do(tok, http.MethodGet, "/api/v1/approvals/inbox"))
	ids := map[string]bool{}
	for _, it := range in.Data {
		ids[it.Type+":"+it.ID] = true
	}
	want := map[string]bool{"certificate_approval:ok": true, "certificate_approval:mine": true, "pending_action:" + ownAction.ID: true}
	if len(ids) != len(want) {
		t.Fatalf("inbox ids: %v want %v", ids, want)
	}
	for k := range want {
		if !ids[k] {
			t.Fatalf("inbox missing %s: %v", k, ids)
		}
	}
}

func TestApproverRole_CannotDecidePendingActions(t *testing.T) {
	e, tok, audit := newApproverEnv(t, false)
	a := e.seedAction(t, "agent", "")
	for _, verb := range []string{"approve", "reject"} {
		for _, p := range []string{"/api/v1/pending-actions/", "/api/v1/approvals/inbox/pending_action/"} {
			if rec := e.do(tok, http.MethodPost, p+a.ID+"/"+verb); rec.Code != http.StatusForbidden {
				t.Fatalf("%s%s: %d %s", p, verb, rec.Code, rec.Body.String())
			}
		}
	}
	if got, _, _ := e.actions.Get(context.Background(), a.ID); got.Status != "pending" {
		t.Fatalf("status %s", got.Status)
	}
	if e.ran.Load() != 0 || len(audit.all("action.approve", AuditOutcomeDenied)) == 0 {
		t.Fatalf("ran=%d audit=%+v", e.ran.Load(), audit.entries)
	}
}

func TestApproverRole_TenantIsolation(t *testing.T) {
	e, tok, _ := newApproverEnv(t, true)
	e.seedCertTpl(t, "mine", "tpl-appr", "ca-acme", "req-1")
	e.seedCertTpl(t, "other", "tpl-appr", "ca-globex", "req-2")
	if rec := e.do(tok, http.MethodPost, "/api/v1/approvals/other/approve"); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant approve: %d %s", rec.Code, rec.Body.String())
	}
	if got, _ := e.approvals.Get(context.Background(), "other"); got.Status != "pending" {
		t.Fatalf("status %s", got.Status)
	}
	in := decodeInbox(t, e.do(tok, http.MethodGet, "/api/v1/approvals/inbox"))
	if len(in.Data) != 1 || in.Data[0].ID != "mine" {
		t.Fatalf("inbox: %+v", in.Data)
	}
	if rec := e.do(tok, http.MethodPost, "/api/v1/approvals/mine/approve"); rec.Code != http.StatusCreated {
		t.Fatalf("own-tenant approve: %d %s", rec.Code, rec.Body.String())
	}
}
