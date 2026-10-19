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
	"testing"
	"time"
)

func TestDecisionChannelSummary_Table(t *testing.T) {
	bg := context.Background()
	itsm, err := NewApprovalChannel(ChannelITSM, "servicenow:INC0012345")
	if err != nil {
		t.Fatal(err)
	}
	evil, err := NewApprovalChannel(ChannelChatOps, "slack:\"T1\"\n/U1")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, action, base string
		ctx                context.Context
		want               string
	}{
		{"ui json empty", "approval.approve", "", bg, `{"channel":"ui"}`},
		{"ui json reject", "approval.reject", `{"reason":"no"}`, bg, `{"channel":"ui","reason":"no"}`},
		{"ui text empty", "action.approve", "", bg, `channel=ui`},
		{"ui text base", "action.reject", "approvals=1/2", bg, `approvals=1/2 channel=ui`},
		{"itsm json", "approval.approve", "", WithApprovalChannel(bg, itsm), `{"channel":"itsm","external_id":"servicenow:INC0012345"}`},
		{"itsm text", "action.approve", "on_behalf_of=A delegate=B", WithApprovalChannel(bg, itsm), `on_behalf_of=A delegate=B channel=itsm external_id=servicenow:INC0012345`},
		{"untouched", "key.revoke", "x", WithApprovalChannel(bg, itsm), "x"},
		{"empty braces", "approval.approve", "{}", bg, `{"channel":"ui"}`},
	}
	for _, c := range cases {
		if got := decisionChannelSummary(c.ctx, c.action, c.base); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}

	got := decisionChannelSummary(WithApprovalChannel(bg, evil), "approval.approve", `{"on_behalf_of":"alice"}`)
	var m map[string]string
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Fatalf("not valid JSON: %v: %s", err, got)
	}
	if m["external_id"] != evil.ExternalID || m["on_behalf_of"] != "alice" || m["channel"] != ChannelChatOps {
		t.Errorf("round trip lost data: %v", m)
	}
	if decisionChannelSummary(nil, "action.approve", "") != "channel=ui" { //nolint:staticcheck // nil-safety is the point
		t.Error("nil ctx should default to ui")
	}
}

func TestNewApprovalChannelRejectsUI(t *testing.T) {
	for _, name := range []string{ChannelUI, "", "bogus"} {
		if _, err := NewApprovalChannel(name, "x"); err == nil {
			t.Errorf("name %q should be rejected", name)
		}
	}
	if _, err := NewApprovalChannel(ChannelITSM, ""); err == nil {
		t.Error("empty external id should be rejected")
	}
	if _, err := NewApprovalChannel(ChannelITSM, strings.Repeat("x", 201)); err == nil {
		t.Error("201-char external id should be rejected")
	}
	if _, err := NewApprovalChannel(ChannelITSM, strings.Repeat("x", 200)); err != nil {
		t.Errorf("200-char external id should pass: %v", err)
	}
}

// certApprovalEnv wires the certificate-approval handlers to a capturing audit.
func certApprovalEnv(t *testing.T) (*http.ServeMux, *Authenticator, ApprovalStore, *expiryAudit, string) {
	t.Helper()
	_, acmeToken, _ := setupTenantWritePathTest(t)
	auth := NewAuthenticatorFromEnv()
	_, token, err := auth.CreateAPIKey("acme-svc2", "svc-principal", "pki-admin", []string{"*"}, "", "acme", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_ = acmeToken
	store, err := newApprovalStoreFromEnv()
	if err != nil || store == nil {
		t.Fatalf("approval store: %v", err)
	}
	audit := &expiryAudit{}
	mux := http.NewServeMux()
	registerApprovalHandlers(mux, auth, store, NewFileCertificateProviderFromEnv(), NewFileTemplateProviderFromEnv(), audit)
	return mux, auth, store, audit, token
}

func seedApproval(t *testing.T, s ApprovalStore, id, requester string) {
	t.Helper()
	err := s.Create(context.Background(), ApprovalRequest{ID: id, TemplateID: "tpl-acme", CAID: "ca-acme", Requester: requester,
		Status: "pending", RequestedAt: time.Now().UTC().Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
}

func injectedReq(method, path, body string, ctx context.Context) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Tenant", "acme")
	return r.WithContext(ctx)
}

func rowsFor(a *expiryAudit, action string) []AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []AuditEntry
	for _, e := range a.entries {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

func approverPD() AuthPrincipal {
	return AuthPrincipal{ID: "u-approver", Role: "pki-admin", AuthType: AuthTypeJWT, Tenant: "acme", TenantScoped: true}
}

func TestApproveDefaultsToUIChannel(t *testing.T) {
	mux, _, store, audit, token := certApprovalEnv(t)
	seedApproval(t, store, "apr-ui", "someone-else")
	rec := httptest.NewRecorder()
	req := bearerReq(token, http.MethodPost, "/api/v1/approvals/apr-ui/reject", []byte(`{"reason":"nope"}`))
	req.Header.Set("X-Tenant", "acme")
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("reject: %d %s", rec.Code, rec.Body.String())
	}
	rows := rowsFor(audit, "approval.reject")
	if len(rows) != 1 || !strings.Contains(rows[0].ChangeSummary, `"channel":"ui"`) || !strings.Contains(rows[0].ChangeSummary, `"reason":"nope"`) {
		t.Fatalf("unexpected rows: %+v", rows)
	}
	if strings.Contains(rows[0].ChangeSummary, "external_id") {
		t.Error("ui rows must not carry external_id")
	}
}

func TestPendingActionApproveDefaultsToUIChannel(t *testing.T) {
	e := newDelegEnv(t, "")
	tok := mintAdminToken(t, e.auth, "appr-a", "")
	a := e.propose(t, "proposer-x", "")
	if rec := e.do(tok, http.MethodPost, "/api/v1/pending-actions/"+a.ID+"/approve", ""); rec.Code >= 300 {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	rows := rowsFor(e.audit, "action.approve")
	if len(rows) == 0 || !strings.Contains(rows[0].ChangeSummary, "channel=ui") {
		t.Fatalf("unexpected rows: %+v", rows)
	}
}

func TestApproveViaChatOpsRecordsExternalIdentity(t *testing.T) {
	mux, _, store, audit, _ := certApprovalEnv(t)
	ch, err := NewApprovalChannel(ChannelChatOps, "slack:T1/U1")
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithInjectedPrincipal(WithApprovalChannel(context.Background(), ch), approverPD())

	seedApproval(t, store, "apr-co", "someone-else")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, injectedReq(http.MethodPost, "/api/v1/approvals/apr-co/approve", `{}`, ctx))
	if rows := rowsFor(audit, "approval.approve"); len(rows) == 0 {
		t.Fatalf("no approval.approve row (status %d: %s)", rec.Code, rec.Body.String())
	} else {
		for _, r := range rows {
			if !strings.Contains(r.ChangeSummary, `"channel":"chatops"`) || !strings.Contains(r.ChangeSummary, `"external_id":"slack:T1/U1"`) {
				t.Errorf("approve row missing channel: %q", r.ChangeSummary)
			}
			if r.ActorID != "u-approver" {
				t.Errorf("actor = %q", r.ActorID)
			}
		}
	}

	seedApproval(t, store, "apr-co2", "someone-else")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, injectedReq(http.MethodPost, "/api/v1/approvals/apr-co2/reject", `{"reason":"r"}`, ctx))
	if rec.Code != http.StatusOK {
		t.Fatalf("reject: %d %s", rec.Code, rec.Body.String())
	}
	rows := rowsFor(audit, "approval.reject")
	if len(rows) != 1 || !strings.Contains(rows[0].ChangeSummary, `"channel":"chatops"`) || !strings.Contains(rows[0].ChangeSummary, `slack:T1/U1`) {
		t.Fatalf("reject rows: %+v", rows)
	}

	e := newDelegEnv(t, "")
	a := e.propose(t, "proposer-x", "")
	pd := AuthPrincipal{ID: "u-approver", Role: "pki-admin", AuthType: AuthTypeJWT, Tenant: DefaultTenant, SuperAdmin: true}
	actx := WithInjectedPrincipal(WithApprovalChannel(context.Background(), ch), pd)
	rec = httptest.NewRecorder()
	e.mux.ServeHTTP(rec, injectedReq(http.MethodPost, "/api/v1/pending-actions/"+a.ID+"/approve", ``, actx))
	if rec.Code >= 300 {
		t.Fatalf("action approve: %d %s", rec.Code, rec.Body.String())
	}
	for _, r := range rowsFor(e.audit, "action.approve") {
		if !strings.Contains(r.ChangeSummary, "channel=chatops") || !strings.Contains(r.ChangeSummary, "external_id=slack:T1/U1") {
			t.Errorf("action.approve row: %q", r.ChangeSummary)
		}
	}
	if len(rowsFor(e.audit, "action.approve")) == 0 {
		t.Error("no action.approve row")
	}
	b := e.propose(t, "proposer-x", "")
	rec = httptest.NewRecorder()
	e.mux.ServeHTTP(rec, injectedReq(http.MethodPost, "/api/v1/pending-actions/"+b.ID+"/reject", `{"reason":"r"}`, actx))
	rj := rowsFor(e.audit, "action.reject")
	if rec.Code >= 300 || len(rj) == 0 || !strings.Contains(rj[0].ChangeSummary, "channel=chatops external_id=slack:T1/U1") {
		t.Fatalf("action reject: %d %s rows=%+v", rec.Code, rec.Body.String(), rj)
	}
}

func TestProposerCannotApproveOnAnyChannel(t *testing.T) {
	for _, name := range []string{ChannelUI, ChannelITSM, ChannelChatOps} {
		t.Run(name, func(t *testing.T) {
			// certificate approvals
			mux, _, store, audit, token := certApprovalEnv(t)
			seedApproval(t, store, "apr-self", "u-approver")
			rec := httptest.NewRecorder()
			if name == ChannelUI {
				req := bearerReq(token, http.MethodPost, "/api/v1/approvals/apr-self/approve", []byte(`{}`))
				req.Header.Set("X-Tenant", "acme")
				// the key's principal is svc-principal: seed a matching request
				seedApproval(t, store, "apr-self-ui", "svc-principal")
				req.URL.Path = "/api/v1/approvals/apr-self-ui/approve"
				mux.ServeHTTP(rec, req)
			} else {
				ch, err := NewApprovalChannel(name, "ext:1")
				if err != nil {
					t.Fatal(err)
				}
				ctx := WithInjectedPrincipal(WithApprovalChannel(context.Background(), ch), approverPD())
				mux.ServeHTTP(rec, injectedReq(http.MethodPost, "/api/v1/approvals/apr-self/approve", `{}`, ctx))
			}
			if rec.Code != http.StatusForbidden {
				t.Fatalf("cert approve: want 403 got %d %s", rec.Code, rec.Body.String())
			}
			rows := rowsFor(audit, "approval.approve")
			if len(rows) != 1 || rows[0].Outcome != AuditOutcomeDenied || !strings.Contains(rows[0].ChangeSummary, `"channel":"`+name+`"`) {
				t.Fatalf("cert denied row: %+v", rows)
			}
			for _, id := range []string{"apr-self", "apr-self-ui"} {
				if apr, err := store.Get(context.Background(), id); err == nil && apr.Status != "pending" {
					t.Errorf("%s no longer pending: %s", id, apr.Status)
				}
			}

			// pending actions
			e := newDelegEnv(t, "")
			a := e.propose(t, "u-approver", "")
			rec = httptest.NewRecorder()
			if name == ChannelUI {
				tok := mintAdminToken(t, e.auth, "u-approver", "")
				rec = e.do(tok, http.MethodPost, "/api/v1/pending-actions/"+a.ID+"/approve", "")
			} else {
				ch, _ := NewApprovalChannel(name, "ext:1")
				pd := AuthPrincipal{ID: "u-approver", Role: "pki-admin", AuthType: AuthTypeJWT, Tenant: DefaultTenant, SuperAdmin: true}
				ctx := WithInjectedPrincipal(WithApprovalChannel(context.Background(), ch), pd)
				e.mux.ServeHTTP(rec, injectedReq(http.MethodPost, "/api/v1/pending-actions/"+a.ID+"/approve", ``, ctx))
			}
			if rec.Code != http.StatusForbidden {
				t.Fatalf("action approve: want 403 got %d %s", rec.Code, rec.Body.String())
			}
			got, _, _ := e.st.Get(context.Background(), a.ID)
			if got.Status != "pending" {
				t.Errorf("action status = %s", got.Status)
			}
			ar := e.audit.all("action.approve", AuditOutcomeDenied)
			if len(ar) != 1 || !strings.Contains(ar[0].ChangeSummary, "channel="+name) {
				t.Fatalf("action denied row: %+v", ar)
			}
		})
	}
}

func TestInjectedPrincipalWithoutChannelIgnored(t *testing.T) {
	mux, _, store, _, _ := certApprovalEnv(t)
	seedApproval(t, store, "apr-nc", "someone-else")
	ctx := WithInjectedPrincipal(context.Background(), approverPD())
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, injectedReq(http.MethodPost, "/api/v1/approvals/apr-nc/approve", `{}`, ctx))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("approvals: want 401 got %d", rec.Code)
	}
	e := newDelegEnv(t, "")
	a := e.propose(t, "p", "")
	rec = httptest.NewRecorder()
	e.mux.ServeHTTP(rec, injectedReq(http.MethodPost, "/api/v1/pending-actions/"+a.ID+"/approve", ``, ctx))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("pending-actions: want 401 got %d", rec.Code)
	}
}
