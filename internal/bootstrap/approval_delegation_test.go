// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func (a *expiryAudit) all(action string, outcome AuditOutcome) []AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []AuditEntry
	for _, e := range a.entries {
		if e.Action == action && e.Outcome == outcome {
			out = append(out, e)
		}
	}
	return out
}

type delegEnv struct {
	mux   *http.ServeMux
	auth  *Authenticator
	st    *dbPendingActionStore
	ds    *approvalDelegationStore
	audit *expiryAudit
	ran   *atomic.Int32
}

func newDelegEnv(t *testing.T, policy string) delegEnv {
	t.Helper()
	t.Setenv(approvalQuorumPolicyEnv, policy)
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := newReportsTestAuth(t)
	st := newTestPendingStore(t)
	audit := &expiryAudit{}
	var ran atomic.Int32
	execs := map[string]ActionExecutor{"revoke": func(context.Context, PendingAction, AuthPrincipal) (json.RawMessage, error) {
		ran.Add(1)
		return json.RawMessage(`{}`), nil
	}}
	mux := http.NewServeMux()
	registerPendingActionHandlers(mux, auth, &reportCertProvider{}, st, audit, execs)
	ds := delegationStoreForActions(st)
	registerApprovalDelegationHandlers(mux, auth, ds, audit)
	return delegEnv{mux, auth, st, ds, audit, &ran}
}

func (e delegEnv) do(token, method, path, body string) *httptest.ResponseRecorder {
	var b []byte
	if body != "" {
		b = []byte(body)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, bearerReq(token, method, path, b))
	return rec
}

func delegBody(delegate string, start, end time.Time) string {
	return fmt.Sprintf(`{"delegate":%q,"starts_at":%q,"ends_at":%q}`, delegate, start.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339))
}

func (e delegEnv) propose(t *testing.T, proposer, tenant string) PendingAction {
	t.Helper()
	a, err := e.st.Create(context.Background(), PendingAction{ActionType: "revoke", Params: json.RawMessage(`{"fingerprint":"fp"}`), ProposedBy: proposer, Tenant: tenant})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestValidateDelegation(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	mk := func(s, e time.Time) ApprovalDelegation {
		return ApprovalDelegation{StartsAt: s.Format(time.RFC3339), EndsAt: e.Format(time.RFC3339)}
	}
	cases := []struct {
		name    string
		d       ApprovalDelegation
		wantErr string
	}{
		{"ok", mk(now, now.Add(48*time.Hour)), ""},
		{"30 days exactly", mk(now, now.Add(30*24*time.Hour)), ""},
		{"31 days", mk(now, now.Add(31*24*time.Hour)), "30 days"},
		{"ends before starts", mk(now.Add(time.Hour), now), "after starts_at"},
		{"already ended", mk(now.Add(-48*time.Hour), now.Add(-time.Hour)), "future"},
		{"bad time", ApprovalDelegation{StartsAt: "x", EndsAt: "y"}, "RFC3339"},
	}
	for _, c := range cases {
		err := validateDelegation(c.d, now)
		if (c.wantErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.wantErr)) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.wantErr)
		}
	}
}

func TestSetDelegationRange400(t *testing.T) {
	e := newDelegEnv(t, "")
	tokA := mintAdminToken(t, e.auth, "appr-a", "")
	mintAdminToken(t, e.auth, "appr-b", "")
	now := time.Now()
	if rec := e.do(tokA, http.MethodPut, "/api/v1/approvals/delegation", delegBody("appr-b", now, now.Add(31*24*time.Hour))); rec.Code != http.StatusBadRequest {
		t.Fatalf("31d: %d %s", rec.Code, rec.Body.String())
	}
	if rec := e.do(tokA, http.MethodPut, "/api/v1/approvals/delegation", delegBody("appr-b", now, now.Add(30*24*time.Hour))); rec.Code != http.StatusOK {
		t.Fatalf("30d: %d %s", rec.Code, rec.Body.String())
	}
	if rec := e.do(tokA, http.MethodPut, "/api/v1/approvals/delegation", delegBody("appr-a", now, now.Add(time.Hour))); rec.Code != http.StatusBadRequest {
		t.Fatalf("self delegate: %d", rec.Code)
	}
	if rec := e.do(tokA, http.MethodGet, "/api/v1/approvals/delegation", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "appr-b") {
		t.Fatalf("get: %d %s", rec.Code, rec.Body.String())
	}
}

func TestDelegateWithoutApproveCapabilityRefused(t *testing.T) {
	e := newDelegEnv(t, "")
	tokA := mintAdminToken(t, e.auth, "appr-a", "")
	if _, _, err := e.auth.CreateAPIKey("viewer-key", "viewer-1", "pki-viewer", []string{"*"}, "", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, delegate := range []string{"viewer-1", "nobody-knows"} {
		if rec := e.do(tokA, http.MethodPut, "/api/v1/approvals/delegation", delegBody(delegate, now, now.Add(time.Hour))); rec.Code != http.StatusForbidden {
			t.Fatalf("%s: %d %s", delegate, rec.Code, rec.Body.String())
		}
	}
	if len(e.audit.all("approval.delegate", AuditOutcomeDenied)) != 2 {
		t.Fatalf("denied audit rows: %+v", e.audit.entries)
	}
	// The bootstrap token (a setup credential) may not delegate at all.
	if rec := e.do("reports-test-token", http.MethodPut, "/api/v1/approvals/delegation", delegBody("appr-a", now, now.Add(time.Hour))); rec.Code != http.StatusForbidden {
		t.Fatalf("bootstrap: %d", rec.Code)
	}
}

func TestDelegateApprovalInsideRange200(t *testing.T) {
	e := newDelegEnv(t, "")
	tokA := mintAdminToken(t, e.auth, "appr-a", "")
	tokB := mintAdminToken(t, e.auth, "appr-b", "")
	now := time.Now()
	if rec := e.do(tokA, http.MethodPut, "/api/v1/approvals/delegation", delegBody("appr-b", now.Add(-time.Minute), now.Add(time.Hour))); rec.Code != http.StatusOK {
		t.Fatalf("set: %d %s", rec.Code, rec.Body.String())
	}
	a := e.propose(t, "prop-c", "")
	rec := e.do(tokB, http.MethodPost, "/api/v1/pending-actions/"+a.ID+"/approve", `{"on_behalf_of":"appr-a"}`)
	if rec.Code != http.StatusOK || e.ran.Load() != 1 {
		t.Fatalf("approve: %d %s ran=%d", rec.Code, rec.Body.String(), e.ran.Load())
	}
	rows := e.audit.all("action.approve", AuditOutcomeSuccess)
	if len(rows) != 1 || !strings.Contains(rows[0].ChangeSummary, "appr-a") || !strings.Contains(rows[0].ChangeSummary, "appr-b") || rows[0].ActorID != "appr-b" {
		t.Fatalf("audit rows: %+v", rows)
	}
	if g, _, _ := e.st.Get(context.Background(), a.ID); g.ApprovedBy != "appr-b" {
		t.Fatalf("approved_by = %s", g.ApprovedBy)
	}
}

func TestDelegateApprovalOutsideRange403(t *testing.T) {
	e := newDelegEnv(t, "")
	mintAdminToken(t, e.auth, "appr-a", "")
	tokB := mintAdminToken(t, e.auth, "appr-b", "")
	now := time.Now().UTC()
	fmtT := func(t time.Time) string { return t.Format(time.RFC3339) }
	for name, w := range map[string][2]time.Time{
		"ended":       {now.Add(-48 * time.Hour), now.Add(-time.Hour)},
		"not started": {now.Add(time.Hour), now.Add(48 * time.Hour)},
	} {
		// Set directly: the API refuses an already-ended window by design.
		if err := e.ds.Set(context.Background(), ApprovalDelegation{Delegator: "appr-a", Delegate: "appr-b", StartsAt: fmtT(w[0]), EndsAt: fmtT(w[1]), CreatedAt: fmtT(now), Tenant: DefaultTenant}); err != nil {
			t.Fatal(err)
		}
		a := e.propose(t, "prop-c", "")
		if rec := e.do(tokB, http.MethodPost, "/api/v1/pending-actions/"+a.ID+"/approve", `{"on_behalf_of":"appr-a"}`); rec.Code != http.StatusForbidden {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if e.ran.Load() != 0 {
		t.Fatal("executor ran outside the delegation window")
	}
}

func TestDelegateWrongPersonRefused(t *testing.T) {
	e := newDelegEnv(t, "")
	tokA := mintAdminToken(t, e.auth, "appr-a", "")
	mintAdminToken(t, e.auth, "appr-b", "")
	tokD := mintAdminToken(t, e.auth, "appr-d", "")
	now := time.Now()
	e.do(tokA, http.MethodPut, "/api/v1/approvals/delegation", delegBody("appr-b", now, now.Add(time.Hour)))
	a := e.propose(t, "prop-c", "")
	if rec := e.do(tokD, http.MethodPost, "/api/v1/pending-actions/"+a.ID+"/approve", `{"on_behalf_of":"appr-a"}`); rec.Code != http.StatusForbidden || e.ran.Load() != 0 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

func TestDelegatorIsProposerRefused(t *testing.T) {
	e := newDelegEnv(t, "")
	tokA := mintAdminToken(t, e.auth, "appr-a", "")
	tokB := mintAdminToken(t, e.auth, "appr-b", "")
	now := time.Now()
	e.do(tokA, http.MethodPut, "/api/v1/approvals/delegation", delegBody("appr-b", now, now.Add(time.Hour)))
	a := e.propose(t, "appr-a", "")
	rec := e.do(tokB, http.MethodPost, "/api/v1/pending-actions/"+a.ID+"/approve", `{"on_behalf_of":"appr-a"}`)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "own action") || e.ran.Load() != 0 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

func TestDelegationAuditOnSetAndClear(t *testing.T) {
	e := newDelegEnv(t, "")
	tokA := mintAdminToken(t, e.auth, "appr-a", "")
	mintAdminToken(t, e.auth, "appr-b", "")
	now := time.Now()
	if rec := e.do(tokA, http.MethodPut, "/api/v1/approvals/delegation", delegBody("appr-b", now, now.Add(time.Hour))); rec.Code != http.StatusOK {
		t.Fatalf("set: %d", rec.Code)
	}
	if rec := e.do(tokA, http.MethodDelete, "/api/v1/approvals/delegation", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("clear: %d", rec.Code)
	}
	rows := e.audit.all("approval.delegate", AuditOutcomeSuccess)
	if len(rows) != 2 || !strings.Contains(rows[0].ChangeSummary, "delegate=appr-b") || rows[1].ChangeSummary != "cleared" {
		t.Fatalf("rows: %+v", rows)
	}
	if rec := e.do(tokA, http.MethodGet, "/api/v1/approvals/delegation", ""); !strings.Contains(rec.Body.String(), `"data":null`) {
		t.Fatalf("get after clear: %s", rec.Body.String())
	}
}

func TestDelegationQuorumCountsOnce(t *testing.T) {
	e := newDelegEnv(t, "revoke=2/3")
	tokA := mintAdminToken(t, e.auth, "appr-a", "")
	tokB := mintAdminToken(t, e.auth, "appr-b", "")
	now := time.Now()
	e.do(tokA, http.MethodPut, "/api/v1/approvals/delegation", delegBody("appr-b", now, now.Add(time.Hour)))
	a := e.propose(t, "prop-c", "")
	if rec := e.do(tokA, http.MethodPost, "/api/v1/pending-actions/"+a.ID+"/approve", ""); rec.Code != http.StatusAccepted {
		t.Fatalf("direct: %d", rec.Code)
	}
	if rec := e.do(tokB, http.MethodPost, "/api/v1/pending-actions/"+a.ID+"/approve", `{"on_behalf_of":"appr-a"}`); rec.Code != http.StatusConflict {
		t.Fatalf("delegated duplicate: %d %s", rec.Code, rec.Body.String())
	}
	if e.ran.Load() != 0 {
		t.Fatal("quorum satisfied by one human")
	}
	// B approving as themselves still counts as a second distinct human.
	if rec := e.do(tokB, http.MethodPost, "/api/v1/pending-actions/"+a.ID+"/approve", ""); rec.Code != http.StatusOK || e.ran.Load() != 1 {
		t.Fatalf("own approval: %d", rec.Code)
	}
}

func TestDelegationIsTenantScoped(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	e := newDelegEnv(t, "")
	t.Setenv("MULTI_TENANCY", "on")
	mk := func(principal, tenant string) string {
		_, tok, err := e.auth.CreateAPIKeyAs("", principal+"-"+tenant, principal, "pki-admin", []string{"*"}, "", tenant, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	acmeA, acmeB := mk("appr-a", "acme"), mk("appr-b", "acme")
	globexA, globexB := mk("appr-a", "globex"), mk("appr-b", "globex")
	now := time.Now()
	if rec := e.do(acmeA, http.MethodPut, "/api/v1/approvals/delegation", delegBody("appr-b", now, now.Add(time.Hour))); rec.Code != http.StatusOK {
		t.Fatalf("acme set: %d %s", rec.Code, rec.Body.String())
	}
	// Same principal id in another tenant sees no delegation and cannot clear acme's.
	if rec := e.do(globexA, http.MethodGet, "/api/v1/approvals/delegation", ""); !strings.Contains(rec.Body.String(), `"data":null`) {
		t.Fatalf("globex sees acme delegation: %s", rec.Body.String())
	}
	e.do(globexA, http.MethodDelete, "/api/v1/approvals/delegation", "")
	if _, ok, _ := e.ds.Get(context.Background(), "appr-a", "acme"); !ok {
		t.Fatal("globex delete removed acme's delegation")
	}
	// Acme delegation is unusable on a globex action: the acme delegate cannot even see it...
	gAction := e.propose(t, "prop-c", "globex")
	if rec := e.do(acmeB, http.MethodPost, "/api/v1/pending-actions/"+gAction.ID+"/approve", `{"on_behalf_of":"appr-a"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("acme delegate on globex action: %d", rec.Code)
	}
	// ...and a globex principal with the same id cannot consume it either.
	if rec := e.do(globexB, http.MethodPost, "/api/v1/pending-actions/"+gAction.ID+"/approve", `{"on_behalf_of":"appr-a"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("globex delegate using acme delegation: %d %s", rec.Code, rec.Body.String())
	}
	// In its own tenant the delegation works.
	aAction := e.propose(t, "prop-c", "acme")
	if rec := e.do(acmeB, http.MethodPost, "/api/v1/pending-actions/"+aAction.ID+"/approve", `{"on_behalf_of":"appr-a"}`); rec.Code != http.StatusOK {
		t.Fatalf("acme in-tenant: %d %s", rec.Code, rec.Body.String())
	}
	if e.ran.Load() != 1 {
		t.Fatalf("ran = %d", e.ran.Load())
	}
}

func TestDelegatedCertificateApproval(t *testing.T) {
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := newReportsTestAuth(t)
	store := newTestApprovalStore(t)
	audit := &expiryAudit{}
	mux := http.NewServeMux()
	registerApprovalHandlers(mux, auth, store, &reportCertProvider{}, foundTemplateProvider{}, audit)
	tokA := mintAdminToken(t, auth, "appr-a", "")
	tokB := mintAdminToken(t, auth, "appr-b", "")
	do := func(tok, method, path, body string) *httptest.ResponseRecorder {
		var b []byte
		if body != "" {
			b = []byte(body)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, bearerReq(tok, method, path, b))
		return rec
	}
	seed := func(id string) {
		if err := store.Create(context.Background(), ApprovalRequest{ID: id, TemplateID: "tpl", CAID: "ca", Requester: "requester", RequestedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	if rec := do(tokA, http.MethodPut, "/api/v1/approvals/delegation", delegBody("appr-b", now, now.Add(time.Hour))); rec.Code != http.StatusOK {
		t.Fatalf("set: %d %s", rec.Code, rec.Body.String())
	}
	seed("apr-1")
	if rec := do(tokB, http.MethodPost, "/api/v1/approvals/apr-1/approve", `{"on_behalf_of":"appr-a"}`); rec.Code != http.StatusCreated {
		t.Fatalf("inside range: %d %s", rec.Code, rec.Body.String())
	}
	rows := audit.all("approval.approve", AuditOutcomeSuccess)
	if len(rows) != 1 || !strings.Contains(rows[0].ChangeSummary, `"on_behalf_of":"appr-a"`) || !strings.Contains(rows[0].ChangeSummary, `"delegate":"appr-b"`) {
		t.Fatalf("audit: %+v", rows)
	}
	// Window over: same delegate, same delegator, now refused.
	ds := delegationStoreForApprovals(store)
	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	if err := ds.Set(context.Background(), ApprovalDelegation{Delegator: "appr-a", Delegate: "appr-b", StartsAt: past, EndsAt: past, CreatedAt: past, Tenant: DefaultTenant}); err != nil {
		t.Fatal(err)
	}
	seed("apr-2")
	if rec := do(tokB, http.MethodPost, "/api/v1/approvals/apr-2/approve", `{"on_behalf_of":"appr-a"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("outside range: %d %s", rec.Code, rec.Body.String())
	}
	// Empty body keeps working.
	if rec := do(tokB, http.MethodPost, "/api/v1/approvals/apr-2/approve", ""); rec.Code != http.StatusCreated {
		t.Fatalf("plain approve: %d %s", rec.Code, rec.Body.String())
	}
}
