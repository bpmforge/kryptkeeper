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

type oboRig struct {
	*enforceRig
	ds                *approvalDelegationStore
	alice, bob, carol string // bearer tokens
}

func newOBORig(t *testing.T) *oboRig {
	t.Helper()
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	prev := activeTenantStore
	activeTenantStore = nil // a store leaked by another test would change CA visibility
	t.Cleanup(func() { activeTenantStore = prev })
	g := newEnforceRig(t)
	registerCertificateOBOHandlers(g.mux, g.auth, g.audit, g.approvals)
	registerApprovalHandlers(g.mux, g.auth, g.approvals, g.certs, g.templates, g.audit)
	o := &oboRig{enforceRig: g, ds: delegationStoreForApprovals(g.approvals)}
	o.alice = mintAdminToken(t, g.auth, "alice", "")
	o.bob = mintAdminToken(t, g.auth, "bob", "")
	o.carol = mintAdminToken(t, g.auth, "carol", "")
	return o
}

func (o *oboRig) delegate(t *testing.T, delegator, delegate, tenant string, start, end time.Time) {
	t.Helper()
	d := ApprovalDelegation{Delegator: delegator, Delegate: delegate, Tenant: tenant,
		StartsAt: start.UTC().Format(time.RFC3339), EndsAt: end.UTC().Format(time.RFC3339), CreatedAt: start.UTC().Format(time.RFC3339)}
	if err := o.ds.Set(context.Background(), d); err != nil {
		t.Fatal(err)
	}
}

func (o *oboRig) delegateNow(t *testing.T, delegator, delegate string) {
	t.Helper()
	o.delegate(t, delegator, delegate, DefaultTenant, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
}

func (o *oboRig) do(tok, method, path, body string) *httptest.ResponseRecorder {
	var b []byte
	if body != "" {
		b = []byte(body)
	}
	rec := httptest.NewRecorder()
	o.mux.ServeHTTP(rec, bearerReq(tok, method, path, b))
	return rec
}

func (o *oboRig) file(t *testing.T, tok, onBehalfOf, cn string) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"ca_id": "ca-1", "template_id": "tpl", "csr_pem": testCSR(t, cn, cn), "on_behalf_of": onBehalfOf})
	return o.do(tok, http.MethodPost, "/api/v1/certificate-requests", string(b))
}

func (o *oboRig) rows(action string, outcome AuditOutcome) []AuditEntry {
	o.audit.mu.Lock()
	defer o.audit.mu.Unlock()
	var out []AuditEntry
	for _, e := range o.audit.entries {
		if e.Action == action && e.Outcome == outcome {
			out = append(out, e)
		}
	}
	return out
}

func detailOf(t *testing.T, e AuditEntry) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(e.ChangeSummary), &m); err != nil {
		t.Fatalf("audit detail %q is not JSON: %v", e.ChangeSummary, err)
	}
	return m
}

func approvalIDOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var b struct {
		Status     string `json:"status"`
		ApprovalID string `json:"approval_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil || b.Status != "pending_approval" || b.ApprovalID == "" {
		t.Fatalf("not a pending approval: %d %s", rec.Code, rec.Body.String())
	}
	return b.ApprovalID
}

func (o *oboRig) wantRefused(t *testing.T, rec *httptest.ResponseRecorder, status int, code, reason string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status %d, want %d: %s", rec.Code, status, rec.Body.String())
	}
	if code != "" && !strings.Contains(rec.Body.String(), code) {
		t.Fatalf("body lacks error_code %q: %s", code, rec.Body.String())
	}
	if n := len(o.approvalsList(t)); n != 0 {
		t.Fatalf("a refusal created %d approvals", n)
	}
	// Every refusal is audited with requester, delegate and the claimed delegator.
	for _, e := range o.audit.entries {
		if e.Action != oboAction || (e.Outcome != AuditOutcomeDenied && e.Outcome != AuditOutcomeFailure) {
			continue
		}
		d := detailOf(t, e)
		if d["reason"] == reason && d["requester"] == "bob" && d["delegate"] == "bob" && d["on_behalf_of"] == "alice" {
			return
		}
	}
	t.Fatalf("no audit row with reason %q, requester/delegate bob, on_behalf_of alice: %+v", reason, o.audit.entries)
}

func (o *oboRig) approvalsList(t *testing.T) []ApprovalRequest {
	t.Helper()
	rows, _, err := o.approvals.List(context.Background(), "", 200, 0)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestOBO_DelegateFilesForOtherTeam_AuditHasThreeFields(t *testing.T) {
	o := newOBORig(t)
	o.delegateNow(t, "alice", "bob")
	id := approvalIDOf(t, o.file(t, o.bob, "alice", "a.corp.example"))
	if rec := o.do(o.carol, http.MethodPost, "/api/v1/approvals/"+id+"/approve", ""); rec.Code != http.StatusCreated {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	fileRows := o.rows(oboAction, AuditOutcomePendingApproval)
	approveRows := o.rows("approval.approve", AuditOutcomeSuccess)
	if len(fileRows) != 1 || len(approveRows) != 1 {
		t.Fatalf("filing rows %d, approve rows %d", len(fileRows), len(approveRows))
	}
	if fileRows[0].ResourceType != "approval" || fileRows[0].ResourceID != id || fileRows[0].ActorID != "bob" {
		t.Fatalf("filing row: %+v", fileRows[0])
	}
	f, a := detailOf(t, fileRows[0]), detailOf(t, approveRows[0])
	got := 0
	if f["requester"] == "bob" && a["requester"] == "bob" {
		got++
	}
	if f["on_behalf_of"] == "alice" && a["on_behalf_of"] == "alice" {
		got++
	}
	if a["approver"] == "carol" {
		got++
	}
	if got != 3 {
		t.Fatalf("requester/on_behalf_of/approver populated %d of 3: filing=%v approve=%v", got, f, a)
	}
	apr, _ := o.approvals.Get(context.Background(), id)
	if apr.Requester != "bob" || apr.TeamID != "alice" || apr.OnBehalfOf != "alice" || apr.Status != "approved" {
		t.Fatalf("stored approval: %+v", apr)
	}
}

func TestOBO_AlwaysGoesToApproval_NeverIssuesDirectly(t *testing.T) {
	o := newOBORig(t)
	o.delegateNow(t, "alice", "bob")
	approvalIDOf(t, o.file(t, o.bob, "alice", "a.corp.example"))
	if o.certs.calls.Load() != 0 {
		t.Fatal("filing must not issue; the approver is part of the audit trail")
	}
}

func TestOBO_NoDelegation_403_obo_no_delegation(t *testing.T) {
	o := newOBORig(t)
	rec := o.file(t, o.bob, "alice", "a.corp.example")
	o.wantRefused(t, rec, http.StatusForbidden, CodeOBONoDelegation, CodeOBONoDelegation)
	if !strings.Contains(rec.Body.String(), "no active delegation from alice to you") {
		t.Fatalf("message: %s", rec.Body.String())
	}
}

// Bob's own team id equalling his principal id is never a delegation.
func TestOBO_TeamIDEqualsCallerIsNotADelegation(t *testing.T) {
	o := newOBORig(t)
	b, _ := json.Marshal(map[string]string{"ca_id": "ca-1", "template_id": "tpl", "csr_pem": testCSR(t, "a.corp.example"), "on_behalf_of": "alice", "team_id": "bob"})
	rec := o.do(o.bob, http.MethodPost, "/api/v1/certificate-requests", string(b))
	o.wantRefused(t, rec, http.StatusForbidden, CodeOBONoDelegation, CodeOBONoDelegation)
}

func TestOBO_DelegationToSomeoneElse_403(t *testing.T) {
	o := newOBORig(t)
	o.delegateNow(t, "alice", "dana")
	o.wantRefused(t, o.file(t, o.bob, "alice", "a.corp.example"), http.StatusForbidden, CodeOBONoDelegation, CodeOBONoDelegation)
}

func TestOBO_ExpiredDelegation_403(t *testing.T) {
	o := newOBORig(t)
	o.delegate(t, "alice", "bob", DefaultTenant, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	o.wantRefused(t, o.file(t, o.bob, "alice", "a.corp.example"), http.StatusForbidden, CodeOBONoDelegation, CodeOBONoDelegation)
}

func TestOBO_NotYetActiveDelegation_403(t *testing.T) {
	o := newOBORig(t)
	o.delegate(t, "alice", "bob", DefaultTenant, time.Now().Add(time.Hour), time.Now().Add(48*time.Hour))
	o.wantRefused(t, o.file(t, o.bob, "alice", "a.corp.example"), http.StatusForbidden, CodeOBONoDelegation, CodeOBONoDelegation)
}

// A delegation recorded in another tenant must not authorise a caller in this one.
func TestOBO_CrossTenantDelegate_Refused(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	o := newOBORig(t)
	t.Setenv("MULTI_TENANCY", "on") // newEnforceRig turned it off
	// Tenant gates fail closed without a store (D-202): map the rig's CA and
	// template to tenant-2 so bob's own-tenant request is visible.
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	ts := NewTenantStoreFromEnv()
	if ts == nil {
		t.Fatal("tenant store unavailable")
	}
	for _, id := range []string{"tenant-1", "tenant-2"} {
		if _, err := ts.CreateTenant(context.Background(), id, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := ts.SetCATenant(context.Background(), "ca-1", "tenant-2"); err != nil {
		t.Fatal(err)
	}
	if err := ts.SetTemplateTenant(context.Background(), "tpl", "tenant-2"); err != nil {
		t.Fatal(err)
	}
	setActiveTenantStore(ts)
	if _, tok, err := o.auth.CreateAPIKey("bob-t2", "bob", "pki-admin", []string{"*"}, "", "tenant-2", time.Now()); err != nil {
		t.Fatal(err)
	} else {
		o.bob = tok
	}
	// alice's delegation to bob lives in tenant-1.
	o.delegate(t, "alice", "bob", "tenant-1", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	o.wantRefused(t, o.file(t, o.bob, "alice", "a.corp.example"), http.StatusForbidden, CodeOBONoDelegation, CodeOBONoDelegation)
	// Control: the same delegation recorded in bob's own tenant works.
	o.delegate(t, "alice", "bob", "tenant-2", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	approvalIDOf(t, o.file(t, o.bob, "alice", "b.corp.example"))
}

func TestOBO_SelfOnBehalf_400(t *testing.T) {
	o := newOBORig(t)
	o.delegateNow(t, "bob", "bob")
	rec := o.file(t, o.bob, "bob", "a.corp.example")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if len(o.rows(oboAction, AuditOutcomeFailure)) != 1 || len(o.approvalsList(t)) != 0 {
		t.Fatalf("self request must be audited and file nothing: %+v", o.audit.entries)
	}
}

// A second credential minted by bob is still bob.
func TestOBO_SameHumanOnBehalf_400(t *testing.T) {
	o := newOBORig(t)
	_, tok, err := o.auth.CreateAPIKeyAs("bob", "bob-2-key", "bob-2", "pki-admin", []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	o.delegateNow(t, "bob", "bob-2")
	if rec := o.file(t, tok, "bob", "a.corp.example"); rec.Code != http.StatusBadRequest {
		t.Fatalf("same human: %d %s", rec.Code, rec.Body.String())
	}
}

func TestOBO_BadInput_400_Audited(t *testing.T) {
	o := newOBORig(t)
	for name, body := range map[string]string{
		"not json":        "nope",
		"no on_behalf_of": `{"ca_id":"ca-1","template_id":"tpl","csr_pem":"x"}`,
		"no csr":          `{"ca_id":"ca-1","template_id":"tpl","on_behalf_of":"alice"}`,
	} {
		before := len(o.rows(oboAction, AuditOutcomeFailure))
		if rec := o.do(o.bob, http.MethodPost, "/api/v1/certificate-requests", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
		if len(o.rows(oboAction, AuditOutcomeFailure)) != before+1 {
			t.Errorf("%s: validation failure not audited", name)
		}
	}
}

func TestOBO_Unauthenticated_401_Audited(t *testing.T) {
	o := newOBORig(t)
	rec := o.do("bad-token", http.MethodPost, "/api/v1/certificate-requests", `{}`)
	if rec.Code != http.StatusUnauthorized || len(o.rows(oboAction, AuditOutcomeDenied)) != 1 {
		t.Fatalf("%d %+v", rec.Code, o.audit.entries)
	}
}

func TestOBO_Approval_ProposerCannotSelfApprove(t *testing.T) {
	o := newOBORig(t)
	o.delegateNow(t, "alice", "bob")
	id := approvalIDOf(t, o.file(t, o.bob, "alice", "a.corp.example"))
	rec := o.do(o.bob, http.MethodPost, "/api/v1/approvals/"+id+"/approve", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("delegate approving own request: %d %s", rec.Code, rec.Body.String())
	}
	// Not even by also claiming the delegator's approval right.
	rec = o.do(o.bob, http.MethodPost, "/api/v1/approvals/"+id+"/approve", `{"on_behalf_of":"alice"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("delegate approving own request on alice's behalf: %d %s", rec.Code, rec.Body.String())
	}
	if apr, _ := o.approvals.Get(context.Background(), id); apr.Status != "pending" {
		t.Fatalf("status %q", apr.Status)
	}
	denied := o.rows("approval.approve", AuditOutcomeDenied)
	if len(denied) == 0 {
		t.Fatal("refusal not audited")
	}
	d := detailOf(t, denied[0])
	if d["requester"] != "bob" || d["on_behalf_of"] != "alice" || d["approver"] != "bob" {
		t.Fatalf("denied approval detail: %v", d)
	}
}

func TestOBO_RejectAuditHasThreeFields(t *testing.T) {
	o := newOBORig(t)
	o.delegateNow(t, "alice", "bob")
	id := approvalIDOf(t, o.file(t, o.bob, "alice", "a.corp.example"))
	if rec := o.do(o.carol, http.MethodPost, "/api/v1/approvals/"+id+"/reject", `{"reason":"no"}`); rec.Code != http.StatusOK {
		t.Fatalf("reject: %d %s", rec.Code, rec.Body.String())
	}
	rows := o.rows("approval.reject", AuditOutcomeSuccess)
	if len(rows) != 1 {
		t.Fatalf("reject rows: %d", len(rows))
	}
	if d := detailOf(t, rows[0]); d["requester"] != "bob" || d["on_behalf_of"] != "alice" || d["approver"] != "carol" || d["reason"] != "no" {
		t.Fatalf("reject detail: %v", d)
	}
}

func TestOBO_QuotaChargedToDelegatorTeam(t *testing.T) {
	o := newOBORig(t)
	if o.enf == nil {
		t.Skip("no team policy enforcer")
	}
	o.delegateNow(t, "alice", "bob")
	pol := func(team string, quota int) {
		if _, err := o.policies.Put(context.Background(), TeamPolicy{Tenant: DefaultTenant, Team: team, MonthlyQuota: quota}, 0, "test"); err != nil {
			t.Fatal(err)
		}
	}
	pol("alice", 1)
	pol("bob", 100)
	approvalIDOf(t, o.file(t, o.bob, "alice", "a.corp.example"))
	if used, _, _, _ := o.enf.Usage(context.Background(), DefaultTenant, "alice"); used != 1 {
		t.Fatalf("alice used %d, want 1", used)
	}
	if used, _, _, _ := o.enf.Usage(context.Background(), DefaultTenant, "bob"); used != 0 {
		t.Fatalf("bob (the delegate) was charged %d", used)
	}
	rec := o.file(t, o.bob, "alice", "b.corp.example")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), CodeTeamQuotaExceeded) {
		t.Fatalf("second request: %d %s", rec.Code, rec.Body.String())
	}
	rows := o.rows("request.quota_exceeded", AuditOutcomeDenied)
	if len(rows) != 1 {
		t.Fatalf("quota audit rows: %d", len(rows))
	}
	if d := detailOf(t, rows[0]); d["requester"] != "bob" || d["delegate"] != "bob" || d["on_behalf_of"] != "alice" {
		t.Fatalf("quota detail: %v", d)
	}
}

// The delegator's policy decides, not the delegate's; D-195 no-policy = unrestricted.
func TestOBO_PolicyIsTheDelegatorsTeam(t *testing.T) {
	o := newOBORig(t)
	o.delegateNow(t, "alice", "bob")
	// bob's own team is locked down, alice's is open: allowed.
	if _, err := o.policies.Put(context.Background(), TeamPolicy{Tenant: DefaultTenant, Team: "bob", AllowedCAs: []string{"only-ca"}}, 0, "test"); err != nil {
		t.Fatal(err)
	}
	approvalIDOf(t, o.file(t, o.bob, "alice", "a.corp.example"))
	// alice's team restricts CAs: refused with the policy code and audited with all three parties.
	if _, err := o.policies.Put(context.Background(), TeamPolicy{Tenant: DefaultTenant, Team: "alice", AllowedCAs: []string{"only-ca"}}, 0, "test"); err != nil {
		t.Fatal(err)
	}
	rec := o.file(t, o.bob, "alice", "b.corp.example")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), CodeTeamCANotAllowed) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	found := false
	for _, e := range o.rows(oboAction, AuditOutcomeDenied) {
		if d := detailOf(t, e); d["reason"] == CodeTeamCANotAllowed && d["requester"] == "bob" && d["on_behalf_of"] == "alice" {
			found = true
		}
	}
	if !found {
		t.Fatalf("policy denial not audited with requester/on_behalf_of: %+v", o.audit.entries)
	}
}

func TestOBO_EnforcementFailsClosed(t *testing.T) {
	o := newOBORig(t)
	o.delegateNow(t, "alice", "bob")
	o.enf.counters.db.Close()
	if rec := o.file(t, o.bob, "alice", "a.corp.example"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if len(o.rows(oboAction, AuditOutcomeFailure)) != 1 {
		t.Fatalf("not audited: %+v", o.audit.entries)
	}
}

func TestOBO_DuplicatePendingReusedAndChargedOnce(t *testing.T) {
	o := newOBORig(t)
	o.delegateNow(t, "alice", "bob")
	if _, err := o.policies.Put(context.Background(), TeamPolicy{Tenant: DefaultTenant, Team: "alice", MonthlyQuota: 5}, 0, "test"); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]string{"ca_id": "ca-1", "template_id": "tpl", "csr_pem": testCSR(t, "a.corp.example"), "on_behalf_of": "alice"})
	first := approvalIDOf(t, o.do(o.bob, http.MethodPost, "/api/v1/certificate-requests", string(b)))
	second := approvalIDOf(t, o.do(o.bob, http.MethodPost, "/api/v1/certificate-requests", string(b)))
	if first != second || len(o.approvalsList(t)) != 1 {
		t.Fatalf("duplicate filed a second approval: %s %s", first, second)
	}
	if used, _, _, _ := o.enf.Usage(context.Background(), DefaultTenant, "alice"); used != 1 {
		t.Fatalf("quota used %d, want 1", used)
	}
}

func TestOBO_WriteGateMapsRoute(t *testing.T) {
	if rt, ok := matchWriteRoute("/api/v1/certificate-requests"); !ok || rt.perm != "certificate.issue" {
		t.Fatalf("gate rule = %+v ok=%v", rt, ok)
	}
}
