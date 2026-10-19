// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"kryptkeeper/internal/ca"
)

func TestPolicyLooseningTable(t *testing.T) {
	base := ca.IssuancePolicy{Enabled: true, Rules: ca.PolicyRules{
		AllowedAlgorithms: []string{"ECDSA-P256", "Ed25519"}, MinRSABits: 3072, MaxValidityDays: 398}}
	mod := func(f func(*ca.IssuancePolicy)) ca.IssuancePolicy {
		p := base
		p.Rules.AllowedAlgorithms = append([]string(nil), base.Rules.AllowedAlgorithms...)
		f(&p)
		return p
	}
	for _, tc := range []struct {
		name  string
		next  ca.IssuancePolicy
		loose bool
	}{
		{"longer validity", mod(func(p *ca.IssuancePolicy) { p.Rules.MaxValidityDays = 700 }), true},
		{"validity removed", mod(func(p *ca.IssuancePolicy) { p.Rules.MaxValidityDays = 0 }), true},
		{"lower rsa floor", mod(func(p *ca.IssuancePolicy) { p.Rules.MinRSABits = 2048 }), true},
		{"rsa floor removed", mod(func(p *ca.IssuancePolicy) { p.Rules.MinRSABits = 0 }), true},
		{"new algorithm", mod(func(p *ca.IssuancePolicy) { p.Rules.AllowedAlgorithms = append(p.Rules.AllowedAlgorithms, "RSA-4096") }), true},
		{"allow-list removed", mod(func(p *ca.IssuancePolicy) { p.Rules.AllowedAlgorithms = nil }), true},
		{"ca certs allowed", mod(func(p *ca.IssuancePolicy) { p.Rules.AllowCACerts = true }), true},
		{"disabled", mod(func(p *ca.IssuancePolicy) { p.Enabled = false }), true},
		{"narrowed to one CA", mod(func(p *ca.IssuancePolicy) { p.CAID = "ca-1" }), true},
		{"shorter validity", mod(func(p *ca.IssuancePolicy) { p.Rules.MaxValidityDays = 90 }), false},
		{"higher rsa floor", mod(func(p *ca.IssuancePolicy) { p.Rules.MinRSABits = 4096 }), false},
		{"fewer algorithms", mod(func(p *ca.IssuancePolicy) { p.Rules.AllowedAlgorithms = []string{"Ed25519"} }), false},
		{"no-op", base, false},
	} {
		if got := policyLoosening(base, tc.next); (len(got) > 0) != tc.loose {
			t.Errorf("%s: reasons=%v, loosening want %v", tc.name, got, tc.loose)
		}
	}
	// Re-enabling and widening scope back to every CA tighten.
	off := mod(func(p *ca.IssuancePolicy) { p.Enabled = false; p.CAID = "ca-1" })
	if r := policyLoosening(off, base); len(r) != 0 {
		t.Errorf("re-enable/widen is a tightening: %v", r)
	}
	// No allow-list -> a new list is a restriction, not a loosening.
	open := ca.IssuancePolicy{Enabled: true}
	if r := policyLoosening(open, ca.IssuancePolicy{Enabled: true, Rules: ca.PolicyRules{AllowedAlgorithms: []string{"Ed25519"}}}); len(r) != 0 {
		t.Errorf("adding an allow-list tightens: %v", r)
	}
}

// policyApprovalRig mounts the approval queue next to the policy API on the
// rig's mux and mints a proposer and an approver.
func policyApprovalRig(t *testing.T, multi bool) (g *policyRig, proposer, approver string, pending PendingActionStore) {
	t.Helper()
	g = newPolicyRig(t, multi)
	pending = NewPendingActionStoreFromEnv()
	if pending == nil {
		t.Fatal("pending store unavailable")
	}
	if g.cfg.actionExecutors[ActionPolicyLoosen] == nil {
		t.Fatal("WithPolicyAdmin must register the policy.loosen executor")
	}
	registerPendingActionHandlers(g.mux, g.auth, nil, pending, g.audit, g.cfg.actionExecutors)
	proposer = mintAdminToken(t, g.auth, "proposer-1", "")
	approver = mintAdminToken(t, g.auth, "approver-1", "")
	return g, proposer, approver, pending
}

func (g *policyRig) baseline(t *testing.T) ca.IssuancePolicy {
	t.Helper()
	p, found, err := g.pe.GetPolicy("pol-baseline")
	if err != nil || !found {
		t.Fatalf("baseline: %v %v", found, err)
	}
	return p
}

func TestLoosenReturns202AndDoesNotApply(t *testing.T) {
	g, proposer, _, pending := policyApprovalRig(t, false)
	rec := doLeakJSON(g.mux, http.MethodPatch, "/api/v1/policies/pol-baseline", proposer, "", `{"rules":{"max_validity_days":700}}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("loosen: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Status   string   `json:"status"`
		ActionID string   `json:"pending_action_id"`
		Reasons  []string `json:"reasons"`
	}
	policyData(t, rec.Body.String(), &out)
	if out.Status != "pending_approval" || out.ActionID == "" || len(out.Reasons) == 0 {
		t.Fatalf("body = %+v", out)
	}
	if got := g.baseline(t).Rules.MaxValidityDays; got != 398 {
		t.Fatalf("policy applied without approval: %d", got)
	}
	a, ok, _ := pending.Get(context.Background(), out.ActionID)
	if !ok || a.ActionType != "policy.loosen" || a.Status != "pending" || a.ProposedBy != "proposer-1" {
		t.Fatalf("pending = %+v", a)
	}
}

func TestSecondApproverAppliesLoosening(t *testing.T) {
	g, proposer, approver, _ := policyApprovalRig(t, false)
	rec := doLeakJSON(g.mux, http.MethodPatch, "/api/v1/policies/pol-baseline", proposer, "", `{"rules":{"max_validity_days":700}}`)
	var out struct {
		ActionID string `json:"pending_action_id"`
	}
	policyData(t, rec.Body.String(), &out)

	if rec := doLeakJSON(g.mux, http.MethodPost, "/api/v1/pending-actions/"+out.ActionID+"/approve", proposer, "", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("self approval: %d", rec.Code)
	}
	if g.baseline(t).Rules.MaxValidityDays != 398 {
		t.Fatal("self-approval applied the change")
	}
	rec = doLeakJSON(g.mux, http.MethodPost, "/api/v1/pending-actions/"+out.ActionID+"/approve", approver, "", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"version":2`) {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	if got := g.baseline(t).Rules.MaxValidityDays; got != 700 {
		t.Fatalf("policy = %d, want 700", got)
	}
	vs, _ := newPolicyVersionStore(g.pe).List(context.Background(), "pol-baseline")
	if len(vs) != 2 || vs[0].Version != 1 || vs[0].ChangedBy != "system" || vs[1].ChangeKind != "loosen" || vs[1].ChangedBy != "approver-1" {
		t.Fatalf("versions = %+v", vs)
	}
	if got := strings.Join(g.actions(), " "); !strings.Contains(got, "policy.update:pending_approval") || !strings.Contains(got, "policy.update:success") {
		t.Fatalf("audit = %s", got)
	}
}

func TestTighteningAppliesImmediately(t *testing.T) {
	g, proposer, _, pending := policyApprovalRig(t, false)
	rec := doLeakJSON(g.mux, http.MethodPatch, "/api/v1/policies/pol-baseline", proposer, "", `{"rules":{"max_validity_days":90}}`)
	if rec.Code != http.StatusOK || g.baseline(t).Rules.MaxValidityDays != 90 {
		t.Fatalf("tighten: %d %s", rec.Code, rec.Body.String())
	}
	if l, _ := pending.List(context.Background(), "pending"); len(l) != 0 {
		t.Fatalf("tightening queued an action: %+v", l)
	}
}

func TestRevertRestoresPriorRowAndAudits(t *testing.T) {
	g, proposer, approver, _ := policyApprovalRig(t, false)
	patch := func(tok, body string) (int, string) {
		rec := doLeakJSON(g.mux, http.MethodPatch, "/api/v1/policies/pol-baseline", tok, "", body)
		return rec.Code, rec.Body.String()
	}
	// v1 = baseline (398d); loosen to 700d through approval = v2.
	code, body := patch(proposer, `{"rules":{"max_validity_days":700}}`)
	var out struct {
		ActionID string `json:"pending_action_id"`
	}
	policyData(t, body, &out)
	if code != 202 {
		t.Fatalf("loosen: %d", code)
	}
	if rec := doLeakJSON(g.mux, http.MethodPost, "/api/v1/pending-actions/"+out.ActionID+"/approve", approver, "", ""); rec.Code != 200 {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}

	// Reverting to v1 (398d) tightens: applies at once and audits policy.revert.
	if code, body := patch(proposer, `{"revert_to":1}`); code != 200 {
		t.Fatalf("revert: %d %s", code, body)
	}
	if got := g.baseline(t).Rules.MaxValidityDays; got != 398 {
		t.Fatalf("restored = %d, want 398", got)
	}
	e, ok := lastAudit(g.audit, "policy.revert")
	if !ok || e.Outcome != AuditOutcomeSuccess || e.ChangeSummary != `{"from":2,"to":1}` || e.ResourceID != "pol-baseline" {
		t.Fatalf("policy.revert audit = %+v ok=%v", e, ok)
	}
	vs, _ := newPolicyVersionStore(g.pe).List(context.Background(), "pol-baseline")
	if len(vs) != 3 || vs[2].ChangeKind != "revert" {
		t.Fatalf("versions = %+v", vs)
	}

	// Reverting to v2 (700d) would loosen: 202, row untouched.
	if code, body := patch(proposer, `{"revert_to":2}`); code != 202 {
		t.Fatalf("loosening revert: %d %s", code, body)
	}
	if g.baseline(t).Rules.MaxValidityDays != 398 {
		t.Fatal("a loosening revert applied without approval")
	}
	if code, _ := patch(proposer, `{"revert_to":99}`); code != http.StatusNotFound {
		t.Fatalf("unknown version: %d", code)
	}
	if code, _ := patch(proposer, `{"revert_to":1,"enabled":true}`); code != http.StatusBadRequest {
		t.Fatalf("mixed revert: %d", code)
	}
	if code, _ := patch(proposer, `{"revert_to":0}`); code != http.StatusBadRequest {
		t.Fatalf("revert_to 0: %d", code)
	}
}

func lastAudit(a *recordingAuditProvider, action string) (AuditEntry, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := len(a.entries) - 1; i >= 0; i-- {
		if a.entries[i].Action == action {
			return a.entries[i], true
		}
	}
	return AuditEntry{}, false
}

func TestStaleBaseVersionFails(t *testing.T) {
	g, proposer, approver, _ := policyApprovalRig(t, false)
	rec := doLeakJSON(g.mux, http.MethodPatch, "/api/v1/policies/pol-baseline", proposer, "", `{"rules":{"max_validity_days":700}}`)
	var out struct {
		ActionID string `json:"pending_action_id"`
	}
	policyData(t, rec.Body.String(), &out)
	// Someone tightens the policy between proposal and approval.
	if rec := doLeakJSON(g.mux, http.MethodPatch, "/api/v1/policies/pol-baseline", proposer, "", `{"rules":{"max_validity_days":60}}`); rec.Code != 200 {
		t.Fatalf("tighten: %d", rec.Code)
	}
	rec = doLeakJSON(g.mux, http.MethodPost, "/api/v1/pending-actions/"+out.ActionID+"/approve", approver, "", "")
	if rec.Code == http.StatusOK || !strings.Contains(rec.Body.String(), "policy changed since proposal") {
		t.Fatalf("stale approval: %d %s", rec.Code, rec.Body.String())
	}
	if got := g.baseline(t).Rules.MaxValidityDays; got != 60 {
		t.Fatalf("row = %d, want 60 (unchanged by the failed approval)", got)
	}
}

func TestVersionsListAndPreW22Base(t *testing.T) {
	g, _, _, _ := policyApprovalRig(t, false)
	rec := doLeakJSON(g.mux, http.MethodGet, "/api/v1/policies/pol-baseline/versions", "root-token", "", "")
	var vs []PolicyVersion
	policyData(t, rec.Body.String(), &vs)
	if rec.Code != 200 || len(vs) != 1 || vs[0].Version != 1 || vs[0].ChangeKind != "create" || vs[0].Rules.MaxValidityDays != 398 {
		t.Fatalf("versions: %d %s", rec.Code, rec.Body.String())
	}
	// POST appends version 1 for a new policy.
	rec = doLeakJSON(g.mux, http.MethodPost, "/api/v1/policies", "root-token", "", `{"name":"n"}`)
	var created ca.IssuancePolicy
	policyData(t, rec.Body.String(), &created)
	list, _ := newPolicyVersionStore(g.pe).List(context.Background(), created.ID)
	if len(list) != 1 || list[0].Version != 1 {
		t.Fatalf("created versions = %+v", list)
	}
	if rec := doLeakJSON(g.mux, http.MethodGet, "/api/v1/policies/nope/versions", "root-token", "", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown policy versions: %d", rec.Code)
	}
}

func TestPolicyVersionsGapFree(t *testing.T) {
	g, _, _, _ := policyApprovalRig(t, false)
	vs := newPolicyVersionStore(g.pe)
	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		n, err := vs.Append(ctx, ca.IssuancePolicy{ID: "pol-x", Name: "x", Rules: ca.PolicyRules{MaxValidityDays: i}}, "u", "update")
		if err != nil || n != i {
			t.Fatalf("append %d = %d, %v", i, n, err)
		}
	}
	if n, _ := vs.Append(ctx, ca.IssuancePolicy{ID: "pol-y", Name: "y"}, "u", "create"); n != 1 {
		t.Fatalf("versions are per policy; got %d", n)
	}
}

// Policies are instance-global: with multi-tenancy on, neither proposing nor
// approving a loosening is open to a tenant-scoped admin.
func TestLooseningIsSuperAdminOnlyWhenMultiTenant(t *testing.T) {
	g, _, _, pending := policyApprovalRig(t, true)
	if rec := doLeakJSON(g.mux, http.MethodPatch, "/api/v1/policies/pol-baseline", g.acme, "acme", `{"rules":{"max_validity_days":700}}`); rec.Code != http.StatusForbidden {
		t.Fatalf("tenant admin loosening: %d", rec.Code)
	}
	if rec := doLeakJSON(g.mux, http.MethodGet, "/api/v1/policies/pol-baseline/versions", g.acme, "acme", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("tenant admin versions: %d", rec.Code)
	}
	// A proposal parked by the super-admin cannot be executed by a
	// tenant-scoped approver, even though the queue would let them decide.
	rec := doLeakJSON(g.mux, http.MethodPatch, "/api/v1/policies/pol-baseline", "root-token", "", `{"rules":{"max_validity_days":700}}`)
	var out struct {
		ActionID string `json:"pending_action_id"`
	}
	policyData(t, rec.Body.String(), &out)
	if rec.Code != 202 {
		t.Fatalf("super-admin loosening: %d %s", rec.Code, rec.Body.String())
	}
	exec := g.cfg.actionExecutors[ActionPolicyLoosen]
	a, _, _ := pending.Get(context.Background(), out.ActionID)
	if _, err := exec(context.Background(), a, AuthPrincipal{ID: "acme-admin", Role: "pki-admin", Tenant: "acme", TenantScoped: true}); err == nil {
		t.Fatal("tenant-scoped approver executed an instance-global policy change")
	}
	if g.baseline(t).Rules.MaxValidityDays != 398 {
		t.Fatal("policy changed")
	}
}
