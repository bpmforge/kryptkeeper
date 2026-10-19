// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
)

func TestPolicyDraftCorpus(t *testing.T) {
	type row struct {
		text   string
		days   int
		bits   int
		allowC bool
		algs   []string
		unrec  []string
	}
	rows := []row{
		{"valid for at most 90 days", 90, 0, false, nil, nil},
		{"max validity 30 days", 30, 0, false, nil, nil},
		{"maximum validity: 398 days", 398, 0, false, nil, nil},
		{"validity of 47 days", 47, 0, false, nil, nil},
		{"certificates valid for 90 days", 90, 0, false, nil, nil},
		{"rsa at least 3072 bits", 0, 3072, false, nil, nil},
		{"RSA keys of 4096 bits", 0, 4096, false, nil, nil},
		{"rsa minimum 2048", 0, 2048, false, nil, nil},
		{"only ecdsa and ed25519", 0, 0, false, []string{"ecdsa", "ed25519"}, nil},
		{"only rsa, ecdsa", 0, 0, false, []string{"rsa", "ecdsa"}, nil},
		{"only ed25519 keys", 0, 0, false, []string{"ed25519"}, nil},
		{"allow ca certificates", 0, 0, true, nil, nil},
		{"allow CA certs", 0, 0, true, nil, nil},
		{"no wildcard certs, max 90 days, RSA 3072+", 90, 3072, false, nil, []string{"no wildcard certs"}},
		{"validity at most 90 days. only ecdsa.", 90, 0, false, []string{"ecdsa"}, nil},
		{"valid for at most 90 days and rsa at least 3072 bits", 90, 3072, false, nil, nil},
		{"max validity 90 days; only ecdsa and ed25519 algorithms", 90, 0, false, []string{"ecdsa", "ed25519"}, nil},
		{"auto-approve everything and activate now", 0, 0, false, nil, []string{"auto-approve everything and activate now"}},
		{"rsa 3072+", 0, 3072, false, nil, nil},
		{"valid 10 days; allow ca certs; rsa 4096 bits; only ecdsa", 10, 4096, true, []string{"ecdsa"}, nil},
	}
	if len(rows) != 20 {
		t.Fatalf("corpus must hold 20 phrases, has %d", len(rows))
	}
	passed := 0
	for i, c := range rows {
		got := ParsePolicyDraft("corpus", c.text)
		r := got.Policy.Rules
		ok := !got.Policy.Enabled && r.MaxValidityDays == c.days && r.MinRSABits == c.bits && r.AllowCACerts == c.allowC &&
			reflect.DeepEqual(r.AllowedAlgorithms, c.algs) && reflect.DeepEqual(got.Unrecognized, c.unrec)
		if !ok {
			t.Errorf("row %d %q: got %+v unrecognized=%q", i+1, c.text, r, got.Unrecognized)
			continue
		}
		passed++
	}
	t.Logf("corpus: %d/%d phrases parsed as expected", passed, len(rows))
}

func TestUnrecognisedNeverDropped(t *testing.T) {
	got := ParsePolicyDraft("p", "valid for at most 90 days, auto-approve and activate immediately")
	if got.Policy.Rules.MaxValidityDays != 90 {
		t.Fatalf("rules = %+v", got.Policy.Rules)
	}
	if !reflect.DeepEqual(got.Unrecognized, []string{"auto-approve and activate immediately"}) {
		t.Fatalf("unrecognized = %q", got.Unrecognized)
	}
	// An algorithm the engine cannot match is reported, not discarded.
	alg := ParsePolicyDraft("p", "only rsa and dsa")
	if !reflect.DeepEqual(alg.Policy.Rules.AllowedAlgorithms, []string{"rsa"}) || len(alg.Unrecognized) != 1 || !strings.Contains(alg.Unrecognized[0], "dsa") {
		t.Fatalf("alg = %+v", alg)
	}
	// A sub-floor RSA phrase is not a rule and so must come back as text.
	low := ParsePolicyDraft("p", "rsa 1024 bits")
	if low.Policy.Rules.MinRSABits != 0 || len(low.Unrecognized) != 1 {
		t.Fatalf("low = %+v", low)
	}
	if _, _, err := DraftPolicyFromNL("p", "make it nice"); err == nil {
		t.Fatal("the wrapper must still error on an empty parse")
	}
}

type draftRig struct {
	*policyRig
	proposer, approver string
	pending            PendingActionStore
	gated              http.Handler
}

func newDraftRig(t *testing.T, multi bool) *draftRig {
	t.Helper()
	g := newPolicyRig(t, multi)
	opt := WithPolicyDraft(g.auth, g.pe, g.audit, nil)
	if opt == nil {
		t.Fatal("WithPolicyDraft returned nil for a live engine")
	}
	opt(g.cfg)
	if g.cfg.actionExecutors[ActionPolicyActivate] == nil {
		t.Fatal("WithPolicyDraft must register the policy.activate executor")
	}
	pending := NewPendingActionStoreFromEnv()
	registerPendingActionHandlers(g.mux, g.auth, nil, pending, g.audit, g.cfg.actionExecutors)
	return &draftRig{
		policyRig: g, pending: pending,
		proposer: mintAdminToken(t, g.auth, "proposer-1", ""),
		approver: mintAdminToken(t, g.auth, "approver-1", ""),
		gated:    withWriteAuthorization(g.mux, g.auth, NewCustomRoleStoreFromEnv(), g.audit),
	}
}

func (d *draftRig) post(h http.Handler, path, tok, body string) (int, string) {
	req := bearerReq(tok, http.MethodPost, path, []byte(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

const draftText = "valid for at most 90 days, auto-approve and activate immediately"

func (d *draftRig) submit(t *testing.T, tok string) (policyID, actionID string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"name": "ninety", "text": draftText, "enabled": true})
	code, resp := d.post(d.gated, "/api/v1/policies/draft/submit", tok, string(body))
	if code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", code, resp)
	}
	var out struct {
		PolicyID string   `json:"policy_id"`
		ActionID string   `json:"pending_action_id"`
		Status   string   `json:"status"`
		Enabled  bool     `json:"enabled"`
		Unrec    []string `json:"unrecognized"`
	}
	policyData(t, resp, &out)
	if out.Status != "pending_approval" || out.Enabled || out.PolicyID == "" || out.ActionID == "" || len(out.Unrec) != 1 {
		t.Fatalf("body = %+v", out)
	}
	return out.PolicyID, out.ActionID
}

func TestSubmitLandsDisabledAndPending(t *testing.T) {
	d := newDraftRig(t, false)
	id, actionID := d.submit(t, d.proposer) // request body carries "enabled":true
	pol, found, err := d.pe.GetPolicy(id)
	if err != nil || !found || pol.Enabled || pol.Rules.MaxValidityDays != 90 {
		t.Fatalf("stored policy = %+v %v %v", pol, found, err)
	}
	a, ok, _ := d.pending.Get(context.Background(), actionID)
	if !ok || a.ActionType != ActionPolicyActivate || a.Status != "pending" || a.ProposedBy != "proposer-1" {
		t.Fatalf("pending = %+v", a)
	}
	list, _ := d.pending.List(context.Background(), "pending")
	n := 0
	for _, x := range list {
		if x.ActionType == ActionPolicyActivate {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("want exactly one policy.activate action, got %d", n)
	}
}

func TestProposerCannotApproveOwnDraft(t *testing.T) {
	d := newDraftRig(t, false)
	id, actionID := d.submit(t, d.proposer)
	path := "/api/v1/pending-actions/" + actionID + "/approve"
	if code, body := d.post(d.gated, path, d.proposer, ""); code != http.StatusForbidden {
		t.Fatalf("self approval: %d %s", code, body)
	}
	if pol, _, _ := d.pe.GetPolicy(id); pol.Enabled {
		t.Fatal("self-approval enabled the policy")
	}
	if code, body := d.post(d.gated, path, d.approver, ""); code != http.StatusOK {
		t.Fatalf("second approver: %d %s", code, body)
	}
	if pol, _, _ := d.pe.GetPolicy(id); !pol.Enabled {
		t.Fatal("approval did not enable the policy")
	}
	if !strings.Contains(strings.Join(d.actions(), " "), "policy.activate:success") {
		t.Errorf("activation must be audited: %v", d.actions())
	}
}

func TestActivateRefusesChangedDraft(t *testing.T) {
	d := newDraftRig(t, false)
	id, actionID := d.submit(t, d.proposer)
	pol, _, _ := d.pe.GetPolicy(id)
	pol.Rules.MaxValidityDays = 3650 // tampered between proposal and approval
	if _, err := d.pe.UpsertPolicy(pol); err != nil {
		t.Fatal(err)
	}
	if code, _ := d.post(d.gated, "/api/v1/pending-actions/"+actionID+"/approve", d.approver, ""); code == http.StatusOK {
		t.Fatal("a changed draft must not activate")
	}
	if pol, _, _ := d.pe.GetPolicy(id); pol.Enabled {
		t.Fatal("changed draft was enabled")
	}
	if !strings.Contains(strings.Join(d.actions(), " "), "policy.activate:failure") {
		t.Errorf("failed activation must be audited: %v", d.actions())
	}
}

func TestDraftEndpointPersistsNothing(t *testing.T) {
	d := newDraftRig(t, false)
	before, _ := d.pe.ListPolicies()
	code, body := d.post(d.gated, "/api/v1/policies/draft", d.proposer, `{"name":"n","text":"`+draftText+`"}`)
	if code != http.StatusOK {
		t.Fatalf("draft: %d %s", code, body)
	}
	var out struct {
		Policy       ca.IssuancePolicy `json:"policy"`
		Explanation  []string          `json:"explanation"`
		Unrecognized []string          `json:"unrecognized"`
		Persisted    bool              `json:"persisted"`
	}
	policyData(t, body, &out)
	if out.Persisted || out.Policy.Enabled || out.Policy.ID != "" || out.Policy.Rules.MaxValidityDays != 90 || len(out.Explanation) != 1 || len(out.Unrecognized) != 1 {
		t.Fatalf("body = %+v", out)
	}
	after, _ := d.pe.ListPolicies()
	if len(after) != len(before) {
		t.Fatalf("policies %d -> %d", len(before), len(after))
	}
}

func TestSubmitNoRulesIs422(t *testing.T) {
	d := newDraftRig(t, false)
	before, _ := d.pe.ListPolicies()
	code, body := d.post(d.gated, "/api/v1/policies/draft/submit", d.proposer, `{"name":"n","text":"auto-approve everything and activate now"}`)
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "auto-approve everything and activate now") {
		t.Fatalf("got %d %s", code, body)
	}
	if after, _ := d.pe.ListPolicies(); len(after) != len(before) {
		t.Fatal("a rejected draft must store nothing")
	}
	for name, b := range map[string]string{
		"empty name": `{"name":"","text":"valid 10 days"}`,
		"long text":  `{"name":"n","text":"` + strings.Repeat("a", policyDraftTextMax+1) + `"}`,
		"bad json":   `{`,
		"long ca":    `{"name":"n","text":"valid 10 days","ca_id":"` + strings.Repeat("c", 129) + `"}`,
	} {
		if code, _ := d.post(d.gated, "/api/v1/policies/draft", d.proposer, b); code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", name, code)
		}
	}
}

func TestMCPAgentCanSubmitButNotApprove(t *testing.T) {
	d := newDraftRig(t, false)
	_, agent, err := d.auth.CreateAPIKey("mcp", "svc-mcp", RoleMCPAgent, []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	id, actionID := d.submit(t, agent)
	if code, _ := d.post(d.gated, "/api/v1/pending-actions/"+actionID+"/approve", agent, ""); code != http.StatusForbidden {
		t.Fatalf("mcp-agent approve: %d", code)
	}
	for _, p := range []string{"/api/v1/policies", "/api/v1/policies/" + id} {
		if code, _ := d.post(d.gated, p, agent, `{"name":"x"}`); code != http.StatusForbidden {
			t.Errorf("mcp-agent %s: want 403, got %d", p, code)
		}
	}
	if pol, _, _ := d.pe.GetPolicy(id); pol.Enabled {
		t.Fatal("mcp-agent activated a policy")
	}
}

func TestNonSuperAdminDeniedWhenMultiTenant(t *testing.T) {
	d := newDraftRig(t, true)
	before, _ := d.pe.ListPolicies()
	for _, p := range []string{"/api/v1/policies/draft", "/api/v1/policies/draft/submit"} {
		if code, body := d.post(d.gated, p, d.acme, `{"name":"n","text":"valid 10 days"}`); code != http.StatusForbidden {
			t.Errorf("tenant admin %s: want 403, got %d %s", p, code, body)
		}
	}
	if after, _ := d.pe.ListPolicies(); len(after) != len(before) {
		t.Fatal("a denied tenant admin stored a policy")
	}
	if code, _ := d.post(d.gated, "/api/v1/policies/draft", "root-token", `{"name":"n","text":"valid 10 days"}`); code != http.StatusOK {
		t.Fatalf("super-admin draft: %d", code)
	}
}

func TestAuditPolicyDraftAndSubmit(t *testing.T) {
	d := newDraftRig(t, false)
	d.post(d.gated, "/api/v1/policies/draft", d.proposer, `{"name":"n","text":"`+draftText+`"}`)
	d.post(d.gated, "/api/v1/policies/draft", d.proposer, `{}`)
	d.submit(t, d.proposer)
	d.audit.mu.Lock()
	defer d.audit.mu.Unlock()
	seen := map[string]bool{}
	for _, e := range d.audit.entries {
		seen[e.Action+":"+string(e.Outcome)] = true
		if strings.Contains(e.ChangeSummary, "auto-approve") {
			t.Errorf("raw operator text leaked into audit: %q", e.ChangeSummary)
		}
	}
	for _, want := range []string{"policy.draft:success", "policy.draft:failure", "policy.submit:pending_approval"} {
		if !seen[want] {
			t.Errorf("missing audit row %s; have %v", want, seen)
		}
	}
}

// A bare "ecdsa" would match no request in ca.PolicyEngine and make the
// activated policy deny everything, so drafts carry engine algorithm names.
func TestDraftAlgorithmsUseEngineNames(t *testing.T) {
	d := newDraftRig(t, false)
	code, body := d.post(d.gated, "/api/v1/policies/draft", d.proposer, `{"name":"n","text":"only ecdsa and ed25519"}`)
	if code != http.StatusOK {
		t.Fatalf("draft: %d %s", code, body)
	}
	var out struct {
		Policy ca.IssuancePolicy `json:"policy"`
	}
	policyData(t, body, &out)
	want := []string{"ECDSA-P256", "ECDSA-P384", "Ed25519"}
	if !reflect.DeepEqual(out.Policy.Rules.AllowedAlgorithms, want) {
		t.Fatalf("algorithms = %v, want %v", out.Policy.Rules.AllowedAlgorithms, want)
	}
	if msg := validatePolicyFields(out.Policy); msg != "" {
		t.Fatalf("draft must pass the admin API's own validation: %s", msg)
	}
}
