// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestWriteTools_Registered(t *testing.T) {
	hub := NewHubClient("http://x", "tok")
	for _, name := range []string{"propose_revoke", "propose_bulk_revoke", "list_pending_actions", "draft_policy"} {
		if findToolHandler(hub, name) == nil {
			t.Errorf("write tool %q not registered", name)
		}
	}
}

func TestProposeRevoke_EnqueuesOnly(t *testing.T) {
	f := newFakeHub(t)
	f.body = `{"data":{"id":"act-1","status":"pending"}}`
	hub := NewHubClient(f.srv.URL, "mcp-token")

	res := call(t, findToolHandler(hub, "propose_revoke"), map[string]any{
		"fingerprint": "fp-bad",
		"rationale":   "leaked key",
		"reason_code": float64(1),
	})
	if res.IsError {
		t.Fatalf("unexpected error: %s", resultText(res))
	}
	// MUST enqueue on the pending-actions queue — never a mutation endpoint.
	if f.lastPath != "/api/v1/pending-actions" {
		t.Fatalf("expected POST to /pending-actions, got %s", f.lastPath)
	}
	if f.lastMethod != http.MethodPost {
		t.Fatalf("expected POST, got %s", f.lastMethod)
	}
	// The only other request allowed is the read-only impact lookup.
	for _, p := range f.paths {
		if p != "POST /api/v1/pending-actions" && !strings.HasPrefix(p, "GET /api/v1/blast-radius") {
			t.Fatalf("unexpected hub call %q", p)
		}
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(f.lastBody), &body); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if body["action_type"] != "revoke" || body["rationale"] != "leaked key" {
		t.Errorf("unexpected proposal body: %v", body)
	}
}

// impactFixture routes /blast-radius and /pending-actions separately.
func impactFixture(t *testing.T, blast fakeRoute) (*fakeHub, *HubClient) {
	t.Helper()
	f := newFakeHub(t)
	f.routes = map[string]fakeRoute{
		"/api/v1/blast-radius":    blast,
		"/api/v1/pending-actions": {200, `{"data":{"id":"act-1","status":"pending"}}`},
	}
	return f, NewHubClient(f.srv.URL, "tok")
}

func proposedParams(t *testing.T, f *fakeHub) (actionType string, params map[string]any) {
	t.Helper()
	var body struct {
		ActionType string         `json:"action_type"`
		Params     map[string]any `json:"params"`
	}
	if err := json.Unmarshal([]byte(f.lastBody), &body); err != nil {
		t.Fatalf("proposal body not JSON: %v", err)
	}
	return body.ActionType, body.Params
}

func TestProposeRevoke_CarriesImpact(t *testing.T) {
	f, hub := impactFixture(t, fakeRoute{200, blastBody})
	res := call(t, findToolHandler(hub, "propose_revoke"), map[string]any{"fingerprint": "fp-1", "rationale": "leak"})
	if res.IsError {
		t.Fatalf("unexpected error: %s", resultText(res))
	}
	at, params := proposedParams(t, f)
	imp, _ := params["impact"].(map[string]any)
	if at != "revoke" || imp["affected_endpoints"] != float64(2) || imp["severity"] != "high" || imp["available"] != true || imp["target"] != "fp-1" {
		t.Fatalf("impact not carried: %s %v", at, params)
	}
	if len(f.paths) != 2 || !strings.HasPrefix(f.paths[0], "GET /api/v1/blast-radius") || f.paths[1] != "POST /api/v1/pending-actions" {
		t.Fatalf("expected GET blast-radius then one POST pending-actions, got %v", f.paths)
	}
}

func TestProposeBulkRevoke_CarriesImpact(t *testing.T) {
	f, hub := impactFixture(t, fakeRoute{200, blastBody})
	call(t, findToolHandler(hub, "propose_bulk_revoke"), map[string]any{"ca_id": "ca-7", "rationale": "compromised"})
	at, params := proposedParams(t, f)
	imp, _ := params["impact"].(map[string]any)
	if at != "bulk_revoke" || imp["action"] != "retire_ca" || imp["target"] != "ca-7" || imp["affected_endpoints"] != float64(2) {
		t.Fatalf("bulk impact not carried: %s %v", at, params)
	}
	if !strings.Contains(f.paths[0], "action=retire_ca") || !strings.Contains(f.paths[0], "target=ca-7") {
		t.Fatalf("wrong blast-radius query: %v", f.paths)
	}
}

func TestProposeRevoke_ImpactLookupFailureStillEnqueues(t *testing.T) {
	f, hub := impactFixture(t, fakeRoute{500, strings.Repeat("boom ", 100)})
	res := call(t, findToolHandler(hub, "propose_revoke"), map[string]any{"fingerprint": "fp-1", "rationale": "leak"})
	if res.IsError {
		t.Fatalf("lookup failure must not block the proposal: %s", resultText(res))
	}
	_, params := proposedParams(t, f)
	imp, _ := params["impact"].(map[string]any)
	msg, _ := imp["error"].(string)
	if imp["available"] != false || msg == "" || len(msg) > 200 {
		t.Fatalf("expected available=false with a truncated error, got %v", imp)
	}
	if f.lastMethod != http.MethodPost || f.lastPath != "/api/v1/pending-actions" {
		t.Fatalf("proposal must still be enqueued, last call %s %s", f.lastMethod, f.lastPath)
	}
}

func TestProposeRevoke_RequiresRationale(t *testing.T) {
	f := newFakeHub(t)
	hub := NewHubClient(f.srv.URL, "tok")
	res := call(t, findToolHandler(hub, "propose_revoke"), map[string]any{"fingerprint": "fp"})
	if !res.IsError {
		t.Fatal("expected error when rationale missing")
	}
}

func TestProposeBulkRevoke_Enqueues(t *testing.T) {
	f := newFakeHub(t)
	f.body = `{"data":{"id":"act-2"}}`
	hub := NewHubClient(f.srv.URL, "tok")
	res := call(t, findToolHandler(hub, "propose_bulk_revoke"), map[string]any{
		"ca_id": "ca-7", "rationale": "CA-7 compromised",
	})
	if res.IsError {
		t.Fatalf("unexpected error: %s", resultText(res))
	}
	if !strings.Contains(f.lastBody, "bulk_revoke") || !strings.Contains(f.lastBody, "ca-7") {
		t.Errorf("proposal body missing fields: %s", f.lastBody)
	}
}

func TestListPendingActions_Reads(t *testing.T) {
	f := newFakeHub(t)
	hub := NewHubClient(f.srv.URL, "tok")
	call(t, findToolHandler(hub, "list_pending_actions"), map[string]any{"status": "pending"})
	if !strings.HasPrefix(f.lastPath, "/api/v1/pending-actions") || f.lastMethod != http.MethodGet {
		t.Errorf("expected GET /pending-actions, got %s %s", f.lastMethod, f.lastPath)
	}
	if !strings.Contains(f.lastPath, "status=pending") {
		t.Errorf("status filter missing: %s", f.lastPath)
	}
}

// --- W5-06: issue/renew/rotate are proposable, enqueue-only ---

func TestW506ToolsRegistered(t *testing.T) {
	hub := NewHubClient("http://x", "tok")
	for _, name := range []string{"propose_issue", "propose_renew", "propose_rotate"} {
		if findToolHandler(hub, name) == nil {
			t.Errorf("tool %s not registered", name)
		}
	}
}

func TestProposeIssueRenewRotate_EnqueueOnly(t *testing.T) {
	cases := []struct {
		tool   string
		args   map[string]any
		action string
	}{
		{"propose_issue", map[string]any{"ca_id": "ca-1", "csr_pem": "PEM", "rationale": "new svc"}, "issue"},
		{"propose_renew", map[string]any{"fingerprint": "fp-1", "csr_pem": "PEM", "rationale": "expiring"}, "renew"},
		{"propose_rotate", map[string]any{"fingerprint": "fp-1", "csr_pem": "PEM", "rationale": "key hygiene"}, "rotate"},
	}
	for _, tc := range cases {
		f := newFakeHub(t)
		f.body = `{"data":{"id":"act-x","status":"pending"}}`
		hub := NewHubClient(f.srv.URL, "tok")
		res := call(t, findToolHandler(hub, tc.tool), tc.args)
		if res.IsError {
			t.Fatalf("%s: unexpected error: %s", tc.tool, resultText(res))
		}
		// The ONLY endpoint any write tool may touch is the queue.
		if f.lastPath != "/api/v1/pending-actions" || f.lastMethod != http.MethodPost {
			t.Fatalf("%s: must enqueue only, got %s %s", tc.tool, f.lastMethod, f.lastPath)
		}
		var body map[string]any
		if err := json.Unmarshal([]byte(f.lastBody), &body); err != nil {
			t.Fatalf("%s: body: %v", tc.tool, err)
		}
		if body["action_type"] != tc.action {
			t.Fatalf("%s: action_type %v, want %s", tc.tool, body["action_type"], tc.action)
		}
	}
}

func TestProposeRotate_RequiresRationaleAndCSR(t *testing.T) {
	f := newFakeHub(t)
	hub := NewHubClient(f.srv.URL, "tok")
	res := call(t, findToolHandler(hub, "propose_rotate"), map[string]any{"fingerprint": "fp"})
	if !res.IsError {
		t.Fatal("rotate without csr/rationale must error")
	}
	if f.lastPath != "" {
		t.Fatalf("nothing may be enqueued on a refused call, got %s", f.lastPath)
	}
}

func TestDraftPolicy_PostsToSubmitOnly(t *testing.T) {
	f := newFakeHub(t)
	f.body = `{"data":{"policy_id":"pol-1","pending_action_id":"act-9","status":"pending_approval","enabled":false}}`
	hub := NewHubClient(f.srv.URL, "mcp-token")

	res := call(t, findToolHandler(hub, "draft_policy"), map[string]any{
		"name": "ninety", "text": "valid for at most 90 days", "rationale": "tighten", "ca_id": "ca-1",
	})
	if res.IsError {
		t.Fatalf("unexpected error: %s", resultText(res))
	}
	if f.lastPath != "/api/v1/policies/draft/submit" || f.lastMethod != http.MethodPost {
		t.Fatalf("want POST /api/v1/policies/draft/submit, got %s %s", f.lastMethod, f.lastPath)
	}
	if strings.Contains(f.lastPath, "approve") || strings.Contains(f.lastPath, "pending-actions") {
		t.Fatalf("draft_policy must never touch approval: %s", f.lastPath)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(f.lastBody), &body); err != nil {
		t.Fatal(err)
	}
	if body["name"] != "ninety" || body["text"] != "valid for at most 90 days" || body["ca_id"] != "ca-1" {
		t.Errorf("unexpected body: %v", body)
	}
	if _, has := body["enabled"]; has {
		t.Error("the tool must not send an enabled flag")
	}
	if res2 := call(t, findToolHandler(hub, "draft_policy"), map[string]any{"name": "x", "text": "y"}); !res2.IsError {
		t.Error("rationale must be required")
	}
}
