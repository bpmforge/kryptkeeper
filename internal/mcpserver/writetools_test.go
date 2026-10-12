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
	for _, name := range []string{"propose_revoke", "propose_bulk_revoke", "list_pending_actions"} {
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
	var body map[string]any
	if err := json.Unmarshal([]byte(f.lastBody), &body); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if body["action_type"] != "revoke" || body["rationale"] != "leaked key" {
		t.Errorf("unexpected proposal body: %v", body)
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
