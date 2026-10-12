// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"
	"testing"
)

func TestHubClient_CheckSelfRole(t *testing.T) {
	f := newFakeHub(t)
	f.body = `{"service":"kryptkeeper","resource":"protected-whoami","principal":"test","auth_mode":"api-key","timestamp":"2026-07-18T00:00:00Z","role":"mcp-agent","can_approve_actions":false}`
	hub := NewHubClient(f.srv.URL, "test-token")

	self, err := hub.CheckSelfRole(context.Background())
	if err != nil {
		t.Fatalf("CheckSelfRole: %v", err)
	}
	if self.Role != "mcp-agent" {
		t.Errorf("Role = %q, want mcp-agent", self.Role)
	}
	if self.CanApproveActions {
		t.Error("CanApproveActions = true, want false")
	}
	if f.lastPath != "/api/v1/protected/whoami" {
		t.Errorf("lastPath = %q, want /api/v1/protected/whoami", f.lastPath)
	}
	if f.lastAuth != "Bearer test-token" {
		t.Errorf("lastAuth = %q, want Bearer test-token", f.lastAuth)
	}
}

func TestHubClient_CheckSelfRole_ApproverCapable(t *testing.T) {
	f := newFakeHub(t)
	f.body = `{"role":"pki-admin","can_approve_actions":true}`
	hub := NewHubClient(f.srv.URL, "test-token")

	self, err := hub.CheckSelfRole(context.Background())
	if err != nil {
		t.Fatalf("CheckSelfRole: %v", err)
	}
	if !self.CanApproveActions {
		t.Error("CanApproveActions = false, want true (this is the case main.go must refuse to start on)")
	}
}

func TestHubClient_CheckSelfRole_HubUnreachableReturnsError(t *testing.T) {
	f := newFakeHub(t)
	f.status = 401
	f.body = `unauthorized`
	hub := NewHubClient(f.srv.URL, "bad-token")

	if _, err := hub.CheckSelfRole(context.Background()); err == nil {
		t.Error("expected an error when the hub denies the whoami request")
	}
}
