// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kryptkeeper/internal/agentclient"
)

func TestInstallUnsupported(t *testing.T) {
	withHints := agentclient.RenewalTask{CertPath: "/etc/nginx/ssl/a.pem", ServerType: "nginx"}
	err := installUnsupported("windows", withHints)
	if err == nil || !strings.Contains(err.Error(), "not supported on the Windows agent") || !strings.Contains(err.Error(), "WinRM/IIS") {
		t.Fatalf("windows with install hints: got %v", err)
	}
	if err := installUnsupported("windows", agentclient.RenewalTask{}); err != nil {
		t.Errorf("windows renew-only must be allowed, got %v", err)
	}
	for _, goos := range []string{"linux", "darwin"} {
		if err := installUnsupported(goos, withHints); err != nil {
			t.Errorf("%s: unexpected refusal %v", goos, err)
		}
	}
}

// The refusal must reach the hub, not just the agent log, or the operator
// sees a renewal that never completes.
func TestReportFailure_PostsFailedResult(t *testing.T) {
	var got agentclient.RenewalResult
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/renewal-result" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
	}))
	defer hub.Close()

	c := agentclient.New(hub.URL, "agent-1", "tok", nil)
	cause := errors.New("install targets are not supported on the Windows agent; use agentless WinRM/IIS")
	task := agentclient.RenewalTask{TaskID: "t1", Fingerprint: "ab12"}
	if err := reportFailure(c, task, cause); !errors.Is(err, cause) {
		t.Fatalf("reportFailure must return the cause, got %v", err)
	}
	if got.TaskID != "t1" || got.Fingerprint != "ab12" || got.Outcome != "failed" || got.Detail != cause.Error() {
		t.Fatalf("reported %+v", got)
	}
}
