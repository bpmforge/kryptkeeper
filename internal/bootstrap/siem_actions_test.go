// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func siemTestRouter(t *testing.T, actions string) (*SIEMRouter, chan SIEMEvent) {
	t.Helper()
	got := make(chan SIEMEvent, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var ev SIEMEvent
		if json.Unmarshal(b, &ev) == nil {
			got <- ev
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("SIEM_WEBHOOK_URL", srv.URL)
	t.Setenv("SIEM_SYSLOG_ADDR", "")
	t.Setenv("SIEM_FORMAT", "json")
	t.Setenv("KRYPTKEEPER_SIEM_ACTIONS", actions)
	return NewSIEMRouterFromEnv(), got
}

func drainSIEM(got chan SIEMEvent, wait time.Duration) []SIEMEvent {
	var out []SIEMEvent
	deadline := time.After(wait)
	for {
		select {
		case ev := <-got:
			out = append(out, ev)
		case <-deadline:
			return out
		}
	}
}

// N-04: audit events outside the old seven-action list reach the SIEM.
func TestSIEMForwardsEveryAuditActionByDefault(t *testing.T) {
	router, got := siemTestRouter(t, "")
	router.EmitFromAuditEntry(AuditEntry{Action: "certificate.revoke", Outcome: "success", ResourceID: "fp1"})
	router.EmitFromAuditEntry(AuditEntry{Action: "users.update", Outcome: "denied", ResourceID: "u1"})
	evs := drainSIEM(got, 600*time.Millisecond)
	if len(evs) != 2 {
		t.Fatalf("want 2 forwarded events, got %d: %+v", len(evs), evs)
	}
	byType := map[string]SIEMEvent{}
	for _, e := range evs {
		byType[e.EventType] = e
	}
	if byType["cert.revoked"].ResourceID != "fp1" {
		t.Errorf("known action lost its historical event type: %+v", evs)
	}
	if e, ok := byType["users.update"]; !ok || e.Severity != "warning" {
		t.Errorf("unmapped denied action should forward as warning under its own name: %+v", evs)
	}
}

func TestSIEMActionAllowlist(t *testing.T) {
	router, got := siemTestRouter(t, " certificate.revoke , key.* ")
	for _, a := range []string{"certificate.revoke", "key.rotate", "users.update", "keys.other"} {
		router.EmitFromAuditEntry(AuditEntry{Action: a, Outcome: "success"})
	}
	evs := drainSIEM(got, 600*time.Millisecond)
	seen := map[string]bool{}
	for _, e := range evs {
		seen[e.EventType] = true
	}
	if len(evs) != 2 || !seen["cert.revoked"] || !seen["key.rotate"] {
		t.Fatalf("allowlist not honoured: %+v", evs)
	}
}
