// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"testing"
	"time"
)

func expiringCert(fp, source string, autoRenew bool, notAfter time.Time) AgentDiscoveredCert {
	return AgentDiscoveredCert{
		Fingerprint:   fp,
		Subject:       "CN=shop.example.com",
		Source:        source,
		NotAfter:      notAfter,
		AutoRenewable: autoRenew,
	}
}

func nginxEndpoint(certPath, keyPath string) AgentEndpoint {
	return AgentEndpoint{
		ServerType: "nginx",
		CertPath:   certPath,
		KeyPath:    keyPath,
		ServerName: "shop.example.com",
		ListenPort: 443,
	}
}

func registerAndInventory(t *testing.T, store AgentStore, certs []AgentDiscoveredCert, eps []AgentEndpoint) (id, token string) {
	t.Helper()
	id, token, err := store.register("agent", AgentTypeLinux)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := store.submitInventory(id, token, certs, eps); err != nil {
		t.Fatalf("submitInventory: %v", err)
	}
	return id, token
}

func TestAssignTasks_MatchesExpiringCertToEndpoint(t *testing.T) {
	store := NewAgentStore()
	soon := time.Now().UTC().Add(10 * 24 * time.Hour)
	id, token := registerAndInventory(t, store,
		[]AgentDiscoveredCert{expiringCert("fp1", "/etc/nginx/ssl/shop.crt", true, soon)},
		[]AgentEndpoint{nginxEndpoint("/etc/nginx/ssl/shop.crt", "/etc/nginx/ssl/shop.key")},
	)

	tasks, err := store.getTasks(id, token)
	if err != nil {
		t.Fatalf("getTasks: %v", err)
	}
	if len(tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(tasks))
	}
	tk := tasks[0]
	if tk.Fingerprint != "fp1" || tk.Action != "renew" {
		t.Errorf("task basics wrong: %+v", tk)
	}
	if tk.CertPath != "/etc/nginx/ssl/shop.crt" || tk.KeyPath != "/etc/nginx/ssl/shop.key" {
		t.Errorf("install hints not populated: %+v", tk)
	}
	if tk.ServerType != "nginx" || tk.VerifyHostPort != "shop.example.com:443" {
		t.Errorf("server/verify hints wrong: %+v", tk)
	}
}

func TestAssignTasks_SkipsNonAutoRenewable(t *testing.T) {
	store := NewAgentStore()
	soon := time.Now().UTC().Add(10 * 24 * time.Hour)
	id, token := registerAndInventory(t, store,
		[]AgentDiscoveredCert{expiringCert("fp1", "/etc/nginx/ssl/shop.crt", false, soon)},
		[]AgentEndpoint{nginxEndpoint("/etc/nginx/ssl/shop.crt", "/etc/nginx/ssl/shop.key")},
	)
	tasks, _ := store.getTasks(id, token)
	if len(tasks) != 0 {
		t.Fatalf("expected 0 tasks for non-auto-renewable cert, got %d", len(tasks))
	}
}

func TestAssignTasks_SkipsWhenNoEndpointMatch(t *testing.T) {
	store := NewAgentStore()
	soon := time.Now().UTC().Add(10 * 24 * time.Hour)
	id, token := registerAndInventory(t, store,
		[]AgentDiscoveredCert{expiringCert("fp1", "/etc/ssl/orphan.crt", true, soon)},
		[]AgentEndpoint{nginxEndpoint("/etc/nginx/ssl/shop.crt", "/etc/nginx/ssl/shop.key")},
	)
	tasks, _ := store.getTasks(id, token)
	if len(tasks) != 0 {
		t.Fatalf("expected 0 tasks when no endpoint matches, got %d", len(tasks))
	}
}

func TestAssignTasks_SkipsNotYetExpiring(t *testing.T) {
	store := NewAgentStore()
	far := time.Now().UTC().Add(100 * 24 * time.Hour) // beyond default 30d threshold
	id, token := registerAndInventory(t, store,
		[]AgentDiscoveredCert{expiringCert("fp1", "/etc/nginx/ssl/shop.crt", true, far)},
		[]AgentEndpoint{nginxEndpoint("/etc/nginx/ssl/shop.crt", "/etc/nginx/ssl/shop.key")},
	)
	tasks, _ := store.getTasks(id, token)
	if len(tasks) != 0 {
		t.Fatalf("expected 0 tasks for cert not near expiry, got %d", len(tasks))
	}
}

func TestAssignTasks_Idempotent(t *testing.T) {
	store := NewAgentStore()
	soon := time.Now().UTC().Add(10 * 24 * time.Hour)
	certs := []AgentDiscoveredCert{expiringCert("fp1", "/etc/nginx/ssl/shop.crt", true, soon)}
	eps := []AgentEndpoint{nginxEndpoint("/etc/nginx/ssl/shop.crt", "/etc/nginx/ssl/shop.key")}
	id, token := registerAndInventory(t, store, certs, eps)

	// Second inventory cycle must not duplicate the task.
	if err := store.submitInventory(id, token, certs, eps); err != nil {
		t.Fatalf("submitInventory 2: %v", err)
	}
	tasks, _ := store.getTasks(id, token)
	if len(tasks) != 1 {
		t.Fatalf("expected 1 task after re-inventory, got %d", len(tasks))
	}
}

func TestAssignTasks_SuccessClearsAndDoesNotRetask(t *testing.T) {
	store := NewAgentStore()
	soon := time.Now().UTC().Add(10 * 24 * time.Hour)
	certs := []AgentDiscoveredCert{expiringCert("fp1", "/etc/nginx/ssl/shop.crt", true, soon)}
	eps := []AgentEndpoint{nginxEndpoint("/etc/nginx/ssl/shop.crt", "/etc/nginx/ssl/shop.key")}
	id, token := registerAndInventory(t, store, certs, eps)

	tasks, _ := store.getTasks(id, token)
	taskID := tasks[0].TaskID

	// Agent reports success → task cleared.
	if err := store.submitRenewalResult(id, token, AgentRenewalResult{
		TaskID: taskID, Fingerprint: "fp1", Outcome: "installed_verified",
	}); err != nil {
		t.Fatalf("submitRenewalResult: %v", err)
	}
	if tasks, _ := store.getTasks(id, token); len(tasks) != 0 {
		t.Fatalf("expected task cleared after success, got %d", len(tasks))
	}

	// Re-inventory (cert still present this cycle) must NOT re-task — verified.
	if err := store.submitInventory(id, token, certs, eps); err != nil {
		t.Fatalf("submitInventory 2: %v", err)
	}
	if tasks, _ := store.getTasks(id, token); len(tasks) != 0 {
		t.Fatalf("expected no re-task after verified success, got %d", len(tasks))
	}
}

func TestAssignTasks_FailureRetasksNextCycle(t *testing.T) {
	store := NewAgentStore()
	soon := time.Now().UTC().Add(10 * 24 * time.Hour)
	certs := []AgentDiscoveredCert{expiringCert("fp1", "/etc/nginx/ssl/shop.crt", true, soon)}
	eps := []AgentEndpoint{nginxEndpoint("/etc/nginx/ssl/shop.crt", "/etc/nginx/ssl/shop.key")}
	id, token := registerAndInventory(t, store, certs, eps)

	tasks, _ := store.getTasks(id, token)
	// Agent reports failure (rolled back) → task cleared.
	if err := store.submitRenewalResult(id, token, AgentRenewalResult{
		TaskID: tasks[0].TaskID, Fingerprint: "fp1", Outcome: "verify_failed", RolledBack: true,
	}); err != nil {
		t.Fatalf("submitRenewalResult: %v", err)
	}
	if tasks, _ := store.getTasks(id, token); len(tasks) != 0 {
		t.Fatalf("expected task cleared after failure, got %d", len(tasks))
	}

	// Next inventory cycle re-tasks it (still expiring, not verified) → retry.
	if err := store.submitInventory(id, token, certs, eps); err != nil {
		t.Fatalf("submitInventory 2: %v", err)
	}
	if tasks, _ := store.getTasks(id, token); len(tasks) != 1 {
		t.Fatalf("expected re-task after failure (auto-retry), got %d", len(tasks))
	}
}

// TestRenewalIdentifiers_SANsFirst covers W19-13 case (a): a cert with
// reported SAN DNS names uses those, never the raw Subject RDN string.
func TestRenewalIdentifiers_SANsFirst(t *testing.T) {
	c := AgentDiscoveredCert{
		Subject:  "CN=shop.example.com",
		DNSNames: []string{"shop.example.com", "www.shop.example.com"},
	}
	got := renewalIdentifiers(c)
	want := []string{"shop.example.com", "www.shop.example.com"}
	if len(got) != len(want) {
		t.Fatalf("renewalIdentifiers = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("renewalIdentifiers[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestRenewalIdentifiers_CNOnlyFallback covers W19-13 case (b): a cert with
// no SANs falls back to a hostname parsed out of Subject's CN, not the raw
// RDN string ("CN=localhost").
func TestRenewalIdentifiers_CNOnlyFallback(t *testing.T) {
	got := renewalIdentifiers(AgentDiscoveredCert{Subject: "CN=localhost"})
	if len(got) != 1 || got[0] != "localhost" {
		t.Fatalf("renewalIdentifiers = %v, want [localhost]", got)
	}
}

// TestRenewalIdentifiers_UnparsableCNYieldsNone covers W19-13 case (c): a CN
// that is not a syntactically valid hostname (e.g. "My Service", containing
// a space) yields no identifiers rather than the invalid string -- an ACME
// order built from it could never validate.
func TestRenewalIdentifiers_UnparsableCNYieldsNone(t *testing.T) {
	got := renewalIdentifiers(AgentDiscoveredCert{Subject: "CN=My Service"})
	if len(got) != 0 {
		t.Fatalf("renewalIdentifiers = %v, want none for a non-hostname CN", got)
	}
}

// TestAssignTasks_UnparsableCNNotQueued proves the honest behaviour end to
// end: matchRenewalTasks must not queue a renewal task for a cert with no
// usable ACME identifier, rather than queuing one doomed to fail forever
// (submitRenewalResult clears a failed task, so a never-validating order
// would retry every inventory cycle).
func TestAssignTasks_UnparsableCNNotQueued(t *testing.T) {
	store := NewAgentStore()
	soon := time.Now().UTC().Add(10 * 24 * time.Hour)
	certs := []AgentDiscoveredCert{{
		Fingerprint: "fp1", Subject: "CN=My Service",
		Source: "/etc/nginx/ssl/shop.crt", NotAfter: soon, AutoRenewable: true,
	}}
	eps := []AgentEndpoint{nginxEndpoint("/etc/nginx/ssl/shop.crt", "/etc/nginx/ssl/shop.key")}
	id, token := registerAndInventory(t, store, certs, eps)

	tasks, err := store.getTasks(id, token)
	if err != nil {
		t.Fatalf("getTasks: %v", err)
	}
	if len(tasks) != 0 {
		t.Fatalf("expected no task queued for an unparsable CN, got %d: %+v", len(tasks), tasks)
	}
}
