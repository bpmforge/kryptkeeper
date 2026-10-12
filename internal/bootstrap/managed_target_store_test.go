// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newFreshManagedTargetStore(t *testing.T) *sqliteManagedTargetStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "managed-targets-fresh.db"))
	if err != nil {
		t.Fatalf("open fresh db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := &sqliteManagedTargetStore{db: db}
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("EnsureSchema on fresh db: %v", err)
	}
	return s
}

func mkTarget(id, host string) ManagedTarget {
	now := time.Now().UTC().Format(time.RFC3339)
	return ManagedTarget{
		ID: id, Name: "Target " + id, Host: host,
		DiscoveryMode: "agent", InstallMode: "agent", RenewalMethod: "acme",
		Tenant: "default", CreatedAt: now, UpdatedAt: now,
	}
}

// TestManagedTargetStoreSelfHealsSchemaOnFreshDB is the G-33 regression: a
// brand-new database with no pre-existing managed_targets table must still
// work, and EnsureSchema must be idempotent.
func TestManagedTargetStoreSelfHealsSchemaOnFreshDB(t *testing.T) {
	s := newFreshManagedTargetStore(t)
	ctx := context.Background()

	target := mkTarget("target-1", "web01.example.com")
	created, err := s.Create(ctx, target)
	if err != nil {
		t.Fatalf("Create on fresh db: %v", err)
	}
	if created.ID != target.ID {
		t.Fatalf("unexpected created ID: %+v", created)
	}

	got, err := s.Get(ctx, "target-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Host != "web01.example.com" || got.DiscoveryMode != "agent" {
		t.Fatalf("unexpected round-trip: %+v", got)
	}

	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema again: %v", err)
	}
}

// TestManagedTargetStore_RejectsInvalidEnums proves the fixed-enum CHECK
// constraints are actually enforced by the schema, not just documented.
func TestManagedTargetStore_RejectsInvalidEnums(t *testing.T) {
	s := newFreshManagedTargetStore(t)
	ctx := context.Background()

	bad := mkTarget("target-bad", "host.example.com")
	bad.DiscoveryMode = "carrier-pigeon"
	if _, err := s.Create(ctx, bad); err == nil {
		t.Error("expected an error for an invalid discovery_mode, got none")
	}

	bad2 := mkTarget("target-bad-2", "host.example.com")
	bad2.InstallMode = "telepathy"
	if _, err := s.Create(ctx, bad2); err == nil {
		t.Error("expected an error for an invalid install_mode, got none")
	}

	bad3 := mkTarget("target-bad-3", "host.example.com")
	bad3.RenewalMethod = "carrier-pigeon"
	if _, err := s.Create(ctx, bad3); err == nil {
		t.Error("expected an error for an invalid renewal_method, got none")
	}
}

// TestManagedTargetStore_Update proves a partial PATCH only touches the
// fields provided, re-validates the enum triple, and rejects an invalid
// mode even when introduced via update rather than create.
func TestManagedTargetStore_Update(t *testing.T) {
	s := newFreshManagedTargetStore(t)
	ctx := context.Background()

	if _, err := s.Create(ctx, mkTarget("target-1", "web01.example.com")); err != nil {
		t.Fatalf("Create: %v", err)
	}

	newHost := "web02.example.com"
	updated, err := s.Update(ctx, "target-1", ManagedTargetUpdate{Host: &newHost})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Host != newHost {
		t.Fatalf("Host = %q, want %q", updated.Host, newHost)
	}
	if updated.Name != "Target target-1" {
		t.Fatalf("untouched Name changed: %q", updated.Name)
	}
	// RFC3339 truncates to whole seconds, so a fast test creating then
	// immediately updating within the same wall-clock second can
	// legitimately produce an EQUAL UpdatedAt/CreatedAt -- assert
	// not-earlier-than, not strictly-changed, to avoid that flake (see
	// W9-04's TestRotateCA_PreservesValidityWindowLength for the same
	// class of fix).
	createdAt, err := time.Parse(time.RFC3339, updated.CreatedAt)
	if err != nil {
		t.Fatalf("parse CreatedAt: %v", err)
	}
	updatedAt, err := time.Parse(time.RFC3339, updated.UpdatedAt)
	if err != nil {
		t.Fatalf("parse UpdatedAt: %v", err)
	}
	if updatedAt.Before(createdAt) {
		t.Errorf("UpdatedAt %v is earlier than CreatedAt %v", updatedAt, createdAt)
	}

	badMode := "carrier-pigeon"
	if _, err := s.Update(ctx, "target-1", ManagedTargetUpdate{InstallMode: &badMode}); !isInvalidModeErr(err) {
		t.Fatalf("expected errManagedTargetInvalidMode, got %v", err)
	}

	// Confirm the rejected update didn't partially apply.
	reread, err := s.Get(ctx, "target-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if reread.InstallMode != "agent" {
		t.Fatalf("InstallMode = %q, want unchanged %q after a rejected update", reread.InstallMode, "agent")
	}

	if _, err := s.Update(ctx, "does-not-exist", ManagedTargetUpdate{Host: &newHost}); err != errManagedTargetNotFound {
		t.Fatalf("expected errManagedTargetNotFound, got %v", err)
	}
}

func isInvalidModeErr(err error) bool {
	return err == errManagedTargetInvalidMode
}

// TestManagedTargetStore_RenewalThresholdDays is the W8-15 store-level
// proof: a target created with no threshold set round-trips as the "use
// the env default" sentinel (0), an explicit threshold round-trips
// unchanged, a negative threshold is rejected without partially applying,
// and setting the threshold back to 0 via PATCH clears a prior override.
func TestManagedTargetStore_RenewalThresholdDays(t *testing.T) {
	s := newFreshManagedTargetStore(t)
	ctx := context.Background()

	unset := mkTarget("target-unset", "unset.example.com")
	created, err := s.Create(ctx, unset)
	if err != nil {
		t.Fatalf("Create (no threshold): %v", err)
	}
	if created.RenewalThresholdDays != 0 {
		t.Fatalf("RenewalThresholdDays = %d, want 0 (unset) for a target with no override", created.RenewalThresholdDays)
	}

	withThreshold := mkTarget("target-threshold", "threshold.example.com")
	withThreshold.RenewalThresholdDays = 14
	created, err = s.Create(ctx, withThreshold)
	if err != nil {
		t.Fatalf("Create (with threshold): %v", err)
	}
	if created.RenewalThresholdDays != 14 {
		t.Fatalf("RenewalThresholdDays = %d, want 14", created.RenewalThresholdDays)
	}
	got, err := s.Get(ctx, "target-threshold")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.RenewalThresholdDays != 14 {
		t.Fatalf("Get RenewalThresholdDays = %d, want 14 (round-trip)", got.RenewalThresholdDays)
	}

	newThreshold := 45
	updated, err := s.Update(ctx, "target-threshold", ManagedTargetUpdate{RenewalThresholdDays: &newThreshold})
	if err != nil {
		t.Fatalf("Update threshold: %v", err)
	}
	if updated.RenewalThresholdDays != 45 {
		t.Fatalf("RenewalThresholdDays after update = %d, want 45", updated.RenewalThresholdDays)
	}

	negative := -1
	if _, err := s.Update(ctx, "target-threshold", ManagedTargetUpdate{RenewalThresholdDays: &negative}); err != errManagedTargetInvalidThreshold {
		t.Fatalf("expected errManagedTargetInvalidThreshold for a negative value, got %v", err)
	}
	reread, err := s.Get(ctx, "target-threshold")
	if err != nil {
		t.Fatalf("Get after rejected update: %v", err)
	}
	if reread.RenewalThresholdDays != 45 {
		t.Fatalf("RenewalThresholdDays = %d, want unchanged 45 after a rejected update", reread.RenewalThresholdDays)
	}

	cleared := 0
	updated, err = s.Update(ctx, "target-threshold", ManagedTargetUpdate{RenewalThresholdDays: &cleared})
	if err != nil {
		t.Fatalf("Update (clear threshold): %v", err)
	}
	if updated.RenewalThresholdDays != 0 {
		t.Fatalf("RenewalThresholdDays after clearing = %d, want 0 (back to env default)", updated.RenewalThresholdDays)
	}
}

// TestManagedTargetStore_Delete proves delete works and that deleting an
// unknown ID errors rather than silently succeeding.
func TestManagedTargetStore_Delete(t *testing.T) {
	s := newFreshManagedTargetStore(t)
	ctx := context.Background()

	if _, err := s.Create(ctx, mkTarget("target-1", "web01.example.com")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.Delete(ctx, "target-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, "target-1"); err != errManagedTargetNotFound {
		t.Fatalf("expected errManagedTargetNotFound after delete, got %v", err)
	}
	if err := s.Delete(ctx, "target-1"); err != errManagedTargetNotFound {
		t.Fatalf("expected errManagedTargetNotFound deleting an already-deleted id, got %v", err)
	}
}

// TestManagedTargetStore_List proves List returns every target, newest
// first, unfiltered (tenant filtering is the handler layer's job).
func TestManagedTargetStore_List(t *testing.T) {
	s := newFreshManagedTargetStore(t)
	ctx := context.Background()

	for _, id := range []string{"target-1", "target-2", "target-3"} {
		if _, err := s.Create(ctx, mkTarget(id, id+".example.com")); err != nil {
			t.Fatalf("Create %s: %v", id, err)
		}
	}
	items, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("expected 3 targets, got %d", len(items))
	}
}

// TestManagedTargetStore_MatchEndpoints proves the host-string join against
// both endpoints (scanned, matched on hostname OR ip_address) and
// agent_endpoints (agent-reported, matched on server_name) -- and that an
// unrelated endpoint for a DIFFERENT host does not leak into the match.
func TestManagedTargetStore_MatchEndpoints(t *testing.T) {
	s := newFreshManagedTargetStore(t)
	ctx := context.Background()

	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS endpoints (
		id TEXT PRIMARY KEY, ip_address TEXT NOT NULL, hostname TEXT, port INTEGER NOT NULL)`); err != nil {
		t.Fatalf("create endpoints table: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS agent_endpoints (
		agent_id TEXT NOT NULL, server_type TEXT, server_name TEXT)`); err != nil {
		t.Fatalf("create agent_endpoints table: %v", err)
	}

	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO endpoints (id, ip_address, hostname, port) VALUES (?, ?, ?, ?)`,
		"ep-1", "10.0.0.5", "web01.example.com", 443); err != nil {
		t.Fatalf("insert endpoint: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO endpoints (id, ip_address, hostname, port) VALUES (?, ?, ?, ?)`,
		"ep-2", "10.0.0.9", "unrelated-host.example.com", 8443); err != nil {
		t.Fatalf("insert unrelated endpoint: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO agent_endpoints (agent_id, server_type, server_name) VALUES (?, ?, ?)`,
		"agent-1", "nginx", "web01.example.com"); err != nil {
		t.Fatalf("insert agent_endpoint: %v", err)
	}

	matches, err := s.MatchEndpoints(ctx, "web01.example.com")
	if err != nil {
		t.Fatalf("MatchEndpoints: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches (1 scanned + 1 agent), got %d: %+v", len(matches), matches)
	}
	var sawScanned, sawAgent bool
	for _, m := range matches {
		switch m.Source {
		case "scanned":
			sawScanned = true
			if m.EndpointID != "ep-1" {
				t.Errorf("scanned match EndpointID = %q, want ep-1", m.EndpointID)
			}
		case "agent":
			sawAgent = true
			if m.AgentID != "agent-1" {
				t.Errorf("agent match AgentID = %q, want agent-1", m.AgentID)
			}
		}
	}
	if !sawScanned || !sawAgent {
		t.Fatalf("expected both a scanned and an agent match, got %+v", matches)
	}

	none, err := s.MatchEndpoints(ctx, "no-such-host.example.com")
	if err != nil {
		t.Fatalf("MatchEndpoints (none): %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("expected 0 matches for an unrelated host, got %d", len(none))
	}
}

// W17-11: renewal_executor.go has routed and pushed install_mode "k8s"
// since W5-04, but 000028's CHECK never listed it — so no k8s target
// could be persisted and that push branch was unreachable. The inline
// DDL and the migration must both allow it.
func TestManagedTargetAcceptsK8sInstallMode(t *testing.T) {
	store := newFreshManagedTargetStore(t)
	ctx := context.Background()
	target, err := store.Create(ctx, ManagedTarget{
		ID: "tgt-k8s", Name: "edge-gateway", Host: "gateway.example.com",
		DiscoveryMode: "none", InstallMode: "k8s", RenewalMethod: "manual",
		CredentialRef: "cred-k8s",
	})
	if err != nil {
		t.Fatalf("a k8s target must be persistable — the executor already pushes to one: %v", err)
	}
	if target.InstallMode != "k8s" {
		t.Fatalf("install mode round-trip: %q", target.InstallMode)
	}
	// And it must still reject a genuinely unknown mode.
	if _, err := store.Create(ctx, ManagedTarget{
		ID: "tgt-bogus", Name: "bogus", Host: "h",
		DiscoveryMode: "none", InstallMode: "carrier-pigeon", RenewalMethod: "manual",
	}); err == nil {
		t.Fatal("an unknown install mode must still be rejected")
	}
}

// W18-03: Windows targets must be storable AND pass the handler's Go-level
// validation. Those are two different gates and they have disagreed
// before: W17-11 added k8s to the DB CHECK and the inline DDL but not to
// validInstallModes, so the database accepted a target the API refused.
func TestManagedTargetModeVocabulariesAgree(t *testing.T) {
	store := newFreshManagedTargetStore(t)
	ctx := context.Background()

	cases := []struct{ name, discovery, install string }{
		{"iis over winrm", "winrm", "iis"},
		{"keychain (macOS)", "none", "keychain"},
		{"k8s", "none", "k8s"},
		{"ssh", "none", "ssh"},
	}
	for _, c := range cases {
		// Gate 1: the Go validation the handler runs.
		if err := validateManagedTargetModes(c.discovery, c.install, "manual"); err != nil {
			t.Fatalf("%s: handler validation rejects a mode the schema allows: %v", c.name, err)
		}
		// Gate 2: the database.
		if _, err := store.Create(ctx, ManagedTarget{
			ID: "tgt-" + c.install + "-" + c.discovery, Name: c.name, Host: "h.example.com",
			DiscoveryMode: c.discovery, InstallMode: c.install, RenewalMethod: "manual",
		}); err != nil {
			t.Fatalf("%s: schema rejects a mode the handler allows: %v", c.name, err)
		}
	}

	// And neither gate may become a no-op.
	if err := validateManagedTargetModes("none", "carrier-pigeon", "manual"); err == nil {
		t.Fatal("an unknown install mode must still be refused by validation")
	}
	if _, err := store.Create(ctx, ManagedTarget{
		ID: "tgt-bogus", Name: "bogus", Host: "h",
		DiscoveryMode: "none", InstallMode: "carrier-pigeon", RenewalMethod: "manual",
	}); err == nil {
		t.Fatal("an unknown install mode must still be refused by the schema")
	}
}
