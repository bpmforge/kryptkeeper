// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// Live-Postgres CRUD round trips for the DB-backed providers. Each test runs
// against a freshly migrated database (migrations first, the "ca" boot order)
// and is skipped unless KRYPTKEEPER_TEST_POSTGRES_DSN is set. They exist
// because the rc.4 upgrade test found the user provider's Postgres path had
// never been executed by any test (SQLite-only types and placeholders).

func openPGForTest(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", os.Getenv("KRYPTKEEPER_TEST_POSTGRES_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestManagedTargetStore_Postgres_CRUD(t *testing.T) {
	migratedPostgresForTest(t)
	s := newManagedTargetStoreFromEnv()
	ctx := context.Background()
	if _, ok := s.(*postgresManagedTargetStore); !ok {
		t.Fatalf("expected postgres store, got %T", s)
	}

	if got, err := s.List(ctx); err != nil || len(got) != 0 {
		t.Fatalf("List on empty: %v %v", got, err)
	}
	tgt := mkTarget("target-pg-1", "web01.example.com")
	tgt.VerifyHostPort = "web01.example.com:8443"
	tgt.AutoRenewSetBy = "tester"
	tgt.AutoRenew = true
	tgt.RenewalThresholdDays = 21
	created, err := s.Create(ctx, tgt)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := s.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Host != "web01.example.com" || got.VerifyHostPort != "web01.example.com:8443" ||
		!got.AutoRenew || got.AutoRenewSetBy != "tester" || got.RenewalThresholdDays != 21 {
		t.Fatalf("round trip lost fields: %+v", got)
	}
	host := "web02.example.com"
	off := false
	upd, err := s.Update(ctx, created.ID, ManagedTargetUpdate{Host: &host, AutoRenew: &off})
	if err != nil || upd.Host != host || upd.AutoRenew {
		t.Fatalf("Update: %+v %v", upd, err)
	}
	if _, err := s.Update(ctx, "nope", ManagedTargetUpdate{Host: &host}); err != errManagedTargetNotFound {
		t.Fatalf("Update missing: %v", err)
	}
	list, err := s.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("List: %v %v", list, err)
	}
	if _, err := s.MatchEndpoints(ctx, host); err != nil {
		t.Fatalf("MatchEndpoints: %v", err)
	}
	if err := s.Delete(ctx, created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, created.ID); err != errManagedTargetNotFound {
		t.Fatalf("Get after delete: %v", err)
	}
}

func TestNotificationProvider_Postgres_RulesAndDeliveries(t *testing.T) {
	migratedPostgresForTest(t)
	p := newDBNotificationProviderFromEnv()
	ctx := context.Background()

	rule, err := p.CreateRule(ctx, "expiry 30d", 30, "email", "ops@example.com")
	if err != nil {
		t.Fatalf("CreateRule: %v", err)
	}
	rules, err := p.ListRules(ctx)
	if err != nil || len(rules) != 1 || rules[0].ID != rule.ID || !rules[0].Enabled || rules[0].CreatedAt == "" {
		t.Fatalf("ListRules: %+v %v", rules, err)
	}
	upd, err := p.UpdateRule(ctx, rule.ID, false, "oncall@example.com")
	if err != nil || upd.Enabled || upd.Target != "oncall@example.com" {
		t.Fatalf("UpdateRule: %+v %v", upd, err)
	}

	if _, err := p.GetSummary(ctx); err != nil {
		t.Fatalf("GetSummary: %v", err)
	}
	if _, err := p.TestDelivery(ctx, "email", "ops@example.com", "hello"); err != nil {
		t.Fatalf("TestDelivery: %v", err)
	}
	res, err := p.ListDeliveries(ctx, NotificationDeliveryQuery{Limit: 10})
	if err != nil {
		t.Fatalf("ListDeliveries: %v", err)
	}
	if res.Total < 1 || len(res.Deliveries) < 1 {
		t.Fatalf("expected the test delivery to be listed: %+v", res)
	}
	id := res.Deliveries[0].ID
	if _, err := p.AckDelivery(ctx, id, "seen"); err != nil {
		t.Fatalf("AckDelivery: %v", err)
	}
	if _, err := p.RetryDelivery(ctx, id, "again"); err != nil {
		t.Fatalf("RetryDelivery: %v", err)
	}
	if _, err := p.ListDeliveries(ctx, NotificationDeliveryQuery{Status: "queued", Channel: "email", Limit: 5}); err != nil {
		t.Fatalf("ListDeliveries filtered: %v", err)
	}

	if err := p.DeleteRule(ctx, rule.ID); err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
	if rules, err := p.ListRules(ctx); err != nil || len(rules) != 0 {
		t.Fatalf("ListRules after delete: %+v %v", rules, err)
	}
}

func TestPendingActionStore_Postgres_CRUD(t *testing.T) {
	migratedPostgresForTest(t)
	s := NewPendingActionStoreFromEnv()
	if s == nil {
		t.Fatal("nil pending action store")
	}
	ctx := context.Background()
	created, err := s.Create(ctx, PendingAction{
		ActionType: "revoke", Params: json.RawMessage(`{"serial":"01"}`),
		ProposedBy: "mcp", Rationale: "test", Tenant: "default",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, ok, err := s.Get(ctx, created.ID)
	if err != nil || !ok || got.Status != "pending" {
		t.Fatalf("Get: %+v ok=%v err=%v", got, ok, err)
	}
	list, err := s.List(ctx, "pending")
	if err != nil || len(list) != 1 {
		t.Fatalf("List: %+v %v", list, err)
	}
	if err := s.Decide(ctx, created.ID, "approved", "admin", json.RawMessage(`{"ok":true}`)); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	got, _, err = s.Get(ctx, created.ID)
	if err != nil || got.Status != "approved" || got.ApprovedBy != "admin" {
		t.Fatalf("after Decide: %+v %v", got, err)
	}
	if list, err := s.List(ctx, ""); err != nil || len(list) != 1 {
		t.Fatalf("List all: %+v %v", list, err)
	}
}

func TestAPIKeyStore_Postgres_RoundTrip(t *testing.T) {
	migratedPostgresForTest(t)
	db := openPGForTest(t)
	s := NewAPIKeyStore(db, true)
	ctx := context.Background()
	now := time.Now().UTC()
	rec := apiKeyRecord{
		Name: "ci", Kid: "kid-pg-1", SecretVerifier: "verifier", PrincipalID: "svc-ci", Role: "pki-operator",
		Scopes: []string{"certificate.read"}, Active: true, CreatedAt: now.Format(time.RFC3339),
		CreatedBy: "admin", Tenant: "default",
	}
	if err := s.Insert(ctx, rec); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	loaded, err := s.LoadActive(ctx)
	if err != nil || len(loaded) != 1 || loaded[0].Kid != "kid-pg-1" || len(loaded[0].Scopes) != 1 || !loaded[0].Active {
		t.Fatalf("LoadActive: %+v %v", loaded, err)
	}
	if err := s.TouchLastUsed(ctx, "kid-pg-1", now); err != nil {
		t.Fatalf("TouchLastUsed: %v", err)
	}
	if err := s.Revoke(ctx, "kid-pg-1", now); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if loaded, err := s.LoadActive(ctx); err != nil || len(loaded) != 0 {
		t.Fatalf("LoadActive after revoke: %+v %v", loaded, err)
	}
}

func TestAuditProvider_Postgres_AppendList(t *testing.T) {
	migratedPostgresForTest(t)
	t.Setenv("APP_AUDIT_PROVIDER", "db")
	p, err := newDBAuditProviderFromEnv()
	if err != nil {
		t.Fatalf("newDBAuditProviderFromEnv: %v", err)
	}
	ctx := context.Background()
	for _, a := range []string{"certificate.issue", "certificate.revoke"} {
		if err := p.AppendEntry(ctx, AuditEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339), Action: a, ActorType: "user", ActorID: "alice",
			ResourceType: "certificate", ResourceID: "01", Outcome: "success", Tenant: "default",
			ChangeSummary: "test",
		}); err != nil {
			t.Fatalf("AppendEntry %s: %v", a, err)
		}
	}
	res, err := p.ListEntries(ctx, AuditListQuery{Limit: 10, Order: "desc"})
	if err != nil || len(res.Entries) != 2 {
		t.Fatalf("ListEntries: %+v %v", res, err)
	}
	if res, err := p.ListEntries(ctx, AuditListQuery{Limit: 10, Action: "certificate.revoke", ActorID: "alice", ResourceType: "certificate"}); err != nil || len(res.Entries) != 1 {
		t.Fatalf("ListEntries filtered: %+v %v", res, err)
	}
}

func TestCertSummaryProvider_Postgres(t *testing.T) {
	migratedPostgresForTest(t)
	db := openPGForTest(t)
	const insert = `INSERT INTO certificates
		(fingerprint_sha256, serial_number, subject_dn, issuer_dn, valid_from, valid_until,
		 public_key_algorithm, signature_algorithm)
		VALUES ($1, $2, 'CN=x', 'CN=ca', NOW() - INTERVAL '1 day', $3, 'ECDSA', 'ecdsa-with-SHA256')`
	if _, err := db.Exec(insert, "fp-sum-1", "1", time.Now().Add(10*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(insert, "fp-sum-2", "2", time.Now().Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	t.Setenv(certSummaryProviderEnv, "db")
	snap, err := NewCertSummaryProviderFromEnv().LoadSummary(context.Background())
	if err != nil {
		t.Fatalf("LoadSummary: %v", err)
	}
	if snap.Total != 2 || snap.Expired != 1 || snap.Expiring30Days != 1 {
		t.Fatalf("snapshot = %+v", snap)
	}
}

func TestDiscoveryProvider_Postgres_ScanLifecycle(t *testing.T) {
	migratedPostgresForTest(t)
	t.Setenv("APP_DISCOVERY_PROVIDER", "db")
	p := NewDiscoveryProviderFromEnv()
	ctx := context.Background()

	if _, err := p.GetSummary(ctx); err != nil {
		t.Fatalf("GetSummary: %v", err)
	}
	if _, err := p.ListEndpoints(ctx, DiscoveryEndpointQuery{Limit: 10}); err != nil {
		t.Fatalf("ListEndpoints: %v", err)
	}
	created, err := p.CreateScan(ctx, "network", "10.0.0.0/30", []int{8443})
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	jobs, err := p.ListScanJobs(ctx, DiscoveryScanJobQuery{Limit: 10})
	if err != nil || len(jobs.ScanJobs) == 0 {
		t.Fatalf("ListScanJobs: %+v %v", jobs, err)
	}
	if _, err := p.CancelScanJob(ctx, created.ID, "test"); err != nil {
		t.Fatalf("CancelScanJob: %v", err)
	}
	if _, err := p.RequeueScanJob(ctx, created.ID, "test"); err != nil {
		t.Fatalf("RequeueScanJob: %v", err)
	}
}
