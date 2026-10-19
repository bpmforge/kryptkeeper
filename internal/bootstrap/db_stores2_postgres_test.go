// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"kryptkeeper/internal/acme"
	"kryptkeeper/internal/ctmonitor"
	"kryptkeeper/internal/scep"
)

// Third sweep: agent store, HA coordinator, SCEP challenges, CT monitor and
// the ACME store on a live Postgres.

func TestAgentStore_Postgres_RoundTrip(t *testing.T) {
	migratedPostgresForTest(t)
	s := NewAgentStoreFromEnv()
	// D-290: a configured database is wrapped in the fail-closed lazy store.
	lazy, ok := s.(*lazyAgentStore)
	if !ok {
		t.Fatalf("expected the lazy DB agent store, got %T", s)
	}
	inner, err := lazy.get()
	if err != nil {
		t.Fatalf("lazy agent store did not open the database: %v", err)
	}
	if _, ok := inner.(*dbAgentStore); !ok {
		t.Fatalf("expected the DB agent store inside the lazy wrapper, got %T", inner)
	}
	id, token, err := s.register("host-1", AgentTypeLinux)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := s.heartbeat(id, token); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	certs := []AgentDiscoveredCert{{
		Fingerprint: "fp-agent-1", Subject: "CN=a", Issuer: "CN=ca",
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		Source: "nginx", DNSNames: []string{"a.example.com"},
	}}
	eps := []AgentEndpoint{{ServerType: "nginx", CertPath: "/etc/ssl/a.pem", KeyPath: "/etc/ssl/a.key", ServerName: "a.example.com", ListenPort: 443}}
	if err := s.submitInventory(id, token, certs, eps); err != nil {
		t.Fatalf("submitInventory: %v", err)
	}
	if got := s.endpointsFor(id); len(got) != 1 {
		t.Fatalf("endpointsFor: %+v", got)
	}
	if n, err := s.endpointCount(); err != nil || n != 1 {
		t.Fatalf("endpointCount: %d %v", n, err)
	}
	total, _ := s.agentCounts()
	if total != 1 {
		t.Fatalf("agentCounts total=%d", total)
	}
	if l := s.list(); len(l) != 1 {
		t.Fatalf("list: %+v", l)
	}
	if _, err := s.getTasks(id, token); err != nil {
		t.Fatalf("getTasks: %v", err)
	}
	_ = s.tasksFor(id)
	_ = s.resultsFor(id)
	_ = s.allResults()
	_ = s.sweepRenewals(time.Now())
}

func TestHACoordinator_Postgres_LeaseSemantics(t *testing.T) {
	migratedPostgresForTest(t)
	c, err := newHACoordinatorFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	got, err := c.TryAcquire(ctx, "sweep", time.Minute)
	if err != nil || !got {
		t.Fatalf("TryAcquire: %v %v", got, err)
	}
	if err := c.Release(ctx, "sweep"); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if got, err := c.TryAcquire(ctx, "sweep", time.Minute); err != nil || !got {
		t.Fatalf("TryAcquire after release: %v %v", got, err)
	}
}

func TestSCEPChallengeStore_Postgres_RoundTrip(t *testing.T) {
	migratedPostgresForTest(t)
	db := openPGForTest(t)
	s := scep.NewDBChallengeStore(db, true)
	ctx := context.Background()
	now := time.Now().UTC()
	c, secret, err := s.Create(ctx, scep.Challenge{CAID: "ca-1", CommonName: "dev1", DNSNames: []string{"dev1.example.com"},
		CreatedBy: "alice", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if l, err := s.List(ctx); err != nil || len(l) != 1 {
		t.Fatalf("List: %+v %v", l, err)
	}
	used, err := s.Consume(ctx, secret, now)
	if err != nil || used.ID != c.ID {
		t.Fatalf("Consume: %+v %v", used, err)
	}
	if _, err := s.Consume(ctx, secret, now); err == nil {
		t.Fatal("second Consume of one-time challenge must fail")
	}
	c2, _, err := s.Create(ctx, scep.Challenge{CAID: "ca-1", CommonName: "dev2", CreatedBy: "alice", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("Create 2: %v", err)
	}
	if err := s.Delete(ctx, c2.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestCTMonitorStore_Postgres_RoundTrip(t *testing.T) {
	migratedPostgresForTest(t)
	db := openPGForTest(t)
	s, err := ctmonitor.NewStore(db, true)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	f := ctmonitor.Finding{ID: "crtsh:1", Domain: "example.com", CommonName: "example.com", DNSNames: []string{"example.com"},
		Issuer: "CN=x", Serial: "01", NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		Source: "crtsh", Status: "open", CreatedAt: time.Now()}
	created, err := s.Record(ctx, f)
	if err != nil || !created {
		t.Fatalf("Record: %v %v", created, err)
	}
	if created, err := s.Record(ctx, f); err != nil || created {
		t.Fatalf("Record duplicate: %v %v", created, err)
	}
	if l, err := s.List(ctx, "open"); err != nil || len(l) != 1 {
		t.Fatalf("List: %+v %v", l, err)
	}
	if err := s.Acknowledge(ctx, f.ID); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}
}

func TestACMEStore_Postgres_RoundTrip(t *testing.T) {
	migratedPostgresForTest(t)
	db := openPGForTest(t)
	s := acme.NewSQLiteStore(db, true)
	if err := s.EnsureSchema(); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	acct := &acme.Account{ID: "acct-1", Key: &key.PublicKey, KeyThumbprint: "tp", Contact: []string{"mailto:a@example.com"},
		Status: "valid", CreatedAt: now}
	if err := s.SaveAccount(acct); err != nil {
		t.Fatalf("SaveAccount: %v", err)
	}
	if err := s.SaveAccount(acct); err != nil {
		t.Fatalf("SaveAccount (upsert): %v", err)
	}
	if got, ok := s.LoadAccount("acct-1"); !ok || got.KeyThumbprint != "tp" {
		t.Fatalf("LoadAccount: %+v ok=%v", got, ok)
	}
	order := &acme.Order{ID: "ord-1", AccountID: "acct-1", Status: "pending",
		Identifiers: []acme.Identifier{{Type: "dns", Value: "a.example.com"}}, Authorizations: []string{"az-1"},
		Finalize: "https://x/finalize", Expires: now.Add(time.Hour), CreatedAt: now}
	if err := s.SaveOrder(order); err != nil {
		t.Fatalf("SaveOrder: %v", err)
	}
	if err := s.SaveOrder(order); err != nil {
		t.Fatalf("SaveOrder (upsert): %v", err)
	}
	if got, ok := s.LoadOrder("ord-1"); !ok || len(got.Identifiers) != 1 {
		t.Fatalf("LoadOrder: %+v ok=%v", got, ok)
	}
	if l := s.ListOrders(); len(l) != 1 {
		t.Fatalf("ListOrders: %d", len(l))
	}
	az := &acme.Authorization{ID: "az-1", AccountID: "acct-1", Identifier: acme.Identifier{Type: "dns", Value: "a.example.com"},
		Status: "pending", Expires: now.Add(time.Hour)}
	if err := s.SaveAuthz(az); err != nil {
		t.Fatalf("SaveAuthz: %v", err)
	}
	if _, ok := s.LoadAuthz("az-1"); !ok {
		t.Fatal("LoadAuthz missing")
	}
	if err := s.SaveCert("c-1", []byte("PEM")); err != nil {
		t.Fatalf("SaveCert: %v", err)
	}
	if got, ok := s.LoadCert("c-1"); !ok || string(got) != "PEM" {
		t.Fatalf("LoadCert: %q ok=%v", got, ok)
	}
	if err := s.SaveEABKey(&acme.EABKey{KID: "kid-1", MACKey: []byte("k"), CreatedAt: now}); err != nil {
		t.Fatalf("SaveEABKey: %v", err)
	}
	if _, ok := s.LoadEABKey("kid-1"); !ok {
		t.Fatal("LoadEABKey missing")
	}
	if err := s.BindAccountEAB("acct-1", "kid-1"); err != nil {
		t.Fatalf("BindAccountEAB: %v", err)
	}
}
