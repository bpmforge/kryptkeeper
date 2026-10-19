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

// TestApprovalStoreSelfHealsSchemaOnFreshDB is the S-06/G-47 regression: a
// brand-new database with no pre-existing cert_approval_requests table (i.e.
// no migration ever ran against it) must still work, since EnsureSchema now
// creates the table inline rather than depending on migration 000013.
func TestApprovalStoreSelfHealsSchemaOnFreshDB(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "fresh.db"))
	if err != nil {
		t.Fatalf("open fresh db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	store := &sqliteApprovalStore{db: db}
	ctx := context.Background()

	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema on fresh db: %v", err)
	}

	req := ApprovalRequest{
		ID: "apr-fresh", TemplateID: "tpl-1", CAID: "ca-1", Requester: "svc",
		Status: "pending", CSRPEM: "placeholder", RequestedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := store.Create(ctx, req); err != nil {
		t.Fatalf("Create on fresh db: %v", err)
	}

	got, err := store.Get(ctx, "apr-fresh")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != req.ID || got.CAID != req.CAID {
		t.Fatalf("unexpected round-trip: %+v", got)
	}

	// EnsureSchema is idempotent — calling it again on an already-migrated
	// DB (the normal case on every process restart) must not error.
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema again: %v", err)
	}
}

// TestApprovalStore_OnBehalfOf_RoundTrip: W33-23 on_behalf_of survives Create,
// Get and List, and is empty for an ordinary row.
func TestApprovalStore_OnBehalfOf_RoundTrip(t *testing.T) {
	s := newTestApprovalStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)
	if err := s.Create(ctx, ApprovalRequest{ID: "apr-obo", TemplateID: "t", CAID: "c", Requester: "bob", CSRPEM: "csr", TeamID: "alice", OnBehalfOf: "alice", RequestedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, ApprovalRequest{ID: "apr-plain", TemplateID: "t", CAID: "c", Requester: "bob", CSRPEM: "csr2", TeamID: "bob", RequestedAt: now}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, "apr-obo")
	if err != nil || got.OnBehalfOf != "alice" || got.Requester != "bob" || got.TeamID != "alice" {
		t.Fatalf("Get: %+v err=%v", got, err)
	}
	rows, _, err := s.List(ctx, "pending", 10, 0)
	if err != nil || len(rows) != 2 {
		t.Fatalf("List: %v %+v", err, rows)
	}
	for _, r := range rows {
		want := map[string]string{"apr-obo": "alice", "apr-plain": ""}[r.ID]
		if r.OnBehalfOf != want {
			t.Errorf("%s on_behalf_of = %q, want %q", r.ID, r.OnBehalfOf, want)
		}
	}
}

// TestCancelPendingForRequester_CancelsOnlyPendingForThatRequester: W33-23
// acceptance 2 (a requester leaving a team cancels their pending requests).
func TestCancelPendingForRequester_CancelsOnlyPendingForThatRequester(t *testing.T) {
	s := newTestApprovalStore(t)
	ctx := context.Background()
	audit := &recordingAuditProvider{}
	now := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	mk := func(id, requester, team, onBehalf string) {
		t.Helper()
		if err := s.Create(ctx, ApprovalRequest{ID: id, TemplateID: "t", CAID: "c", Requester: requester, CSRPEM: id, TeamID: team, OnBehalfOf: onBehalf, RequestedAt: now.Format(time.RFC3339)}); err != nil {
			t.Fatal(err)
		}
	}
	mk("a1", "bob", "T", "")
	mk("a2", "bob", "T", "")
	mk("a3", "dana", "T", "")
	mk("a4", "bob", "U", "")          // another team of the same requester
	mk("a5", "bob", "T", "")          // already approved below
	mk("a6", "bob", "alice", "alice") // bob filing for alice; bob leaving T does not touch it
	if err := s.Decide(ctx, "a5", "carol", "approved", ""); err != nil {
		t.Fatal(err)
	}
	n, err := CancelPendingForRequester(ctx, s, audit, "bob", "T", now)
	if err != nil || n != 2 {
		t.Fatalf("cancelled %d err=%v, want 2", n, err)
	}
	for id, want := range map[string]string{"a1": "rejected", "a2": "rejected", "a3": "pending", "a4": "pending", "a5": "approved", "a6": "pending"} {
		got, _ := s.Get(ctx, id)
		if got.Status != want {
			t.Errorf("%s status = %q, want %q", id, got.Status, want)
		}
	}
	got, _ := s.Get(ctx, "a1")
	if got.RejectReason == nil || *got.RejectReason != "requester left team T" || got.DecidedBy == nil || *got.DecidedBy != approvalSystemActor {
		t.Errorf("a1 reject reason/decider: %+v", got)
	}
	cancels := 0
	for _, e := range audit.entries {
		if e.Action == "approval.cancel" && e.ActorType == "system" && e.Outcome == AuditOutcomeSuccess && e.ChangeSummary == "requester=bob team=T reason=left_team" {
			cancels++
		}
	}
	if cancels != 2 {
		t.Fatalf("approval.cancel audit rows = %d, want 2: %+v", cancels, audit.entries)
	}
	if n, err := CancelPendingForRequester(ctx, s, audit, "bob", "T", now); err != nil || n != 0 {
		t.Fatalf("second call cancelled %d err=%v, want 0", n, err)
	}
	// The delegator leaving cancels requests filed for them.
	if n, err := CancelPendingForRequester(ctx, s, audit, "alice", "alice", now); err != nil || n != 1 {
		t.Fatalf("delegator leaving cancelled %d err=%v, want 1", n, err)
	}
	if _, err := CancelPendingForRequester(ctx, s, audit, "", "T", now); err == nil {
		t.Fatal("empty requester must be refused")
	}
}
