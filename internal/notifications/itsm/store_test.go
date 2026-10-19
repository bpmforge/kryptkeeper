// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package itsm

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	kkdb "kryptkeeper/internal/db"

	_ "modernc.org/sqlite"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "itsm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	return NewStore(db, false)
}

func TestStore_BothDialectsRebind(t *testing.T) {
	q := "SELECT 1 FROM t WHERE a = ? AND b = ? AND c <= ?"
	if got := (&Store{postgres: false}).q(q); got != q {
		t.Errorf("sqlite must keep ?: %s", got)
	}
	want := "SELECT 1 FROM t WHERE a = $1 AND b = $2 AND c <= $3"
	if got := (&Store{postgres: true}).q(q); got != want {
		t.Errorf("postgres rewrite: got %s want %s", got, want)
	}
}

func TestStore_ConnectionRoundTripAndDelete(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	c, err := s.CreateConnection(ctx, Connection{ID: "c1", Kind: "jira", Name: "J", BaseURL: "https://x.example", CredentialRef: "cred-1", EventClasses: []EventClass{{Class: "expiry", TicketType: "incident"}}, Enabled: true}, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetConnection(ctx, c.ID)
	if err != nil || got.Tenant != "default" || !got.Enabled || len(got.EventClasses) != 1 || !got.CreatedAt.Equal(now) {
		t.Fatalf("round trip: %+v err=%v", got, err)
	}
	if _, err := s.InsertEvent(ctx, EventRow{EventID: "e1", ConnectionID: "c1", Class: "expiry", Payload: "{}"}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteConnection(ctx, "c1"); err != ErrConnectionInUse {
		t.Fatalf("delete with history: %v", err)
	}
	if err := s.DeleteConnection(ctx, "nope"); err != ErrNotFound {
		t.Fatalf("delete missing: %v", err)
	}
	if _, err := s.GetConnection(ctx, "nope"); err != ErrNotFound {
		t.Fatalf("get missing: %v", err)
	}
}

func TestStore_InsertEventIsIdempotent(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	now := time.Now()
	if _, err := s.CreateConnection(ctx, Connection{ID: "c1", Kind: "jira", Name: "J", BaseURL: "https://x", CredentialRef: "r", Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	for i, want := range []bool{true, false, false} {
		got, err := s.InsertEvent(ctx, EventRow{EventID: "e1", ConnectionID: "c1", Class: "x", Payload: "{}"}, now)
		if err != nil || got != want {
			t.Fatalf("insert %d: got %v err %v want %v", i, got, err, want)
		}
	}
	rows, _ := s.ListEvents(ctx, "", 10)
	if len(rows) != 1 {
		t.Fatalf("rows=%d", len(rows))
	}
}

func TestStore_EventClassesLegacyStringArrayStillReads(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	now := time.Now()
	if _, err := s.CreateConnection(ctx, Connection{ID: "c1", Kind: "jira", Name: "J", BaseURL: "https://x", CredentialRef: "r", Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE itsm_connections SET event_classes = '["renewal_failed"]' WHERE id = 'c1'`); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetConnection(ctx, "c1")
	if err != nil || len(got.EventClasses) != 1 || got.EventClasses[0] != (EventClass{Class: "renewal_failed"}) {
		t.Fatalf("legacy read: %+v err=%v", got.EventClasses, err)
	}
}
