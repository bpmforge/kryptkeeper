// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ctmonitor

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "ct.db"))
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s, err := NewStore(db, false)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return s
}

func testFinding(id string) Finding {
	return Finding{
		ID: id, Domain: "example.com", CommonName: "rogue.example.com",
		DNSNames: []string{"rogue.example.com"}, Issuer: "C=XX, O=Shady CA",
		Serial:    "0abc",
		NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		Source: "crtsh",
	}
}

func TestStoreRecordIsIdempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.Record(ctx, testFinding("crtsh:1"))
	if err != nil || !created {
		t.Fatalf("first record: created=%v err=%v", created, err)
	}
	created, err = s.Record(ctx, testFinding("crtsh:1"))
	if err != nil || created {
		t.Fatalf("duplicate must not re-create: created=%v err=%v", created, err)
	}

	list, err := s.List(ctx, "open")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].ID != "crtsh:1" || list[0].CommonName != "rogue.example.com" {
		t.Fatalf("unexpected findings: %+v", list)
	}
	if len(list[0].DNSNames) != 1 || list[0].DNSNames[0] != "rogue.example.com" {
		t.Fatalf("dns names lost: %+v", list[0])
	}
}

func TestStoreAcknowledge(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.Record(ctx, testFinding("crtsh:2")); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := s.Acknowledge(ctx, "crtsh:2"); err != nil {
		t.Fatalf("ack: %v", err)
	}
	open, _ := s.List(ctx, "open")
	if len(open) != 0 {
		t.Fatalf("acknowledged finding still open: %+v", open)
	}
	acked, _ := s.List(ctx, "acknowledged")
	if len(acked) != 1 {
		t.Fatalf("expected 1 acknowledged, got %d", len(acked))
	}
	if err := s.Acknowledge(ctx, "no-such"); err == nil {
		t.Fatal("acknowledging a missing finding must error")
	}
}

func TestResolveKnownIssuer(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.Record(ctx, testFinding("crtsh:3")); err != nil {
		t.Fatalf("record: %v", err)
	}
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	if err := s.Resolve(ctx, "crtsh:3", ResolutionKnownIssuer, "alice", at); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	f, err := s.Get(ctx, "crtsh:3")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if f.Status != "acknowledged" || f.Resolution != ResolutionKnownIssuer || f.ResolvedBy != "alice" || !f.ResolvedAt.Equal(at) {
		t.Fatalf("unexpected resolved finding: %+v", f)
	}
	if err := s.Resolve(ctx, "crtsh:3", "bogus", "alice", at); err == nil {
		t.Fatal("invalid resolution must be rejected")
	}
}

func TestRecordAfterAcknowledgeDoesNotReopen(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.Record(ctx, testFinding("crtsh:4")); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := s.Resolve(ctx, "crtsh:4", ResolutionAcknowledged, "bob", time.Now()); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	created, err := s.Record(ctx, testFinding("crtsh:4"))
	if err != nil || created {
		t.Fatalf("re-scan must not re-create: created=%v err=%v", created, err)
	}
	f, _ := s.Get(ctx, "crtsh:4")
	if f.Status != "acknowledged" || f.Resolution != ResolutionAcknowledged || f.ResolvedBy != "bob" {
		t.Fatalf("re-scan reopened or cleared the finding: %+v", f)
	}
}

func TestGetNotFound(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Get(context.Background(), "nope"); !errors.Is(err, ErrFindingNotFound) {
		t.Fatalf("Get err = %v, want ErrFindingNotFound", err)
	}
	if err := s.Resolve(context.Background(), "nope", ResolutionAcknowledged, "x", time.Now()); !errors.Is(err, ErrFindingNotFound) {
		t.Fatalf("Resolve err = %v, want ErrFindingNotFound", err)
	}
}

func TestEnsureSchemaUpgradesOldTable(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "old.db"))
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`CREATE TABLE ct_findings (
		id TEXT PRIMARY KEY, domain TEXT NOT NULL, common_name TEXT NOT NULL DEFAULT '',
		dns_names TEXT NOT NULL DEFAULT '[]', issuer TEXT NOT NULL DEFAULT '',
		serial TEXT NOT NULL DEFAULT '', not_before TEXT NOT NULL DEFAULT '',
		not_after TEXT NOT NULL DEFAULT '', source TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged')),
		created_at TEXT NOT NULL)`); err != nil {
		t.Fatalf("old table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO ct_findings (id, domain, source, created_at)
		VALUES ('crtsh:old', 'example.com', 'crtsh', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("old row: %v", err)
	}
	s, err := NewStore(db, false)
	if err != nil {
		t.Fatalf("NewStore on old table: %v", err)
	}
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("second EnsureSchema must be idempotent: %v", err)
	}
	f, err := s.Get(context.Background(), "crtsh:old")
	if err != nil {
		t.Fatalf("get old row: %v", err)
	}
	if f.Tenant != DefaultTenant || f.Resolution != "" {
		t.Fatalf("old row defaults wrong: %+v", f)
	}
}
