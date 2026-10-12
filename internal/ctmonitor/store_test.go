// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ctmonitor

import (
	"context"
	"database/sql"
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
