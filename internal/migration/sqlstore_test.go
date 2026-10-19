// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package migration

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func newSQLiteStore(t *testing.T) *SQLStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "m.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st := NewSQLStore(db, false)
	if err := st.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestSQLStoreSupersedeIsAtomicWithSaveBatch(t *testing.T) {
	st := newSQLiteStore(t)
	ctx := context.Background()
	b1 := Batch{ID: "mb_1", Source: "s", Status: "applied", CreatedBy: "a", CreatedAt: "2026-10-18T10:00:00Z"}
	if err := st.SaveBatch(ctx, b1, []BatchItem{{BatchID: "mb_1", SourceKey: "k", TemplateID: "t1", Name: "A", ContentHash: "h1", CreatedAt: b1.CreatedAt}}); err != nil {
		t.Fatal(err)
	}

	// The second item collides on the primary key after the supersede UPDATE
	// ran: the whole transaction must roll back, old item still active.
	b2 := Batch{ID: "mb_2", Source: "s", Status: "applied", CreatedBy: "a", CreatedAt: "2026-10-18T11:00:00Z"}
	dup := BatchItem{BatchID: "mb_2", SourceKey: "k", TemplateID: "t1", Name: "A", ContentHash: "h2", CreatedAt: b2.CreatedAt, SupersedesBatchID: "mb_1"}
	if err := st.SaveBatch(ctx, b2, []BatchItem{dup, dup}); err == nil {
		t.Fatal("want a primary-key failure")
	}
	it, ok, err := st.FindActiveItem(ctx, "s", "k")
	if err != nil || !ok || it.BatchID != "mb_1" {
		t.Fatalf("failed save must leave the old item active: %+v ok=%v err=%v", it, ok, err)
	}
	if _, _, found, _ := st.GetBatch(ctx, "mb_2"); found {
		t.Fatal("failed save left a batch row")
	}

	if err := st.SaveBatch(ctx, b2, []BatchItem{dup}); err != nil {
		t.Fatal(err)
	}
	it, ok, _ = st.FindActiveItem(ctx, "s", "k")
	if !ok || it.BatchID != "mb_2" {
		t.Fatalf("after a good save the new item is the active one: %+v", it)
	}
}

func TestSQLStoreSnapshotRoundTripAndOrigin(t *testing.T) {
	st := newSQLiteStore(t)
	ctx := context.Background()
	b := Batch{ID: "mb_1", Source: "s", Status: "applied", CreatedBy: "a", CreatedAt: "2026-10-18T10:00:00Z"}
	items := []BatchItem{
		{BatchID: "mb_1", SourceKey: "k1", TemplateID: "t1", Name: "A", ContentHash: "h", CreatedAt: b.CreatedAt, PriorJSON: `{"x":1}`},
		{BatchID: "mb_1", SourceKey: "k2", TemplateID: "t2", Name: "B", ContentHash: "h", CreatedAt: b.CreatedAt},
	}
	if err := st.SaveBatch(ctx, b, items); err != nil {
		t.Fatal(err)
	}
	_, got, _, err := st.GetBatch(ctx, "mb_1")
	if err != nil || len(got) != 2 || got[0].PriorJSON != `{"x":1}` || got[1].PriorJSON != "" {
		t.Fatalf("snapshots: %+v %v", got, err)
	}
	if it, ok, err := st.FindItemByTemplate(ctx, "t2"); err != nil || !ok || it.Name != "B" {
		t.Fatalf("origin lookup: %+v %v %v", it, ok, err)
	}
	if _, ok, _ := st.FindItemByTemplate(ctx, "hub-native"); ok {
		t.Fatal("a template no batch made must not be found")
	}
}

// R-05 on the real store: restoring an update reactivates the superseded item,
// and FindItemByTemplate prefers it over the newer retired item.
func TestSQLStoreMarkItemRestoredReactivatesSuperseded(t *testing.T) {
	st := newSQLiteStore(t)
	ctx := context.Background()
	b1 := Batch{ID: "mb_1", Source: "s", Status: "applied", CreatedBy: "a", CreatedAt: "2026-10-18T10:00:00Z"}
	if err := st.SaveBatch(ctx, b1, []BatchItem{{BatchID: "mb_1", SourceKey: "k", TemplateID: "t1", Name: "A", ContentHash: "h1", CreatedAt: b1.CreatedAt}}); err != nil {
		t.Fatal(err)
	}
	b2 := Batch{ID: "mb_2", Source: "s", Status: "applied", CreatedBy: "a", CreatedAt: "2026-10-18T11:00:00Z"}
	if err := st.SaveBatch(ctx, b2, []BatchItem{{BatchID: "mb_2", SourceKey: "k", TemplateID: "t1", Name: "A", ContentHash: "h2", CreatedAt: b2.CreatedAt, PriorJSON: "{}", SupersedesBatchID: "mb_1"}}); err != nil {
		t.Fatal(err)
	}
	if _, items, _, _ := st.GetBatch(ctx, "mb_2"); items[0].SupersedesBatchID != "mb_1" {
		t.Fatalf("supersedes link not stored: %+v", items[0])
	}
	if err := st.MarkItemRestored(ctx, "mb_2", "k", "2026-10-18T12:00:00Z"); err != nil {
		t.Fatal(err)
	}
	it, ok, _ := st.FindActiveItem(ctx, "s", "k")
	if !ok || it.BatchID != "mb_1" {
		t.Fatalf("original item must be active again: %+v ok=%v", it, ok)
	}
	if o, _, _ := st.FindItemByTemplate(ctx, "t1"); o.BatchID != "mb_1" || o.DisabledAt != "" {
		t.Fatalf("the active item owns the template: %+v", o)
	}
}
