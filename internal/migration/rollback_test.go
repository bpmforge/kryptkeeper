// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package migration

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func (m *memStore) MarkItemDisabled(_ context.Context, batchID, key, at string) error {
	m.writes++
	for i := range m.items[batchID] {
		if m.items[batchID][i].SourceKey == key {
			m.items[batchID][i].DisabledAt, m.items[batchID][i].KeepReason = at, ""
		}
	}
	return nil
}

func (m *memStore) MarkItemRestored(ctx context.Context, batchID, key, at string) error {
	var sup string
	for _, it := range m.items[batchID] {
		if it.SourceKey == key {
			sup = it.SupersedesBatchID
		}
	}
	if err := m.MarkItemDisabled(ctx, batchID, key, at); err != nil {
		return err
	}
	if sup == "" || m.batches[sup].Status != "applied" {
		return nil
	}
	for i := range m.items[sup] {
		if m.items[sup][i].SourceKey == key && m.items[sup][i].DisabledAt == m.batches[batchID].CreatedAt {
			m.items[sup][i].DisabledAt = ""
		}
	}
	return nil
}

func (m *memStore) MarkItemKept(_ context.Context, batchID, key, reason string) error {
	m.writes++
	for i := range m.items[batchID] {
		if m.items[batchID][i].SourceKey == key {
			m.items[batchID][i].KeepReason = reason
		}
	}
	return nil
}

func (m *memStore) MarkBatchRolledBack(_ context.Context, batchID, by, at string) error {
	m.writes++
	b := m.batches[batchID]
	b.Status, b.RolledBackBy, b.RolledBackAt = "rolled_back", by, at
	m.batches[batchID] = b
	return nil
}

func applyThree(t *testing.T) (*Service, *fakeSink, *memStore, Report) {
	t.Helper()
	svc, sink, store := newTestService()
	rep, err := svc.Apply(context.Background(), in(obj("k1", "A"), obj("k2", "B"), obj("k3", "C")), "alice")
	if err != nil || rep.Created != 3 {
		t.Fatalf("apply: %+v %v", rep, err)
	}
	return svc, sink, store, rep
}

func TestRollbackDisablesEveryTemplateOfBatch(t *testing.T) {
	svc, sink, store, rep := applyThree(t)
	res, err := svc.Rollback(context.Background(), rep.BatchID, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if res.Disabled != 3 || res.Kept != 0 || len(sink.disabled) != 3 || sink.deletes != 0 {
		t.Fatalf("result %+v disabled=%v deletes=%d", res, sink.disabled, sink.deletes)
	}
	want := map[string]bool{"tpl-1": true, "tpl-2": true, "tpl-3": true}
	for _, id := range sink.disabled {
		if !want[id] {
			t.Fatalf("disabled a template the batch did not create: %s", id)
		}
	}
	if res.Items[0].Name != "A" || res.Items[2].Name != "C" {
		t.Fatalf("items not sorted by name: %+v", res.Items)
	}
	b, items, _, _ := store.GetBatch(context.Background(), rep.BatchID)
	if b.Status != "rolled_back" || b.RolledBackBy != "bob" {
		t.Fatalf("batch: %+v", b)
	}
	for _, it := range items {
		if it.DisabledAt == "" {
			t.Fatalf("item not marked disabled: %+v", it)
		}
	}
	// Disabled items no longer block re-importing the same export.
	d, _ := svc.DryRun(context.Background(), in(obj("k1", "A")))
	if d.Entries[0].Action == ActionSkip {
		t.Fatalf("a rolled-back item must not count as imported: %+v", d.Entries[0])
	}
}

func TestRollbackKeepsTemplatesWithPendingApprovals(t *testing.T) {
	svc, sink, store, rep := applyThree(t)
	sink.pending["tpl-2"] = true
	res, err := svc.Rollback(context.Background(), rep.BatchID, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if res.Kept != 1 || res.Disabled != 2 {
		t.Fatalf("result: %+v", res)
	}
	for _, id := range sink.disabled {
		if id == "tpl-2" {
			t.Fatal("disabled a template with a pending approval")
		}
	}
	if res.Items[1].Outcome != OutcomeKept || res.Items[1].Reason != "pending approvals" {
		t.Fatalf("kept item: %+v", res.Items[1])
	}
	_, items, _, _ := store.GetBatch(context.Background(), rep.BatchID)
	for _, it := range items {
		if it.TemplateID == "tpl-2" && (it.KeepReason != "pending approvals" || it.DisabledAt != "") {
			t.Fatalf("kept item row: %+v", it)
		}
	}
	if b, _, _, _ := store.GetBatch(context.Background(), rep.BatchID); b.Status != "rolled_back" {
		t.Fatal("a batch with kept items is still rolled back")
	}
}

func TestRollbackTwiceIsNoOp(t *testing.T) {
	svc, sink, store, rep := applyThree(t)
	ctx := context.Background()
	if _, err := svc.Rollback(ctx, rep.BatchID, "bob"); err != nil {
		t.Fatal(err)
	}
	disabled, writes := len(sink.disabled), store.writes
	res, err := svc.Rollback(ctx, rep.BatchID, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if !res.AlreadyRolledBack || res.Disabled != 0 || res.Kept != 0 || len(res.Items) != 0 {
		t.Fatalf("second call: %+v", res)
	}
	if len(sink.disabled) != disabled || store.writes != writes {
		t.Fatalf("second call changed state: disabled %d->%d writes %d->%d", disabled, len(sink.disabled), writes, store.writes)
	}
}

func TestRollbackResumesAfterDisableError(t *testing.T) {
	svc, sink, store, rep := applyThree(t)
	ctx := context.Background()
	sink.disableErr["tpl-2"] = errors.New("boom")
	if _, err := svc.Rollback(ctx, rep.BatchID, "bob"); err == nil || !strings.Contains(err.Error(), `"B"`) {
		t.Fatalf("want error naming B, got %v", err)
	}
	if b, _, _, _ := store.GetBatch(ctx, rep.BatchID); b.Status != "applied" {
		t.Fatalf("failed rollback must leave the batch applied, got %s", b.Status)
	}
	delete(sink.disableErr, "tpl-2")
	res, err := svc.Rollback(ctx, rep.BatchID, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if res.Items[0].Outcome != OutcomeAlreadyDisabled || res.Disabled != 2 {
		t.Fatalf("resume: %+v", res)
	}
	count := map[string]int{}
	for _, id := range sink.disabled {
		count[id]++
	}
	if count["tpl-1"] != 1 || count["tpl-2"] != 1 || count["tpl-3"] != 1 {
		t.Fatalf("a template was disabled more than once: %v", count)
	}
}

func TestRollbackUnknownBatch(t *testing.T) {
	svc, _, _ := newTestService()
	if _, err := svc.Rollback(context.Background(), "mb_nope", "bob"); !errors.Is(err, ErrBatchNotFound) {
		t.Fatalf("got %v", err)
	}
}
