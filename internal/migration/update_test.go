// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package migration

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func (m *memStore) FindItemByTemplate(_ context.Context, templateID string) (BatchItem, bool, error) {
	var best BatchItem
	found := false
	for _, items := range m.items {
		for _, it := range items {
			if it.TemplateID == templateID && (!found || (it.DisabledAt == "") && best.DisabledAt != "" || (it.DisabledAt == "") == (best.DisabledAt == "") && it.BatchID > best.BatchID) {
				best, found = it, true
			}
		}
	}
	return best, found, nil
}

type tplState struct {
	Tmpl   Template
	Active bool
}

// updSink is a fakeSink that can also update, inspect, snapshot and restore.
type updSink struct {
	*fakeSink
	states  map[string]*tplState
	updates int
}

func newUpdSink() *updSink {
	return &updSink{fakeSink: newFakeSink(), states: map[string]*tplState{}}
}

func (u *updSink) Create(ctx context.Context, t Template) (string, error) {
	id, err := u.fakeSink.Create(ctx, t)
	if err == nil {
		u.states[id] = &tplState{Tmpl: t, Active: true}
	}
	return id, err
}

func (u *updSink) Disable(ctx context.Context, id string) error {
	if err := u.fakeSink.Disable(ctx, id); err != nil {
		return err
	}
	u.states[id].Active = false
	return nil
}

func (u *updSink) Update(_ context.Context, id string, t Template) error {
	u.updates++
	u.states[id] = &tplState{Tmpl: t, Active: true}
	return nil
}

func (u *updSink) Inspect(_ context.Context, id string) (TemplateState, bool, error) {
	st, ok := u.states[id]
	if !ok {
		return TemplateState{}, false, nil
	}
	return TemplateState{OID: st.Tmpl.OID, Active: st.Active}, true, nil
}

func (u *updSink) Snapshot(_ context.Context, id string) (string, error) {
	raw, err := json.Marshal(u.states[id])
	return string(raw), err
}

func (u *updSink) Restore(_ context.Context, id, snapshot string) error {
	var st tplState
	if err := json.Unmarshal([]byte(snapshot), &st); err != nil {
		return err
	}
	u.states[id] = &st
	return nil
}

func newUpdService() (*Service, *updSink, *memStore) {
	svc, _, store := newTestService()
	sink := newUpdSink()
	svc.sink = sink
	return svc, sink, store
}

func objDays(key, name string, days float64) map[string]any {
	return map[string]any{"key": key, "name": name, "days": days}
}

func TestUpdateNeverOverwritesHubNativeTemplate(t *testing.T) {
	svc, sink, _ := newUpdService()
	sink.byName["Web"] = "native-1"
	sink.states["native-1"] = &tplState{Tmpl: Template{Name: "Web", ValidityPeriod: "P1D"}, Active: true}
	ctx := context.Background()

	d, err := svc.DryRun(ctx, in(obj("k1", "Web")))
	if err != nil {
		t.Fatal(err)
	}
	e := d.Entries[0]
	if e.Action != ActionConflict || !strings.Contains(e.Reason, "not created by a migration") {
		t.Fatalf("hub-native name match must be a conflict: %+v", e)
	}
	rep, err := svc.Apply(ctx, in(obj("k1", "Web")), "alice")
	if err != nil || rep.Created+rep.Updated != 0 || sink.updates != 0 {
		t.Fatalf("apply touched a hub-native template: %+v err=%v updates=%d", rep, err, sink.updates)
	}
	if got := sink.states["native-1"]; got.Tmpl.ValidityPeriod != "P1D" || !got.Active {
		t.Fatalf("native template changed: %+v", got)
	}
}

func TestUpdateNeverReactivatesAdminDisabledTemplate(t *testing.T) {
	svc, sink, _ := newUpdService()
	ctx := context.Background()
	if _, err := svc.Apply(ctx, in(objDays("k1", "A", 10)), "alice"); err != nil {
		t.Fatal(err)
	}
	sink.states["tpl-1"].Active = false // an admin disables it; the batch item stays active

	d, err := svc.DryRun(ctx, in(objDays("k1", "A", 20)))
	if err != nil {
		t.Fatal(err)
	}
	if e := d.Entries[0]; e.Action != ActionConflict || !strings.Contains(e.Reason, "disabled by an administrator") {
		t.Fatalf("disabled template must conflict: %+v", e)
	}
	if rep, err := svc.Apply(ctx, in(objDays("k1", "A", 20)), "alice"); err != nil || rep.Updated != 0 || sink.updates != 0 {
		t.Fatalf("apply updated a disabled template: %+v err=%v", rep, err)
	}
	if sink.states["tpl-1"].Active {
		t.Fatal("template was reactivated")
	}
}

func TestUpdateReappliesToMigrationMadeTemplate(t *testing.T) {
	svc, sink, _ := newUpdService()
	ctx := context.Background()
	if _, err := svc.Apply(ctx, in(objDays("k1", "A", 10)), "alice"); err != nil {
		t.Fatal(err)
	}
	rep, err := svc.Apply(ctx, in(objDays("k1", "A", 20)), "alice")
	if err != nil || rep.Updated != 1 || sink.states["tpl-1"].Tmpl.ValidityPeriod != "P20D" {
		t.Fatalf("update: %+v err=%v state=%+v", rep, err, sink.states["tpl-1"])
	}
}

func TestRollbackOfUpdateRestoresPriorFields(t *testing.T) {
	svc, sink, store := newUpdService()
	ctx := context.Background()
	if _, err := svc.Apply(ctx, in(objDays("k1", "A", 10)), "alice"); err != nil {
		t.Fatal(err)
	}
	before, _ := sink.Snapshot(ctx, "tpl-1")
	rep, err := svc.Apply(ctx, in(objDays("k1", "A", 20)), "alice")
	if err != nil || rep.Updated != 1 {
		t.Fatalf("update: %+v %v", rep, err)
	}
	_, items, _, _ := store.GetBatch(ctx, rep.BatchID)
	if len(items) != 1 || items[0].PriorJSON != before {
		t.Fatalf("snapshot not recorded on the item: %+v", items)
	}

	res, err := svc.Rollback(ctx, rep.BatchID, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if res.Restored != 1 || res.Disabled != 0 || res.Items[0].Outcome != OutcomeRestored || len(sink.disabled) != 0 {
		t.Fatalf("rollback must restore, not disable: %+v disabled=%v", res, sink.disabled)
	}
	if after, _ := sink.Snapshot(ctx, "tpl-1"); after != before {
		t.Fatalf("template not restored exactly:\nbefore %s\nafter  %s", before, after)
	}
	if !sink.states["tpl-1"].Active {
		t.Fatal("restored template should be active as before")
	}
}

func objOID(key, name, oid string, days float64) map[string]any {
	o := objDays(key, name, days)
	o["oid"] = oid
	return o
}

func TestUpdateOfRolledBackTemplateNeedsMigrationOrigin(t *testing.T) {
	svc, sink, _ := newUpdService()
	ctx := context.Background()
	rep, err := svc.Apply(ctx, in(objOID("k1", "A", "1.2.3.4", 10)), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Rollback(ctx, rep.BatchID, "bob"); err != nil {
		t.Fatal(err)
	}
	if sink.states["tpl-1"].Active {
		t.Fatal("rollback of a create must disable")
	}
	d, err := svc.DryRun(ctx, in(objOID("k1", "A", "1.2.3.4", 10)))
	if err != nil {
		t.Fatal(err)
	}
	if e := d.Entries[0]; e.Action != ActionUpdate || e.Reason == "" || !strings.Contains(e.Reason, "name and OID") {
		t.Fatalf("rolled-back migration template is updated and reactivated: %+v", e)
	}
}

// Rescan R-01: a name match with no OID on either side is not proof of the
// same template (vault/keyfactor/venafi exports carry none), so it must not
// overwrite another source's migrated template.
func TestNameMatchWithoutOIDIsAConflict(t *testing.T) {
	svc, sink, _ := newUpdService()
	ctx := context.Background()
	rep, err := svc.Apply(ctx, in(objDays("vault:web", "web", 10)), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Rollback(ctx, rep.BatchID, "bob"); err != nil {
		t.Fatal(err)
	}
	d, err := svc.DryRun(ctx, in(objDays("keyfactor:7", "web", 20)))
	if err != nil {
		t.Fatal(err)
	}
	if e := d.Entries[0]; e.Action != ActionConflict {
		t.Fatalf("OID-less name match must conflict: %+v", e)
	}
	if rep, err := svc.Apply(ctx, in(objDays("keyfactor:7", "web", 20)), "alice"); err != nil || rep.Updated != 0 || sink.updates != 0 {
		t.Fatalf("apply overwrote by name alone: %+v err=%v", rep, err)
	}
	if sink.states["tpl-1"].Active || sink.states["tpl-1"].Tmpl.ValidityPeriod != "P10D" {
		t.Fatalf("template changed: %+v", sink.states["tpl-1"])
	}
}

// Rescan R-01: an admin-disabled template whose batch item is still active
// must not be reactivated through the name+OID path when the export names it
// under a different source key.
func TestNameMatchNeverReactivatesTemplateOwnedUnderAnotherKey(t *testing.T) {
	svc, sink, store := newUpdService()
	ctx := context.Background()
	if _, err := svc.Apply(ctx, in(objOID("CN=A,old", "A", "1.2.3.4", 10)), "alice"); err != nil {
		t.Fatal(err)
	}
	sink.states["tpl-1"].Active = false // an admin disables it; the batch item stays active

	d, err := svc.DryRun(ctx, in(objOID("CN=A,new", "A", "1.2.3.4", 20)))
	if err != nil {
		t.Fatal(err)
	}
	if e := d.Entries[0]; e.Action != ActionConflict || !strings.Contains(e.Reason, "another source key") {
		t.Fatalf("template owned under another key must conflict: %+v", e)
	}
	if rep, err := svc.Apply(ctx, in(objOID("CN=A,new", "A", "1.2.3.4", 20)), "alice"); err != nil || rep.Updated != 0 || sink.updates != 0 {
		t.Fatalf("apply updated an owned, disabled template: %+v err=%v", rep, err)
	}
	if sink.states["tpl-1"].Active {
		t.Fatal("admin-disabled template was reactivated")
	}
	if n := len(activeItems(store, "CN=A,old")) + len(activeItems(store, "CN=A,new")); n != 1 {
		t.Fatalf("want one active item for the template, got %d", n)
	}
}

func activeItems(store *memStore, key string) []BatchItem {
	var out []BatchItem
	for _, items := range store.items {
		for _, it := range items {
			if it.SourceKey == key && it.DisabledAt == "" {
				out = append(out, it)
			}
		}
	}
	return out
}

// H-F6: the superseded item is retired with the new batch, never before or
// after it, so one template never has two active items (or none).
func TestApplyUpdateRetiresSupersededItemWithTheBatch(t *testing.T) {
	svc, _, store := newUpdService()
	ctx := context.Background()
	first, err := svc.Apply(ctx, in(objDays("k1", "A", 10)), "alice")
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Apply(ctx, in(objDays("k1", "A", 20)), "alice")
	if err != nil || second.Updated != 1 {
		t.Fatalf("update: %+v %v", second, err)
	}
	if act := activeItems(store, "k1"); len(act) != 1 || act[0].BatchID != second.BatchID {
		t.Fatalf("want exactly the new item active, got %+v", act)
	}
	if _, old, _, _ := store.GetBatch(ctx, first.BatchID); old[0].DisabledAt == "" {
		t.Fatal("superseded item was not retired")
	}
}

func TestApplyUpdateSaveFailureLeavesOldItemActive(t *testing.T) {
	svc, _, store := newUpdService()
	ctx := context.Background()
	first, err := svc.Apply(ctx, in(objDays("k1", "A", 10)), "alice")
	if err != nil {
		t.Fatal(err)
	}
	store.saveErr = errors.New("db down")
	if _, err := svc.Apply(ctx, in(objDays("k1", "A", 20)), "alice"); err == nil || !strings.Contains(err.Error(), "db down") {
		t.Fatalf("want the save error, got %v", err)
	}
	if act := activeItems(store, "k1"); len(act) != 1 || act[0].BatchID != first.BatchID {
		t.Fatalf("a failed save must leave the old item as the only active one: %+v", act)
	}
}

// Rescan R-05: rolling back an update restores the template and gives the
// superseded item back, so a batch owns the template again and a later admin
// disable is respected by a re-import.
func TestRollbackOfUpdateReactivatesSupersededItem(t *testing.T) {
	svc, sink, store := newUpdService()
	ctx := context.Background()
	first, err := svc.Apply(ctx, in(objDays("k1", "A", 10)), "alice")
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Apply(ctx, in(objDays("k1", "A", 20)), "alice")
	if err != nil || second.Updated != 1 {
		t.Fatalf("update: %+v %v", second, err)
	}
	if _, err := svc.Rollback(ctx, second.BatchID, "bob"); err != nil {
		t.Fatal(err)
	}
	act := activeItems(store, "k1")
	if len(act) != 1 || act[0].BatchID != first.BatchID {
		t.Fatalf("the original item must be active again: %+v", act)
	}
	if !sink.states["tpl-1"].Active || sink.states["tpl-1"].Tmpl.ValidityPeriod != "P10D" {
		t.Fatalf("template not restored: %+v", sink.states["tpl-1"])
	}
	if owner, ok, _ := store.FindItemByTemplate(ctx, "tpl-1"); !ok || owner.DisabledAt != "" {
		t.Fatalf("an active batch item must own the template: %+v", owner)
	}

	sink.states["tpl-1"].Active = false // an admin disables it
	d, err := svc.DryRun(ctx, in(objDays("k1", "A", 30)))
	if err != nil {
		t.Fatal(err)
	}
	if e := d.Entries[0]; e.Action != ActionConflict || !strings.Contains(e.Reason, "disabled by an administrator") {
		t.Fatalf("admin-disabled template must conflict on re-import: %+v", e)
	}
}

// A superseded item whose own batch was rolled back stays retired.
func TestRollbackOfUpdateKeepsRolledBackBatchItemRetired(t *testing.T) {
	svc, _, store := newUpdService()
	ctx := context.Background()
	first, _ := svc.Apply(ctx, in(objDays("k1", "A", 10)), "alice")
	second, err := svc.Apply(ctx, in(objDays("k1", "A", 20)), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Rollback(ctx, first.BatchID, "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Rollback(ctx, second.BatchID, "bob"); err != nil {
		t.Fatal(err)
	}
	if act := activeItems(store, "k1"); len(act) != 0 {
		t.Fatalf("item of a rolled-back batch must stay retired: %+v", act)
	}
}
