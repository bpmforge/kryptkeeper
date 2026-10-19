// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package migration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

// fakeImporter parses a JSON array of {"key","name","days","bad"} objects.
type fakeImporter struct{}

func (fakeImporter) Source() string { return "fake" }

func (fakeImporter) Parse(_ context.Context, in Input) ([]SourceObject, error) {
	var raw []map[string]any
	if err := json.Unmarshal(in.Content, &raw); err != nil {
		return nil, err
	}
	out := make([]SourceObject, 0, len(raw))
	for _, r := range raw {
		out = append(out, SourceObject{Kind: "template", SourceKey: fmt.Sprint(r["key"]), Name: fmt.Sprint(r["name"]), Raw: r})
	}
	return out, nil
}

func (fakeImporter) Map(o SourceObject) (Mapped, error) {
	if o.Raw["bad"] == true {
		return Mapped{Unsupported: "uses an unsupported enrollment flow"}, nil
	}
	days, _ := o.Raw["days"].(float64)
	t := Template{Name: o.Name, DisplayName: o.Name, KeyUsage: []string{"digitalSignature"},
		ExtendedKeyUsage: []string{"serverAuth"}, AllowedAlgorithms: []string{"RSA"},
		ValidityPeriod: ValidityFromDuration(time.Duration(days) * 24 * time.Hour), OwnerHint: "team-a"}
	t.OID, _ = o.Raw["oid"].(string)
	if o.Raw["incomplete"] == true {
		t.AllowedAlgorithms = nil
	}
	return Mapped{Template: t, Fields: []FieldReport{
		{Field: "validity", Status: FieldMapped, Target: "validity_period"},
		{Field: "owner", Status: FieldPartial, Target: "owner_hint", Note: "no template home"},
		{Field: "archive", Status: FieldUnmapped},
	}}, nil
}

type fakeSink struct {
	byName     map[string]string
	creates    int
	deletes    int
	failOn     string
	pending    map[string]bool
	disabled   []string
	disableErr map[string]error
	seq        int
}

func newFakeSink() *fakeSink {
	return &fakeSink{byName: map[string]string{}, pending: map[string]bool{}, disableErr: map[string]error{}}
}

func (f *fakeSink) FindByName(_ context.Context, n string) (string, bool, error) {
	id, ok := f.byName[n]
	return id, ok, nil
}

func (f *fakeSink) Create(_ context.Context, t Template) (string, error) {
	if t.Name == f.failOn {
		return "", errors.New("boom")
	}
	f.seq++
	id := fmt.Sprintf("tpl-%d", f.seq)
	f.byName[t.Name] = id
	f.creates++
	return id, nil
}

func (f *fakeSink) Disable(_ context.Context, id string) error {
	if err := f.disableErr[id]; err != nil {
		return err
	}
	f.disabled = append(f.disabled, id)
	return nil
}

func (f *fakeSink) HasPendingApprovals(_ context.Context, id string) (bool, error) {
	return f.pending[id], nil
}

type memStore struct {
	batches map[string]Batch
	items   map[string][]BatchItem
	writes  int
	saveErr error
}

func newMemStore() *memStore {
	return &memStore{batches: map[string]Batch{}, items: map[string][]BatchItem{}}
}

func (m *memStore) EnsureSchema(context.Context) error { return nil }

func (m *memStore) SaveBatch(_ context.Context, b Batch, items []BatchItem) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.writes++
	m.batches[b.ID] = b
	m.items[b.ID] = append([]BatchItem(nil), items...)
	for _, it := range items {
		if it.SupersedesBatchID == "" {
			continue
		}
		old := m.items[it.SupersedesBatchID]
		for i := range old {
			if old[i].SourceKey == it.SourceKey && old[i].DisabledAt == "" {
				old[i].DisabledAt, old[i].KeepReason = b.CreatedAt, ""
			}
		}
	}
	return nil
}

func (m *memStore) FindActiveItem(_ context.Context, source, key string) (BatchItem, bool, error) {
	for id, items := range m.items {
		if m.batches[id].Source != source {
			continue
		}
		for _, it := range items {
			if it.SourceKey == key && it.DisabledAt == "" {
				return it, true, nil
			}
		}
	}
	return BatchItem{}, false, nil
}

func (m *memStore) GetBatch(_ context.Context, id string) (Batch, []BatchItem, bool, error) {
	b, ok := m.batches[id]
	return b, append([]BatchItem(nil), m.items[id]...), ok, nil
}

func (m *memStore) ListBatches(context.Context, int) ([]Batch, error) {
	out := []Batch{}
	for _, b := range m.batches {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func newTestService() (*Service, *fakeSink, *memStore) {
	sink, store := newFakeSink(), newMemStore()
	svc := NewService(sink, store, fakeImporter{})
	n := 0
	svc.newID = func() string { n++; return fmt.Sprintf("mb_%016d", n) }
	svc.now = func() time.Time { return time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC) }
	return svc, sink, store
}

func in(objs ...map[string]any) Input {
	raw, _ := json.Marshal(objs)
	return Input{Source: "fake", Content: raw}
}

func obj(key, name string) map[string]any {
	return map[string]any{"key": key, "name": name, "days": 30.0}
}

func TestDryRunWritesNothing(t *testing.T) {
	svc, sink, store := newTestService()
	if _, err := svc.DryRun(context.Background(), in(obj("k1", "A"), obj("k2", "B"))); err != nil {
		t.Fatal(err)
	}
	if sink.creates != 0 || store.writes != 0 {
		t.Fatalf("dry-run wrote: creates=%d saves=%d", sink.creates, store.writes)
	}
}

func TestDryRunByteIdentical(t *testing.T) {
	svc, _, _ := newTestService()
	input := in(obj("k2", "B"), obj("k1", "A"), obj("k3", "C"))
	d1, err := svc.DryRun(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	d2, _ := svc.DryRun(context.Background(), input)
	j1, _ := json.Marshal(d1)
	j2, _ := json.Marshal(d2)
	if string(j1) != string(j2) {
		t.Fatalf("dry-runs differ:\n%s\n%s", j1, j2)
	}
	names := []string{}
	for _, e := range d1.Entries {
		names = append(names, e.Name)
	}
	if strings.Join(names, ",") != "A,B,C" {
		t.Fatalf("entries not sorted: %v", names)
	}
	for _, k := range []string{`"create":3`, `"skip":0`, `"conflict":0`} {
		if !strings.Contains(string(j1), k) {
			t.Fatalf("counts missing %s in %s", k, j1)
		}
	}
	for _, e := range d1.Entries {
		for i := 1; i < len(e.Fields); i++ {
			if e.Fields[i-1].Field > e.Fields[i].Field {
				t.Fatalf("fields not sorted: %+v", e.Fields)
			}
		}
	}
}

func TestClassifyCreateSkipConflict(t *testing.T) {
	svc, sink, _ := newTestService()
	ctx := context.Background()
	sink.byName["Existing"] = "tpl-x"
	d, err := svc.DryRun(ctx, in(obj("k1", "A"), obj("k2", "Existing")))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Action{}
	for _, e := range d.Entries {
		got[e.Name] = e.Action
	}
	if got["A"] != ActionCreate || got["Existing"] != ActionConflict {
		t.Fatalf("classification: %v", got)
	}
	if _, err := svc.Apply(ctx, in(obj("k1", "A")), "alice"); err != nil {
		t.Fatal(err)
	}
	d, _ = svc.DryRun(ctx, in(obj("k1", "A")))
	if d.Entries[0].Action != ActionSkip || !strings.Contains(d.Entries[0].Reason, "already imported in batch mb_") {
		t.Fatalf("same hash must skip: %+v", d.Entries[0])
	}
	changed := obj("k1", "A")
	changed["days"] = 99.0
	d, _ = svc.DryRun(ctx, in(changed))
	if d.Entries[0].Action != ActionConflict || !strings.Contains(d.Entries[0].Reason, "source changed since batch") {
		t.Fatalf("changed hash must conflict: %+v", d.Entries[0])
	}
}

func TestDuplicateNameInExportConflicts(t *testing.T) {
	svc, _, _ := newTestService()
	d, err := svc.DryRun(context.Background(), in(obj("k2", "Same"), obj("k1", "Same")))
	if err != nil {
		t.Fatal(err)
	}
	if d.Entries[0].SourceKey != "k1" || d.Entries[0].Action != ActionCreate {
		t.Fatalf("first in sort order must win: %+v", d.Entries)
	}
	if d.Entries[1].Action != ActionConflict || d.Entries[1].Reason != "duplicate name in export" {
		t.Fatalf("second must conflict: %+v", d.Entries[1])
	}
}

func TestApplyTwiceCreatesZero(t *testing.T) {
	svc, sink, store := newTestService()
	ctx := context.Background()
	input := in(obj("k1", "A"), obj("k2", "B"))
	r1, err := svc.Apply(ctx, input, "alice")
	if err != nil || r1.Created != 2 || r1.BatchID == "" {
		t.Fatalf("first apply: %+v %v", r1, err)
	}
	r2, err := svc.Apply(ctx, input, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if r2.Created != 0 || r2.BatchID != "" || sink.creates != 2 || store.writes != 1 {
		t.Fatalf("rerun must create nothing: %+v creates=%d saves=%d", r2, sink.creates, store.writes)
	}
	b, items, ok, _ := store.GetBatch(ctx, r1.BatchID)
	if !ok || b.CreatedBy != "alice" || len(items) != 2 || items[0].OwnerHint != "team-a" {
		t.Fatalf("batch not recorded: %+v %+v", b, items)
	}
}

func TestApplyPartialFailureStillRecordsBatch(t *testing.T) {
	svc, sink, store := newTestService()
	sink.failOn = "B"
	rep, err := svc.Apply(context.Background(), in(obj("k1", "A"), obj("k2", "B"), obj("k3", "C")), "alice")
	if err == nil || !strings.Contains(err.Error(), `"B"`) {
		t.Fatalf("want error naming B, got %v", err)
	}
	if rep.Created != 1 || rep.BatchID == "" || store.writes != 1 || sink.creates != 1 {
		t.Fatalf("created so far must be recorded and later items not attempted: %+v creates=%d", rep, sink.creates)
	}
}

func TestReportListsFieldStatuses(t *testing.T) {
	svc, _, _ := newTestService()
	ctx := context.Background()
	rep, err := svc.Apply(ctx, in(obj("k1", "A")), "alice")
	if err != nil {
		t.Fatal(err)
	}
	_, stored, ok, err := svc.Report(ctx, rep.BatchID)
	if err != nil || !ok {
		t.Fatalf("report: %v %v", ok, err)
	}
	seen := map[FieldStatus]bool{}
	for _, f := range stored.Entries[0].Fields {
		seen[f.Status] = true
	}
	if !seen[FieldMapped] || !seen[FieldPartial] || !seen[FieldUnmapped] || stored.Entries[0].TemplateID == "" {
		t.Fatalf("report must list mapped, partial and unmapped per object: %+v", stored.Entries[0])
	}
	d, _ := svc.DryRun(ctx, in(obj("k9", "Z")))
	if d.Unmapped != 1 {
		t.Fatalf("Unmapped count: %d", d.Unmapped)
	}
}

func TestUnsupportedNeverCreated(t *testing.T) {
	svc, sink, _ := newTestService()
	bad := obj("k1", "Bad")
	bad["bad"] = true
	incomplete := obj("k2", "Inc")
	incomplete["incomplete"] = true
	rep, err := svc.Apply(context.Background(), in(bad, incomplete), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if sink.creates != 0 || rep.Created != 0 || rep.BatchID != "" {
		t.Fatalf("unsupported objects were created: %+v", rep)
	}
	d, _ := svc.DryRun(context.Background(), in(bad, incomplete))
	if d.Unsupported != 2 || d.Counts[ActionSkip] != 2 {
		t.Fatalf("counts: %+v", d)
	}
	for _, e := range d.Entries {
		if e.Action != ActionSkip || !strings.HasPrefix(e.Reason, "unsupported: ") {
			t.Fatalf("entry: %+v", e)
		}
	}
	if !strings.Contains(d.Entries[1].Reason, "incomplete mapping: missing allowed_algorithms") {
		t.Fatalf("incomplete reason: %q", d.Entries[0].Reason)
	}
}

func TestServiceErrors(t *testing.T) {
	svc, _, _ := newTestService()
	ctx := context.Background()
	if _, err := svc.DryRun(ctx, Input{Source: "nope"}); !errors.Is(err, ErrUnknownSource) {
		t.Fatalf("unknown source: %v", err)
	}
	if _, err := svc.DryRun(ctx, Input{Source: "fake", Content: []byte("[]")}); !errors.Is(err, ErrNoObjects) {
		t.Fatalf("empty: %v", err)
	}
	if _, err := svc.DryRun(ctx, Input{Source: "fake", Content: make([]byte, MaxInputBytes+1)}); !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("too large: %v", err)
	}
	if got := svc.Sources(); len(got) != 1 || got[0] != "fake" {
		t.Fatalf("sources: %v", got)
	}
}

func TestPercentMapped(t *testing.T) {
	f := []FieldReport{
		{Field: "a", Status: FieldMapped}, {Field: "b", Status: FieldPartial},
		{Field: "c", Status: FieldUnmapped}, {Field: "d", Status: FieldUnmapped},
		{Field: "(default ekus)", Status: FieldMapped},
	}
	if got := PercentMapped(f); got != 50 {
		t.Fatalf("got %d, want 50", got)
	}
	if PercentMapped(nil) != 100 || PercentMapped([]FieldReport{{Field: "(x)", Status: FieldUnmapped}}) != 100 {
		t.Fatal("no countable fields must be 100")
	}
}

func TestHelpers(t *testing.T) {
	if n, ok := EKUFromOID("1.3.6.1.5.5.7.3.9"); !ok || n != "OCSPSigning" {
		t.Fatal("oid")
	}
	if _, ok := EKUFromOID("1.2.3"); ok {
		t.Fatal("unknown oid accepted")
	}
	for _, s := range []string{"ServerAuth", "server_auth", "serverAuth"} {
		if n, ok := EKUFromName(s); !ok || n != "serverAuth" {
			t.Fatalf("name %q -> %q %v", s, n, ok)
		}
	}
	if ValidityFromDuration(0) != "P1D" || ValidityFromDuration(25*time.Hour) != "P2D" || ValidityFromDuration(48*time.Hour) != "P2D" {
		t.Fatal("validity rounding")
	}
}

// B2: a source template with no key size gets the floor with a "set" note,
// one below the floor a "raised from N" note, and a non-RSA one nothing.
func TestRaiseToFloorWording(t *testing.T) {
	floor := KeyFloor{RSABits: 3072, Policy: "Baseline"}
	for _, tc := range []struct {
		tmpl     Template
		wantBits int
		wantNote string
	}{
		{Template{AllowedAlgorithms: []string{"RSA"}}, 3072, `key size set to 3072 to meet policy "Baseline"`},
		{Template{AllowedAlgorithms: []string{"RSA"}, MinKeySize: 2048}, 3072, `key size raised from 2048 to 3072 to meet policy "Baseline"`},
		{Template{AllowedAlgorithms: []string{"RSA"}, MinKeySize: 4096}, 4096, ""},
		{Template{AllowedAlgorithms: []string{"ECDSA"}, MinKeySize: 256}, 256, ""},
	} {
		tmpl := tc.tmpl
		if note := raiseToFloor(&tmpl, floor); note != tc.wantNote || tmpl.MinKeySize != tc.wantBits {
			t.Errorf("%+v: note %q bits %d, want %q %d", tc.tmpl, note, tmpl.MinKeySize, tc.wantNote, tc.wantBits)
		}
	}
}
