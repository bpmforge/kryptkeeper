// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package itsm

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeSource struct {
	mu     sync.Mutex
	owners map[string]CMDBOwner
	errFor map[string]bool
	calls  atomic.Int32
}

func (f *fakeSource) LookupOwner(_ context.Context, host string) (CMDBOwner, bool, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errFor[host] {
		return CMDBOwner{}, false, fmt.Errorf("%w: boom", ErrTemporary)
	}
	o, ok := f.owners[host]
	return o, ok, nil
}

type fakeWriter struct {
	mu     sync.Mutex
	hosts  []CertHost
	writes map[string]CMDBOwner
	fail   map[string]bool
}

func (w *fakeWriter) ListCertHosts(context.Context) ([]CertHost, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]CertHost(nil), w.hosts...), nil
}

func (w *fakeWriter) SetCMDBOwnership(_ context.Context, fp string, o CMDBOwner, svc string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fail[fp] {
		return errors.New("db down")
	}
	if w.writes == nil {
		w.writes = map[string]CMDBOwner{}
	}
	w.writes[fp] = o
	for i := range w.hosts { // later runs see the cmdb-sourced owner
		if w.hosts[i].Fingerprint == fp {
			w.hosts[i].OwnerTeam, w.hosts[i].OwnerEmail, w.hosts[i].OwnershipSource = o.OwnerTeam, o.OwnerEmail, "cmdb"
		}
	}
	return nil
}

type auditRow struct {
	action, id string
	ok         bool
	detail     string
}
type fakeAudit struct {
	mu   sync.Mutex
	rows []auditRow
}

func (a *fakeAudit) Record(_ context.Context, action, id string, ok bool, detail string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rows = append(a.rows, auditRow{action, id, ok, detail})
}

func seed(n int) (*fakeSource, *fakeWriter) {
	src := &fakeSource{owners: map[string]CMDBOwner{}, errFor: map[string]bool{}}
	w := &fakeWriter{}
	for i := 0; i < n; i++ {
		host := fmt.Sprintf("host%03d.example.com", i)
		w.hosts = append(w.hosts, CertHost{Fingerprint: fmt.Sprintf("fp%03d", i), Host: host, ServiceName: "svc"})
		src.owners[host] = CMDBOwner{OwnerEmail: fmt.Sprintf("o%d@example.com", i), OwnerTeam: "team"}
	}
	return src, w
}

func TestRunOnce_Populates100Of100(t *testing.T) {
	src, w := seed(100)
	a := &fakeAudit{}
	j := &CMDBSyncJob{Source: src, Writer: w, Audit: a}
	rep, err := j.RunOnce(context.Background())
	if err != nil || rep.Updated != 100 || rep.Errors != 0 || len(w.writes) != 100 || len(a.rows) != 100 {
		t.Fatalf("rep=%+v err=%v writes=%d audit=%d", rep, err, len(w.writes), len(a.rows))
	}
	for _, r := range a.rows {
		if r.action != "certificate.ownership_update" || !r.ok || !strings.Contains(r.detail, `"ownership_source":"cmdb"`) {
			t.Fatalf("bad audit row %+v", r)
		}
	}
}

func TestRunOnce_OwnerNotFoundLeavesUnchanged(t *testing.T) {
	src, w := seed(10)
	for i := 0; i < 3; i++ {
		delete(src.owners, fmt.Sprintf("host%03d.example.com", i))
	}
	a := &fakeAudit{}
	rep, err := (&CMDBSyncJob{Source: src, Writer: w, Audit: a}).RunOnce(context.Background())
	if err != nil || rep.Errors != 0 || len(rep.NotFound) != 3 || rep.Updated != 7 || len(w.writes) != 7 || len(a.rows) != 7 {
		t.Fatalf("rep=%+v err=%v", rep, err)
	}
	for i := 0; i < 3; i++ {
		if _, ok := w.writes[fmt.Sprintf("fp%03d", i)]; ok {
			t.Fatalf("unfound host %d written", i)
		}
	}
}

func TestRunOnce_NeverOverwritesManual(t *testing.T) {
	src, w := seed(0)
	add := func(fp, source, team string) {
		h := fp + ".example.com"
		w.hosts = append(w.hosts, CertHost{Fingerprint: fp, Host: h, OwnershipSource: source, OwnerTeam: team})
		src.owners[h] = CMDBOwner{OwnerTeam: "cmdb-team", OwnerEmail: "c@example.com"}
	}
	add("manual", "manual", "mine")
	add("legacy", "", "legacy-team")
	add("imported", "import", "imp")
	add("agent", "agent", "ag")
	add("prev", "cmdb", "old")
	add("unowned", "", "")
	rep, err := (&CMDBSyncJob{Source: src, Writer: w}).RunOnce(context.Background())
	if err != nil || rep.SkippedManual != 2 || rep.SkippedOther != 2 || rep.Updated != 2 {
		t.Fatalf("rep=%+v err=%v", rep, err)
	}
	if _, ok := w.writes["prev"]; !ok {
		t.Fatal("previous cmdb owner not refreshed")
	}
	if _, ok := w.writes["manual"]; ok {
		t.Fatal("manual overwritten")
	}
}

func TestRunOnce_IdempotentSecondRun(t *testing.T) {
	src, w := seed(5)
	a := &fakeAudit{}
	j := &CMDBSyncJob{Source: src, Writer: w, Audit: a}
	if _, err := j.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := len(a.rows)
	rep, _ := j.RunOnce(context.Background())
	if rep.Updated != 0 || rep.Unchanged != 5 || len(a.rows) != before {
		t.Fatalf("rep=%+v audit %d->%d", rep, before, len(a.rows))
	}
}

func TestRunOnce_LookupErrorContinues(t *testing.T) {
	src, w := seed(5)
	src.errFor["host002.example.com"] = true
	rep, err := (&CMDBSyncJob{Source: src, Writer: w}).RunOnce(context.Background())
	if err != nil || rep.Errors != 1 || rep.Updated != 4 {
		t.Fatalf("rep=%+v err=%v", rep, err)
	}
}

func TestRunOnce_WriteErrorAuditedAndContinues(t *testing.T) {
	src, w := seed(3)
	w.fail = map[string]bool{"fp001": true}
	a := &fakeAudit{}
	rep, _ := (&CMDBSyncJob{Source: src, Writer: w, Audit: a}).RunOnce(context.Background())
	if rep.Errors != 1 || rep.Updated != 2 || len(a.rows) != 3 {
		t.Fatalf("rep=%+v rows=%d", rep, len(a.rows))
	}
}

func TestRunOnce_HostLowercasedForLookup(t *testing.T) {
	src, w := seed(0)
	w.hosts = []CertHost{{Fingerprint: "fp", Host: "Web.Example.COM"}}
	src.owners["web.example.com"] = CMDBOwner{OwnerTeam: "t"}
	rep, _ := (&CMDBSyncJob{Source: src, Writer: w}).RunOnce(context.Background())
	if rep.Updated != 1 {
		t.Fatalf("rep=%+v", rep)
	}
}

func TestRunOnce_NoSourceSkips(t *testing.T) {
	_, w := seed(2)
	j := &CMDBSyncJob{SourceFn: func(context.Context) (CMDBSource, error) { return nil, nil }, Writer: w}
	rep, err := j.RunOnce(context.Background())
	if err != nil || rep.Updated != 0 || len(w.writes) != 0 {
		t.Fatalf("rep=%+v err=%v", rep, err)
	}
}

func TestStart_RunsImmediatelyThenTicks(t *testing.T) {
	src, w := seed(1)
	j := &CMDBSyncJob{Source: src, Writer: w, Interval: 10 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	j.Start(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for src.calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if src.calls.Load() < 2 {
		t.Fatalf("expected >=2 runs, lookups=%d", src.calls.Load())
	}
}
