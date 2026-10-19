// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ctmonitor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/notifications/delivery"
)

// W6-06: a CT entry not in inventory raises exactly one finding, and
// findings feed the W4-01 delivery channels.

type fakeSource struct{ entries []CTEntry }

func (f *fakeSource) Name() string { return "crtsh" }
func (f *fakeSource) Search(context.Context, string) ([]CTEntry, error) {
	return f.entries, nil
}

type fakeInventory struct{ known map[string]bool }

func (f *fakeInventory) HasSerial(_ context.Context, serial string) (bool, error) {
	return f.known[serial], nil
}

type recordingChannel struct{ events []delivery.Event }

func (r *recordingChannel) Name() string { return "slack" }
func (r *recordingChannel) Send(_ context.Context, ev delivery.Event) error {
	r.events = append(r.events, ev)
	return nil
}

func liveEntry(id, serial string) CTEntry {
	return CTEntry{
		EntryID: id, CommonName: "svc.example.com",
		DNSNames: []string{"svc.example.com"},
		Issuer:   "C=XX, O=Some CA", Serial: serial,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
	}
}

func TestScanRaisesFindingForUnknownCertOnly(t *testing.T) {
	store := newTestStore(t)
	source := &fakeSource{entries: []CTEntry{
		liveEntry("100", "known-serial"),
		liveEntry("101", "rogue-serial"),
	}}
	inventory := &fakeInventory{known: map[string]bool{"known-serial": true}}
	channel := &recordingChannel{}
	m, err := NewMonitor(source, inventory, store, &ChannelNotifier{Channel: channel, Target: "#security"}, []string{"example.com"})
	if err != nil {
		t.Fatalf("monitor: %v", err)
	}

	report, err := m.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.NewFindings) != 1 || report.NewFindings[0] != "crtsh:101" {
		t.Fatalf("expected exactly the rogue entry, got %v (errors %v)", report.NewFindings, report.Errors)
	}
	open, _ := store.List(context.Background(), "open")
	if len(open) != 1 || open[0].Serial != "rogue-serial" {
		t.Fatalf("finding not persisted correctly: %+v", open)
	}

	// The W4-01 channel received one high-priority event with the
	// identity in the message.
	if len(channel.events) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(channel.events))
	}
	ev := channel.events[0]
	if ev.Priority != "high" || ev.Target != "#security" {
		t.Fatalf("alert misrouted: %+v", ev)
	}
	if !strings.Contains(ev.Message, "rogue-serial") || !strings.Contains(ev.Message, "NOT in the Kryptkeeper inventory") {
		t.Fatalf("alert message must carry the identity: %s", ev.Message)
	}

	// Re-scan: nothing new, nothing re-alerted.
	report, err = m.Scan(context.Background())
	if err != nil {
		t.Fatalf("rescan: %v", err)
	}
	if len(report.NewFindings) != 0 || len(channel.events) != 1 {
		t.Fatalf("re-scan must raise nothing new: %v / %d alerts", report.NewFindings, len(channel.events))
	}
}

func TestScanSkipsExpiredEntries(t *testing.T) {
	store := newTestStore(t)
	expired := liveEntry("200", "expired-serial")
	expired.NotAfter = time.Now().Add(-24 * time.Hour)
	m, _ := NewMonitor(&fakeSource{entries: []CTEntry{expired}},
		&fakeInventory{known: map[string]bool{}}, store, nil, []string{"example.com"})

	report, err := m.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.NewFindings) != 0 {
		t.Fatalf("expired entries must not raise findings: %v", report.NewFindings)
	}
}

func TestCrtShSourceParsesResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("output") != "json" || !strings.Contains(r.URL.Query().Get("q"), "example.com") {
			t.Errorf("unexpected query: %s", r.URL.String())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"id": 42, "issuer_name": "C=US, O=Public CA", "common_name": "shadow.example.com",
			 "name_value": "shadow.example.com\nalt.example.com",
			 "serial_number": "0ABCDEF", "not_before": "2026-01-01T00:00:00", "not_after": "2027-01-01T00:00:00"}
		]`))
	}))
	defer srv.Close()

	source := NewCrtShSource(srv.URL)
	entries, err := source.Search(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.EntryID != "42" || e.CommonName != "shadow.example.com" || e.Serial != "0abcdef" {
		t.Fatalf("parse wrong: %+v", e)
	}
	if len(e.DNSNames) != 2 || e.DNSNames[1] != "alt.example.com" {
		t.Fatalf("SANs parse wrong: %v", e.DNSNames)
	}
	if e.NotAfter.Year() != 2027 {
		t.Fatalf("validity parse wrong: %v", e.NotAfter)
	}
}

func TestNotifyFailureIsReportedNotFatal(t *testing.T) {
	store := newTestStore(t)
	m, _ := NewMonitor(&fakeSource{entries: []CTEntry{liveEntry("300", "s1")}},
		&fakeInventory{known: map[string]bool{}}, store,
		&failingNotifier{}, []string{"example.com"})

	report, err := m.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan must survive a broken channel: %v", err)
	}
	if len(report.NewFindings) != 1 {
		t.Fatalf("finding must persist despite notify failure: %v", report.NewFindings)
	}
	if report.Errors["notify:crtsh:300"] == "" {
		t.Fatalf("notify failure must be reported, got %v", report.Errors)
	}
}

type failingNotifier struct{}

func (failingNotifier) NotifyFinding(context.Context, Finding) error {
	return context.DeadlineExceeded
}

// --- W24-20 ---

// sharedLock models ha_scheduler_locks: the first caller wins the lease, the
// same holder renews, another holder wins only after the lease lapsed.
type sharedLock struct {
	holder  string
	expires time.Time
	now     *time.Time
}

type replicaLock struct {
	shared *sharedLock
	id     string
	err    error
}

func (r *replicaLock) TryAcquire(_ context.Context, name string, lease time.Duration) (bool, error) {
	if r.err != nil {
		return false, r.err
	}
	s := r.shared
	if s.holder == "" || s.holder == r.id || s.expires.Before(*s.now) {
		s.holder, s.expires = r.id, s.now.Add(lease)
		return true, nil
	}
	return false, nil
}

type countingSource struct {
	name    string
	entries []CTEntry
	err     error
	calls   map[string]int
}

func (c *countingSource) Name() string { return c.name }
func (c *countingSource) Search(_ context.Context, domain string) ([]CTEntry, error) {
	if c.calls == nil {
		c.calls = map[string]int{}
	}
	c.calls[domain]++
	return c.entries, c.err
}

func TestTwoReplicasPollOncePerInterval(t *testing.T) {
	clock := time.Now()
	shared := &sharedLock{now: &clock}
	src := &countingSource{name: "crtsh"}
	inv := &fakeInventory{}
	mk := func(id string) *Monitor {
		m, err := NewMonitor(src, inv, newTestStore(t), nil, []string{"example.com"})
		if err != nil {
			t.Fatal(err)
		}
		m.SetLeaderLock(&replicaLock{shared: shared, id: id})
		return m
	}
	a, b := mk("a"), mk("b")
	interval := time.Hour
	a.tick(context.Background(), interval)
	b.tick(context.Background(), interval)
	if src.calls["example.com"] != 1 {
		t.Fatalf("two replicas polled %d times, want 1", src.calls["example.com"])
	}
	// Next interval: the holder renews, the other replica still loses.
	clock = clock.Add(interval)
	b.tick(context.Background(), interval)
	a.tick(context.Background(), interval)
	if src.calls["example.com"] != 2 {
		t.Fatalf("after interval 2 polls expected, got %d", src.calls["example.com"])
	}
	// The leader dies: once the 2*interval lease lapses, b takes over.
	clock = clock.Add(3 * interval)
	b.tick(context.Background(), interval)
	if src.calls["example.com"] != 3 || shared.holder != "b" {
		t.Fatalf("failover failed: calls=%d holder=%s", src.calls["example.com"], shared.holder)
	}
}

func TestLockErrorFailsClosed(t *testing.T) {
	clock := time.Now()
	src := &countingSource{name: "crtsh"}
	m, _ := NewMonitor(src, &fakeInventory{}, newTestStore(t), nil, []string{"example.com"})
	m.SetLeaderLock(&replicaLock{shared: &sharedLock{now: &clock}, id: "a", err: errors.New("db down")})
	m.tick(context.Background(), time.Hour)
	if len(src.calls) != 0 {
		t.Fatalf("scanned despite lock error: %v", src.calls)
	}
}

func TestDomainsFromProviderApplyWithoutRestart(t *testing.T) {
	src := &countingSource{name: "crtsh"}
	m, _ := NewMonitor(src, &fakeInventory{}, newTestStore(t), nil, nil)
	domains := []string{"a.com"}
	m.SetDomainProvider(func(context.Context) []string { return domains })
	if _, err := m.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if src.calls["b.com"] != 0 {
		t.Fatal("b.com queried before configured")
	}
	domains = []string{"a.com", "b.com"}
	if _, err := m.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if src.calls["b.com"] != 1 || src.calls["a.com"] != 2 {
		t.Fatalf("provider change not applied: %v", src.calls)
	}
}

func TestParseDomainList(t *testing.T) {
	got := ParseDomainList(" Example.com,,b.org , example.com,B.ORG ")
	if len(got) != 2 || got[0] != "example.com" || got[1] != "b.org" {
		t.Fatalf("got %v", got)
	}
	if len(ParseDomainList("")) != 0 {
		t.Fatal("empty csv must yield no domains")
	}
}

func TestCrtshFailsSecondSourceStillReports(t *testing.T) {
	crt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer crt.Close()
	der := testCertDER(t, 0x77, "rogue.example.com", "rogue.example.com")
	cs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("after") != "" {
			_, _ = w.Write([]byte("[]"))
			return
		}
		_ = json.NewEncoder(w).Encode([]any{issuance("9", der, "rogue.example.com")})
	}))
	defer cs.Close()

	store := newTestStore(t)
	m, _ := NewMonitor(NewCrtShSource(crt.URL), &fakeInventory{}, store, nil, []string{"example.com"})
	m.AddSource(NewCertSpotterSource(cs.URL, ""))
	report, err := m.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Errors["example.com@crtsh"] == "" {
		t.Fatalf("crt.sh failure not recorded per domain+source: %v", report.Errors)
	}
	if len(report.NewFindings) != 1 || report.NewFindings[0] != "certspotter:9" {
		t.Fatalf("second source must still report: %v", report.NewFindings)
	}
}

func TestSameCertFromTwoSourcesOneFinding(t *testing.T) {
	store := newTestStore(t)
	channel := &recordingChannel{}
	s1 := &countingSource{name: "crtsh", entries: []CTEntry{liveEntry("100", "0ABC")}}
	s2 := &countingSource{name: "certspotter", entries: []CTEntry{liveEntry("zz", "0a:bc")}}
	m, _ := NewMonitor(s1, &fakeInventory{}, store, &ChannelNotifier{Channel: channel, Target: "#sec"}, []string{"example.com"})
	m.AddSource(s2)
	for i := 0; i < 2; i++ { // second scan: cross-scan dedupe too
		if _, err := m.Scan(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	all, _ := store.List(context.Background(), "")
	if len(all) != 1 || len(channel.events) != 1 {
		t.Fatalf("findings=%d notifications=%d, want 1 and 1", len(all), len(channel.events))
	}
}

func TestSingleSourceKeepsDomainErrorKey(t *testing.T) {
	src := &countingSource{name: "crtsh", err: errors.New("boom")}
	m, _ := NewMonitor(src, &fakeInventory{}, newTestStore(t), nil, []string{"example.com"})
	report, _ := m.Scan(context.Background())
	if report.Errors["example.com"] != "boom" {
		t.Fatalf("errors = %v", report.Errors)
	}
}

func TestEmptyDomainsIsNoop(t *testing.T) {
	src := &countingSource{name: "crtsh"}
	m, _ := NewMonitor(src, &fakeInventory{}, newTestStore(t), nil, nil)
	report, err := m.Scan(context.Background())
	if err != nil || len(src.calls) != 0 || report.Domains != 0 || len(report.Errors) != 0 {
		t.Fatalf("expected quiet no-op: %+v err=%v calls=%v", report, err, src.calls)
	}
}
