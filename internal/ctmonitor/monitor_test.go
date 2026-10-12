// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ctmonitor

import (
	"context"
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
