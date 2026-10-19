// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"testing"
	"time"
)

func ac(fp, subj, src string) AgentDiscoveredCert {
	return AgentDiscoveredCert{Fingerprint: fp, Subject: subj, Source: src}
}

func TestDiffAgentInventory(t *testing.T) {
	at := time.Unix(1000, 0).UTC()
	tests := []struct {
		name       string
		prev, next []AgentDiscoveredCert
		want       int
	}{
		{"first push", nil, []AgentDiscoveredCert{ac("a", "CN=x", "/p")}, 0},
		{"identical", []AgentDiscoveredCert{ac("a", "CN=x", "/p")}, []AgentDiscoveredCert{ac("a", "CN=x", "/p")}, 0},
		{"same path new fp same subject", []AgentDiscoveredCert{ac("a", "CN=x", "/p")}, []AgentDiscoveredCert{ac("b", "CN=x", "/p")}, 1},
		{"cert removed", []AgentDiscoveredCert{ac("a", "CN=x", "/p"), ac("c", "CN=y", "/p")}, []AgentDiscoveredCert{ac("a", "CN=x", "/p")}, 0},
		{"cert added at new path", []AgentDiscoveredCert{ac("a", "CN=x", "/p")}, []AgentDiscoveredCert{ac("a", "CN=x", "/p"), ac("b", "CN=x", "/q")}, 0},
		{"two replaced at one jks", []AgentDiscoveredCert{ac("a", "CN=x", "/j"), ac("b", "CN=y", "/j")}, []AgentDiscoveredCert{ac("c", "CN=y", "/j"), ac("d", "CN=x", "/j")}, 2},
		{"same path new subject", []AgentDiscoveredCert{ac("a", "CN=x", "/p")}, []AgentDiscoveredCert{ac("b", "CN=z", "/p")}, 0},
		{"order shuffled only", []AgentDiscoveredCert{ac("a", "CN=x", "/p"), ac("b", "CN=y", "/q")}, []AgentDiscoveredCert{ac("b", "CN=y", "/q"), ac("a", "CN=x", "/p")}, 0},
		{"never pairs across sources", []AgentDiscoveredCert{ac("a", "CN=x", "/p"), ac("z", "CN=k", "/q")}, []AgentDiscoveredCert{ac("b", "CN=x", "/q"), ac("z", "CN=k", "/q")}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := diffAgentInventory("id1", "n1", tc.prev, tc.next, at)
			if len(got) != tc.want {
				t.Fatalf("got %d events want %d: %+v", len(got), tc.want, got)
			}
		})
	}
	ev := diffAgentInventory("id1", "n1", []AgentDiscoveredCert{ac("a", "CN=x", "/p")}, []AgentDiscoveredCert{ac("b", "CN=x", "/p")}, at)[0]
	if ev.OldFP != "a" || ev.NewFP != "b" || ev.Source != "/p" || ev.Type != agentEventCertReplaced || ev.AgentName != "n1" {
		t.Fatalf("bad event %+v", ev)
	}
}

func TestStaleTrackerEdgeTriggered(t *testing.T) {
	var tr staleTracker
	t0 := time.Unix(10000, 0).UTC()
	info := AgentInfo{ID: "a1", Name: "n", LastSeen: &t0}
	if tr.observe(info, t0.Add(time.Minute)) != nil {
		t.Fatal("active must not fire")
	}
	if tr.observe(info, t0.Add(5*time.Minute)) == nil {
		t.Fatal("stale must fire")
	}
	if tr.observe(info, t0.Add(6*time.Minute)) != nil {
		t.Fatal("must not refire")
	}
	t1 := t0.Add(7 * time.Minute)
	info.LastSeen = &t1
	if tr.observe(info, t1.Add(time.Second)) != nil {
		t.Fatal("active again must not fire")
	}
	if tr.observe(info, t1.Add(5*time.Minute)) == nil {
		t.Fatal("silent again must refire")
	}
	if tr.observe(AgentInfo{ID: "never"}, t1) != nil {
		t.Fatal("never-seen agent must not fire")
	}
}

type recSink struct{ evs []agentChangeEvent }

func (r *recSink) sink(_ context.Context, ev agentChangeEvent) { r.evs = append(r.evs, ev) }

func TestSubmitInventoryEmitsOncePerReplacement(t *testing.T) {
	s := newTestDBAgentStore(t)
	rec := &recSink{}
	s.SetAgentChangeSink(rec.sink)
	id, tok, _ := s.register("host-a", AgentTypeLinux)
	a := []AgentDiscoveredCert{ac("fpA", "CN=x", "/etc/x.pem")}
	b := []AgentDiscoveredCert{ac("fpB", "CN=x", "/etc/x.pem")}
	if err := s.submitInventory(id, tok, a, nil); err != nil || len(rec.evs) != 0 {
		t.Fatalf("push A: err=%v evs=%d", err, len(rec.evs))
	}
	if err := s.submitInventory(id, tok, b, nil); err != nil || len(rec.evs) != 1 {
		t.Fatalf("push B: err=%v evs=%d", err, len(rec.evs))
	}
	if rec.evs[0].AgentName != "host-a" || rec.evs[0].OldFP != "fpA" || rec.evs[0].NewFP != "fpB" {
		t.Fatalf("bad event %+v", rec.evs[0])
	}
	if err := s.submitInventory(id, tok, b, nil); err != nil || len(rec.evs) != 1 {
		t.Fatalf("push B again: err=%v evs=%d", err, len(rec.evs))
	}
}

func TestSubmitInventorySuppressesAgentOwnRenewal(t *testing.T) {
	s := newTestDBAgentStore(t)
	rec := &recSink{}
	s.SetAgentChangeSink(rec.sink)
	id, tok, _ := s.register("host-a", AgentTypeLinux)
	_ = s.submitInventory(id, tok, []AgentDiscoveredCert{ac("fpA", "CN=x", "/p")}, nil)
	if err := s.submitRenewalResult(id, tok, AgentRenewalResult{Fingerprint: "fpA", Outcome: "installed_verified"}); err != nil {
		t.Fatal(err)
	}
	_ = s.submitInventory(id, tok, []AgentDiscoveredCert{ac("fpB", "CN=x", "/p")}, nil)
	if len(rec.evs) != 0 {
		t.Fatalf("agent's own renewal must not alert: %+v", rec.evs)
	}
}

func TestSinkFailureDoesNotFailPush(t *testing.T) {
	s := newTestDBAgentStore(t)
	s.SetAgentChangeSink(func(context.Context, agentChangeEvent) { panic("boom") })
	id, tok, _ := s.register("h", AgentTypeLinux)
	_ = s.submitInventory(id, tok, []AgentDiscoveredCert{ac("a", "CN=x", "/p")}, nil)
	if err := s.submitInventory(id, tok, []AgentDiscoveredCert{ac("b", "CN=x", "/p")}, nil); err != nil {
		t.Fatalf("push failed: %v", err)
	}
}

func TestSweepStaleEmitsOnce(t *testing.T) {
	s := newTestDBAgentStore(t)
	rec := &recSink{}
	s.SetAgentChangeSink(rec.sink)
	id, tok, _ := s.register("h", AgentTypeLinux)
	_ = s.heartbeat(id, tok)
	s.sweepStale(time.Now().UTC().Add(time.Hour))
	s.sweepStale(time.Now().UTC().Add(2 * time.Hour))
	if len(rec.evs) != 1 || rec.evs[0].Type != agentEventStale {
		t.Fatalf("want 1 stale event, got %+v", rec.evs)
	}
}
