// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"sync"
	"time"

	"kryptkeeper/internal/logging"
)

// W24-15: agent change detection. Two consecutive inventory pushes are diffed
// inside the hub; an out-of-band replacement of a leaf at the same
// path/store raises CERTIFICATE_REPLACED, and an agent going silent raises
// AGENT_STALE. Delivery rides the W24-06 scan-diff notifier (no second path).

const (
	agentEventCertReplaced = ScanDiffCertificateReplaced
	agentEventStale        = "AGENT_STALE"

	// agentRenewalSuppressWindow is how long a successful agent-reported
	// renewal of the old fingerprint explains a replacement (DECISION 3).
	agentRenewalSuppressWindow = 24 * time.Hour
)

type agentChangeEvent struct {
	Type         string // agentEventCertReplaced | agentEventStale
	AgentID      string
	AgentName    string
	Source       string // path / store (CERTIFICATE_REPLACED only)
	Subject      string
	OldFP, NewFP string // CERTIFICATE_REPLACED only
	At           time.Time
}

type agentChangeSink func(ctx context.Context, ev agentChangeEvent)

// agentChangeSinkSetter is implemented by stores that can emit change events.
type agentChangeSinkSetter interface {
	SetAgentChangeSink(agentChangeSink)
}

// SetAgentChangeSink installs the sink; call before the store serves traffic.
func (s *dbAgentStore) SetAgentChangeSink(f agentChangeSink) { s.changeSink = f }

// agentChangeSinkFrom adapts the W24-06 notifier to an agent change sink.
func agentChangeSinkFrom(n ScanDiffNotifier) agentChangeSink {
	return func(ctx context.Context, ev agentChangeEvent) {
		detail := "agent went silent"
		if ev.Type == agentEventCertReplaced {
			detail = fmt.Sprintf("certificate %q replaced out-of-band", ev.Subject)
		}
		if err := n.Notify(ctx, ScanDiffEvent{
			Kind: ev.Type, Host: ev.AgentName, Port: 0,
			OldFingerprint: ev.OldFP, NewFingerprint: ev.NewFP,
			Detail: fmt.Sprintf("agent %s %s: %s", ev.AgentID, ev.Source, detail),
			At:     ev.At,
		}); err != nil {
			logging.Infof("agent change: notify %s agent %s: %v", ev.Type, ev.AgentID, err)
		}
	}
}

// diffAgentInventory is pure. Within each Source present in both slices, a
// removed cert is paired with an added cert of the same Subject (fingerprint
// order, each cert used once); each pair is one CERTIFICATE_REPLACED. Unpaired
// removals/additions emit nothing. Never pairs across sources.
func diffAgentInventory(agentID, agentName string, prev, next []AgentDiscoveredCert, at time.Time) []agentChangeEvent {
	if len(prev) == 0 {
		return nil
	}
	group := func(certs []AgentDiscoveredCert) map[string][]AgentDiscoveredCert {
		m := map[string][]AgentDiscoveredCert{}
		for _, c := range certs {
			m[c.Source] = append(m[c.Source], c)
		}
		return m
	}
	pg, ng := group(prev), group(next)
	sources := make([]string, 0, len(pg))
	for src := range pg {
		if _, ok := ng[src]; ok {
			sources = append(sources, src)
		}
	}
	sort.Strings(sources)

	var events []agentChangeEvent
	for _, src := range sources {
		removed := certsNotIn(pg[src], ng[src])
		added := certsNotIn(ng[src], pg[src])
		used := make([]bool, len(added))
		for _, r := range removed {
			for i, a := range added {
				if used[i] || a.Subject != r.Subject {
					continue
				}
				used[i] = true
				events = append(events, agentChangeEvent{
					Type: agentEventCertReplaced, AgentID: agentID, AgentName: agentName,
					Source: src, Subject: r.Subject, OldFP: r.Fingerprint, NewFP: a.Fingerprint, At: at,
				})
				break
			}
		}
	}
	return events
}

// certsNotIn returns certs of a whose fingerprint is absent from b, sorted by fingerprint.
func certsNotIn(a, b []AgentDiscoveredCert) []AgentDiscoveredCert {
	have := make(map[string]bool, len(b))
	for _, c := range b {
		have[c.Fingerprint] = true
	}
	var out []AgentDiscoveredCert
	for _, c := range a {
		if !have[c.Fingerprint] {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fingerprint < out[j].Fingerprint })
	return out
}

// staleTracker is edge-triggered: AGENT_STALE fires once on active->stale (or
// ->offline) and re-arms when the agent is active again. An agent that never
// reported (nil LastSeen) never fires: it was never active.
type staleTracker struct {
	mu    sync.Mutex
	fired map[string]bool
}

func (t *staleTracker) observe(info AgentInfo, now time.Time) *agentChangeEvent {
	t.mu.Lock()
	defer t.mu.Unlock()
	if info.LastSeen == nil {
		return nil
	}
	if computeAgentStatusAt(info.LastSeen, now) == AgentStatusActive {
		delete(t.fired, info.ID)
		return nil
	}
	if t.fired[info.ID] {
		return nil
	}
	if t.fired == nil {
		t.fired = map[string]bool{}
	}
	t.fired[info.ID] = true
	return &agentChangeEvent{Type: agentEventStale, AgentID: info.ID, AgentName: info.Name, At: now}
}

// sweepStale emits AGENT_STALE for agents that went silent since the last sweep.
func (s *dbAgentStore) sweepStale(now time.Time) {
	if s.changeSink == nil {
		return
	}
	for _, a := range s.list() {
		if ev := s.stale.observe(a, now); ev != nil {
			s.sendChange(context.Background(), *ev)
		}
	}
}

// sendChange delivers one event; a sink panic must never break the caller.
func (s *dbAgentStore) sendChange(ctx context.Context, ev agentChangeEvent) {
	defer func() {
		if r := recover(); r != nil {
			logging.Infof("agent change: sink panic for agent %s: %v", ev.AgentID, r)
		}
	}()
	s.changeSink(ctx, ev)
}

// loadInventoryTx reads an agent's inventory rows (fingerprint/subject/source only).
func (s *dbAgentStore) loadInventoryTx(ctx context.Context, tx *sql.Tx, agentID string) ([]AgentDiscoveredCert, error) {
	rows, err := tx.QueryContext(ctx, fmt.Sprintf("SELECT fingerprint, COALESCE(subject,''), COALESCE(source,'') FROM agent_inventory WHERE agent_id = %s", s.ph(1)), agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentDiscoveredCert
	for rows.Next() {
		var c AgentDiscoveredCert
		if err := rows.Scan(&c.Fingerprint, &c.Subject, &c.Source); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *dbAgentStore) agentName(ctx context.Context, tx *sql.Tx, agentID string) string {
	var name string
	if err := tx.QueryRowContext(ctx, fmt.Sprintf("SELECT name FROM agents WHERE id = %s", s.ph(1)), agentID).Scan(&name); err != nil {
		logging.Infof("agent change: read name of agent %s: %v", agentID, err)
	}
	return name
}

// renewedByAgent reports whether the agent itself reported a successful
// install for oldFP within the suppression window (DECISION 3).
func (s *dbAgentStore) renewedByAgent(ctx context.Context, agentID, oldFP string, now time.Time) bool {
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf("SELECT COALESCE(reported_at,'') FROM agent_results WHERE agent_id = %s AND fingerprint = %s AND outcome IN ('installed','installed_verified')", s.ph(1), s.ph(2)), agentID, oldFP)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var ts string
		if rows.Scan(&ts) != nil {
			continue
		}
		if t, err := time.Parse(time.RFC3339, ts); err == nil && now.Sub(t) <= agentRenewalSuppressWindow {
			return true
		}
	}
	return false
}

// emitInventoryChanges diffs and sends after the push committed.
func (s *dbAgentStore) emitInventoryChanges(ctx context.Context, agentID, agentName string, prev, next []AgentDiscoveredCert) {
	now := time.Now().UTC()
	for _, ev := range diffAgentInventory(agentID, agentName, prev, next, now) {
		if s.renewedByAgent(ctx, agentID, ev.OldFP, now) {
			continue
		}
		s.sendChange(ctx, ev)
	}
}
