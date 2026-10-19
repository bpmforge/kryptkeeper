// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kryptkeeper/internal/notifications/delivery"
)

// W12-03: scheduled anomaly detection — real-event derivation, latched
// paging, empty-estate silence, and the report surface.

func churnItems(now time.Time) []CertificateItem {
	// 5 issuances of the same subject within 24h → subject_churn.
	var items []CertificateItem
	for i := 0; i < 5; i++ {
		items = append(items, CertificateItem{
			FingerprintSHA256: string(rune('a' + i)),
			CommonName:        "churny.example.com",
			CAID:              "ca-1",
			TeamID:            "team-web",
			ValidFrom:         now.Add(-time.Duration(i) * time.Hour).Format(time.RFC3339),
			ValidUntil:        now.Add(30 * 24 * time.Hour).Format(time.RFC3339),
		})
	}
	return items
}

func TestAnomalyTickDetectsAndServes(t *testing.T) {
	now := time.Now()
	ch := &sloFakeChannel{}
	s := &AnomalyScheduler{
		certProvider: &reportCertProvider{items: churnItems(now)},
		detector:     NewAnomalyDetector(),
		channel:      ch,
		target:       "ops@example.com",
		pollInterval: time.Minute,
		seen:         map[string]bool{},
		stop:         make(chan struct{}),
	}
	s.tick(context.Background(), now)

	// Finding is served on the report surface.
	auth := newReportsTestAuth(t)
	mux := http.NewServeMux()
	registerAnomalyHandlers(mux, auth, s)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/reports/anomalies", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp struct {
		Data struct {
			Findings []AnomalyFinding `json:"findings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// 5-in-24h churn data also trips volume_spike (5 >= min sample,
	// 0.2/day trailing average) — both findings served.
	kinds := map[string]bool{}
	for _, f := range resp.Data.Findings {
		kinds[f.Kind] = true
	}
	if len(resp.Data.Findings) != 2 || !kinds["subject_churn"] || !kinds["volume_spike"] {
		t.Fatalf("expected churn + spike served: %+v", resp.Data.Findings)
	}

	// Both NEW findings paged, once each.
	if len(ch.events) != 2 || ch.events[0].Priority != "high" {
		t.Fatalf("new findings must page once each: %v", ch.events)
	}
	// Steady findings: no re-page on the next tick.
	s.tick(context.Background(), now)
	if len(ch.events) != 2 {
		t.Fatalf("steady findings must not re-page: %v", ch.events)
	}
	// Cleared then re-appearing: pages again.
	s.certProvider = &reportCertProvider{items: nil}
	s.tick(context.Background(), now)
	s.certProvider = &reportCertProvider{items: churnItems(now)}
	s.tick(context.Background(), now)
	if len(ch.events) != 4 {
		t.Fatalf("re-appearing findings must page again: %v", ch.events)
	}
}

func TestAnomalyTickEmptyEstateIsSilent(t *testing.T) {
	ch := &sloFakeChannel{}
	s := &AnomalyScheduler{
		certProvider: &reportCertProvider{items: nil},
		detector:     NewAnomalyDetector(),
		channel:      ch,
		pollInterval: time.Minute,
		seen:         map[string]bool{},
		stop:         make(chan struct{}),
	}
	s.tick(context.Background(), time.Now())
	findings, _ := s.Snapshot()
	if len(findings) != 0 || len(ch.events) != 0 {
		t.Fatalf("empty estate must be silent: %v %v", findings, ch.events)
	}
}

func TestAnomalyAuthRequired(t *testing.T) {
	auth := newReportsTestAuth(t)
	mux := http.NewServeMux()
	registerAnomalyHandlers(mux, auth, NewAnomalySchedulerFromEnv(&reportCertProvider{}, nil, ""))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/reports/anomalies", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// --- W30-07: requester attribution ---------------------------------------

type issuerAudit struct {
	entries []AuditEntry
	err     error
	calls   int
}

func (a *issuerAudit) AppendEntry(context.Context, AuditEntry) error { return nil }

func (a *issuerAudit) ListEntries(_ context.Context, q AuditListQuery) (AuditListResult, error) {
	a.calls++
	if a.err != nil {
		return AuditListResult{}, a.err
	}
	var m []AuditEntry
	for _, e := range a.entries {
		if (q.Action == "" || e.Action == q.Action) && (q.Outcome == "" || e.Outcome == q.Outcome) {
			m = append(m, e)
		}
	}
	if q.Offset >= len(m) {
		return AuditListResult{}, nil
	}
	m = m[q.Offset:]
	if q.Limit > 0 && len(m) > q.Limit {
		m = m[:q.Limit]
	}
	return AuditListResult{Entries: m}, nil
}

func issueRow(fp, actor string, outcome AuditOutcome) AuditEntry {
	return AuditEntry{Action: "certificate.issue", ActorType: "user", ActorID: actor, ResourceType: "certificate", ResourceID: fp, Outcome: outcome}
}

func twoTeamCerts(now time.Time) []CertificateItem {
	var items []CertificateItem
	for _, fp := range []string{"fp-1", "fp-2"} {
		items = append(items, CertificateItem{FingerprintSHA256: fp, CommonName: fp + ".example.com", CAID: "ca-1", TeamID: "team-x", ValidFrom: now.Add(-time.Hour).Format(time.RFC3339)})
	}
	return items
}

func TestIssuanceEventsCarryRealRequester(t *testing.T) {
	now := time.Now()
	s := (&AnomalyScheduler{certProvider: &reportCertProvider{items: twoTeamCerts(now)}}).
		WithAuditProvider(&issuerAudit{entries: []AuditEntry{issueRow("fp-1", "alice", AuditOutcomeSuccess)}})
	events, err := s.issuanceEvents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range events {
		got[e.Fingerprint] = e.RequestedBy
	}
	if got["fp-1"] != "alice" || got["fp-2"] != "" {
		t.Fatalf("requesters = %v, want fp-1=alice fp-2 empty (never team-x)", got)
	}
}

func TestIssuerByFingerprintPagesAndSkipsSystem(t *testing.T) {
	a := &issuerAudit{}
	for i := 0; i < 1203; i++ {
		a.entries = append(a.entries, issueRow(fmt.Sprintf("fp-%d", i), "bob", AuditOutcomeSuccess))
	}
	sys := issueRow("fp-sys", "bootstrap", AuditOutcomeSuccess)
	sys.ActorType = "system"
	a.entries = append(a.entries, sys)
	m, err := (&AnomalyScheduler{audit: a}).issuerByFingerprint(context.Background(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 1203 || m["fp-1202"] != "bob" || m["fp-sys"] != "" {
		t.Fatalf("got %d entries, fp-1202=%q fp-sys=%q", len(m), m["fp-1202"], m["fp-sys"])
	}
}

func TestUnknownRequestersNotPooled(t *testing.T) {
	now := time.Now()
	var events []IssuanceEvent
	for i := 0; i < 15; i++ {
		events = append(events, evAt(fmt.Sprintf("s%d.example.com", i), "ca-1", "", now.Add(-time.Duration(i)*time.Minute)))
	}
	if fs := NewAnomalyDetector().Scan(events, now); hasKind(fs, "requester_burst") {
		t.Fatalf("unknown requesters were pooled: %+v", fs)
	}
}

func TestAuditFailureDegradesGracefully(t *testing.T) {
	now := time.Now()
	s := &AnomalyScheduler{
		certProvider: &reportCertProvider{items: churnItems(now)},
		detector:     NewAnomalyDetector(),
		pollInterval: time.Minute,
		seen:         map[string]bool{},
		stop:         make(chan struct{}),
	}
	s.WithAuditProvider(&issuerAudit{err: errors.New("audit down")})
	s.tick(context.Background(), now)
	findings, at := s.Snapshot()
	if at.IsZero() || !hasKind(findings, "subject_churn") || !hasKind(findings, "volume_spike") {
		t.Fatalf("tick must still detect churn/spike: %+v", findings)
	}
	events, _ := s.issuanceEvents(context.Background())
	for _, e := range events {
		if e.RequestedBy != "" {
			t.Fatalf("requester %q set despite audit failure", e.RequestedBy)
		}
	}
}

func TestFailedIssueRowsIgnored(t *testing.T) {
	now := time.Now()
	// The fake honours the Outcome filter, so these also prove the query
	// asks for success only; a permissive provider is covered by the
	// explicit empty-actor check below.
	s := (&AnomalyScheduler{certProvider: &reportCertProvider{items: twoTeamCerts(now)}}).
		WithAuditProvider(&issuerAudit{entries: []AuditEntry{
			issueRow("fp-1", "mallory", AuditOutcomeFailure),
			issueRow("fp-2", "mallory", AuditOutcomeDenied),
		}})
	events, err := s.issuanceEvents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.RequestedBy != "" {
			t.Fatalf("non-success row attributed %q to %s", e.RequestedBy, e.Fingerprint)
		}
	}
}
func TestAnomalyFindingFansOut(t *testing.T) {
	now := time.Now()
	a, b := &fanFake{name: "a"}, &fanFake{name: "b"}
	s := &AnomalyScheduler{
		certProvider: &reportCertProvider{items: churnItems(now)},
		detector:     NewAnomalyDetector(),
		channel:      NewFanOutChannel([]delivery.Channel{a, b}),
		target:       "ops@example.com",
		pollInterval: time.Minute,
		seen:         map[string]bool{},
		stop:         make(chan struct{}),
	}
	s.tick(context.Background(), now)
	if len(a.events) != 2 || len(b.events) != 2 {
		t.Fatalf("fresh findings must reach every member once: a=%d b=%d", len(a.events), len(b.events))
	}
	s.tick(context.Background(), now)
	if len(a.events) != 2 || len(b.events) != 2 {
		t.Fatalf("steady findings must not re-send: a=%d b=%d", len(a.events), len(b.events))
	}
}
