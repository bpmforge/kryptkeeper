// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/ca"
)

// W7-04: deterministic issuance-anomaly rules + NL policy drafting
// that can never activate a rule.

func evAt(subject, caID, by string, at time.Time) IssuanceEvent {
	return IssuanceEvent{Subject: subject, CAID: caID, RequestedBy: by, IssuedAt: at}
}

func TestVolumeSpikeDetection(t *testing.T) {
	d := NewAnomalyDetector()
	now := time.Now()
	var events []IssuanceEvent
	// Steady state: 1/day for 29 days.
	for i := 2; i <= 30; i++ {
		events = append(events, evAt("steady", "ca-1", "svc", now.Add(-time.Duration(i)*24*time.Hour)))
	}
	// Spike: 10 in the last day (avg ≈ 1.3/day → 10 > 2×avg, ≥ MinSample).
	for i := 0; i < 10; i++ {
		events = append(events, evAt("burst", "ca-1", "svc", now.Add(-time.Duration(i)*time.Minute)))
	}
	findings := d.Scan(events, now)
	var spike *AnomalyFinding
	for i := range findings {
		if findings[i].Kind == "volume_spike" {
			spike = &findings[i]
		}
	}
	if spike == nil {
		t.Fatalf("expected volume_spike, got %v", findings)
	}
	if spike.Evidence[0] != "ca-1" {
		t.Fatalf("evidence must name the CA: %v", spike.Evidence)
	}
}

func TestVolumeSpikeMinSampleGuard(t *testing.T) {
	d := NewAnomalyDetector()
	now := time.Now()
	// 3 certs today, none before: huge relative spike but below MinSample
	// — an empty estate must never alarm (S-45 agreement).
	events := []IssuanceEvent{
		evAt("a", "ca-1", "svc", now.Add(-time.Minute)),
		evAt("b", "ca-1", "svc", now.Add(-2*time.Minute)),
		evAt("c", "ca-1", "svc", now.Add(-3*time.Minute)),
	}
	for _, f := range d.Scan(events, now) {
		if f.Kind == "volume_spike" {
			t.Fatalf("below-min-sample data must not alarm: %+v", f)
		}
	}
}

func TestSubjectChurnDetection(t *testing.T) {
	d := NewAnomalyDetector()
	now := time.Now()
	var events []IssuanceEvent
	for i := 0; i < 5; i++ { // 5 > limit of 3
		events = append(events, evAt("api.example.com", "ca-1", "svc", now.Add(-time.Duration(i)*time.Hour)))
	}
	findings := d.Scan(events, now)
	found := false
	for _, f := range findings {
		if f.Kind == "subject_churn" && f.Evidence[0] == "api.example.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected subject_churn, got %v", findings)
	}
	// At the limit: no finding.
	for _, f := range d.Scan(events[:3], now) {
		if f.Kind == "subject_churn" {
			t.Fatalf("at-limit churn must not alarm: %+v", f)
		}
	}
}

func TestRequesterBurstDetection(t *testing.T) {
	d := NewAnomalyDetector()
	now := time.Now()
	var events []IssuanceEvent
	for i := 0; i < 12; i++ { // 12 distinct subjects > limit of 10
		events = append(events, evAt("host-"+string(rune('a'+i))+".example.com", "ca-1", "rogue-svc", now.Add(-time.Duration(i)*time.Minute)))
	}
	findings := d.Scan(events, now)
	found := false
	for _, f := range findings {
		if f.Kind == "requester_burst" && strings.Contains(f.Detail, "rogue-svc") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected requester_burst, got %v", findings)
	}
}

func TestDraftPolicyFromNLExtractsRules(t *testing.T) {
	draft, explanation, err := DraftPolicyFromNL("web-policy",
		"Certificates should be valid for at most 90 days, rsa at least 3072 bits, and only ecdsa and ed25519 keys.")
	if err != nil {
		t.Fatalf("draft: %v", err)
	}
	if draft.Rules.MaxValidityDays != 90 {
		t.Errorf("max validity: %d", draft.Rules.MaxValidityDays)
	}
	if draft.Rules.MinRSABits != 3072 {
		t.Errorf("rsa bits: %d", draft.Rules.MinRSABits)
	}
	if len(draft.Rules.AllowedAlgorithms) != 2 {
		t.Errorf("algorithms: %v", draft.Rules.AllowedAlgorithms)
	}
	if draft.Enabled {
		t.Fatal("a drafted policy must never be enabled")
	}
	if len(explanation) != 3 {
		t.Fatalf("explanation must name every extracted rule: %v", explanation)
	}

	// Junk text errors instead of yielding a silently-empty policy.
	if _, _, err := DraftPolicyFromNL("junk", "make everything nice please"); err == nil {
		t.Fatal("unrecognized text must error")
	}
}

const anomalyPolicySchema = `
CREATE TABLE IF NOT EXISTS issuance_policies (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
    ca_id      TEXT NOT NULL DEFAULT '',
    rules      TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);`

func TestNLDraftLandsDisabledEvenWhenActivationRequested(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "policy.db"))
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(anomalyPolicySchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	engine, err := ca.NewPolicyEngine(db, false)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	// The text explicitly asks for activation. The draft still lands
	// disabled — the NL path proposes, never activates.
	draft, _, err := DraftPolicyFromNL("urgent-policy",
		"Max validity 30 days. Enable it immediately and activate it now.")
	if err != nil {
		t.Fatalf("draft: %v", err)
	}
	// Even a caller flipping the field is overridden at submit time.
	draft.Enabled = true
	stored, err := SubmitPolicyDraft(engine, draft)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if stored.Enabled {
		t.Fatal("submitted draft must be stored disabled")
	}
	list, err := engine.ListPolicies()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, p := range list {
		if p.ID == stored.ID && p.Enabled {
			t.Fatal("policy row must be disabled in the table")
		}
	}
}
