// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"database/sql"
	"fmt"
	"math/rand"
	"path/filepath"
	"sort"
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

// --- W30-07 precision/recall harness ------------------------------------

type burstInjection struct {
	requester string
	times     []time.Time
}

// steadyCorpusDays is 30 days of scanned history plus the 20-day scan window:
// the detector's 30d volume average only exists for a tick if the corpus
// reaches 30 days behind it.
const steadyCorpusDays = 50

// genSteadyCorpus is deterministic (explicit seed, caller-supplied now). It is
// quiet by construction: certs are issued at 8 fixed daily slots 3h apart, one
// cert per CA per slot, so any 1h window holds at most 3 distinct requesters
// and any 24h window at most 8 certs per CA; a subject is rejected when it
// already has 2 issuances in the preceding 24h.
func genSteadyCorpus(seed int64, now time.Time) []IssuanceEvent {
	rng := rand.New(rand.NewSource(seed))
	cas := []string{"ca-a", "ca-b", "ca-c"}
	subjectTimes := map[string][]time.Time{}
	dayZero := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	var events []IssuanceEvent
	for d := steadyCorpusDays - 1; d >= 0; d-- {
		day := dayZero.AddDate(0, 0, -d)
		for ci, caID := range cas {
			n := 4 + rng.Intn(3)
			for j := 0; j < n; j++ {
				slot := (j + ci) % 8
				at := day.Add(time.Duration(slot)*3*time.Hour + 30*time.Minute + time.Duration(rng.Intn(10))*time.Minute)
				if at.After(now) {
					continue
				}
				subject := ""
				for {
					cand := fmt.Sprintf("svc-%d.example.com", rng.Intn(200))
					recent := 0
					for _, ts := range subjectTimes[cand] {
						if at.Sub(ts) <= 24*time.Hour {
							recent++
						}
					}
					if recent < 2 {
						subject = cand
						break
					}
				}
				subjectTimes[subject] = append(subjectTimes[subject], at)
				events = append(events, IssuanceEvent{
					Subject: subject, CAID: caID,
					RequestedBy: fmt.Sprintf("u%02d", 1+rng.Intn(12)), IssuedAt: at,
				})
			}
		}
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].IssuedAt.Before(events[j].IssuedAt) })
	return events
}

// injectBurst adds n distinct subjects over 50 minutes from start.
func injectBurst(events []IssuanceEvent, requester string, start time.Time, n int) ([]IssuanceEvent, burstInjection) {
	inj := burstInjection{requester: requester}
	for k := 0; k < n; k++ {
		at := start.Add(time.Duration(k) * 50 * time.Minute / time.Duration(n-1))
		if n == 1 {
			at = start
		}
		inj.times = append(inj.times, at)
		events = append(events, IssuanceEvent{Subject: fmt.Sprintf("burst-%d.example.com", k), CAID: "ca-a", RequestedBy: requester, IssuedAt: at})
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].IssuedAt.Before(events[j].IssuedAt) })
	return events, inj
}

// burstPositive is the detector-independent oracle: some injection has >= 11
// events inside (tick-1h, tick].
func burstPositive(injs []burstInjection, tick time.Time) bool {
	for _, inj := range injs {
		in := 0
		for _, at := range inj.times {
			if at.After(tick.Add(-time.Hour)) && !at.After(tick) {
				in++
			}
		}
		if in >= 11 {
			return true
		}
	}
	return false
}

func hasKind(fs []AnomalyFinding, kind string) bool {
	for _, f := range fs {
		if f.Kind == kind {
			return true
		}
	}
	return false
}

var harnessNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func TestRequesterBurstDetected20of20(t *testing.T) {
	d := NewAnomalyDetector()
	detected := 0
	var failing []int64
	for seed := int64(1); seed <= 20; seed++ {
		rng := rand.New(rand.NewSource(seed * 7919))
		events := genSteadyCorpus(seed, harnessNow)
		// Minute offset 3 keeps burst events off the 10-minute tick grid.
		start := harnessNow.Add(-time.Duration(24+rng.Intn(9*24)) * time.Hour).Truncate(time.Hour).Add(3 * time.Minute)
		events, inj := injectBurst(events, "u07", start, 11)
		ok := false
		for _, f := range d.Scan(events, start.Add(55*time.Minute)) {
			if f.Kind != "requester_burst" || !strings.Contains(f.Detail, "u07") {
				continue
			}
			have := map[string]bool{}
			for _, e := range f.Evidence {
				have[e] = true
			}
			ok = true
			for k := range inj.times {
				if !have[fmt.Sprintf("burst-%d.example.com", k)] {
					ok = false
				}
			}
		}
		if ok {
			detected++
		} else {
			failing = append(failing, seed)
		}
	}
	t.Logf("burst detected in %d/20 seeded runs", detected)
	if detected != 20 {
		t.Fatalf("detected %d/20, failing seeds %v", detected, failing)
	}
}

func TestAnomalyPrecisionRecall(t *testing.T) {
	d := NewAnomalyDetector()
	steady := genSteadyCorpus(42, harnessNow)

	// The generator is built to be quiet: no finding of any kind on steady data.
	for tick := harnessNow.Add(-20 * 24 * time.Hour); !tick.After(harnessNow); tick = tick.Add(10 * time.Minute) {
		if fs := d.Scan(steady, tick); len(fs) > 0 {
			t.Fatalf("steady corpus must be quiet, tick %s produced %+v", tick, fs)
		}
	}

	events := steady
	var injs []burstInjection
	// Four days apart, off the 10-minute tick grid (minute offset 3).
	for i, req := range []string{"u02", "u05", "u07", "u09", "u11"} {
		start := harnessNow.Add(-time.Duration(2+4*i) * 24 * time.Hour).Truncate(time.Hour).Add(time.Duration(7+i)*time.Hour + 3*time.Minute)
		var inj burstInjection
		events, inj = injectBurst(events, req, start, 11)
		injs = append(injs, inj)
	}

	var tp, fp, fn int
	ticks := 0
	for tick := harnessNow.Add(-20 * 24 * time.Hour); ticks < 2880; tick = tick.Add(10 * time.Minute) {
		ticks++
		predicted := hasKind(d.Scan(events, tick), "requester_burst")
		label := burstPositive(injs, tick)
		switch {
		case predicted && label:
			tp++
		case predicted && !label:
			fp++
		case !predicted && label:
			fn++
		}
	}
	precision := float64(tp) / float64(tp+fp)
	recall := float64(tp) / float64(tp+fn)
	t.Logf("ticks=%d TP=%d FP=%d FN=%d precision=%.3f recall=%.3f", ticks, tp, fp, fn, precision, recall)
	if tp == 0 {
		t.Fatal("no true positives: harness is not exercising the detector")
	}
	if precision < 0.95 || recall < 0.90 {
		t.Fatalf("precision %.3f (want >= 0.95) recall %.3f (want >= 0.90)", precision, recall)
	}
}

func TestBurstAtLimitIsNotFlagged(t *testing.T) {
	events, _ := injectBurst(nil, "u01", harnessNow.Add(-2*time.Hour), 10)
	if fs := NewAnomalyDetector().Scan(events, harnessNow.Add(-2*time.Hour).Add(55*time.Minute)); hasKind(fs, "requester_burst") {
		t.Fatalf("exactly 10 distinct subjects must not be flagged: %+v", fs)
	}
}

// CB-09: certificates with no issuing CA in this hub (imported, discovered)
// must not pool under "" and raise a volume_spike about a CA with an empty id.
func TestVolumeSpikeIgnoresCertificatesWithoutAHubCA(t *testing.T) {
	d := NewAnomalyDetector()
	now := time.Now()
	var events []IssuanceEvent
	for i := 2; i <= 30; i++ {
		events = append(events, evAt("steady", "", "", now.Add(-time.Duration(i)*24*time.Hour)))
	}
	for i := 0; i < 10; i++ {
		events = append(events, evAt(fmt.Sprintf("bulk-%d", i), "", "", now.Add(-time.Duration(i)*time.Minute)))
	}
	for _, f := range d.Scan(events, now) {
		if f.Kind == "volume_spike" {
			t.Fatalf("no CA, no CA volume finding: %+v", f)
		}
	}
}

// CB-11: the phrasing the user guide uses must parse, and a RSA mention must
// not borrow a number from a different clause.
func TestDraftPolicyParsesGuidePhrase(t *testing.T) {
	res := ParsePolicyDraft("guide", "RSA keys must be at least 3072 bits. Maximum validity 90 days.")
	if res.Policy.Rules.MinRSABits != 3072 || res.Policy.Rules.MaxValidityDays != 90 {
		t.Fatalf("rules = %+v, explanation %v, unrecognized %v", res.Policy.Rules, res.Explanation, res.Unrecognized)
	}
	if len(res.Unrecognized) != 0 {
		t.Fatalf("unexpected leftovers: %v", res.Unrecognized)
	}
	borrowed := ParsePolicyDraft("x", "rsa is fine, certificates valid for 3650 days")
	if borrowed.Policy.Rules.MinRSABits != 0 {
		t.Fatalf("RSA must not take a number from another clause: %+v", borrowed.Policy.Rules)
	}
}
