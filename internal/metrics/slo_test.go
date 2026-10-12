// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/notifications/delivery"
)

// W7-03: quantile estimation, SLI math, transition-latched breach
// alerting, and dashboard/exposition agreement.

func TestQuantileEstimation(t *testing.T) {
	h := newHistogram([]float64{1, 2, 5, 10})
	// 90 fast observations, 10 slow ones → p95 lands in the 2..5 bucket.
	for i := 0; i < 90; i++ {
		h.Observe(0.5)
	}
	for i := 0; i < 10; i++ {
		h.Observe(3)
	}
	p95, ok := Quantile(h, 0.95)
	if !ok {
		t.Fatal("expected data")
	}
	if p95 < 2 || p95 > 5 {
		t.Fatalf("p95 %v outside the 2..5 bucket", p95)
	}
	// Empty histogram: no data, never a value.
	if _, ok := Quantile(newHistogram([]float64{1}), 0.5); ok {
		t.Fatal("empty histogram must report no data")
	}
}

func TestObserveTimeToExpiryClampsNegative(t *testing.T) {
	before := CertExpiryDays.totalN.Load()
	ObserveTimeToExpiry(-48 * time.Hour)
	ObserveTimeToExpiry(30 * 24 * time.Hour)
	if CertExpiryDays.totalN.Load() != before+2 {
		t.Fatal("both observations must land")
	}
}

// fakeChannel records sent events and can fail on demand.
type fakeChannel struct {
	events []delivery.Event
	fail   bool
}

func (f *fakeChannel) Name() string { return "fake" }
func (f *fakeChannel) Send(_ context.Context, ev delivery.Event) error {
	if f.fail {
		return fmt.Errorf("boom")
	}
	f.events = append(f.events, ev)
	return nil
}

// switchableSLO lets a test drive the SLI value directly.
func switchableSLO(name string, value *float64, objective float64) SLO {
	return SLO{
		Name:      name,
		Objective: objective,
		Current:   func() (float64, bool) { return *value, true },
		Meets:     func(cur, obj float64) bool { return cur >= obj },
	}
}

func TestEvaluateAndNotifyLatchesOnTransition(t *testing.T) {
	val := 1.0
	set := NewSLOSet(switchableSLO("renewal-success-rate", &val, 0.99))
	ch := &fakeChannel{}
	now := time.Now()

	// Healthy: nothing fires.
	fired, errs := set.EvaluateAndNotify(context.Background(), now, ch, "ops@example.com")
	if len(fired) != 0 || len(errs) != 0 || len(ch.events) != 0 {
		t.Fatalf("healthy SLO must not page: %v %v", fired, ch.events)
	}

	// Breach: exactly one critical event.
	val = 0.5
	fired, errs = set.EvaluateAndNotify(context.Background(), now, ch, "ops@example.com")
	if len(errs) != 0 || len(fired) != 1 || len(ch.events) != 1 {
		t.Fatalf("breach must page once: fired=%v events=%v errs=%v", fired, ch.events, errs)
	}
	if ch.events[0].Priority != "critical" || !strings.Contains(ch.events[0].Subject, "renewal-success-rate") {
		t.Fatalf("event shape: %+v", ch.events[0])
	}

	// Steady breach: no re-page.
	fired, _ = set.EvaluateAndNotify(context.Background(), now, ch, "ops@example.com")
	if len(fired) != 0 || len(ch.events) != 1 {
		t.Fatalf("steady breach must not re-page: %v", ch.events)
	}

	// Recovery re-arms; a NEW breach pages again.
	val = 1.0
	_, _ = set.EvaluateAndNotify(context.Background(), now, ch, "ops@example.com")
	val = 0.2
	fired, _ = set.EvaluateAndNotify(context.Background(), now, ch, "ops@example.com")
	if len(fired) != 1 || len(ch.events) != 2 {
		t.Fatalf("re-breach after recovery must page again: %v", ch.events)
	}
}

func TestEvaluateAndNotifySurfacesSendFailures(t *testing.T) {
	val := 0.1
	set := NewSLOSet(switchableSLO("renewal-success-rate", &val, 0.99))
	ch := &fakeChannel{fail: true}
	_, errs := set.EvaluateAndNotify(context.Background(), time.Now(), ch, "ops@example.com")
	if len(errs) != 1 {
		t.Fatalf("send failure must be returned, got %v", errs)
	}
}

func TestNoDataSLOIsNotBreached(t *testing.T) {
	set := NewSLOSet(SLO{
		Name: "empty", Objective: 0.99,
		Current: func() (float64, bool) { return 0, false },
		Meets:   func(cur, obj float64) bool { return cur >= obj },
	})
	if b := set.Evaluate(time.Now()); len(b) != 0 {
		t.Fatalf("no-data SLO must not breach: %v", b)
	}
}

func TestDefaultPKISLOsWiredToLiveMetrics(t *testing.T) {
	set := DefaultPKISLOs()
	if len(set.slos) != 3 {
		t.Fatalf("expected 3 default SLOs, got %d", len(set.slos))
	}
	// Drive the live renewal counters into breach and confirm Evaluate
	// sees it (global counters, so only push them in one direction).
	CertRenewalFailure.Add(1000)
	breaches := set.Evaluate(time.Now())
	found := false
	for _, b := range breaches {
		if b.SLO == "renewal-success-rate" {
			found = true
		}
	}
	if !found {
		t.Fatalf("renewal-success-rate must breach after 1000 failures: %v", breaches)
	}
}

// TestDashboardReferencesExportedSeries pins the dashboard to reality:
// every metric name the panels query must appear in the exposition.
func TestDashboardReferencesExportedSeries(t *testing.T) {
	raw, err := os.ReadFile("../../docs/ops/pki-slo-dashboard.json")
	if err != nil {
		t.Fatalf("dashboard missing: %v", err)
	}
	var dash map[string]any
	if err := json.Unmarshal(raw, &dash); err != nil {
		t.Fatalf("dashboard is not valid JSON: %v", err)
	}
	var expo strings.Builder
	Default.WritePrometheus(&expo)
	for _, name := range []string{
		"kryptkeeper_cert_issue_duration_seconds",
		"kryptkeeper_cert_renewal_success_total",
		"kryptkeeper_cert_renewal_failure_total",
		"kryptkeeper_cert_expiry_days",
		"kryptkeeper_slo_breaches_total",
	} {
		if !strings.Contains(string(raw), name) {
			t.Errorf("dashboard does not chart %s", name)
		}
		if !strings.Contains(expo.String(), name) {
			t.Errorf("exposition does not export %s", name)
		}
	}
}
