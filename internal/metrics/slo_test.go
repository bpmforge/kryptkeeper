// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
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
// every metric name any panel queries must appear in the exposition, and the
// budget/burn series must be charted.
func TestDashboardReferencesExportedSeries(t *testing.T) {
	raw, err := os.ReadFile("../../docs/ops/pki-slo-dashboard.json")
	if err != nil {
		t.Fatalf("dashboard missing: %v", err)
	}
	var dash struct {
		Panels []struct {
			Targets []struct {
				Expr string `json:"expr"`
			} `json:"targets"`
		} `json:"panels"`
	}
	if err := json.Unmarshal(raw, &dash); err != nil {
		t.Fatalf("dashboard is not valid JSON: %v", err)
	}
	DefaultPKISLOs().RegisterMetrics(Default)
	var expoB strings.Builder
	Default.WritePrometheus(&expoB)
	expo := expoB.String()

	required := []string{
		"kryptkeeper_cert_issue_duration_seconds",
		"kryptkeeper_cert_renewal_success_total",
		"kryptkeeper_cert_renewal_failure_total",
		"kryptkeeper_cert_expiry_days",
		"kryptkeeper_slo_breaches_total",
		"kryptkeeper_slo_burn_rate",
		"kryptkeeper_slo_error_budget_remaining_ratio",
	}
	for _, name := range required {
		if !strings.Contains(string(raw), name) {
			t.Errorf("dashboard does not chart %s", name)
		}
		if !strings.Contains(expo, name) {
			t.Errorf("exposition does not export %s", name)
		}
	}

	// Every kryptkeeper_* identifier in any query must be a real series
	// (histogram _bucket/_sum/_count suffixes map back to the family).
	ident := regexp.MustCompile(`kryptkeeper_[a-z0-9_]+`)
	queried := 0
	for _, p := range dash.Panels {
		for _, tg := range p.Targets {
			for _, id := range ident.FindAllString(tg.Expr, -1) {
				queried++
				base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(id, "_bucket"), "_sum"), "_count")
				if !strings.Contains(expo, "# TYPE "+id+" ") && !strings.Contains(expo, "# TYPE "+base+" ") {
					t.Errorf("dashboard queries %s, which the exposition does not export", id)
				}
			}
		}
	}
	if queried == 0 {
		t.Fatal("dashboard has no queries")
	}
}

func ratioFixture(objective float64) (*SLOSet, *Counter, *Counter) {
	good, bad := &Counter{}, &Counter{}
	return NewSLOSet(RatioSLO("renewal-success-rate", "test", objective, good, bad)), good, bad
}

func TestBudgetAndBurnMath(t *testing.T) {
	set, good, bad := ratioFixture(0.99)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	set.Observe(t0)
	good.Add(990)
	bad.Add(10)
	now := t0.Add(30 * time.Minute)
	st := set.Status(now)
	if len(st) != 1 || !st[0].HasData || !st[0].HasBudget {
		t.Fatalf("status: %+v", st)
	}
	if math.Abs(st[0].BurnRate1h-1.0) > 1e-9 || math.Abs(st[0].BurnRate6h-1.0) > 1e-9 {
		t.Fatalf("burn: %+v", st[0])
	}
	if st[0].BudgetRemainingPct > 1e-9 {
		t.Fatalf("budget: %+v", st[0])
	}
	if st[0].Breached {
		t.Fatal("exactly 99% meets the objective")
	}

	clean, g2, _ := ratioFixture(0.99)
	clean.Observe(t0)
	g2.Add(1000)
	st = clean.Status(now)
	if st[0].BudgetRemainingPct != 100 || st[0].BurnRate1h != 0 || !st[0].HasData {
		t.Fatalf("zero-error status: %+v", st[0])
	}
}

func TestBurnRatesSeparateWindows(t *testing.T) {
	set, good, bad := ratioFixture(0.99)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	set.Observe(t0)
	// 5h ago: heavy errors; last hour: clean.
	good.Add(900)
	bad.Add(100)
	set.Observe(t0.Add(1 * time.Hour))
	good.Add(1000)
	set.Observe(t0.Add(6 * time.Hour))
	st := set.Status(t0.Add(6 * time.Hour))[0]
	if st.BurnRate1h != 0 {
		t.Fatalf("1h burn should be 0, got %v", st.BurnRate1h)
	}
	if st.BurnRate6h <= 0 {
		t.Fatalf("6h burn should see the earlier errors, got %v", st.BurnRate6h)
	}
}

func TestCounterResetIsNotNegative(t *testing.T) {
	set, good, _ := ratioFixture(0.99)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	good.Add(500)
	set.Observe(t0)
	// Simulated restart: fresh counters smaller than the last sample.
	g2, b2 := &Counter{}, &Counter{}
	set.slos[0] = RatioSLO("renewal-success-rate", "test", 0.99, g2, b2)
	g2.Add(40)
	b2.Add(10)
	w, ok := set.windowed(set.slos[0], t0.Add(10*time.Minute), SLOBudgetWindow)
	if !ok || w.good != 40 || w.total != 50 {
		t.Fatalf("post-reset increase should equal the new value, got %+v", w)
	}
}

func TestRenewalBelow99PagesExactlyOnce(t *testing.T) {
	set, good, bad := ratioFixture(0.99)
	ch := &fakeChannel{}
	ctx := context.Background()
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	set.Observe(t0)

	good.Add(90)
	bad.Add(10)
	tick := func(at time.Time) {
		set.Observe(at)
		if _, errs := set.EvaluateAndNotify(ctx, at, ch, "ops"); len(errs) != 0 {
			t.Fatalf("errs: %v", errs)
		}
	}
	tick(t0.Add(15 * time.Minute))
	if len(ch.events) != 1 {
		t.Fatalf("breach must page exactly once, got %d", len(ch.events))
	}
	tick(t0.Add(30 * time.Minute))
	tick(t0.Add(45 * time.Minute))
	if len(ch.events) != 1 {
		t.Fatalf("steady breach must not re-page, got %d", len(ch.events))
	}

	// Recover above 99% over the window, then breach again: re-armed.
	good.Add(100000)
	tick(t0.Add(time.Hour))
	if len(ch.events) != 1 {
		t.Fatalf("recovery must not page, got %d", len(ch.events))
	}
	bad.Add(5000)
	tick(t0.Add(75 * time.Minute))
	if len(ch.events) != 2 {
		t.Fatalf("re-breach after recovery must page again, got %d", len(ch.events))
	}
}

func TestIdleEstateNeverPages(t *testing.T) {
	set, _, _ := ratioFixture(0.99)
	ch := &fakeChannel{}
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 200; i++ {
		at := t0.Add(time.Duration(i) * 15 * time.Minute)
		set.Observe(at)
		if fired, _ := set.EvaluateAndNotify(context.Background(), at, ch, "ops"); len(fired) != 0 {
			t.Fatalf("idle estate fired: %v", fired)
		}
	}
	if len(ch.events) != 0 {
		t.Fatalf("idle estate paged: %v", ch.events)
	}
	if st := set.Status(t0.Add(time.Hour))[0]; st.HasData || st.BudgetRemainingPct != 100 {
		t.Fatalf("idle status: %+v", st)
	}
}

func TestSampleHistoryIsBounded(t *testing.T) {
	set, good, _ := ratioFixture(0.99)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < maxSLOSamples+500; i++ {
		good.Inc()
		set.Observe(t0.Add(time.Duration(i) * time.Minute))
	}
	if n := len(set.hist["renewal-success-rate"]); n > maxSLOSamples {
		t.Fatalf("history unbounded: %d", n)
	}
}

func TestGaugeFuncExposition(t *testing.T) {
	r := newTestRegistry()
	r.GaugeFunc("test_gauge", "first", func() []LabeledValue { return nil })
	r.GaugeFunc("test_gauge", "replaced", func() []LabeledValue {
		return []LabeledValue{{Labels: `slo="b",window="6h"`, Value: 2}, {Labels: `slo="a",window="1h"`, Value: 0.5}}
	})
	var sb strings.Builder
	r.WritePrometheus(&sb)
	out := sb.String()
	for _, want := range []string{"# TYPE test_gauge gauge", "# HELP test_gauge replaced", `test_gauge{slo="a",window="1h"} 0.5`, `test_gauge{slo="b",window="6h"} 2.0`} {
		if !strings.Contains(out, want) {
			t.Errorf("exposition missing %q:\n%s", want, out)
		}
	}
	if strings.Index(out, `slo="a"`) > strings.Index(out, `slo="b"`) {
		t.Error("labelled lines must be sorted")
	}
	if strings.Count(out, "# TYPE test_gauge") != 1 {
		t.Error("re-registering must replace, not append")
	}
}

func TestRegisterMetricsIsIdempotent(t *testing.T) {
	r := newTestRegistry()
	set, good, bad := ratioFixture(0.99)
	set.RegisterMetrics(r)
	set.RegisterMetrics(r)
	t0 := time.Now().Add(-time.Minute)
	set.Observe(t0)
	good.Add(99)
	bad.Add(1)
	var sb strings.Builder
	r.WritePrometheus(&sb)
	for _, want := range []string{
		`kryptkeeper_slo_objective{slo="renewal-success-rate"} 0.99`,
		`kryptkeeper_slo_error_budget_remaining_ratio{slo="renewal-success-rate"}`,
		`kryptkeeper_slo_burn_rate{slo="renewal-success-rate",window="1h"}`,
		`kryptkeeper_slo_burn_rate{slo="renewal-success-rate",window="6h"}`,
	} {
		if !strings.Contains(sb.String(), want) {
			t.Errorf("missing %q:\n%s", want, sb.String())
		}
	}
}
