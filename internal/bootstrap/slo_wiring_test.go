// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/metrics"
	"kryptkeeper/internal/notifications/delivery"
)

// W12-02: SLO scheduler — expiry sweep feeds the histogram, breaches
// page the channel, HA-denied ticks do nothing, renewal outcomes count.

type sloFakeChannel struct{ events []delivery.Event }

func (f *sloFakeChannel) Name() string { return "fake" }
func (f *sloFakeChannel) Send(_ context.Context, ev delivery.Event) error {
	f.events = append(f.events, ev)
	return nil
}

func sloTestScheduler(items []CertificateItem, ch delivery.Channel) *SLOScheduler {
	return &SLOScheduler{
		certProvider: &reportCertProvider{items: items},
		set:          metrics.DefaultPKISLOs(),
		channel:      ch,
		target:       "ops@example.com",
		pollInterval: time.Minute,
		stop:         make(chan struct{}),
	}
}

func TestSLOTickFeedsExpiryHistogram(t *testing.T) {
	now := time.Now()
	items := []CertificateItem{
		{FingerprintSHA256: "aa", ValidUntil: now.Add(30 * 24 * time.Hour).Format(time.RFC3339)},
		{FingerprintSHA256: "bb", ValidUntil: now.Add(5 * 24 * time.Hour).Format(time.RFC3339)},
		{FingerprintSHA256: "cc", ValidUntil: "not-a-date"}, // skipped, not fatal
	}
	s := sloTestScheduler(items, nil)
	_, counts := metrics.CertExpiryDays.BucketCounts()
	var before int64
	for _, c := range counts {
		before += c
	}
	s.tick(context.Background(), now)
	_, counts = metrics.CertExpiryDays.BucketCounts()
	var after int64
	for _, c := range counts {
		after += c
	}
	if after-before != 2 {
		t.Fatalf("expected 2 expiry observations, got %d", after-before)
	}
}

func TestSLOTickPagesOnBreach(t *testing.T) {
	// Drive the live renewal counters into breach (global metrics: only
	// push one direction; other tests tolerate it).
	ch := &sloFakeChannel{}
	s := sloTestScheduler(nil, ch)
	// W30-05: paging is judged over the 30-day window, so the first tick
	// records the baseline and the failures must land after it.
	base := time.Now()
	s.tick(context.Background(), base)
	metrics.CertRenewalFailure.Add(5000)
	s.tick(context.Background(), base.Add(15*time.Minute))
	found := false
	for _, ev := range ch.events {
		if ev.Priority == "critical" {
			found = true
		}
	}
	if !found {
		t.Fatalf("breached SLO must page the channel, got %v", ch.events)
	}
	// Steady breach on the next tick: no re-page (transition latch).
	n := len(ch.events)
	s.tick(context.Background(), base.Add(30*time.Minute))
	if len(ch.events) != n {
		t.Fatalf("steady breach must not re-page: %v", ch.events)
	}
}

func TestSLOTickSurvivesProviderError(t *testing.T) {
	s := &SLOScheduler{
		certProvider: erroringCertProvider{},
		set:          metrics.DefaultPKISLOs(),
		pollInterval: time.Minute,
		stop:         make(chan struct{}),
	}
	s.tick(context.Background(), time.Now()) // must not panic
}

type erroringCertProvider struct{ CertificateProvider }

func (erroringCertProvider) ListCertificates(context.Context, CertificateListQuery) (CertificateListResult, error) {
	return CertificateListResult{}, fmt.Errorf("db down")
}

func TestExecuteRenewalCountsFailures(t *testing.T) {
	before := metrics.CertRenewalFailure.Load()
	e := NewRenewalExecutorFromEnv(&reportCertProvider{})
	// Non-SSH target: a refusal, which deliberately counts as a failure —
	// a target that cannot renew is what should erode the SLO.
	_, err := e.ExecuteRenewal(context.Background(), "aa", ManagedTarget{InstallMode: "agent"}, RenewalInstallProfile{})
	if err == nil {
		t.Fatal("expected refusal")
	}
	if metrics.CertRenewalFailure.Load() != before+1 {
		t.Fatalf("failure must increment the renewal-failure counter")
	}
}

type fanFake struct {
	name   string
	events []delivery.Event
	err    error
	cfg    bool
}

func (f *fanFake) Name() string { return f.name }
func (f *fanFake) Send(_ context.Context, ev delivery.Event) error {
	f.events = append(f.events, ev)
	return f.err
}

type fanConfigurable struct{ fanFake }

func (f *fanConfigurable) Configured(context.Context) bool { return f.cfg }

func TestFanOutDeliversOnAllChannels(t *testing.T) {
	a, b, c := &fanFake{name: "a"}, &fanFake{name: "b"}, &fanFake{name: "c"}
	f := NewFanOutChannel([]delivery.Channel{a, b, c})
	if err := f.Send(context.Background(), delivery.Event{ID: "x", Channel: "fanout"}); err != nil {
		t.Fatal(err)
	}
	for _, m := range []*fanFake{a, b, c} {
		if len(m.events) != 1 || m.events[0].Channel != m.name || m.events[0].ID != "x#"+m.name {
			t.Fatalf("%s: got %+v", m.name, m.events)
		}
	}
	if f.Members() != 3 || f.Name() != "fanout" {
		t.Fatalf("members=%d name=%s", f.Members(), f.Name())
	}
}

func TestFanOutOneFailureDoesNotBlockOthers(t *testing.T) {
	a, b, c := &fanFake{name: "a"}, &fanFake{name: "b", err: errors.New("boom")}, &fanFake{name: "c"}
	err := NewFanOutChannel([]delivery.Channel{a, b, c}).Send(context.Background(), delivery.Event{ID: "x"})
	if err == nil || !strings.Contains(err.Error(), "b:") {
		t.Fatalf("expected error mentioning b:, got %v", err)
	}
	if len(a.events) != 1 || len(c.events) != 1 {
		t.Fatalf("a=%d c=%d", len(a.events), len(c.events))
	}
}

func TestFanOutSkipsUnconfigured(t *testing.T) {
	off := &fanConfigurable{fanFake{name: "off", cfg: false}}
	on := &fanConfigurable{fanFake{name: "on", cfg: true}}
	if err := NewFanOutChannel([]delivery.Channel{off, on}).Send(context.Background(), delivery.Event{ID: "x"}); err != nil {
		t.Fatal(err)
	}
	if len(off.events) != 0 || len(on.events) != 1 {
		t.Fatalf("off=%d on=%d", len(off.events), len(on.events))
	}
}

func TestFanOutNoMembersReportsUndelivered(t *testing.T) {
	err := NewFanOutChannel(nil).Send(context.Background(), delivery.Event{})
	if !errors.Is(err, ErrNoConfiguredChannel) {
		t.Fatalf("want ErrNoConfiguredChannel, got %v", err)
	}
}

func TestSLOBreachFansOut(t *testing.T) {
	a, b, c := &fanFake{name: "a"}, &fanFake{name: "b", err: errors.New("down")}, &fanFake{name: "c"}
	s := sloTestScheduler(nil, NewFanOutChannel([]delivery.Channel{a, b, c}))
	base := time.Now()
	s.tick(context.Background(), base) // W30-05: baseline before the failures
	metrics.CertRenewalFailure.Add(5000)
	s.tick(context.Background(), base.Add(15*time.Minute))
	if len(a.events) == 0 || len(b.events) != len(a.events) || len(c.events) != len(a.events) {
		t.Fatalf("every member must get each page: a=%d b=%d c=%d", len(a.events), len(b.events), len(c.events))
	}
	// A failing member must not cause a re-page next sweep (breach is latched).
	n := len(a.events)
	s.tick(context.Background(), base.Add(30*time.Minute))
	if len(a.events) != n || len(b.events) != n || len(c.events) != n {
		t.Fatalf("steady breach re-paged: a=%d b=%d c=%d", len(a.events), len(b.events), len(c.events))
	}
}

func TestSLOTickPublishesBudgetStatus(t *testing.T) {
	s := sloTestScheduler(nil, nil)
	s.set = metrics.NewSLOSet(metrics.RatioSLO("renewal-success-rate", "t", 0.99, &metrics.Counter{}, &metrics.Counter{}))
	s.tick(context.Background(), time.Now())
	got := latestSLOStatus()
	if len(got) != 1 || got[0].Name != "renewal-success-rate" || got[0].HasData || got[0].BudgetRemainingPct != 100 {
		t.Fatalf("published status: %+v", got)
	}
}

// w3006Scheduler builds a scheduler whose renewal SLO reads private counters
// (90% success once feed is called), so the test controls the SLI without
// touching globals. Ratio SLOs are judged over a window, so feed must run
// after the baseline tick.
func w3006Scheduler(t *testing.T, store ConfigStore) (s *SLOScheduler, feed func()) {
	t.Helper()
	good := metrics.Default.Counter("w3006_"+t.Name()+"_good", "test")
	bad := metrics.Default.Counter("w3006_"+t.Name()+"_bad", "test")
	s = sloTestScheduler(nil, nil)
	s.set = metrics.NewSLOSet(metrics.RatioSLO("renewal-success-rate", "test", 0.99, good, bad))
	s.configStore = store
	return s, func() { good.Add(90); bad.Add(10) }
}

func renewalBreached(s *SLOScheduler, now time.Time) bool {
	return len(s.set.Evaluate(now)) > 0
}

func TestObjectiveChangeAppliesNextTick(t *testing.T) {
	t.Setenv("KRYPTKEEPER_SLO_RENEWAL_OBJECTIVE", "")
	store := newConfigTestStore(t)
	s, feed := w3006Scheduler(t, store)
	set := s.set
	now := time.Now()

	s.tick(context.Background(), now)
	feed()
	s.tick(context.Background(), now.Add(time.Minute))
	if !renewalBreached(s, now) {
		t.Fatal("90% success must breach the 0.99 default")
	}
	if err := store.Set(context.Background(), "slo.renewal_success_objective", "0.80", "tester"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	s.tick(context.Background(), now.Add(15*time.Minute))
	if renewalBreached(s, now.Add(15*time.Minute)) {
		t.Fatal("objective 0.80 must clear the breach on the next tick")
	}
	if s.set != set {
		t.Fatal("SLOSet was rebuilt; the change must apply in place")
	}
	if st := s.set.Status(now); len(st) != 1 || st[0].Objective != 0.80 {
		t.Fatalf("status objective = %+v, want 0.80", st)
	}
}

func TestObjectiveResetRestoresDefault(t *testing.T) {
	t.Setenv("KRYPTKEEPER_SLO_RENEWAL_OBJECTIVE", "")
	store := newConfigTestStore(t)
	s, feed := w3006Scheduler(t, store)
	now := time.Now()
	s.tick(context.Background(), now.Add(-time.Minute))
	feed()
	if err := store.Set(context.Background(), "slo.renewal_success_objective", "0.80", "tester"); err != nil {
		t.Fatal(err)
	}
	s.tick(context.Background(), now)
	if renewalBreached(s, now) {
		t.Fatal("override must clear the breach")
	}
	if err := store.Delete(context.Background(), "slo.renewal_success_objective"); err != nil {
		t.Fatal(err)
	}
	s.tick(context.Background(), now.Add(15*time.Minute))
	if st := s.set.Status(now); len(st) != 1 || st[0].Objective != 0.99 {
		t.Fatalf("objective after reset = %+v, want 0.99", st)
	}
}

func TestEnvObjectiveFallback(t *testing.T) {
	t.Setenv("KRYPTKEEPER_SLO_RENEWAL_OBJECTIVE", "0.95")
	s, _ := w3006Scheduler(t, nil)
	s.tick(context.Background(), time.Now())
	if st := s.set.Status(time.Now()); len(st) != 1 || st[0].Objective != 0.95 {
		t.Fatalf("env objective not applied: %+v", st)
	}
	t.Setenv("KRYPTKEEPER_SLO_RENEWAL_OBJECTIVE", "2")
	s.tick(context.Background(), time.Now())
	if st := s.set.Status(time.Now()); st[0].Objective != 0.99 {
		t.Fatalf("invalid env objective must fall back to default: %+v", st)
	}
}
