// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kryptkeeper/internal/notifications/delivery"
)

// RC5 P1/P2: a wide rule must not turn one tick into an unbounded burst, and
// the in-memory delivery log must not grow without limit.

func TestRuleSendCapSpreadsMatchesAcrossTicks(t *testing.T) {
	const certsN, cap = 25, 10
	now := time.Now().UTC()
	items := make([]CertificateItem, 0, certsN)
	for i := 0; i < certsN; i++ {
		items = append(items, CertificateItem{
			FingerprintSHA256: fmt.Sprintf("fp-%02d", i), CommonName: fmt.Sprintf("h%d.example.com", i),
			ValidUntil: now.Add(45 * 24 * time.Hour).Format(time.RFC3339),
		})
	}
	rec := &countingRuleProvider{rules: []NotificationRule{
		{ID: "r1", Name: "60d", ThresholdDays: 60, Channel: "slack", Target: "#x", Enabled: true},
	}}
	s := &RenewalScheduler{
		certProvider: &reportCertProvider{items: items}, notifProvider: rec, auditProvider: stubAuditProvider{},
		thresholdDays: 30, pollInterval: 24 * time.Hour, cooldown: time.Hour, ruleSendCap: cap,
		cooldownStore: newFreshRenewalAlertCooldownStore(t),
	}

	for tick, want := range []int{10, 20, 25, 25} {
		s.runScan()
		if got := rec.sends.Load(); int(got) != want {
			t.Fatalf("after tick %d: want %d cumulative sends, got %d", tick+1, want, got)
		}
	}
}

func TestRuleSendCapDefaultsAndEnv(t *testing.T) {
	if got := (&RenewalScheduler{}).effectiveRuleSendCap(); got != defaultRuleSendCap {
		t.Fatalf("default cap: got %d", got)
	}
	t.Setenv(ruleSendCapEnv, "7")
	if got := NewRenewalSchedulerFromEnv(nil, nil, nil).effectiveRuleSendCap(); got != 7 {
		t.Fatalf("env cap: got %d", got)
	}
	t.Setenv(ruleSendCapEnv, "garbage")
	if got := NewRenewalSchedulerFromEnv(nil, nil, nil).effectiveRuleSendCap(); got != defaultRuleSendCap {
		t.Fatalf("bad env must fall back to default, got %d", got)
	}
}

type countingRuleProvider struct {
	NotificationProvider
	rules []NotificationRule
	sends atomic.Int64
}

func (c *countingRuleProvider) Delivers() bool { return true }
func (c *countingRuleProvider) Name() string   { return "counting" }
func (c *countingRuleProvider) ListRules(context.Context) ([]NotificationRule, error) {
	return c.rules, nil
}
func (c *countingRuleProvider) TestDelivery(context.Context, string, string, string) (NotificationTestDeliveryResult, error) {
	c.sends.Add(1)
	return NotificationTestDeliveryResult{Status: "queued", Dispatched: true}, nil
}

func TestDeliveryLogIsBounded(t *testing.T) {
	l := newDeliveryLog(5)
	for i := 0; i < 12; i++ {
		l.add(NotificationDelivery{ID: fmt.Sprintf("n%d", i)})
	}
	var ids []string
	l.each(func(d NotificationDelivery) { ids = append(ids, d.ID) })
	want := []string{"n7", "n8", "n9", "n10", "n11"}
	if fmt.Sprint(ids) != fmt.Sprint(want) {
		t.Fatalf("want newest 5 oldest-first %v, got %v", want, ids)
	}
	if l.find("n6") != nil || l.find("n11") == nil {
		t.Fatal("oldest must be dropped, newest kept")
	}
}

func TestDeliveryProviderLogBoundedUnderBurst(t *testing.T) {
	ch := &captureChannel{name: "slack"}
	p := newDeliveryNotificationProvider([]delivery.Channel{ch}, 1, nil)
	p.log = newDeliveryLog(20)
	for i := 0; i < 100; i++ {
		if _, err := p.TestDelivery(context.Background(), "slack", fmt.Sprintf("#c%d", i), "m"); err != nil {
			t.Fatal(err)
		}
	}
	res, err := p.ListDeliveries(context.Background(), NotificationDeliveryQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 20 {
		t.Fatalf("log must hold at most 20 entries, got %d", res.Total)
	}
}

// Sends run on a fixed pool: a burst never has more than deliverySendWorkers
// in flight, and creates no goroutine per send.
func TestDeliverySendsUseBoundedPool(t *testing.T) {
	var inflight, peak atomic.Int64
	release := make(chan struct{})
	ch := &blockingChannel{name: "slack", inflight: &inflight, peak: &peak, release: release}
	p := newDeliveryNotificationProvider([]delivery.Channel{ch}, 1, nil)

	before := runtime.NumGoroutine()
	const burst = 3 * deliverySendWorkers
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < burst; i++ {
			_, _ = p.TestDelivery(context.Background(), "slack", "#a", "m")
		}
	}()
	wg.Wait() // all enqueued (queue depth > burst), most still waiting
	time.Sleep(100 * time.Millisecond)
	if got := peak.Load(); got > deliverySendWorkers {
		t.Fatalf("peak concurrent sends %d exceeds pool of %d", got, deliverySendWorkers)
	}
	if grew := runtime.NumGoroutine() - before; grew > deliverySendWorkers+4 {
		t.Fatalf("goroutines grew by %d for %d sends; want a fixed pool of %d", grew, burst, deliverySendWorkers)
	}
	close(release)
}

type blockingChannel struct {
	name           string
	inflight, peak *atomic.Int64
	release        chan struct{}
}

func (b *blockingChannel) Name() string { return b.name }
func (b *blockingChannel) Send(ctx context.Context, _ delivery.Event) error {
	n := b.inflight.Add(1)
	for {
		old := b.peak.Load()
		if n <= old || b.peak.CompareAndSwap(old, n) {
			break
		}
	}
	defer b.inflight.Add(-1)
	select {
	case <-b.release:
	case <-ctx.Done():
	}
	return nil
}
