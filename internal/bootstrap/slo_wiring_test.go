// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"
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
	metrics.CertRenewalFailure.Add(5000)
	ch := &sloFakeChannel{}
	s := sloTestScheduler(nil, ch)
	s.tick(context.Background(), time.Now())
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
	s.tick(context.Background(), time.Now())
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
