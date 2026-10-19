// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"testing"
	"time"
)

// RC1-A-02: an unbounded threshold made every tick renew a freshly issued
// successor again. The API bounds it; the scheduler caps it per successor.
func TestValidateRenewalThresholdDaysBounds(t *testing.T) {
	for _, ok := range []int{0, 1, 30, 365} {
		if err := validateRenewalThresholdDays(ok); err != nil {
			t.Errorf("%d rejected: %v", ok, err)
		}
	}
	for _, bad := range []int{-1, 366, 3650, 1 << 30} {
		if err := validateRenewalThresholdDays(bad); err == nil {
			t.Errorf("%d accepted", bad)
		}
	}
}

func TestEffectiveThresholdDaysCapsSuccessorsAtHalfLife(t *testing.T) {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cert := func(days int, successor bool) CertificateItem {
		c := CertificateItem{
			ValidFrom:  from.Format(time.RFC3339),
			ValidUntil: from.Add(time.Duration(days) * 24 * time.Hour).Format(time.RFC3339),
		}
		if successor {
			p := "predecessor"
			c.PredecessorFP = &p
		}
		return c
	}
	// A hub-renewed 90d successor with threshold >= 90 would be due again at
	// once; it is held to half its life.
	if got := effectiveThresholdDays(cert(90, true), 3650); got != 45 {
		t.Fatalf("successor with huge threshold = %d, want 45", got)
	}
	if got := effectiveThresholdDays(cert(90, true), 30); got != 30 {
		t.Fatalf("successor with sane threshold = %d, want 30", got)
	}
	// An initial or imported certificate keeps the configured value: a 72h
	// certificate under a 30d window must still renew immediately.
	if got := effectiveThresholdDays(cert(3, false), 30); got != 30 {
		t.Fatalf("initial certificate = %d, want 30", got)
	}
}

// W27-04: target beats group beats the global default.
func TestEffectiveTargetThresholdPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		own, group, def            int
		wantDays                   int
		wantSource                 string
		wantHostMapEntry, wantMapD int
	}{
		{"own wins over a larger group", 10, 20, 30, 10, "target", 1, 10},
		{"own wins over a smaller group", 50, 20, 30, 50, "target", 1, 50},
		{"group wins over default", 0, 20, 30, 20, "group", 1, 20},
		{"default when neither", 0, 0, 30, 30, "default", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := ManagedTarget{ID: "t1", Host: "h.example.com", RenewalThresholdDays: tc.own}
			days, src := effectiveTargetThreshold(target, tc.group, tc.def)
			if days != tc.wantDays || src != tc.wantSource {
				t.Fatalf("got %d/%q, want %d/%q", days, src, tc.wantDays, tc.wantSource)
			}
			hosts := hostRenewalThresholds([]ManagedTarget{target}, map[string]int{"t1": tc.group})
			if len(hosts) != tc.wantHostMapEntry || hosts["h.example.com"] != tc.wantMapD {
				t.Fatalf("hostRenewalThresholds = %v", hosts)
			}
		})
	}
}

func TestGroupThresholdBounds(t *testing.T) {
	for _, bad := range []int{0, -1, 399, 1 << 20} {
		if err := validateGroupThresholdDays(bad); err == nil {
			t.Errorf("%d accepted", bad)
		}
	}
	for _, ok := range []int{1, 45, 398} {
		if err := validateGroupThresholdDays(ok); err != nil {
			t.Errorf("%d rejected: %v", ok, err)
		}
	}
	// The per-target bound is deliberately untouched by the wider group bound.
	if validateRenewalThresholdDays(366) == nil || maxRenewalThresholdDays != 365 {
		t.Fatal("the per-target bound moved")
	}
}

func TestMaxThresholdInForce(t *testing.T) {
	if got := maxThresholdInForce(30, nil); got != 30 {
		t.Fatalf("no overrides = %d", got)
	}
	if got := maxThresholdInForce(30, map[string]int{"a": 5, "b": 45}); got != 45 {
		t.Fatalf("with a 45 override = %d", got)
	}
	if got := maxThresholdInForce(30, map[string]int{"a": 5}); got != 30 {
		t.Fatalf("narrower overrides must not lower it: %d", got)
	}
}

// Change a group's threshold from 30 to 45 and the very next tick, on the same
// scheduler instance, treats a 40-day certificate as a candidate.
func TestSchedulerGroupThresholdChangeTakesEffectNextTick(t *testing.T) {
	ctx := context.Background()
	targetStore := newFreshManagedTargetStore(t)
	if _, err := targetStore.Create(ctx, mkTarget("tg-1", "h.example.com")); err != nil {
		t.Fatal(err)
	}
	groups := newFreshTargetGroupStore(t)
	if _, err := groups.Upsert(ctx, TargetGroup{Name: "g", RenewalThresholdDays: 30, TargetIDs: []string{"tg-1"}}); err != nil {
		t.Fatal(err)
	}
	certs := &reportCertProvider{items: []CertificateItem{{
		FingerprintSHA256: "forty", CommonName: "h.example.com", OwnerEmail: "o@example.com",
		ValidUntil: time.Now().UTC().Add(40 * 24 * time.Hour).Format(time.RFC3339),
	}}}
	s := &RenewalScheduler{
		certProvider: certs, notifProvider: &recordingNotificationProvider{}, auditProvider: stubAuditProvider{},
		thresholdDays: 30, pollInterval: 24 * time.Hour, targetStore: targetStore,
	}
	s.WithGroupStore(groups)

	s.runScan()
	if st := s.Status(); st.LastCandidates != 0 || st.MaxThresholdDays != 30 {
		t.Fatalf("at 30d: %+v", st)
	}

	if _, err := groups.Upsert(ctx, TargetGroup{Name: "g", RenewalThresholdDays: 45, TargetIDs: []string{"tg-1"}}); err != nil {
		t.Fatal(err)
	}
	s.runScan()
	st := s.Status()
	if st.LastCandidates != 1 {
		t.Fatalf("a 40d cert is not a candidate under a 45d group threshold: %+v", st)
	}
	if st.ThresholdDays != 30 || st.MaxThresholdDays != 45 {
		t.Fatalf("status threshold_days=%d max_threshold_days=%d, want 30/45", st.ThresholdDays, st.MaxThresholdDays)
	}
	if latest, _ := LatestRenewalStatus(); latest.MaxThresholdDays != 45 {
		t.Fatalf("published status = %+v", latest)
	}

	// A target's own threshold beats the larger group value.
	own := 10
	if _, err := targetStore.Update(ctx, "tg-1", ManagedTargetUpdate{RenewalThresholdDays: &own}); err != nil {
		t.Fatal(err)
	}
	s.runScan()
	if st := s.Status(); st.LastCandidates != 0 {
		t.Fatalf("the target's own 10d threshold lost to its group's 45d: %+v", st)
	}
}

// A scheduler built without a group store (every existing literal fixture)
// behaves exactly as before groups existed.
func TestSchedulerNilGroupStoreMeansNoGroups(t *testing.T) {
	s := &RenewalScheduler{}
	if got := s.tickGroupDays(context.Background()); got != nil {
		t.Fatalf("nil store produced %v", got)
	}
}
