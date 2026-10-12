// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"fmt"
	"sync"
	"time"

	"kryptkeeper/internal/notifications/delivery"
)

// W7-03 (D-057): SRE-grade PKI SLOs over the stdlib metrics registry.
// New golden signals here; issuance latency already exists as
// kryptkeeper_cert_issue_duration_seconds in vars.go.

// Renewal outcome counters — the renewal-success-rate SLI.
var (
	CertRenewalSuccess = Default.Counter("kryptkeeper_cert_renewal_success_total", "Certificate renewals that completed successfully")
	CertRenewalFailure = Default.Counter("kryptkeeper_cert_renewal_failure_total", "Certificate renewals that failed")
)

// Time-to-expiry distribution in days, fed at issuance/renewal and by
// inventory sweeps. Buckets chosen to match the renewal thresholds ops
// actually acts on.
var expiryDayBuckets = []float64{1, 7, 14, 30, 60, 90, 180, 365}

var CertExpiryDays = Default.Histogram("kryptkeeper_cert_expiry_days", "Distribution of certificate time-to-expiry in days", expiryDayBuckets)

// SLOBreachesTotal counts ok→breach transitions across all SLOs.
var SLOBreachesTotal = Default.Counter("kryptkeeper_slo_breaches_total", "SLO breach transitions detected")

// ObserveTimeToExpiry records one certificate's remaining lifetime.
func ObserveTimeToExpiry(remaining time.Duration) {
	days := remaining.Hours() / 24
	if days < 0 {
		days = 0
	}
	CertExpiryDays.Observe(days)
}

// BucketCounts returns the histogram's per-bucket counts (last entry is
// +Inf) and upper bounds — the raw material for quantile estimation.
func (h *Histogram) BucketCounts() (bounds []float64, counts []int64) {
	bounds = make([]float64, len(h.bounds))
	copy(bounds, h.bounds)
	counts = make([]int64, len(h.counts))
	for i := range h.counts {
		counts[i] = h.counts[i].Load()
	}
	return bounds, counts
}

// Quantile estimates the q-quantile (0 < q < 1) from histogram buckets
// using Prometheus-style linear interpolation within the located
// bucket. ok=false when the histogram holds no observations.
func Quantile(h *Histogram, q float64) (float64, bool) {
	bounds, counts := h.BucketCounts()
	var total int64
	for _, c := range counts {
		total += c
	}
	if total == 0 {
		return 0, false
	}
	rank := q * float64(total)
	var cum int64
	for i, c := range counts {
		cum += c
		if float64(cum) >= rank {
			if i == len(bounds) {
				// +Inf bucket: the highest finite bound is the best
				// honest estimate (matches histogram_quantile).
				if len(bounds) == 0 {
					return 0, true
				}
				return bounds[len(bounds)-1], true
			}
			lower := 0.0
			if i > 0 {
				lower = bounds[i-1]
			}
			upper := bounds[i]
			inBucket := float64(c)
			if inBucket == 0 {
				return upper, true
			}
			posInBucket := rank - float64(cum-c)
			return lower + (upper-lower)*(posInBucket/inBucket), true
		}
	}
	return bounds[len(bounds)-1], true
}

// SLO is one objective over a live SLI. Current's bool is the no-data
// guard: an SLO with no observations is NOT breached — an empty
// cluster must never page.
type SLO struct {
	Name        string
	Description string
	Objective   float64
	Current     func() (float64, bool)
	Meets       func(current, objective float64) bool
}

// Breach is one SLO found out of objective.
type Breach struct {
	SLO       string
	Objective float64
	Actual    float64
	At        time.Time
}

// SLOSet evaluates SLOs and latches breach state so alerts fire on the
// ok→breach TRANSITION only (steady breach does not re-page; recovery
// re-arms).
type SLOSet struct {
	mu       sync.Mutex
	slos     []SLO
	breached map[string]bool
}

func NewSLOSet(slos ...SLO) *SLOSet {
	return &SLOSet{slos: slos, breached: map[string]bool{}}
}

// successRate returns good/(good+bad) with a no-data guard.
func successRate(good, bad *Counter) func() (float64, bool) {
	return func() (float64, bool) {
		g, b := good.Load(), bad.Load()
		if g+b == 0 {
			return 0, false
		}
		return float64(g) / float64(g+b), true
	}
}

// DefaultPKISLOs are the shipped objectives. Objectives are the
// dashboard's documented constants; the SLI sources are the live
// registry metrics.
func DefaultPKISLOs() *SLOSet {
	atMost := func(cur, obj float64) bool { return cur <= obj }
	atLeast := func(cur, obj float64) bool { return cur >= obj }
	return NewSLOSet(
		SLO{
			Name:        "issuance-latency-p95",
			Description: "95th percentile end-to-end issuance latency (seconds)",
			Objective:   5.0,
			Current:     func() (float64, bool) { return Quantile(CertIssueDuration, 0.95) },
			Meets:       atMost,
		},
		SLO{
			Name:        "renewal-success-rate",
			Description: "Fraction of renewal attempts that succeed",
			Objective:   0.99,
			Current:     successRate(CertRenewalSuccess, CertRenewalFailure),
			Meets:       atLeast,
		},
		SLO{
			Name:        "issuance-success-rate",
			Description: "Fraction of issuance attempts that succeed",
			Objective:   0.995,
			Current:     successRate(CertIssueTotal, CertIssueErrors),
			Meets:       atLeast,
		},
	)
}

// Evaluate returns the SLOs currently out of objective (no latching).
func (s *SLOSet) Evaluate(now time.Time) []Breach {
	var out []Breach
	for _, slo := range s.slos {
		cur, ok := slo.Current()
		if !ok {
			continue
		}
		if !slo.Meets(cur, slo.Objective) {
			out = append(out, Breach{SLO: slo.Name, Objective: slo.Objective, Actual: cur, At: now})
		}
	}
	return out
}

// EvaluateAndNotify evaluates every SLO and, for each ok→breach
// transition, sends one CRITICAL event on the W4-01 delivery channel
// and increments the breach counter. Send failures are returned, never
// swallowed — an unpageable breach must stay visible to the caller.
func (s *SLOSet) EvaluateAndNotify(ctx context.Context, now time.Time, ch delivery.Channel, target string) ([]Breach, []error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var fired []Breach
	var errs []error
	current := map[string]bool{}
	breaches := s.Evaluate(now)
	for _, b := range breaches {
		current[b.SLO] = true
		if s.breached[b.SLO] {
			continue // steady breach state: already paged
		}
		s.breached[b.SLO] = true
		SLOBreachesTotal.Inc()
		fired = append(fired, b)
		if ch == nil {
			continue
		}
		ev := delivery.Event{
			ID:        fmt.Sprintf("slo-%s-%d", b.SLO, now.Unix()),
			Channel:   ch.Name(),
			Target:    target,
			Subject:   "PKI SLO breach: " + b.SLO,
			Message:   fmt.Sprintf("SLO %q breached: current %.4g vs objective %.4g", b.SLO, b.Actual, b.Objective),
			Priority:  "critical",
			CreatedAt: now,
		}
		if err := ch.Send(ctx, ev); err != nil {
			errs = append(errs, fmt.Errorf("slo breach alert for %s: %w", b.SLO, err))
		}
	}
	// Recovery re-arms the latch.
	for name := range s.breached {
		if !current[name] {
			delete(s.breached, name)
		}
	}
	return fired, errs
}
