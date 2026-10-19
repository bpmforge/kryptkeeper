// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"fmt"
	"math"
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
	// Counts is non-nil for ratio SLOs (good, total cumulative event counts);
	// it feeds the windowed error budget and burn rates. Nil for latency.
	Counts func() (good, total int64)
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
	mu sync.Mutex
	// objMu guards the SLO objectives separately from mu: EvaluateAndNotify
	// holds mu while calling Evaluate, which must read objectives too.
	objMu    sync.RWMutex
	slos     []SLO
	breached map[string]bool
	// defaults holds each objective as built, so ResetObjective restores the
	// constructor value rather than a package constant.
	defaults map[string]float64

	// histMu guards hist separately from mu: EvaluateAndNotify holds mu while
	// calling Evaluate, which reads hist. Samples are in-memory only, so a hub
	// restart restarts the 30-day window ("since first observation").
	histMu sync.Mutex
	hist   map[string][]sloSample
}

type sloSample struct {
	at          time.Time
	good, total int64
}

// SLOBudgetWindow is the error-budget window.
const SLOBudgetWindow = 30 * 24 * time.Hour

// maxSLOSamples bounds per-SLO history (30d at a 15m sweep is ~2900 points).
const maxSLOSamples = 4000

func NewSLOSet(slos ...SLO) *SLOSet {
	defaults := make(map[string]float64, len(slos))
	for _, slo := range slos {
		defaults[slo.Name] = slo.Objective
	}
	return &SLOSet{slos: slos, breached: map[string]bool{}, defaults: defaults, hist: map[string][]sloSample{}}
}

// SetObjective overrides one SLO's objective at runtime. false when the SLO
// is unknown. Safe against concurrent Evaluate/Status.
func (s *SLOSet) SetObjective(name string, v float64) bool {
	s.objMu.Lock()
	defer s.objMu.Unlock()
	for i := range s.slos {
		if s.slos[i].Name == name {
			s.slos[i].Objective = v
			return true
		}
	}
	return false
}

// ResetObjective restores the objective the SLO was constructed with.
func (s *SLOSet) ResetObjective(name string) bool {
	def, ok := s.defaults[name]
	if !ok {
		return false
	}
	return s.SetObjective(name, def)
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

// RatioSLO builds a good/(good+bad) SLO; Current keeps the lifetime-rate
// semantics and Counts exposes the raw counters for windowed budgets.
func RatioSLO(name, desc string, objective float64, good, bad *Counter) SLO {
	return SLO{
		Name:        name,
		Description: desc,
		Objective:   objective,
		Current:     successRate(good, bad),
		Meets:       func(cur, obj float64) bool { return cur >= obj },
		Counts: func() (int64, int64) {
			g, b := good.Load(), bad.Load()
			return g, g + b
		},
	}
}

// DefaultPKISLOs are the shipped objectives. Objectives are the
// dashboard's documented constants; the SLI sources are the live
// registry metrics.
func DefaultPKISLOs() *SLOSet {
	atMost := func(cur, obj float64) bool { return cur <= obj }
	return NewSLOSet(
		SLO{
			Name:        "issuance-latency-p95",
			Description: "95th percentile end-to-end issuance latency (seconds)",
			Objective:   5.0,
			Current:     func() (float64, bool) { return Quantile(CertIssueDuration, 0.95) },
			Meets:       atMost,
		},
		RatioSLO("renewal-success-rate", "Fraction of renewal attempts that succeed", 0.99, CertRenewalSuccess, CertRenewalFailure),
		RatioSLO("issuance-success-rate", "Fraction of issuance attempts that succeed", 0.995, CertIssueTotal, CertIssueErrors),
	)
}

// snapshot copies the SLO slice so callers read a consistent set of
// objectives without holding objMu across SLI callbacks.
func (s *SLOSet) snapshot() []SLO {
	s.objMu.RLock()
	defer s.objMu.RUnlock()
	return append([]SLO(nil), s.slos...)
}

// Evaluate returns the SLOs currently out of objective (no latching).
// Ratio SLOs are judged over the 30-day window once Observe has recorded
// samples; before that they fall back to the lifetime rate.
func (s *SLOSet) Evaluate(now time.Time) []Breach {
	var out []Breach
	for _, slo := range s.snapshot() {
		if slo.Counts != nil {
			if w, ok := s.windowed(slo, now, SLOBudgetWindow); ok {
				if w.total > 0 && w.rate() < slo.Objective {
					out = append(out, Breach{SLO: slo.Name, Objective: slo.Objective, Actual: w.rate(), At: now})
				}
				continue
			}
		}
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

type windowCounts struct{ good, total int64 }

func (w windowCounts) rate() float64 { return float64(w.good) / float64(w.total) }

// Observe snapshots every ratio SLO's counters. Call once per sweep.
func (s *SLOSet) Observe(now time.Time) {
	s.histMu.Lock()
	defer s.histMu.Unlock()
	for _, slo := range s.slos {
		if slo.Counts == nil {
			continue
		}
		g, t := slo.Counts()
		h := append(s.hist[slo.Name], sloSample{at: now, good: g, total: t})
		cut := 0
		for cut < len(h)-1 && h[cut].at.Before(now.Add(-SLOBudgetWindow-time.Hour)) {
			cut++
		}
		if over := len(h) - cut - maxSLOSamples; over > 0 {
			cut += over
		}
		s.hist[slo.Name] = append([]sloSample(nil), h[cut:]...)
	}
}

// windowed returns the Prometheus-style increase of the SLO's counters over
// w. ok=false when no sample has been observed yet.
func (s *SLOSet) windowed(slo SLO, now time.Time, w time.Duration) (windowCounts, bool) {
	s.histMu.Lock()
	h := s.hist[slo.Name]
	if len(h) == 0 {
		s.histMu.Unlock()
		return windowCounts{}, false
	}
	pts := make([]sloSample, len(h), len(h)+1)
	copy(pts, h)
	s.histMu.Unlock()
	g, t := slo.Counts()
	pts = append(pts, sloSample{at: now, good: g, total: t})

	start := 0
	for i, p := range pts {
		if !p.at.After(now.Add(-w)) {
			start = i
		}
	}
	var out windowCounts
	for i := start + 1; i < len(pts); i++ {
		prev, cur := pts[i-1], pts[i]
		if cur.total < prev.total || cur.good < prev.good {
			// Counter reset (process restart): the new value is the increase.
			out.good += cur.good
			out.total += cur.total
			continue
		}
		out.good += cur.good - prev.good
		out.total += cur.total - prev.total
	}
	return out, true
}

// SLOStatus is the error-budget view of one SLO.
type SLOStatus struct {
	Name               string
	Objective          float64
	HasBudget          bool
	HasData            bool
	Breached           bool
	BudgetRemainingPct float64 // 0..100; 100 when there is no data
	BurnRate1h         float64
	BurnRate6h         float64
}

// Status is a pure read of the current budget and burn rates for every ratio
// SLO. Latency SLOs have no budget and are omitted.
func (s *SLOSet) Status(now time.Time) []SLOStatus {
	out := []SLOStatus{}
	for _, slo := range s.snapshot() {
		if slo.Counts == nil || slo.Objective >= 1 {
			continue
		}
		st := SLOStatus{Name: slo.Name, Objective: slo.Objective, HasBudget: true, BudgetRemainingPct: 100}
		w30, ok := s.windowed(slo, now, SLOBudgetWindow)
		if !ok {
			// No sample yet: the counters' lifetime is the best window we have.
			g, t := slo.Counts()
			w30 = windowCounts{good: g, total: t}
		}
		if w30.total > 0 {
			st.HasData = true
			burn30 := burnRate(w30, slo.Objective)
			st.BudgetRemainingPct = math.Min(100, math.Max(0, 100*(1-burn30)))
			st.Breached = w30.rate() < slo.Objective
			if w1, ok := s.windowed(slo, now, time.Hour); ok {
				st.BurnRate1h = burnRate(w1, slo.Objective)
			} else {
				st.BurnRate1h = burn30
			}
			if w6, ok := s.windowed(slo, now, 6*time.Hour); ok {
				st.BurnRate6h = burnRate(w6, slo.Objective)
			} else {
				st.BurnRate6h = burn30
			}
		}
		out = append(out, st)
	}
	return out
}

func burnRate(w windowCounts, objective float64) float64 {
	if w.total == 0 {
		return 0
	}
	errRatio := float64(w.total-w.good) / float64(w.total)
	return errRatio / (1 - objective)
}

// RegisterMetrics exports the budget gauges on r. Idempotent: re-registering
// replaces the previous closure.
func (s *SLOSet) RegisterMetrics(r *Registry) {
	gather := func(each func(st SLOStatus) []LabeledValue) func() []LabeledValue {
		return func() []LabeledValue {
			var out []LabeledValue
			for _, st := range s.Status(time.Now()) {
				if st.HasBudget {
					out = append(out, each(st)...)
				}
			}
			return out
		}
	}
	lbl := func(st SLOStatus) string { return fmt.Sprintf("slo=%q", st.Name) }
	r.GaugeFunc("kryptkeeper_slo_objective", "SLO objective as a ratio", gather(func(st SLOStatus) []LabeledValue {
		return []LabeledValue{{Labels: lbl(st), Value: st.Objective}}
	}))
	r.GaugeFunc("kryptkeeper_slo_error_budget_remaining_ratio", "Fraction of the 30-day error budget remaining (0..1)", gather(func(st SLOStatus) []LabeledValue {
		return []LabeledValue{{Labels: lbl(st), Value: st.BudgetRemainingPct / 100}}
	}))
	r.GaugeFunc("kryptkeeper_slo_burn_rate", "Error budget burn rate (1.0 = exactly on budget) per window", gather(func(st SLOStatus) []LabeledValue {
		return []LabeledValue{
			{Labels: lbl(st) + `,window="1h"`, Value: st.BurnRate1h},
			{Labels: lbl(st) + `,window="6h"`, Value: st.BurnRate6h},
		}
	}))
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
