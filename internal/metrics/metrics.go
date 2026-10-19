// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package metrics provides lightweight Prometheus-compatible counters and histograms
// using only stdlib (sync/atomic). Output format is Prometheus text exposition v0.0.4.
package metrics

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Counter is a monotonically increasing int64 counter.
type Counter struct {
	v atomic.Int64
}

func (c *Counter) Inc()        { c.v.Add(1) }
func (c *Counter) Add(n int64) { c.v.Add(n) }
func (c *Counter) Load() int64 { return c.v.Load() }

// Histogram tracks a distribution of float64 observations using fixed buckets.
// It stores count, sum, and per-bucket counts (le="upper bound").
type Histogram struct {
	bounds []float64      // sorted upper bounds
	counts []atomic.Int64 // len == len(bounds)+1 (last bucket is +Inf)
	sum    atomic.Int64   // sum * 1e6 (fixed-point, avoids float atomics)
	totalN atomic.Int64
}

func newHistogram(bounds []float64) *Histogram {
	sorted := make([]float64, len(bounds))
	copy(sorted, bounds)
	sort.Float64s(sorted)
	return &Histogram{
		bounds: sorted,
		counts: make([]atomic.Int64, len(sorted)+1),
	}
}

func (h *Histogram) Observe(v float64) {
	bucket := len(h.bounds) // +Inf bucket
	for i, b := range h.bounds {
		if v <= b {
			bucket = i
			break
		}
	}
	h.counts[bucket].Add(1)
	h.totalN.Add(1)
	h.sum.Add(int64(v * 1e6))
}

// Registry holds named metrics and serializes them as Prometheus text.
type Registry struct {
	mu         sync.RWMutex
	counters   map[string]*Counter
	histograms map[string]*Histogram
	gauges     map[string]func() []LabeledValue
	help       map[string]string
	mtype      map[string]string // "counter", "histogram" or "gauge"
}

// LabeledValue is one gauge sample. Labels is pre-rendered
// (`slo="renewal-success-rate",window="1h"`); "" means no labels.
type LabeledValue struct {
	Labels string
	Value  float64
}

var Default = &Registry{
	counters:   make(map[string]*Counter),
	histograms: make(map[string]*Histogram),
	help:       make(map[string]string),
	mtype:      make(map[string]string),
}

// Counter returns (creating if necessary) a named counter.
func (r *Registry) Counter(name, helpText string) *Counter {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.counters[name]; ok {
		return c
	}
	c := &Counter{}
	r.counters[name] = c
	r.help[name] = helpText
	r.mtype[name] = "counter"
	return c
}

// Histogram returns (creating if necessary) a named histogram with the given bucket bounds.
func (r *Registry) Histogram(name, helpText string, bounds []float64) *Histogram {
	r.mu.Lock()
	defer r.mu.Unlock()
	if h, ok := r.histograms[name]; ok {
		return h
	}
	h := newHistogram(bounds)
	r.histograms[name] = h
	r.help[name] = helpText
	r.mtype[name] = "histogram"
	return h
}

// GaugeFunc registers (or replaces) a gauge family whose samples are computed at
// scrape time. fn runs under the registry read lock, so it must not call back
// into the registry.
func (r *Registry) GaugeFunc(name, helpText string, fn func() []LabeledValue) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.gauges == nil {
		r.gauges = make(map[string]func() []LabeledValue)
	}
	r.gauges[name] = fn
	r.help[name] = helpText
	r.mtype[name] = "gauge"
}

// WritePrometheus writes all metrics in Prometheus text exposition format (v0.0.4).
func (r *Registry) WritePrometheus(w io.Writer) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Counters
	names := make([]string, 0, len(r.counters))
	for n := range r.counters {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		c := r.counters[name]
		fmt.Fprintf(w, "# HELP %s %s\n", name, r.help[name])
		fmt.Fprintf(w, "# TYPE %s counter\n", name)
		fmt.Fprintf(w, "%s %d\n", name, c.Load())
	}

	// Histograms
	hnames := make([]string, 0, len(r.histograms))
	for n := range r.histograms {
		hnames = append(hnames, n)
	}
	sort.Strings(hnames)
	for _, name := range hnames {
		h := r.histograms[name]
		fmt.Fprintf(w, "# HELP %s %s\n", name, r.help[name])
		fmt.Fprintf(w, "# TYPE %s histogram\n", name)
		var cumulative int64
		for i, bound := range h.bounds {
			cumulative += h.counts[i].Load()
			fmt.Fprintf(w, "%s_bucket{le=\"%s\"} %d\n", name, formatFloat(bound), cumulative)
		}
		cumulative += h.counts[len(h.bounds)].Load()
		fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n", name, cumulative)
		fmt.Fprintf(w, "%s_sum %s\n", name, formatFloat(float64(h.sum.Load())/1e6))
		fmt.Fprintf(w, "%s_count %d\n", name, h.totalN.Load())
	}

	// Gauges
	gnames := make([]string, 0, len(r.gauges))
	for n := range r.gauges {
		gnames = append(gnames, n)
	}
	sort.Strings(gnames)
	for _, name := range gnames {
		fmt.Fprintf(w, "# HELP %s %s\n", name, r.help[name])
		fmt.Fprintf(w, "# TYPE %s gauge\n", name)
		vals := r.gauges[name]()
		sort.SliceStable(vals, func(i, j int) bool { return vals[i].Labels < vals[j].Labels })
		for _, v := range vals {
			if v.Labels == "" {
				fmt.Fprintf(w, "%s %s\n", name, formatFloat(v.Value))
			} else {
				fmt.Fprintf(w, "%s{%s} %s\n", name, v.Labels, formatFloat(v.Value))
			}
		}
	}
}

func formatFloat(f float64) string {
	if f == math.Trunc(f) && f < 1e15 {
		return fmt.Sprintf("%.1f", f)
	}
	s := fmt.Sprintf("%g", f)
	if !strings.Contains(s, ".") && !strings.Contains(s, "e") {
		s += ".0"
	}
	return s
}
