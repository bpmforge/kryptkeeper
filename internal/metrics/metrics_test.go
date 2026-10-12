// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"strings"
	"testing"
)

func newTestRegistry() *Registry {
	return &Registry{
		counters:   make(map[string]*Counter),
		histograms: make(map[string]*Histogram),
		help:       make(map[string]string),
		mtype:      make(map[string]string),
	}
}

func TestCounter_IncAndLoad(t *testing.T) {
	r := newTestRegistry()
	c := r.Counter("test_counter_total", "A test counter")
	if c.Load() != 0 {
		t.Fatal("expected zero initial value")
	}
	c.Inc()
	c.Inc()
	c.Add(3)
	if c.Load() != 5 {
		t.Fatalf("expected 5, got %d", c.Load())
	}
}

func TestCounter_SameNameReturnsSameInstance(t *testing.T) {
	r := newTestRegistry()
	c1 := r.Counter("dedup_counter", "help")
	c2 := r.Counter("dedup_counter", "help")
	c1.Inc()
	if c2.Load() != 1 {
		t.Fatal("same-name counters must share state")
	}
}

func TestHistogram_Observe(t *testing.T) {
	r := newTestRegistry()
	h := r.Histogram("test_hist", "A test histogram", []float64{0.01, 0.1, 1.0})

	h.Observe(0.005) // lands in le=0.01
	h.Observe(0.05)  // lands in le=0.1
	h.Observe(5.0)   // lands in +Inf

	if h.totalN.Load() != 3 {
		t.Fatalf("expected count 3, got %d", h.totalN.Load())
	}
	// First bucket (le=0.01): 1 obs
	if h.counts[0].Load() != 1 {
		t.Fatalf("bucket[0] expected 1, got %d", h.counts[0].Load())
	}
	// Second bucket (le=0.1): 1 obs
	if h.counts[1].Load() != 1 {
		t.Fatalf("bucket[1] expected 1, got %d", h.counts[1].Load())
	}
	// +Inf bucket: 1 obs
	if h.counts[3].Load() != 1 {
		t.Fatalf("+Inf bucket expected 1, got %d", h.counts[3].Load())
	}
}

func TestWritePrometheus_CounterFormat(t *testing.T) {
	r := newTestRegistry()
	c := r.Counter("http_requests_total", "Total HTTP requests")
	c.Add(42)

	var sb strings.Builder
	r.WritePrometheus(&sb)
	out := sb.String()

	if !strings.Contains(out, "# HELP http_requests_total Total HTTP requests") {
		t.Errorf("missing HELP line:\n%s", out)
	}
	if !strings.Contains(out, "# TYPE http_requests_total counter") {
		t.Errorf("missing TYPE line:\n%s", out)
	}
	if !strings.Contains(out, "http_requests_total 42") {
		t.Errorf("missing value line:\n%s", out)
	}
}

func TestWritePrometheus_HistogramFormat(t *testing.T) {
	r := newTestRegistry()
	h := r.Histogram("latency_seconds", "Request latency", []float64{0.1, 1.0})
	h.Observe(0.05)
	h.Observe(0.5)
	h.Observe(2.0)

	var sb strings.Builder
	r.WritePrometheus(&sb)
	out := sb.String()

	if !strings.Contains(out, "# TYPE latency_seconds histogram") {
		t.Errorf("missing TYPE line:\n%s", out)
	}
	if !strings.Contains(out, `latency_seconds_bucket{le="0.1"} 1`) {
		t.Errorf("bucket le=0.1 wrong:\n%s", out)
	}
	if !strings.Contains(out, `latency_seconds_bucket{le="1.0"} 2`) {
		t.Errorf("bucket le=1.0 wrong:\n%s", out)
	}
	if !strings.Contains(out, `latency_seconds_bucket{le="+Inf"} 3`) {
		t.Errorf("+Inf bucket wrong:\n%s", out)
	}
	if !strings.Contains(out, "latency_seconds_count 3") {
		t.Errorf("count wrong:\n%s", out)
	}
}

func TestVars_AllRegistered(t *testing.T) {
	// Verify the well-known vars compile and are non-nil.
	if OCSPRequestsGood == nil || OCSPRequestsRevoked == nil {
		t.Fatal("OCSP counters not initialized")
	}
	if CertIssueTotal == nil || CertIssueDuration == nil {
		t.Fatal("cert issue metrics not initialized")
	}
	if ACMEOrdersCreated == nil {
		t.Fatal("ACME counter not initialized")
	}
}
