// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package perf compares the output of tests/perf/bench.sh with tests/perf/budgets.json.
// Without KK_PERF_RESULTS the results-driven tests skip, so `go test ./...` stays green.
package perf

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"testing"
)

type metricBudget struct {
	// Suite names the results file kind a metric belongs to: "" or "bench" for bench.sh,
	// "storm" for storm.sh (W30-22).
	Suite     string   `json:"suite"`
	Direction string   `json:"direction"`
	Bar       *float64 `json:"bar"`
	Baseline  *float64 `json:"baseline"`
}

type budgets struct {
	Version      int                     `json:"version"`
	TolerancePct float64                 `json:"tolerance_pct"`
	BarCerts     int                     `json:"bar_certs"`
	Metrics      map[string]metricBudget `json:"metrics"`
}

func loadBudgets(t *testing.T) budgets {
	t.Helper()
	raw, err := os.ReadFile("budgets.json")
	if err != nil {
		t.Fatalf("read budgets.json: %v", err)
	}
	var b budgets
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("parse budgets.json: %v", err)
	}
	return b
}

// loadResults returns the numeric fields of results.json and its suite ("bench" unless the file
// says "storm"), or skips when KK_PERF_RESULTS is unset.
func loadResults(t *testing.T) (map[string]float64, string) {
	t.Helper()
	path := os.Getenv("KK_PERF_RESULTS")
	if path == "" {
		t.Skip("KK_PERF_RESULTS not set; run tests/perf/bench.sh and point it at results.json")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var all map[string]any
	if err := json.Unmarshal(raw, &all); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	out := map[string]float64{}
	for k, v := range all {
		if f, ok := v.(float64); ok {
			out[k] = f
		}
	}
	if _, ok := out["certs"]; !ok {
		t.Fatalf("%s has no numeric certs field", path)
	}
	suite, _ := all["suite"].(string)
	if suite == "" {
		suite = "bench"
	}
	return out, suite
}

func inSuite(m metricBudget, suite string) bool {
	if m.Suite == "" {
		return suite == "bench"
	}
	return m.Suite == suite
}

func sortedNames(m map[string]metricBudget) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// checkBar reports a violation of the absolute pass bar. A zero bar on a "lower" metric means
// the value must be exactly zero (issue_failures); every other lower bar is a strict upper limit.
func checkBar(name string, m metricBudget, value float64) error {
	if m.Bar == nil {
		return nil
	}
	switch m.Direction {
	case "lower":
		if *m.Bar == 0 {
			if value != 0 {
				return fmt.Errorf("%s = %v, must be exactly 0", name, value)
			}
			return nil
		}
		if !(value < *m.Bar) {
			return fmt.Errorf("%s = %v, must be < %v", name, value, *m.Bar)
		}
	case "higher":
		if !(value >= *m.Bar) {
			return fmt.Errorf("%s = %v, must be >= %v", name, value, *m.Bar)
		}
	}
	return nil
}

// checkRegression reports a move of more than tolerancePct in the bad direction against baseline.
func checkRegression(name string, m metricBudget, value, tolerancePct float64) error {
	if m.Baseline == nil {
		return nil
	}
	f := tolerancePct / 100
	switch m.Direction {
	case "lower":
		if limit := *m.Baseline * (1 + f); value > limit {
			return fmt.Errorf("%s regressed: %v > %v (baseline %v + %v%%)", name, value, limit, *m.Baseline, tolerancePct)
		}
	case "higher":
		if limit := *m.Baseline * (1 - f); value < limit {
			return fmt.Errorf("%s regressed: %v < %v (baseline %v - %v%%)", name, value, limit, *m.Baseline, tolerancePct)
		}
	}
	return nil
}

func TestBudgetsWellFormed(t *testing.T) {
	b := loadBudgets(t)
	if b.TolerancePct != 20 {
		t.Errorf("tolerance_pct = %v, want 20", b.TolerancePct)
	}
	if b.BarCerts <= 0 {
		t.Errorf("bar_certs = %d, want > 0", b.BarCerts)
	}
	if len(b.Metrics) == 0 {
		t.Fatal("no metrics")
	}
	for _, name := range sortedNames(b.Metrics) {
		m := b.Metrics[name]
		if m.Direction != "lower" && m.Direction != "higher" {
			t.Errorf("%s: direction %q, want lower or higher", name, m.Direction)
		}
		if m.Bar == nil || math.IsNaN(*m.Bar) {
			t.Errorf("%s: bar must be numeric", name)
		}
	}
}

func TestResultsMeetBars(t *testing.T) {
	b := loadBudgets(t)
	res, suite := loadResults(t)
	if suite != "bench" {
		t.Skipf("%s results are judged by TestStormMeetsBar", suite)
	}
	certs := int(res["certs"])
	if certs < b.BarCerts {
		t.Skipf("%d certs is below bar_certs %d; no pass bar applies", certs, b.BarCerts)
	}
	if certs >= 10*b.BarCerts {
		t.Skipf("%d certs: published without a pass bar", certs)
	}
	for _, name := range sortedNames(b.Metrics) {
		if !inSuite(b.Metrics[name], suite) {
			continue
		}
		v, ok := res[name]
		if !ok {
			t.Errorf("results.json is missing %s", name)
			continue
		}
		if err := checkBar(name, b.Metrics[name], v); err != nil {
			t.Error(err)
		}
	}
}

func TestNoRegression(t *testing.T) {
	b := loadBudgets(t)
	res, suite := loadResults(t)
	if suite != "bench" {
		t.Skipf("%s results are judged by TestStormMeetsBar", suite)
	}
	if int(res["certs"]) != b.BarCerts {
		t.Skipf("baselines are recorded at %d certs; this run has %d", b.BarCerts, int(res["certs"]))
	}
	for _, name := range sortedNames(b.Metrics) {
		m := b.Metrics[name]
		if m.Baseline == nil || !inSuite(m, suite) {
			continue
		}
		v, ok := res[name]
		if !ok {
			t.Errorf("results.json is missing %s", name)
			continue
		}
		if err := checkRegression(name, m, v, b.TolerancePct); err != nil {
			t.Error(err)
		}
	}
}

// stormKey maps a storm run's certificate count to its budget key: the full 50,000-cert drain is
// judged at 60 minutes, the scaled 5,000-cert nightly run at 6.
func stormKey(certs int) (string, bool) {
	switch certs {
	case 50000:
		return "storm_drain_minutes", true
	case 5000:
		return "storm_drain_minutes_5k", true
	}
	return "", false
}

func TestStormMeetsBar(t *testing.T) {
	b := loadBudgets(t)
	res, suite := loadResults(t)
	if suite != "storm" {
		t.Skipf("%s results; TestStormMeetsBar judges storm.json", suite)
	}
	key, ok := stormKey(int(res["certs"]))
	if !ok {
		t.Skipf("%d certs has no storm budget; published without a pass bar", int(res["certs"]))
	}
	m, ok := b.Metrics[key]
	if !ok {
		t.Fatalf("budgets.json has no %s", key)
	}
	if res["failures"] != 0 {
		t.Errorf("%v of %v renewals did not succeed", res["failures"], res["certs"])
	}
	v, ok := res["storm_drain_minutes"]
	if !ok {
		t.Fatal("storm.json is missing storm_drain_minutes")
	}
	if err := checkBar(key, m, v); err != nil {
		t.Error(err)
	}
	if err := checkRegression(key, m, v, b.TolerancePct); err != nil {
		t.Error(err)
	}
}

func TestStormBudgetsPresent(t *testing.T) {
	b := loadBudgets(t)
	for key, bar := range map[string]float64{"storm_drain_minutes": 60, "storm_drain_minutes_5k": 6} {
		m, ok := b.Metrics[key]
		if !ok {
			t.Errorf("budgets.json has no %s", key)
			continue
		}
		if m.Suite != "storm" || m.Direction != "lower" || m.Bar == nil || *m.Bar != bar {
			t.Errorf("%s = %+v, want suite storm, lower, bar %v", key, m, bar)
		}
	}
}

func TestRegressionEdge(t *testing.T) {
	base := 100.0
	lower := metricBudget{Direction: "lower", Baseline: &base}
	higher := metricBudget{Direction: "higher", Baseline: &base}
	cases := []struct {
		name    string
		m       metricBudget
		value   float64
		wantErr bool
	}{
		{"lower +19% passes", lower, 119, false},
		{"lower exactly +20% passes", lower, 120, false},
		{"lower +21% fails", lower, 121, true},
		{"lower improvement passes", lower, 50, false},
		{"higher -19% passes", higher, 81, false},
		{"higher exactly -20% passes", higher, 80, false},
		{"higher -21% fails", higher, 79, true},
		{"higher improvement passes", higher, 300, false},
		{"null baseline never fails", metricBudget{Direction: "lower"}, 1e9, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkRegression("m", tc.m, tc.value, 20)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestBarEdge(t *testing.T) {
	bar := 500.0
	zero := 0.0
	sixty := 60.0
	cases := []struct {
		name    string
		m       metricBudget
		value   float64
		wantErr bool
	}{
		{"lower below bar", metricBudget{Direction: "lower", Bar: &bar}, 499.9, false},
		{"lower at bar fails", metricBudget{Direction: "lower", Bar: &bar}, 500, true},
		{"higher at bar passes", metricBudget{Direction: "higher", Bar: &bar}, 500, false},
		{"higher below bar fails", metricBudget{Direction: "higher", Bar: &bar}, 499, true},
		{"storm_drain_minutes 59.9 passes", metricBudget{Direction: "lower", Bar: &sixty}, 59.9, false},
		{"storm_drain_minutes 61 fails bar", metricBudget{Direction: "lower", Bar: &sixty}, 61, true},
		{"zero bar needs exactly zero", metricBudget{Direction: "lower", Bar: &zero}, 0, false},
		{"zero bar rejects one failure", metricBudget{Direction: "lower", Bar: &zero}, 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkBar("m", tc.m, tc.value)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
