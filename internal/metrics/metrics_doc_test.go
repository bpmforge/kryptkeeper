// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"bytes"
	"os"
	"regexp"
	"sort"
	"testing"
)

// TestMetricsDocMatchesRegistry keeps docs/ops/METRICS.md exact: every family
// the hub exposes is documented and every documented name exists.
func TestMetricsDocMatchesRegistry(t *testing.T) {
	doc, err := os.ReadFile("../../docs/ops/METRICS.md")
	if err != nil {
		t.Fatal(err)
	}
	documented := map[string]bool{}
	for _, m := range regexp.MustCompile("(?m)^\\| `(kryptkeeper_[a-z0-9_]+)` \\|").FindAllSubmatch(doc, -1) {
		documented[string(m[1])] = true
	}

	DefaultPKISLOs().RegisterMetrics(Default)
	var buf bytes.Buffer
	Default.WritePrometheus(&buf)
	registered := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^# TYPE (\S+) `).FindAllSubmatch(buf.Bytes(), -1) {
		registered[string(m[1])] = true
	}

	var problems []string
	for n := range registered {
		if !documented[n] {
			problems = append(problems, "undocumented: "+n)
		}
	}
	for n := range documented {
		if !registered[n] {
			problems = append(problems, "documented but not registered: "+n)
		}
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}
