// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import "testing"

// S-L8: per-component caps did not bound the total; seven maxed components
// wrapped int64 to a positive ~115 years.
func TestParseValidityPeriodBoundsTotal(t *testing.T) {
	for _, tc := range []struct {
		in string
		ok bool
	}{
		{"P36500D", true},
		{"P100Y", true},
		{"P99Y364D", true},
		{"P100Y1D", false},
		{"P100Y1M", false},
		{"P100Y100W", false},
		{"P36501D", false},
		{"36501d", false},
		{"876001h", false},
		{"2562047h", false},
		// every component at its own cap: the old code wrapped to ~115y and passed
		{"P100Y1200M5214W36500DT876000H52560000M3153600000S", false},
		{"P100YT876000H", false},
	} {
		got, err := ParseValidityPeriod(tc.in)
		if tc.ok && (err != nil || got <= 0 || got > maxValidityPeriod) {
			t.Errorf("ParseValidityPeriod(%q) = %v, %v; want ok", tc.in, got, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("ParseValidityPeriod(%q) = %v; want error", tc.in, got)
		}
	}
}
