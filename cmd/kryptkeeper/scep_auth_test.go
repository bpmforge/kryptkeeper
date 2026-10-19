// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// W20-16: SCEP runs only when enabled with a database, and never while the
// removed static-challenge variable is still set.
func TestSCEPDisabledReason(t *testing.T) {
	for _, tc := range []struct {
		name    string
		legacy  string
		enabled bool
		db      bool
		want    string
	}{
		{"enabled with DB", "", true, true, ""},
		{"legacy static challenge set", "hunter2", true, true, "no longer supported"},
		{"not enabled", "", false, true, "KRYPTKEEPER_SCEP_ENABLED=true"},
		{"no database", "", true, false, "database"},
	} {
		got := scepDisabledReason(tc.legacy, tc.enabled, tc.db)
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("%s: %q, want containing %q", tc.name, got, tc.want)
		}
		if strings.Contains(got, "hunter2") {
			t.Errorf("%s: the legacy secret leaked into the log line", tc.name)
		}
	}
}

func TestSCEPNotRSAReasonNamesTheFix(t *testing.T) {
	got := scepNotRSAReason("ca-ec")
	for _, want := range []string{"ca-ec", "RSA", "KRYPTKEEPER_SCEP_CA_ID"} {
		if !strings.Contains(got, want) {
			t.Fatalf("reason %q lacks %q", got, want)
		}
	}
}
