// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestAuditArchiveEligible(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	cases := []struct {
		desc string
		env  map[string]string
		want bool
	}{
		{"db (default)", nil, true},
		{"db (APP_AUDIT_PROVIDER)", nil, true},
		{"file (default)", nil, false},
		{"db (default)", map[string]string{"APP_AUDIT_DB_DSN": "postgres://elsewhere"}, false},
	}
	for _, c := range cases {
		if got := auditArchiveEligible(c.desc, env(c.env)); got != c.want {
			t.Errorf("auditArchiveEligible(%q, %v) = %v, want %v", c.desc, c.env, got, c.want)
		}
	}
}
