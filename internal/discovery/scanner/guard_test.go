// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"errors"
	"testing"
)

func TestCheckTarget(t *testing.T) {
	t.Setenv(EnvDenyCIDRs, "10.99.0.0/16, bogus, 192.0.2.7")
	deny := DenyCIDRsFromEnv()
	cases := []struct {
		target string
		ports  int
		max    int
		want   error
	}{
		{"169.254.169.254", 1, 100, ErrTargetDenied},
		{"169.254.169.254:80", 1, 100, ErrTargetDenied},
		{"169.254.0.0/16", 1, 1 << 20, ErrTargetDenied},
		{"169.254.1.0/24", 1, 1 << 20, ErrTargetDenied},
		{"fe80::1", 1, 100, ErrTargetDenied},
		{"::ffff:169.254.169.254", 1, 100, ErrTargetDenied},
		{"10.99.4.0/24", 1, 1000, ErrTargetDenied},
		{"192.0.2.7", 1, 100, ErrTargetDenied},
		{"10.0.0.0/24", 1, 256, nil},
		{"10.0.0.0/24", 2, 256, ErrTooManyTargets},
		{"10.0.0.0/8", 1, DefaultMaxTargets, ErrTooManyTargets},
		{"2001:db8::/48", 1, DefaultMaxTargets, ErrTooManyTargets},
		{"10.0.0.0/8", 1, 1 << 24, nil},
		{"example.com", 20, 10, nil},
		{"10.0.0.5:8443", 50, 10, nil},
	}
	for _, tc := range cases {
		if got := CheckTarget(tc.target, tc.ports, deny, tc.max); !errors.Is(got, tc.want) {
			t.Errorf("%q ports=%d max=%d: got %v want %v", tc.target, tc.ports, tc.max, got, tc.want)
		}
	}
}

func TestMaxTargetsFromEnv(t *testing.T) {
	if MaxTargetsFromEnv() != DefaultMaxTargets {
		t.Fatal("default cap wrong")
	}
	t.Setenv(EnvMaxTargets, "500")
	if MaxTargetsFromEnv() != 500 {
		t.Fatal("env override ignored")
	}
}

func TestExpandTargetsSkipsDeniedAndCaps(t *testing.T) {
	s := New(ScanConfig{Targets: []string{"169.254.169.250/30", "169.254.169.254:443", "10.0.0.1:443"}, Ports: []int{443}})
	got := s.expandTargets()
	if len(got) != 1 || got[0] != "10.0.0.1:443" {
		t.Fatalf("denied targets must be skipped, got %v", got)
	}
	t.Setenv(EnvMaxTargets, "10")
	s = New(ScanConfig{Targets: []string{"10.0.0.0/16"}, Ports: []int{443}})
	if n := len(s.expandTargets()); n != 10 {
		t.Fatalf("expansion must stop at the cap, got %d", n)
	}
}
