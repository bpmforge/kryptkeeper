// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"testing"
	"time"
)

// RC1-A-02: an unbounded threshold made every tick renew a freshly issued
// successor again. The API bounds it; the scheduler caps it per successor.
func TestValidateRenewalThresholdDaysBounds(t *testing.T) {
	for _, ok := range []int{0, 1, 30, 365} {
		if err := validateRenewalThresholdDays(ok); err != nil {
			t.Errorf("%d rejected: %v", ok, err)
		}
	}
	for _, bad := range []int{-1, 366, 3650, 1 << 30} {
		if err := validateRenewalThresholdDays(bad); err == nil {
			t.Errorf("%d accepted", bad)
		}
	}
}

func TestEffectiveThresholdDaysCapsSuccessorsAtHalfLife(t *testing.T) {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cert := func(days int, successor bool) CertificateItem {
		c := CertificateItem{
			ValidFrom:  from.Format(time.RFC3339),
			ValidUntil: from.Add(time.Duration(days) * 24 * time.Hour).Format(time.RFC3339),
		}
		if successor {
			p := "predecessor"
			c.PredecessorFP = &p
		}
		return c
	}
	// A hub-renewed 90d successor with threshold >= 90 would be due again at
	// once; it is held to half its life.
	if got := effectiveThresholdDays(cert(90, true), 3650); got != 45 {
		t.Fatalf("successor with huge threshold = %d, want 45", got)
	}
	if got := effectiveThresholdDays(cert(90, true), 30); got != 30 {
		t.Fatalf("successor with sane threshold = %d, want 30", got)
	}
	// An initial or imported certificate keeps the configured value: a 72h
	// certificate under a 30d window must still renew immediately.
	if got := effectiveThresholdDays(cert(3, false), 30); got != 30 {
		t.Fatalf("initial certificate = %d, want 30", got)
	}
}
