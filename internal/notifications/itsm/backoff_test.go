// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package itsm

import (
	"testing"
	"time"
)

func TestBackoffDelay_Sequence(t *testing.T) {
	want := []time.Duration{5, 10, 20, 40, 80, 160, 320, 360}
	for i, w := range want {
		if got := BackoffDelay(i + 1); got != w*time.Minute {
			t.Errorf("attempt %d: got %v want %v", i+1, got, w*time.Minute)
		}
	}
}

func TestBackoffDelay_Cap(t *testing.T) {
	for _, a := range []int{9, 10, 64, 1 << 30} {
		if got := BackoffDelay(a); got != 6*time.Hour {
			t.Errorf("attempt %d: got %v want 6h", a, got)
		}
	}
	if BackoffDelay(0) != 5*time.Minute {
		t.Error("attempt < 1 should clamp to the base delay")
	}
}
