// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
	"time"
)

func TestRetryPolicyFromEnv(t *testing.T) {
	p := retryPolicyFromEnv()
	if p.MaxAttempts != 8 || p.Base != time.Minute || p.Cap != time.Hour {
		t.Fatalf("default = %+v, want 8 attempts, 1m base, 1h cap", p)
	}
	t.Setenv("KRYPTKEEPER_NOTIFY_RETRY_ATTEMPTS", "5")
	t.Setenv("KRYPTKEEPER_NOTIFY_RETRY_BASE", "2s")
	t.Setenv("KRYPTKEEPER_NOTIFY_RETRY_CAP", "10s")
	if p := retryPolicyFromEnv(); p.MaxAttempts != 5 || p.Base != 2*time.Second || p.Cap != 10*time.Second {
		t.Fatalf("override = %+v", p)
	}
	t.Setenv("KRYPTKEEPER_NOTIFY_RETRY_ATTEMPTS", "0")
	t.Setenv("KRYPTKEEPER_NOTIFY_RETRY_BASE", "soon")
	t.Setenv("KRYPTKEEPER_NOTIFY_RETRY_CAP", "-1s")
	if p := retryPolicyFromEnv(); p.MaxAttempts != 8 || p.Base != time.Minute || p.Cap != time.Hour {
		t.Fatalf("malformed values must fall back to the defaults, got %+v", p)
	}
}
