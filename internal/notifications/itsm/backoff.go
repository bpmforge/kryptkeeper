// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package itsm

import "time"

const (
	backoffBase = 5 * time.Minute
	backoffCap  = 6 * time.Hour
)

// BackoffDelay is the wait after the attempt-th consecutive failure:
// min(6h, 5m * 2^(attempt-1)). attempt < 1 is treated as 1.
func BackoffDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	// 5m * 2^8 already exceeds the cap; clamping the shift avoids overflow.
	if attempt > 9 {
		return backoffCap
	}
	d := backoffBase << (attempt - 1)
	if d > backoffCap {
		return backoffCap
	}
	return d
}
