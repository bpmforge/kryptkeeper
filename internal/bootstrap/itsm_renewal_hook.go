// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"sync/atomic"
)

// RenewalVerifiedFunc is told that a certificate's replacement was installed
// and passed the post-install TLS check (W32-26: the ITSM service closes the
// tickets of the replaced certificate). It runs on the renewal path, so an
// implementation that talks to a remote system must not block: hand off.
type RenewalVerifiedFunc func(ctx context.Context, predecessorFingerprint, newFingerprint string)

// renewalVerifiedHook is process-wide because renewal executors are built in
// several places (scheduler, manual execute route, key lifecycle) and the
// hook must see every successful renewal. Nil means nobody is listening.
var renewalVerifiedHook atomic.Pointer[RenewalVerifiedFunc]

// SetRenewalVerifiedHook installs fn (nil removes it).
func SetRenewalVerifiedHook(fn RenewalVerifiedFunc) {
	if fn == nil {
		renewalVerifiedHook.Store(nil)
		return
	}
	renewalVerifiedHook.Store(&fn)
}

// notifyRenewalVerified reports a successful, verified renewal. A renewal that
// installed but could not be verified is not reported: its ticket stays open.
func notifyRenewalVerified(ctx context.Context, result RenewalExecuteResult) {
	if !result.Renewed || !result.Verified || !installSucceeded(result.InstallOutcome) || result.PredecessorFingerprint == "" {
		return
	}
	if fn := renewalVerifiedHook.Load(); fn != nil {
		(*fn)(ctx, result.PredecessorFingerprint, result.NewFingerprint)
	}
}
