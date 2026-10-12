// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"sync"
	"time"
)

// renewalTriggerMaxAttempts is the retry budget for a single certificate's
// renewal-notification trigger: after this many consecutive failed attempts
// (one per scheduler poll), the fingerprint is dead-lettered instead of
// silently retrying forever with nothing but a log line to show for it.
const renewalTriggerMaxAttempts = 3

// renewalRetryTracker tracks consecutive renewal-trigger failures per
// certificate and holds the dead-letter surface once a fingerprint exhausts
// its retry budget. It is package-level (mirrors the existing
// renewalStatusHolder pattern in renewal_scheduler.go) so
// registerRenewalSLOHandler can read it without threading the scheduler
// instance through the handler registration in main.go.
type renewalRetryTracker struct {
	mu          sync.Mutex
	attempts    map[string]int
	deadLetters map[string]FailedRenewal
}

var renewalRetryState = &renewalRetryTracker{
	attempts:    make(map[string]int),
	deadLetters: make(map[string]FailedRenewal),
}

// recordRenewalTriggerFailure registers one failed renewal-notification
// attempt for fingerprint and returns the running attempt count plus whether
// this call just pushed it past its retry budget. Once consecutive failures
// reach renewalTriggerMaxAttempts, the fingerprint is (re-)dead-lettered with
// the latest failure detail — overwritten each time so the entry always
// reflects the most recent reason, not the first.
func recordRenewalTriggerFailure(fingerprint, detail string) (attempts int, deadLettered bool) {
	if fingerprint == "" {
		return 0, false
	}
	renewalRetryState.mu.Lock()
	defer renewalRetryState.mu.Unlock()
	renewalRetryState.attempts[fingerprint]++
	attempts = renewalRetryState.attempts[fingerprint]
	if attempts >= renewalTriggerMaxAttempts {
		renewalRetryState.deadLetters[fingerprint] = FailedRenewal{
			AgentID:     "renewal-scheduler",
			Fingerprint: fingerprint,
			Outcome:     "notification_dead_letter",
			Detail:      detail,
			ReportedAt:  time.Now().UTC().Format(time.RFC3339),
		}
		deadLettered = true
	}
	return attempts, deadLettered
}

// recordRenewalTriggerSuccess clears fingerprint's failure count and any
// existing dead-letter entry — a later successful notification means the
// certificate is no longer stuck, so it should stop appearing as failed.
func recordRenewalTriggerSuccess(fingerprint string) {
	if fingerprint == "" {
		return
	}
	renewalRetryState.mu.Lock()
	defer renewalRetryState.mu.Unlock()
	delete(renewalRetryState.attempts, fingerprint)
	delete(renewalRetryState.deadLetters, fingerprint)
}

// renewalDeadLetterSnapshot returns a copy of the current dead-letter
// surface for the renewal-SLO report.
func renewalDeadLetterSnapshot() []FailedRenewal {
	renewalRetryState.mu.Lock()
	defer renewalRetryState.mu.Unlock()
	out := make([]FailedRenewal, 0, len(renewalRetryState.deadLetters))
	for _, entry := range renewalRetryState.deadLetters {
		out = append(out, entry)
	}
	return out
}

// resetRenewalRetryStateForTest clears all tracked attempts/dead-letters.
// Package-level state must not leak between tests.
func resetRenewalRetryStateForTest() {
	renewalRetryState.mu.Lock()
	defer renewalRetryState.mu.Unlock()
	renewalRetryState.attempts = make(map[string]int)
	renewalRetryState.deadLetters = make(map[string]FailedRenewal)
}
