// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"os"
	"strings"
	"sync"
	"time"

	"github.com/russellhaering/gosaml2/types"
)

// SAML request/replay guards (A2A7-008 / A07-2). gosaml2 checks signature,
// time window and audience but neither ties a response to a request this hub
// issued nor remembers assertions it has already accepted, so a captured
// SAMLResponse could be replayed until its NotOnOrAfter.
//
// Both tables are in-memory and per process, like oidcLoginStateStore and
// refreshSessions: a restart forgets them (a replay of an assertion consumed
// before the restart works until it expires, and logins in flight at the
// restart must be retried), and replicas do not share them (sticky routing
// for the login round trip is required, and a replay against a different
// replica is not caught). Both are bounded and refuse new entries when full,
// since evicting would let a flood erase the protection.
const (
	samlRequestTTL         = 10 * time.Minute
	maxPendingSAMLRequests = 4096
	maxSAMLReplayEntries   = 8192
	// samlReplayFallbackTTL applies when an assertion carries no parseable
	// NotOnOrAfter; gosaml2 would already have flagged such an assertion as
	// invalid-time, so this is only a floor.
	samlReplayFallbackTTL = 10 * time.Minute
)

// samlGuardState's zero value is ready to use.
type samlGuardState struct {
	mu       sync.Mutex
	requests map[string]time.Time // issued AuthnRequest ID -> expiry
	seen     map[string]time.Time // accepted assertion ID -> NotOnOrAfter
}

func sweepExpired(m map[string]time.Time, now time.Time) {
	for k, exp := range m {
		if !now.Before(exp) {
			delete(m, k)
		}
	}
}

// issueRequest records an AuthnRequest ID the hub just sent to the IdP.
func (g *samlGuardState) issueRequest(id string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.requests == nil {
		g.requests = map[string]time.Time{}
	}
	sweepExpired(g.requests, now)
	if len(g.requests) >= maxPendingSAMLRequests {
		return false
	}
	g.requests[id] = now.Add(samlRequestTTL)
	return true
}

// consumeRequest is single-use: it reports whether id was issued, is still
// unexpired, and removes it either way.
func (g *samlGuardState) consumeRequest(id string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	exp, ok := g.requests[id]
	delete(g.requests, id)
	return ok && now.Before(exp)
}

// acceptAssertion records an assertion ID until notOnOrAfter and reports
// false for a replay (or a full table).
func (g *samlGuardState) acceptAssertion(id string, notOnOrAfter time.Time, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen == nil {
		g.seen = map[string]time.Time{}
	}
	if exp, ok := g.seen[id]; ok && now.Before(exp) {
		return false
	}
	if len(g.seen) >= maxSAMLReplayEntries {
		sweepExpired(g.seen, now)
		if len(g.seen) >= maxSAMLReplayEntries {
			return false
		}
	}
	if !notOnOrAfter.After(now) {
		notOnOrAfter = now.Add(samlReplayFallbackTTL)
	}
	g.seen[id] = notOnOrAfter
	return true
}

// samlIdPInitiatedAllowed reports APP_SAML_ALLOW_IDP_INITIATED. IdP-initiated
// SSO has no request to bind the response to, so replay of a captured
// response is limited to the assertion cache alone; it stays off unless an
// operator whose IdP only offers that flow turns it on.
func samlIdPInitiatedAllowed() bool {
	v := strings.TrimSpace(os.Getenv("APP_SAML_ALLOW_IDP_INITIATED"))
	return strings.EqualFold(v, "true") || v == "1"
}

// samlAssertionInResponseTo returns the first InResponseTo the response's
// bearer confirmations carry ("" for an unsolicited, IdP-initiated response).
func samlAssertionInResponseTo(assertions []types.Assertion) string {
	for _, a := range assertions {
		if a.Subject == nil || a.Subject.SubjectConfirmation == nil || a.Subject.SubjectConfirmation.SubjectConfirmationData == nil {
			continue
		}
		if id := strings.TrimSpace(a.Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo); id != "" {
			return id
		}
	}
	return ""
}

// samlAssertionExpiry is the latest time the assertion could still pass
// gosaml2's own checks: its Conditions NotOnOrAfter, else the subject
// confirmation's. Zero means neither parsed.
func samlAssertionExpiry(a types.Assertion) time.Time {
	var candidates []string
	if a.Conditions != nil {
		candidates = append(candidates, a.Conditions.NotOnOrAfter)
	}
	if a.Subject != nil && a.Subject.SubjectConfirmation != nil && a.Subject.SubjectConfirmation.SubjectConfirmationData != nil {
		candidates = append(candidates, a.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter)
	}
	var latest time.Time
	for _, c := range candidates {
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(c)); err == nil && t.After(latest) {
			latest = t
		}
	}
	return latest
}

// checkSAMLResponseFreshness enforces request binding and replay protection
// on an assertion set gosaml2 has already validated. It reports false for any
// reason to refuse the login, without saying which.
func (g *samlGuardState) checkSAMLResponseFreshness(assertions []types.Assertion, allowIdPInitiated bool, now time.Time) bool {
	if len(assertions) == 0 {
		return false
	}
	if inResponseTo := samlAssertionInResponseTo(assertions); inResponseTo != "" {
		if !g.consumeRequest(inResponseTo, now) {
			return false
		}
	} else if !allowIdPInitiated {
		return false
	}
	for _, a := range assertions {
		if strings.TrimSpace(a.ID) == "" {
			return false
		}
		if !g.acceptAssertion(a.ID, samlAssertionExpiry(a), now) {
			return false
		}
	}
	return true
}
