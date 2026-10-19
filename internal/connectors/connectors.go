// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package connectors makes the certificate issuer an interface (W11-03,
// V5/D-106) — the same move the keystore made for signing backends. The
// internal CA engine is the first implementation; upstream CAs (ACME et al,
// W11-04+) plug in beside it. A connector receives a CSR and returns
// certificate PEM: key material never crosses this boundary in either
// direction.
package connectors

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"kryptkeeper/internal/logging"
)

// Health is a connector's live probe result. A failing probe is a visible
// state, never a dropped listing (the S-50 lesson at the connector layer).
type Health struct {
	Status string `json:"status"` // healthy | degraded | unknown
	Detail string `json:"detail,omitempty"`
}

// IssueRequest carries what an issuer needs. CSRPEM is a key-adjacent field
// but holds no private material.
//
// Signer and Decrypter (W19-28) are in-process handles onto the requester's
// private key, never its bytes: a real SCEP PKIOperation must be signed by
// the key that produced CSRPEM, and its CertRep reply is encrypted back to
// that same key, so a connector speaking real SCEP cannot work from CSRPEM
// alone. Because these are interfaces wrapping live key material, only
// callers running in this same process (e.g. the renewal executor, which
// generates the key hub-side) can populate them -- there is no wire
// representation, and there must never be one. Connectors that don't need
// them (ACME, EST, WSTEP, the internal engine) ignore both fields.
type IssueRequest struct {
	CSRPEM     string
	TemplateID string
	TeamID     string
	Signer     crypto.Signer
	Decrypter  crypto.Decrypter
}

// IssueResult is the issued certificate. PEM may include the chain.
type IssueResult struct {
	FingerprintSHA256 string
	CertificatePEM    string
}

// IssuerConnector is the issuer abstraction. Origin is the estate origin
// value certificates issued through this connector carry (W11-01):
// "internal" for the in-process engine, "synced" for upstream CAs.
type IssuerConnector interface {
	ID() string
	Type() string
	Origin() string
	Health(ctx context.Context) Health
	Issue(ctx context.Context, req IssueRequest) (IssueResult, error)
}

var ErrConnectorNotFound = errors.New("connector not found")

// Registry is a concurrency-safe id→connector map. Construction-time
// registration only — no global state (house rule).
type Registry struct {
	mu         sync.RWMutex
	connectors map[string]IssuerConnector
	// throttle nil means DefaultThrottle (W27-33).
	throttle *Throttle
}

// WithThrottle makes this registry issue through t instead of DefaultThrottle.
func (r *Registry) WithThrottle(t *Throttle) *Registry {
	r.throttle = t
	return r
}

func NewRegistry() *Registry {
	return &Registry{connectors: map[string]IssuerConnector{}}
}

func (r *Registry) Register(c IssuerConnector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.connectors[c.ID()] = c
}

func (r *Registry) Get(id string) (IssuerConnector, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.connectors[id]
	if !ok {
		return nil, ErrConnectorNotFound
	}
	return c, nil
}

// List returns registered connectors in stable id order.
func (r *Registry) List() []IssuerConnector {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]IssuerConnector, 0, len(r.connectors))
	for _, c := range r.connectors {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// Issue resolves id and issues through it — the one call site the rest of
// the platform uses, so routing is uniform and testable. Every issuance passes
// the per-connector throttle; the connector's own error is returned unchanged.
func (r *Registry) Issue(ctx context.Context, id string, req IssueRequest) (IssueResult, error) {
	c, err := r.Get(id)
	if err != nil {
		return IssueResult{}, err
	}
	t := r.throttle
	if t == nil {
		t = DefaultThrottle
	}
	release, err := t.Acquire(ctx, id)
	if err != nil {
		return IssueResult{}, err
	}
	res, err := c.Issue(r.withGate(ctx, t, id), req)
	release(err)
	return res, err
}

// W27-33: one shared admission gate in front of every upstream issuance. The
// IssuerConnector method set is deliberately untouched (it would break every
// connector and fake); the hook is the Registry.Issue seam.

const (
	defaultMaxConcurrent = 10
	minRateLimitBackoff  = 30 * time.Second
	maxRateLimitBackoff  = time.Hour
	maxRetryAfter        = 24 * time.Hour
)

// Limits caps one connector. DailyBudget 0 means unlimited; MaxConcurrent <= 0
// falls back to the throttle default.
type Limits struct{ MaxConcurrent, DailyBudget int }

// RateLimitError is an upstream (or local) refusal to issue right now. Reason
// is "upstream_429", "backoff" or "daily_budget".
type RateLimitError struct {
	ConnectorID string
	Reason      string
	RetryAfter  time.Duration
	Err         error
}

func (e *RateLimitError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("connector %s rate limited (%s), retry after %s", e.ConnectorID, e.Reason, e.RetryAfter.Round(time.Second))
}

func (e *RateLimitError) Unwrap() error { return e.Err }

// ThrottleEvent is delivered to the observer when an upstream 429 starts a
// backoff window, so the caller can audit it.
type ThrottleEvent struct {
	ConnectorID string
	Reason      string
	RetryAfter  time.Duration
	Failures    int
}

// ThrottleStatus is one connector's live state for the SLO report.
type ThrottleStatus struct {
	ConnectorID      string `json:"connector_id"`
	InFlight         int    `json:"in_flight"`
	MaxConcurrent    int    `json:"max_concurrent"`
	Waiting          int    `json:"waiting"`
	RateLimitedTotal int    `json:"rate_limited_total"`
	BlockedUntil     string `json:"blocked_until"`
	DailyBudget      int    `json:"daily_budget"`
	DailyUsed        int    `json:"daily_used"`
}

type connState struct {
	inFlight, waiting, failures, rateLimited, dailyUsed int
	blockedUntil                                        time.Time
	// holdUntil is the upstream-announced pause (UpstreamGate): waiters sleep
	// through it instead of being refused.
	holdUntil time.Time
	day       string
	// notify is closed and replaced whenever capacity may have freed up.
	notify chan struct{}
}

// Throttle bounds concurrent issuances per connector, backs a connector off
// after an upstream 429 and enforces an optional daily budget.
type Throttle struct {
	mu       sync.Mutex
	def      Limits
	per      map[string]Limits
	st       map[string]*connState
	now      func() time.Time
	observer func(ThrottleEvent)
	// minBackoff is the floor of the post-429 backoff (minRateLimitBackoff
	// unless KRYPTKEEPER_CONNECTOR_MIN_BACKOFF says otherwise).
	minBackoff time.Duration
}

func NewThrottle(def Limits, now func() time.Time) *Throttle {
	if def.MaxConcurrent <= 0 {
		def.MaxConcurrent = defaultMaxConcurrent
	}
	if now == nil {
		now = time.Now
	}
	return &Throttle{def: def, per: map[string]Limits{}, st: map[string]*connState{}, now: now, minBackoff: minRateLimitBackoff}
}

func (t *Throttle) SetLimits(connectorID string, l Limits) {
	t.mu.Lock()
	t.per[connectorID] = l
	t.mu.Unlock()
}

func (t *Throttle) SetObserver(fn func(ThrottleEvent)) {
	t.mu.Lock()
	t.observer = fn
	t.mu.Unlock()
}

func (t *Throttle) limitsLocked(id string) Limits {
	l, ok := t.per[id]
	if !ok {
		return t.def
	}
	if l.MaxConcurrent <= 0 {
		l.MaxConcurrent = t.def.MaxConcurrent
	}
	return l
}

func (t *Throttle) stateLocked(id string, now time.Time) *connState {
	s, ok := t.st[id]
	if !ok {
		s = &connState{notify: make(chan struct{})}
		t.st[id] = s
	}
	if day := now.UTC().Format("2006-01-02"); s.day != day {
		s.day, s.dailyUsed = day, 0
	}
	return s
}

// Acquire reserves one issuance slot. It refuses immediately while the
// connector is backing off or its daily budget is spent, and otherwise blocks
// (honouring ctx) until a slot frees. Call release exactly once with the
// issuance error so a 429 can start a backoff window.
func (t *Throttle) Acquire(ctx context.Context, connectorID string) (func(err error), error) {
	for {
		t.mu.Lock()
		now := t.now()
		s := t.stateLocked(connectorID, now)
		lim := t.limitsLocked(connectorID)
		switch {
		case now.Before(s.blockedUntil):
			e := &RateLimitError{ConnectorID: connectorID, Reason: "backoff", RetryAfter: s.blockedUntil.Sub(now)}
			t.mu.Unlock()
			return nil, e
		case lim.DailyBudget > 0 && s.dailyUsed >= lim.DailyBudget:
			midnight := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day()+1, 0, 0, 0, 0, time.UTC)
			e := &RateLimitError{ConnectorID: connectorID, Reason: "daily_budget", RetryAfter: midnight.Sub(now)}
			t.mu.Unlock()
			return nil, e
		case s.inFlight < lim.MaxConcurrent:
			s.inFlight++
			s.dailyUsed++
			t.mu.Unlock()
			var once sync.Once
			return func(err error) { once.Do(func() { t.release(connectorID, err) }) }, nil
		}
		s.waiting++
		wake := s.notify
		t.mu.Unlock()

		var ctxErr error
		select {
		case <-wake:
		case <-ctx.Done():
			ctxErr = ctx.Err()
		}
		t.mu.Lock()
		s.waiting--
		t.mu.Unlock()
		if ctxErr != nil {
			return nil, ctxErr
		}
	}
}

func (t *Throttle) release(id string, err error) {
	var ev *ThrottleEvent
	t.mu.Lock()
	now := t.now()
	s := t.stateLocked(id, now)
	s.inFlight--
	if ra, limited := RetryAfterOf(err); limited {
		s.failures++
		wait := maxRateLimitBackoff
		if shifted := t.minBackoff << min(s.failures-1, 20); shifted > 0 && shifted < maxRateLimitBackoff { // the shift cap avoids overflow
			wait = shifted
		}
		if ra > wait {
			wait = ra
		}
		if wait > maxRateLimitBackoff {
			wait = maxRateLimitBackoff
		}
		s.blockedUntil = now.Add(wait)
		s.rateLimited++
		ev = &ThrottleEvent{ConnectorID: id, Reason: "upstream_429", RetryAfter: wait, Failures: s.failures}
	} else if err == nil && !now.Before(s.blockedUntil) {
		// A sibling that was already in flight when another call drew a 429
		// can still succeed; its success must not erase the sibling's backoff.
		s.failures = 0
	}
	close(s.notify)
	s.notify = make(chan struct{})
	obs := t.observer
	t.mu.Unlock()
	if ev != nil && obs != nil {
		obs(*ev)
	}
}

// Snapshot returns every connector the throttle has seen, sorted by id.
func (t *Throttle) Snapshot() []ThrottleStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	out := make([]ThrottleStatus, 0, len(t.st))
	for id, s := range t.st {
		s = t.stateLocked(id, now)
		lim := t.limitsLocked(id)
		blocked := ""
		if now.Before(s.blockedUntil) {
			blocked = s.blockedUntil.UTC().Format(time.RFC3339)
		}
		out = append(out, ThrottleStatus{ConnectorID: id, InFlight: s.inFlight, MaxConcurrent: lim.MaxConcurrent,
			Waiting: s.waiting, RateLimitedTotal: s.rateLimited, BlockedUntil: blocked,
			DailyBudget: lim.DailyBudget, DailyUsed: s.dailyUsed})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ConnectorID < out[j].ConnectorID })
	return out
}

// ParseRetryAfter reads a Retry-After header value (delta-seconds or an
// HTTP-date) and clamps it to [0, 24h]. Unparseable values yield 0.
func ParseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	var d time.Duration
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		if secs > int64(maxRetryAfter/time.Second) {
			return maxRetryAfter
		}
		d = time.Duration(secs) * time.Second
	} else if at, err := http.ParseTime(v); err == nil {
		d = at.Sub(now)
	}
	switch {
	case d < 0:
		return 0
	case d > maxRetryAfter:
		return maxRetryAfter
	}
	return d
}

// RetryAfterOf reports whether err is an upstream rate-limit refusal and, if
// so, how long the upstream asked callers to wait (0 when it said nothing).
func RetryAfterOf(err error) (time.Duration, bool) {
	if err == nil {
		return 0, false
	}
	var rl *RateLimitError
	if errors.As(err, &rl) {
		return rl.RetryAfter, true
	}
	var ae *acme.Error
	if errors.As(err, &ae) && ae.StatusCode == http.StatusTooManyRequests {
		return ParseRetryAfter(ae.Header.Get("Retry-After"), time.Now()), true
	}
	return 0, false
}

// Env keys, exactly as the spec freezes them.
const (
	envMaxConcurrent = "KRYPTKEEPER_CONNECTOR_MAX_CONCURRENT"
	envDailyBudget   = "KRYPTKEEPER_CONNECTOR_DAILY_BUDGET"
	envLimits        = "KRYPTKEEPER_CONNECTOR_LIMITS"
	envMinBackoff    = "KRYPTKEEPER_CONNECTOR_MIN_BACKOFF"
)

// MinBackoffFromEnv reads the floor of the post-429 backoff (a Go duration,
// default 30s). A scaled-time harness shrinks it so its Retry-After windows
// are not dwarfed by the floor. Invalid values are logged and ignored.
func MinBackoffFromEnv(getenv func(string) string) time.Duration {
	raw := strings.TrimSpace(getenv(envMinBackoff))
	if raw == "" {
		return minRateLimitBackoff
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 || d > maxRateLimitBackoff {
		logging.Infof("connectors: invalid %s=%q, using %s", envMinBackoff, raw, minRateLimitBackoff)
		return minRateLimitBackoff
	}
	return d
}

// LimitsFromEnv reads the throttle configuration. Invalid values are logged
// and replaced by the defaults, never fatal: a typo must not stop renewals.
func LimitsFromEnv(getenv func(string) string) (def Limits, per map[string]Limits) {
	def = Limits{MaxConcurrent: defaultMaxConcurrent}
	per = map[string]Limits{}
	if raw := strings.TrimSpace(getenv(envMaxConcurrent)); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			def.MaxConcurrent = n
		} else {
			logging.Infof("connectors: invalid %s=%q, using %d", envMaxConcurrent, raw, defaultMaxConcurrent)
		}
	}
	if raw := strings.TrimSpace(getenv(envDailyBudget)); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 0 {
			def.DailyBudget = n
		} else {
			logging.Infof("connectors: invalid %s=%q, using unlimited", envDailyBudget, raw)
		}
	}
	if raw := strings.TrimSpace(getenv(envLimits)); raw != "" {
		var parsed map[string]struct {
			MaxConcurrent int `json:"max_concurrent"`
			DailyBudget   int `json:"daily_budget"`
		}
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			logging.Infof("connectors: invalid %s, ignoring per-connector limits: %v", envLimits, err)
		} else {
			for id, l := range parsed {
				if l.MaxConcurrent < 0 || l.DailyBudget < 0 {
					logging.Infof("connectors: invalid limits for %q in %s, ignoring", id, envLimits)
					continue
				}
				per[id] = Limits{MaxConcurrent: l.MaxConcurrent, DailyBudget: l.DailyBudget}
			}
		}
	}
	return def, per
}

// DefaultThrottle is the process-wide gate. It is package-level on purpose
// (W27-33 decision): the registry is rebuilt for every renewal, so a
// per-registry throttle could never enforce a cap across renewals, and the
// connector-management handlers that build registries are outside this
// ticket. Tests use Registry.WithThrottle instead.
var DefaultThrottle = newEnvThrottle()

func newEnvThrottle() *Throttle {
	def, per := LimitsFromEnv(os.Getenv)
	t := NewThrottle(def, time.Now)
	t.minBackoff = MinBackoffFromEnv(os.Getenv)
	for id, l := range per {
		t.SetLimits(id, l)
	}
	return t
}
