// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"kryptkeeper/internal/logging"

	"kryptkeeper/internal/connectors"
)

// W26-28: ACME upstream Retry-After backoff and rate-limit gate.
//
// When the upstream CA rate-limits the connector we remember its Retry-After,
// refuse to call the CA again until it (plus jitter) elapses, and surface a
// typed acmeRateLimitError so the scheduler defers the renewal instead of
// counting a failed attempt. State is package-level on purpose: connector
// structs are rebuilt per renewal (WithEnvConnectorRegistry).

const (
	defaultRateLimitWait = 10 * time.Minute // CA gave no usable Retry-After
	maxRateLimitWait     = 24 * time.Hour   // clamp a hostile/huge Retry-After
	stuckOrderWait       = 5 * time.Minute
	stuckOrderMaxRetries = 5

	acmeProblemRateLimited = "ratelimited" // suffix of urn:ietf:params:acme:error:rateLimited
)

// errACMERateLimited is matched with errors.Is on any *acmeRateLimitError.
var errACMERateLimited = errors.New("acme upstream rate limited")

// acmeRateLimitError means "retry later", never "failed". It carries no
// secrets: Reason is the CA's own detail text.
type acmeRateLimitError struct {
	ConnectorID string
	RetryAt     time.Time
	Reason      string
}

func (e *acmeRateLimitError) Error() string {
	return fmt.Sprintf("acme upstream rate limited (connector %s): retry after %s: %s",
		e.ConnectorID, e.RetryAt.UTC().Format(time.RFC3339), e.Reason)
}

func (e *acmeRateLimitError) Is(t error) bool { return t == errACMERateLimited }

// Test seams (restore with t.Cleanup).
var (
	acmeNow       = time.Now
	acmeIssueOnce = (*acmeIssuerConnector).issueOnce
	acmeJitter    = func() time.Duration { return time.Duration(rand.Int64N(int64(acmeJitterMax()) + 1)) }
	acmeAlert     = func(event, resourceID, detail string) {
		logging.Infof("ALERT %s resource=%q %q", event, resourceID, detail)
	}
	acmeBackoff     connectorBackoff = newMemoryBackoff()
	acmeStuckOrders                  = &stuckCounter{n: map[string]int{}}
)

// acmeJitterMax is the upper bound of the random delay added to a CA
// Retry-After. KRYPTKEEPER_ACME_RATELIMIT_JITTER_MAX (a Go duration) overrides
// the 60s default; a scaled-time harness shrinks it like every other wall-clock
// quantity. Invalid or negative values fall back to the default.
func acmeJitterMax() time.Duration {
	if v := strings.TrimSpace(os.Getenv("KRYPTKEEPER_ACME_RATELIMIT_JITTER_MAX")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= 0 {
			return d
		}
	}
	return 60 * time.Second
}

// connectorBackoff is the minimal shared gate. W27-33 (connector framework
// queue) can replace the implementation without touching callers.
type connectorBackoff interface {
	Block(key string, until time.Time)
	BlockedUntil(key string, now time.Time) (time.Time, bool)
	Clear(key string)
}

type memoryBackoff struct {
	mu    sync.Mutex
	until map[string]time.Time
}

func newMemoryBackoff() *memoryBackoff { return &memoryBackoff{until: map[string]time.Time{}} }

func (m *memoryBackoff) Block(key string, until time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cur, ok := m.until[key]; !ok || until.After(cur) {
		m.until[key] = until
	}
}

func (m *memoryBackoff) BlockedUntil(key string, now time.Time) (time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	until, ok := m.until[key]
	if !ok {
		return time.Time{}, false
	}
	if !now.Before(until) {
		delete(m.until, key)
		return time.Time{}, false
	}
	return until, true
}

func (m *memoryBackoff) Clear(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.until, key)
}

type stuckCounter struct {
	mu sync.Mutex
	n  map[string]int
}

func (s *stuckCounter) inc(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n[key]++
	return s.n[key]
}

func (s *stuckCounter) clear(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.n, key)
}

// acmeConnectorBackedOff reports whether the connector's gate is closed. The
// scheduler uses it to skip candidates (and dedupe audit rows) while backed off.
func acmeConnectorBackedOff(connectorID string) (time.Time, bool) {
	if connectorID == "" {
		return time.Time{}, false
	}
	return acmeBackoff.BlockedUntil(connectorID, acmeNow())
}

// ACMERetryAfter extracts the CA's Retry-After from err (unwrapping first:
// acme.RateLimit asserts *acme.Error directly and misses wrapped errors).
// limited is true for a 429, a rateLimited problem, or a 503 carrying
// Retry-After. wait is 0 when the CA gave no usable value. Reusable by any
// ACME caller that needs the CA's delay.
func ACMERetryAfter(err error) (wait time.Duration, limited bool) {
	var ae *acme.Error
	if !errors.As(err, &ae) {
		return 0, false
	}
	var hdr string
	if ae.Header != nil {
		hdr = ae.Header.Get("Retry-After")
	}
	if d, ok := ParseRetryAfterHeader(hdr, acmeNow()); ok {
		wait = d
	}
	switch {
	case ae.StatusCode == http.StatusTooManyRequests,
		strings.HasSuffix(strings.ToLower(ae.ProblemType), ":"+acmeProblemRateLimited),
		ae.StatusCode == http.StatusServiceUnavailable && hdr != "":
		return wait, true
	}
	return 0, false
}

// acmeRetryBackoff is the acme.Client.RetryBackoff. The library otherwise
// sleeps the CA's Retry-After in-process (up to hours) on a 429; returning 0
// makes it surface the error so the gate, not a blocked goroutine, owns the wait.
//
// W27-34: the 429 is also reported to the connector-wide upstream gate first,
// so sibling orders already queued on this connector hold too instead of
// each drawing its own 429.
func acmeRetryBackoff(n int, req *http.Request, res *http.Response) time.Duration {
	if res != nil {
		if res.StatusCode == http.StatusTooManyRequests ||
			(res.StatusCode == http.StatusServiceUnavailable && res.Header.Get("Retry-After") != "") {
			if req != nil {
				ra, ok := ParseRetryAfterHeader(res.Header.Get("Retry-After"), time.Now())
				if !ok || ra <= 0 {
					ra = time.Second
				}
				connectors.UpstreamGateFrom(req.Context()).NoteRetryAfter(ra)
			}
			return 0
		}
	}
	n = min(max(n, 1), 30)
	d := time.Duration(1<<uint(n-1)) * time.Second
	return min(d, 10*time.Second)
}

// acmeOrderKey identifies an order by connector + the CSR's sorted identifiers.
func acmeOrderKey(connectorID, csrPEM string) string {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return ""
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return ""
	}
	set := map[string]struct{}{}
	if csr.Subject.CommonName != "" {
		set[csr.Subject.CommonName] = struct{}{}
	}
	for _, d := range csr.DNSNames {
		set[d] = struct{}{}
	}
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	sum := sha256.Sum256([]byte(strings.Join(names, "\n")))
	return connectorID + "|" + hex.EncodeToString(sum[:])
}

// Issue wraps issueOnce with the rate-limit gate and stuck-order retry.
func (c *acmeIssuerConnector) Issue(ctx context.Context, req connectors.IssueRequest) (connectors.IssueResult, error) {
	orderKey := acmeOrderKey(c.id, req.CSRPEM)
	now := acmeNow()
	for _, key := range []string{c.id, orderKey} {
		if key == "" {
			continue
		}
		if until, ok := acmeBackoff.BlockedUntil(key, now); ok {
			return connectors.IssueResult{}, &acmeRateLimitError{ConnectorID: c.id, RetryAt: until, Reason: "gate still closed"}
		}
	}

	res, err := acmeIssueOnce(c, ctx, req)
	if err == nil {
		// The connector gate is deliberately NOT cleared here: the gate was
		// open when this call started, so if it is closed now a sibling drew a
		// 429 meanwhile, and this late success must not erase that wait. The
		// gate lapses on its own at Retry-After (+jitter).
		if orderKey != "" {
			acmeStuckOrders.clear(orderKey)
			acmeBackoff.Clear(orderKey)
		}
		return res, nil
	}

	if wait, limited := ACMERetryAfter(err); limited {
		if wait <= 0 {
			wait = defaultRateLimitWait
		}
		wait = min(wait, maxRateLimitWait)
		until := acmeNow().Add(wait + acmeJitter())
		acmeBackoff.Block(c.id, until)
		reason := "rate limited"
		var ae *acme.Error
		if errors.As(err, &ae) && ae.Detail != "" {
			reason = ae.Detail
		}
		return connectors.IssueResult{}, &acmeRateLimitError{ConnectorID: c.id, RetryAt: until, Reason: reason}
	}

	var oe *acme.OrderError
	stuck := errors.Is(err, context.DeadlineExceeded)
	if errors.As(err, &oe) {
		switch oe.Status {
		case acme.StatusPending, acme.StatusProcessing, acme.StatusReady:
			stuck = true
		}
	}
	if stuck && orderKey != "" {
		if acmeStuckOrders.inc(orderKey) < stuckOrderMaxRetries {
			until := acmeNow().Add(stuckOrderWait)
			acmeBackoff.Block(orderKey, until)
			return connectors.IssueResult{}, &acmeRateLimitError{ConnectorID: c.id, RetryAt: until, Reason: "order stuck pending, retrying"}
		}
		acmeStuckOrders.clear(orderKey)
		acmeAlert("acme.upstream.order.failed", c.id, err.Error())
	}
	return connectors.IssueResult{}, err
}
