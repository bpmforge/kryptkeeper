// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newClockedCA(t *testing.T, limit int, window time.Duration) (*stubCA, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	ca, err := newStubCA(stubConfig{Limit: limit, Window: window, Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	return ca, clk
}

func TestRateLimiterSlidingWindow(t *testing.T) {
	ca, clk := newClockedCA(t, 3, 10*time.Second)
	for i := 0; i < 3; i++ {
		if ok, _ := ca.admit(clk.now()); !ok {
			t.Fatalf("order %d refused inside the limit", i)
		}
		clk.advance(time.Second) // t=1,2,3
	}
	ok, wait := ca.admit(clk.now()) // t=3, oldest accepted at t=0
	if ok {
		t.Fatal("4th order inside the window was accepted")
	}
	if wait != 7*time.Second {
		t.Fatalf("wait = %s, want 7s", wait)
	}
	clk.advance(7 * time.Second) // t=10: the t=0 order has aged out
	if ok, _ := ca.admit(clk.now()); !ok {
		t.Fatal("slot did not free after the oldest order aged out")
	}
	if ca.st.Violations != 0 || ca.st.LimitHits != 1 {
		t.Fatalf("violations=%d limit_hits=%d, want 0 and 1", ca.st.Violations, ca.st.LimitHits)
	}
}

func TestViolationCountedWhenRetryAfterIgnored(t *testing.T) {
	ca, clk := newClockedCA(t, 1, 10*time.Second)
	ca.admit(clk.now())
	if ok, _ := ca.admit(clk.now()); ok {
		t.Fatal("second order accepted")
	}
	// A sibling request that was already in flight when the 429 went out
	// breaks the window but is not a late violation.
	if ok, _ := ca.admit(clk.now()); ok {
		t.Fatal("order accepted while blocked")
	}
	if ca.st.Violations != 1 || ca.st.LateViolations != 0 {
		t.Fatalf("concurrent request: violations=%d late=%d, want 1 and 0", ca.st.Violations, ca.st.LateViolations)
	}
	clk.advance(2 * time.Second) // still inside the advertised wait
	if ok, _ := ca.admit(clk.now()); ok {
		t.Fatal("order accepted while blocked")
	}
	if ca.st.Violations != 2 || ca.st.LateViolations != 1 {
		t.Fatalf("late request: violations=%d late=%d, want 2 and 1", ca.st.Violations, ca.st.LateViolations)
	}
	clk.advance(8 * time.Second) // wait honoured
	if ok, _ := ca.admit(clk.now()); !ok {
		t.Fatal("order refused after Retry-After elapsed")
	}
	if ca.st.Violations != 2 {
		t.Fatalf("honouring Retry-After added a violation: %d", ca.st.Violations)
	}
}

func TestRetryAfterIsCeilingOfWait(t *testing.T) {
	ca, clk := newClockedCA(t, 1, 1500*time.Millisecond)
	srv := httptest.NewServer(ca.Handler())
	defer srv.Close()
	ca.admit(clk.now())
	// Drive the real handler so the header is what a client would see.
	ca.cfg.Now = clk.now
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/order", jwsBody(`{"identifiers":[{"type":"dns","value":"a.test"}]}`))
	ca.Handler().ServeHTTP(rec, req)
	if rec.Code != 429 {
		t.Fatalf("status %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "2" {
		t.Fatalf("Retry-After = %q, want 2 (ceil of 1.5s)", got)
	}
	if rec.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("content type %q", rec.Header().Get("Content-Type"))
	}
}

func TestInFlightPeakTracksOverlap(t *testing.T) {
	ca, clk := newClockedCA(t, 100, time.Minute)
	srv := httptest.NewTLSServer(ca.Handler())
	defer srv.Close()
	var orders []*acme.Order
	var clients []*acme.Client
	for i := 0; i < 3; i++ {
		c := newACMEClient(t, srv)
		o, err := c.AuthorizeOrder(context.Background(), []acme.AuthzID{{Type: "dns", Value: "p" + strconv.Itoa(i) + ".test"}})
		if err != nil {
			t.Fatal(err)
		}
		clients, orders = append(clients, c), append(orders, o)
	}
	if got := ca.Stats().PeakInFlight; got != 3 {
		t.Fatalf("peak after 3 overlapping orders = %d, want 3", got)
	}
	for i, c := range clients {
		finalizeAndFetch(t, c, orders[i], "p"+strconv.Itoa(i)+".test")
	}
	ca.mu.Lock()
	left := ca.inFlight
	ca.mu.Unlock()
	if left != 0 || ca.Stats().PeakInFlight != 3 {
		t.Fatalf("in flight %d / peak %d after all downloads, want 0 / 3", left, ca.Stats().PeakInFlight)
	}

	// An abandoned order stops counting after the idle timeout.
	c := newACMEClient(t, srv)
	if _, err := c.AuthorizeOrder(context.Background(), []acme.AuthzID{{Type: "dns", Value: "gone.test"}}); err != nil {
		t.Fatal(err)
	}
	clk.advance(2 * time.Minute)
	ca.Stats()
	ca.mu.Lock()
	left = ca.inFlight
	ca.mu.Unlock()
	if left != 0 {
		t.Fatalf("idle order still in flight: %d", left)
	}
}

func TestDuplicateFinalizeCounted(t *testing.T) {
	ca, _ := newClockedCA(t, 100, time.Minute)
	srv := httptest.NewTLSServer(ca.Handler())
	defer srv.Close()
	for i := 0; i < 2; i++ {
		c := newACMEClient(t, srv)
		o, err := c.AuthorizeOrder(context.Background(), []acme.AuthzID{{Type: "dns", Value: "dup.test"}})
		if err != nil {
			t.Fatal(err)
		}
		finalizeAndFetch(t, c, o, "dup.test")
	}
	other := newACMEClient(t, srv)
	o, _ := other.AuthorizeOrder(context.Background(), []acme.AuthzID{{Type: "dns", Value: "once.test"}})
	finalizeAndFetch(t, other, o, "once.test")
	st := ca.Stats()
	if st.FinalizedUnique != 2 || st.Duplicates != 1 {
		t.Fatalf("finalized_unique=%d duplicates=%d, want 2 and 1", st.FinalizedUnique, st.Duplicates)
	}
}

// The real client the hub uses must be able to issue from the stub.
func TestACMEClientCanIssueFromStub(t *testing.T) {
	ca, err := newStubCA(stubConfig{Limit: 100, Window: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(ca.Handler())
	defer srv.Close()
	c := newACMEClient(t, srv)
	o, err := c.AuthorizeOrder(context.Background(), []acme.AuthzID{{Type: "dns", Value: "issue.storm.test"}})
	if err != nil {
		t.Fatal(err)
	}
	authz, err := c.GetAuthorization(context.Background(), o.AuthzURLs[0])
	if err != nil || authz.Status != acme.StatusValid {
		t.Fatalf("authorization: %v %+v", err, authz)
	}
	chain := finalizeAndFetch(t, c, o, "issue.storm.test")
	if len(chain) != 2 {
		t.Fatalf("chain has %d certs, want leaf+root", len(chain))
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "issue.storm.test" {
		t.Fatalf("SANs = %v", leaf.DNSNames)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.RootPEM())
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "issue.storm.test"}); err != nil {
		t.Fatalf("leaf does not verify against the stub root: %v", err)
	}
}

func newACMEClient(t *testing.T, srv *httptest.Server) *acme.Client {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hc := srv.Client()
	hc.Transport.(interface{ CloseIdleConnections() }).CloseIdleConnections()
	c := &acme.Client{Key: key, DirectoryURL: srv.URL + "/directory", HTTPClient: hc}
	if _, err := c.Register(context.Background(), &acme.Account{}, acme.AcceptTOS); err != nil && err != acme.ErrAccountAlreadyExists {
		t.Fatal(err)
	}
	return c
}

// finalizeAndFetch drives finalize + download exactly as connector_acme.go does.
func finalizeAndFetch(t *testing.T, c *acme.Client, o *acme.Order, name string) [][]byte {
	t.Helper()
	if _, err := c.WaitOrder(context.Background(), o.URI); err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{name}}, key)
	if err != nil {
		t.Fatal(err)
	}
	chain, _, err := c.CreateOrderCert(context.Background(), o.FinalizeURL, csr, true)
	if err != nil {
		t.Fatal(err)
	}
	return chain
}

func jwsBody(payload string) *strings.Reader {
	return strings.NewReader(`{"protected":"e30","payload":"` + base64.RawURLEncoding.EncodeToString([]byte(payload)) + `","signature":"AA"}`)
}

func mustDER(t *testing.T, certPEM []byte) []byte {
	t.Helper()
	b, _ := pem.Decode(certPEM)
	if b == nil {
		t.Fatal("not PEM")
	}
	return b.Bytes
}
