// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package connectors

import (
	"context"
	"errors"
	"testing"
	"time"
)

type issueOnly struct{ id string }

func (c issueOnly) ID() string                    { return c.id }
func (c issueOnly) Type() string                  { return "fake" }
func (c issueOnly) Origin() string                { return "synced" }
func (c issueOnly) Health(context.Context) Health { return Health{Status: "healthy"} }
func (c issueOnly) Issue(context.Context, IssueRequest) (IssueResult, error) {
	return IssueResult{}, nil
}

type revoker struct {
	issueOnly
	got []RevokeRequest
	err error
}

func (c *revoker) Revoke(_ context.Context, req RevokeRequest) error {
	c.got = append(c.got, req)
	return c.err
}

func TestRegistryRevokeRoutesToRevokingConnector(t *testing.T) {
	r := NewRegistry().WithThrottle(NewThrottle(Limits{MaxConcurrent: 1}, time.Now))
	rc := &revoker{issueOnly: issueOnly{id: "vault"}}
	r.Register(rc)
	r.Register(issueOnly{id: "scep"})

	if !r.SupportsRevoke("vault") || r.SupportsRevoke("scep") || r.SupportsRevoke("missing") {
		t.Fatal("SupportsRevoke wrong")
	}
	req := RevokeRequest{SerialHex: "0a1b", Reason: 1}
	if err := r.Revoke(context.Background(), "vault", req); err != nil {
		t.Fatal(err)
	}
	if len(rc.got) != 1 || rc.got[0] != req {
		t.Fatalf("connector got %+v", rc.got)
	}
	if err := r.Revoke(context.Background(), "scep", req); !errors.Is(err, ErrRevokeUnsupported) {
		t.Fatalf("want ErrRevokeUnsupported, got %v", err)
	}
	if err := r.Revoke(context.Background(), "missing", req); !errors.Is(err, ErrConnectorNotFound) {
		t.Fatalf("want ErrConnectorNotFound, got %v", err)
	}
}

func TestRegistryRevokeHonoursBackoffButNotDailyBudget(t *testing.T) {
	clk := newClock()
	th := NewThrottle(Limits{MaxConcurrent: 2, DailyBudget: 1}, clk.Now)
	r := NewRegistry().WithThrottle(th)
	rc := &revoker{issueOnly: issueOnly{id: "c"}}
	r.Register(rc)

	// Spend the day's issuance budget; revocation must still pass.
	if _, err := r.Issue(context.Background(), "c", IssueRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Issue(context.Background(), "c", IssueRequest{}); err == nil {
		t.Fatal("issuance over budget should be refused")
	}
	if err := r.Revoke(context.Background(), "c", RevokeRequest{SerialHex: "01"}); err != nil {
		t.Fatalf("revoke refused by issuance budget: %v", err)
	}

	// An upstream 429 on revoke starts the shared backoff window.
	rc.err = &RateLimitError{ConnectorID: "c", Reason: "upstream_429", RetryAfter: time.Minute}
	if err := r.Revoke(context.Background(), "c", RevokeRequest{SerialHex: "02"}); err == nil {
		t.Fatal("want upstream error")
	}
	rc.err = nil
	var rl *RateLimitError
	if err := r.Revoke(context.Background(), "c", RevokeRequest{SerialHex: "03"}); !errors.As(err, &rl) || rl.Reason != "backoff" {
		t.Fatalf("want backoff refusal, got %v", err)
	}
	if len(rc.got) != 2 {
		t.Fatalf("backoff must not reach the upstream, calls=%d", len(rc.got))
	}
	clk.Advance(2 * time.Minute)
	if err := r.Revoke(context.Background(), "c", RevokeRequest{SerialHex: "04"}); err != nil {
		t.Fatalf("after backoff: %v", err)
	}
}
