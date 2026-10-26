// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"kryptkeeper/internal/plugins/delivery"
)

// Ticket is what a ticket mock recorded, normalised across services.
type Ticket struct {
	Key string
	// Text is every human-readable string the service received for the ticket.
	Text     string
	Resolved bool
	// Note is the comment recorded when the ticket was resolved.
	Note string
}

// TicketService is a mock of a ticket plugin's service, driven by TicketSuite.
type TicketService interface {
	Env() delivery.Env
	// Ticket returns the ticket the mock holds, if it still does.
	Ticket(key string) (Ticket, bool)
	// Count is how many live tickets the mock holds.
	Count() int
	// Delete removes a ticket behind the hub's back (an agent deleting it).
	Delete(key string)
	// FailNext makes the next request fail: "server_error" answers 500,
	// "rate_limit" 429 with Retry-After RateLimitSeconds, "unauthorized" 401.
	FailNext(mode string)
	Reset()
}

// TicketSuite grades a ticket plugin against its mock service. It asserts what
// the hub's ITSM service relies on: create returns a key and an https link,
// exists is true until the ticket is deleted externally and then false (never
// an error), resolve closes the ticket and leaves the comment, a probe for an
// unknown ticket is a clean "no", failures are classified temporary or
// permanent with the service's retry hint, and no credential value reaches an
// event, an error or a result.
func TicketSuite(t *testing.T, p *delivery.Plugin, svc TicketService) {
	ctx := context.Background()
	if p.Kind() != abi.KindTicket {
		t.Fatalf("plugin kind %q is not ticket", p.Kind())
	}
	ev := abi.TicketEvent{
		ID: "renewal_failed:ab-cd:1", Class: "renewal_failed", CN: "shop.example.com", Serial: "01AB", Risk: "high",
		DeepLink: "https://kk.example.com/certificates/ab-cd", Fingerprint: "ab:cd", NotAfter: "2026-12-01T00:00:00Z",
	}
	env := func(t *testing.T) (delivery.Env, func(string)) {
		e := svc.Env()
		var seen []string
		e.Events = func(x delivery.Event) { seen = append(seen, x.Detail) }
		e.Timeout = time.Minute
		return e, func(extra string) {
			seen = append(seen, extra)
			for _, name := range e.Secrets {
				v := e.Credential[name]
				for _, s := range seen {
					if v != "" && strings.Contains(s, v) {
						t.Errorf("credential %s leaks into %q", name, s)
					}
				}
			}
			for _, s := range seen {
				if strings.Contains(s, "-----BEGIN") {
					t.Errorf("PEM block in %q", s)
				}
			}
		}
	}
	create := func(t *testing.T) abi.TicketCreateResult {
		e, check := env(t)
		res, err := p.TicketCreate(ctx, e, ev)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		check(res.Key + res.URL)
		return res
	}

	t.Run("create opens a ticket with a key and an https link", func(t *testing.T) {
		svc.Reset()
		res := create(t)
		if res.Key == "" || !strings.HasPrefix(res.URL, "https://") {
			t.Fatalf("result %+v", res)
		}
		got, ok := svc.Ticket(res.Key)
		if !ok || !strings.Contains(got.Text, "shop.example.com") {
			t.Fatalf("service ticket %+v ok=%v lacks the certificate name", got, ok)
		}
		if got.Resolved {
			t.Error("a new ticket arrived resolved")
		}
	})

	t.Run("exists is true, then false once deleted externally", func(t *testing.T) {
		svc.Reset()
		res := create(t)
		e, check := env(t)
		ok, err := p.TicketExists(ctx, e, res.Key, res.URL)
		if err != nil || !ok {
			t.Fatalf("exists = %v, %v", ok, err)
		}
		svc.Delete(res.Key)
		ok, err = p.TicketExists(ctx, e, res.Key, res.URL)
		if err != nil || ok {
			t.Fatalf("exists after delete = %v, %v: a deleted ticket must be a clean false", ok, err)
		}
		check("")
	})

	t.Run("the probe key is a clean no", func(t *testing.T) {
		svc.Reset()
		e, check := env(t)
		ok, err := p.TicketExists(ctx, e, abi.ProbeTicketKey, "")
		if err != nil || ok {
			t.Fatalf("probe = %v, %v", ok, err)
		}
		check("")
	})

	t.Run("a key that is not a ticket id never reaches the service as a path", func(t *testing.T) {
		svc.Reset()
		e, _ := env(t)
		ok, err := p.TicketExists(ctx, e, "../../users/me", "")
		if err != nil || ok {
			t.Fatalf("exists = %v, %v", ok, err)
		}
	})

	t.Run("resolve closes the ticket with the comment", func(t *testing.T) {
		svc.Reset()
		res := create(t)
		e, check := env(t)
		if err := p.TicketResolve(ctx, e, res.Key, res.URL, "Certificate replaced and verified"); err != nil {
			t.Fatal(err)
		}
		got, ok := svc.Ticket(res.Key)
		if !ok || !got.Resolved || !strings.Contains(got.Note, "replaced and verified") {
			t.Fatalf("service ticket %+v ok=%v", got, ok)
		}
		check("")
	})

	classify := func(t *testing.T, mode string, wantTemporary bool, wantRetry int) {
		t.Helper()
		svc.Reset()
		svc.FailNext(mode)
		e, check := env(t)
		_, err := p.TicketCreate(ctx, e, ev)
		var te *delivery.TicketError
		if !errors.As(err, &te) || te.Temporary != wantTemporary || te.RetryAfterSeconds != wantRetry {
			t.Fatalf("%s: err %v, want temporary=%v retry=%d", mode, err, wantTemporary, wantRetry)
		}
		if n := svc.Count(); n != 0 {
			t.Fatalf("service holds %d tickets after a failed create", n)
		}
		check(err.Error())
	}
	t.Run("a server error is temporary", func(t *testing.T) { classify(t, "server_error", true, 0) })
	t.Run("a rate limit is temporary and passes its retry hint on", func(t *testing.T) { classify(t, "rate_limit", true, RateLimitSeconds) })
	t.Run("a refused credential is permanent", func(t *testing.T) { classify(t, "unauthorized", false, 0) })

	t.Run("a failed exists is an error, not a false", func(t *testing.T) {
		svc.Reset()
		res := create(t)
		svc.FailNext("server_error")
		e, _ := env(t)
		ok, err := p.TicketExists(ctx, e, res.Key, res.URL)
		var te *delivery.TicketError
		if ok || !errors.As(err, &te) || !te.Temporary {
			t.Fatalf("exists = %v, %v: an outage must not read as a deleted ticket (the hub would recreate it)", ok, err)
		}
	})

	t.Run("then recovers", func(t *testing.T) {
		svc.Reset()
		if res := create(t); res.Key == "" {
			t.Fatal("no key")
		}
	})
}
