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

// Alert is what a notify mock recorded, normalised across services so one
// suite grades them all.
type Alert struct {
	// Text is every human-readable string the service received for the alert
	// (title and body, wherever the service puts them).
	Text string
	// Key is the service-side de-duplication key (PagerDuty dedup_key, Opsgenie
	// alias); empty for services that have none.
	Key string
	// Resolved is true when the alert cleared an earlier one.
	Resolved bool
}

// Receiver is a mock of a notify plugin's service, driven by NotifySuite.
type Receiver interface {
	// Env reaches the mock: credential and HTTP client.
	Env() delivery.Env
	// Received lists the alerts the mock accepted, oldest first.
	Received() []Alert
	// FailNext makes the next request fail: "server_error" answers 500,
	// "rate_limit" answers 429 with a Retry-After of RateLimitSeconds.
	FailNext(mode string)
	// KeepsDedupe says the service de-duplicates on a key; CanResolve says it
	// can clear an alert.
	KeepsDedupe() bool
	CanResolve() bool
	Reset()
}

// RateLimitSeconds is the Retry-After a mock sends for FailNext("rate_limit").
const RateLimitSeconds = 7

// NotifySuite grades a notify plugin against its mock service. It asserts
// what the hub relies on: a 2xx is delivered, a refusal is an error the hub
// can classify (never a silent success), the service's rate-limit hint
// reaches the hub, resolves clear the right alert, and nothing in the plugin's
// events or errors carries a credential value.
func NotifySuite(t *testing.T, p *delivery.Plugin, rx Receiver) {
	ctx := context.Background()
	if p.Kind() != abi.KindNotify {
		t.Fatalf("plugin kind %q is not notify", p.Kind())
	}
	req := func(class string) abi.NotifySendRequest {
		return abi.NotifySendRequest{
			EventClass: class, Severity: abi.SeverityCritical, Title: "Certificate shop.example.com expires in 5 days",
			Body:     "Renewal failed twice.",
			Fields:   map[string]string{"common_name": "shop.example.com", "fingerprint": "ab:cd"},
			DeepLink: "https://kk.example.com/certificates/ab-cd", DedupeKey: "expiry-abcd-7",
		}
	}
	send := func(t *testing.T, r abi.NotifySendRequest) (abi.NotifySendResult, error) {
		env := rx.Env()
		var events []delivery.Event
		env.Events = func(e delivery.Event) { events = append(events, e) }
		env.Timeout = time.Minute
		res, err := p.Notify(ctx, env, r)
		var leaks []string
		for _, e := range events {
			leaks = append(leaks, e.Detail)
		}
		leaks = append(leaks, res.Detail, res.ProviderID)
		if err != nil {
			leaks = append(leaks, err.Error())
		}
		for _, name := range env.Secrets {
			v := env.Credential[name]
			for _, s := range leaks {
				if v != "" && strings.Contains(s, v) {
					t.Errorf("credential %s leaks into %q", name, s)
				}
			}
		}
		for _, s := range leaks {
			if strings.Contains(s, "-----BEGIN") {
				t.Errorf("PEM block in %q", s)
			}
		}
		return res, err
	}

	t.Run("delivers an alert", func(t *testing.T) {
		rx.Reset()
		res, err := send(t, req("certificate.expiry"))
		if err != nil || !res.Delivered {
			t.Fatalf("result %+v err %v", res, err)
		}
		got := rx.Received()
		if len(got) != 1 {
			t.Fatalf("service received %d alerts, want 1", len(got))
		}
		if !strings.Contains(got[0].Text, "shop.example.com") {
			t.Errorf("alert text %q lacks the title", got[0].Text)
		}
		if got[0].Resolved {
			t.Error("an expiry alert arrived as resolved")
		}
		if rx.KeepsDedupe() && got[0].Key != "expiry-abcd-7" {
			t.Errorf("dedupe key %q, want the request's", got[0].Key)
		}
	})

	t.Run("a repeat carries the same dedupe key", func(t *testing.T) {
		if !rx.KeepsDedupe() {
			t.Skip("service has no dedupe key")
		}
		rx.Reset()
		for range 2 {
			if _, err := send(t, req("certificate.expiry")); err != nil {
				t.Fatal(err)
			}
		}
		got := rx.Received()
		if len(got) != 2 || got[0].Key != got[1].Key {
			t.Fatalf("keys %+v", got)
		}
	})

	t.Run("a resolved class clears the alert", func(t *testing.T) {
		if !rx.CanResolve() {
			t.Skip("service cannot clear alerts")
		}
		rx.Reset()
		if _, err := send(t, req("certificate.expiry")); err != nil {
			t.Fatal(err)
		}
		if _, err := send(t, req("certificate.expiry"+abi.ResolvedSuffix)); err != nil {
			t.Fatal(err)
		}
		got := rx.Received()
		if len(got) != 2 || !got[1].Resolved || got[1].Key != got[0].Key {
			t.Fatalf("received %+v", got)
		}
	})

	t.Run("a server error is a failed delivery", func(t *testing.T) {
		rx.Reset()
		rx.FailNext("server_error")
		res, err := send(t, req("certificate.expiry"))
		var ne *delivery.NotifyError
		if err == nil || res.Delivered || !errors.As(err, &ne) {
			t.Fatalf("result %+v err %v: a 500 must surface as a NotifyError, not success", res, err)
		}
		if n := len(rx.Received()); n != 0 {
			t.Fatalf("service recorded %d alerts for a failed request", n)
		}
	})

	t.Run("a rate limit passes its retry hint on", func(t *testing.T) {
		rx.Reset()
		rx.FailNext("rate_limit")
		_, err := send(t, req("certificate.expiry"))
		var ne *delivery.NotifyError
		if !errors.As(err, &ne) || ne.RetryAfterSeconds != RateLimitSeconds {
			t.Fatalf("err %v: want a NotifyError with retry_after_seconds=%d", err, RateLimitSeconds)
		}
	})

	t.Run("then recovers", func(t *testing.T) {
		rx.Reset()
		if res, err := send(t, req("certificate.expiry")); err != nil || !res.Delivered {
			t.Fatalf("result %+v err %v", res, err)
		}
	})
}
