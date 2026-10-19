// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"kryptkeeper/internal/egress"
	"kryptkeeper/internal/notifications/delivery"
)

type escRecChannel struct {
	name string
	fail bool
	mu   sync.Mutex
	got  []delivery.Event
	n    int
	// mutable lets a test flip behavior between sends.
	err error
}

func (c *escRecChannel) Name() string { return c.name }
func (c *escRecChannel) Send(_ context.Context, ev delivery.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	c.got = append(c.got, ev)
	if c.fail {
		if c.err != nil {
			return c.err
		}
		return errors.New("boom")
	}
	return nil
}
func (c *escRecChannel) attempts() int { c.mu.Lock(); defer c.mu.Unlock(); return c.n }
func (c *escRecChannel) events() []delivery.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]delivery.Event(nil), c.got...)
}

func escWaitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not met within 5s")
}

func resolveTo(ch, target string) EscalationResolver {
	return func(context.Context) (string, string) { return ch, target }
}

func TestFailedDeliveryEscalatesToSecondChannel(t *testing.T) {
	a := &escRecChannel{name: "slack", fail: true, err: errors.New(`Post "https://hooks.slack.com/services/T0/B0/SECRETTOKEN": dial tcp: refused`)}
	b := &escRecChannel{name: "email"}
	p := newDeliveryNotificationProviderForTest([]delivery.Channel{a, b}, 3, time.Millisecond, nil, resolveTo("email", "ops@example.com"))

	start := time.Now()
	if _, err := p.SendEvent(context.Background(), delivery.Event{ID: "n1", Channel: "slack", Target: "x", Subject: "s", Message: "body-with-secret"}); err != nil {
		t.Fatal(err)
	}
	escWaitFor(t, func() bool { return len(b.events()) == 1 })
	if elapsed := time.Since(start); elapsed >= 5*time.Minute {
		t.Fatalf("escalation took %s", elapsed)
	}
	if a.attempts() != 3 {
		t.Fatalf("channel A attempts = %d, want 3", a.attempts())
	}
	ev := b.events()[0]
	if ev.Subject != escalationSubject || ev.Target != "ops@example.com" || ev.ID != "esc-n1" {
		t.Fatalf("unexpected escalation event: %+v", ev)
	}
	if strings.Contains(ev.Message, "SECRETTOKEN") || strings.Contains(ev.Message, "body-with-secret") {
		t.Fatalf("escalation message leaks secret: %q", ev.Message)
	}
	escWaitFor(t, func() bool {
		res, _ := p.ListDeliveries(context.Background(), NotificationDeliveryQuery{})
		failed, sent := false, false
		for _, d := range res.Deliveries {
			if d.ID == "n1" && d.Status == "failed" {
				failed = true
			}
			if d.ID == "esc-n1" && d.Status == "sent" {
				sent = true
			}
		}
		return failed && sent
	})
}

func TestEscalationNeverLoops(t *testing.T) {
	a := &escRecChannel{name: "slack", fail: true}
	b := &escRecChannel{name: "email", fail: true}
	c := &escRecChannel{name: "webhook"}
	p := newDeliveryNotificationProviderForTest([]delivery.Channel{a, b, c}, 3, time.Millisecond, nil, resolveTo("email", "ops@example.com"))
	if _, err := p.SendEvent(context.Background(), delivery.Event{ID: "n1", Channel: "slack", Subject: "s"}); err != nil {
		t.Fatal(err)
	}
	escWaitFor(t, func() bool { return b.attempts() == 3 })
	time.Sleep(50 * time.Millisecond)
	if b.attempts() != 3 || c.attempts() != 0 {
		t.Fatalf("b=%d c=%d, want 3 and 0", b.attempts(), c.attempts())
	}
}

func TestEscalationSkippedWhenSameChannel(t *testing.T) {
	a := &escRecChannel{name: "slack", fail: true}
	p := newDeliveryNotificationProviderForTest([]delivery.Channel{a}, 2, time.Millisecond, nil, resolveTo("slack", "t"))
	if _, err := p.SendEvent(context.Background(), delivery.Event{ID: "n1", Channel: "slack"}); err != nil {
		t.Fatal(err)
	}
	escWaitFor(t, func() bool { return a.attempts() == 2 })
	time.Sleep(50 * time.Millisecond)
	if a.attempts() != 2 {
		t.Fatalf("attempts = %d, want 2", a.attempts())
	}
}

func TestEscalationSkippedWhenUnset(t *testing.T) {
	for name, resolve := range map[string]EscalationResolver{
		"nil resolver":  nil,
		"empty channel": resolveTo("", "t"),
		"empty target":  resolveTo("email", ""),
	} {
		t.Run(name, func(t *testing.T) {
			a := &escRecChannel{name: "slack", fail: true}
			b := &escRecChannel{name: "email"}
			p := newDeliveryNotificationProviderForTest([]delivery.Channel{a, b}, 2, time.Millisecond, nil, resolve)
			if _, err := p.SendEvent(context.Background(), delivery.Event{ID: "n1", Channel: "slack"}); err != nil {
				t.Fatal(err)
			}
			escWaitFor(t, func() bool { return a.attempts() == 2 })
			time.Sleep(50 * time.Millisecond)
			if b.attempts() != 0 {
				t.Fatalf("unexpected escalation send: %d", b.attempts())
			}
		})
	}
}

func TestEscalationRowMasksNonEmailTarget(t *testing.T) {
	a := &escRecChannel{name: "email", fail: true}
	b := &escRecChannel{name: "webhook"}
	const secretURL = "https://hooks.example.com/t/TOKEN123"
	p := newDeliveryNotificationProviderForTest([]delivery.Channel{a, b}, 1, time.Millisecond, nil, resolveTo("webhook", secretURL))
	if _, err := p.SendEvent(context.Background(), delivery.Event{ID: "n1", Channel: "email", Target: "a@b.c"}); err != nil {
		t.Fatal(err)
	}
	escWaitFor(t, func() bool { return b.attempts() == 1 })
	escWaitFor(t, func() bool {
		res, _ := p.ListDeliveries(context.Background(), NotificationDeliveryQuery{})
		for _, d := range res.Deliveries {
			if strings.Contains(d.Target, "TOKEN123") {
				t.Fatalf("delivery row leaks escalation target: %+v", d)
			}
			if d.ID == "esc-n1" && d.Status == "sent" {
				return true
			}
		}
		return false
	})
}

func TestProviderSendUsesLatestConfig(t *testing.T) {
	// The channel decides success from mutable "config" read at send time,
	// exactly how configuredChannel re-resolves the config store per Send.
	var mu sync.Mutex
	configured := false
	ch := &cfgChannel{name: "slack", ok: func() bool { mu.Lock(); defer mu.Unlock(); return configured }}
	p := newDeliveryNotificationProviderForTest([]delivery.Channel{ch}, 1, time.Millisecond, nil, nil)

	status := func(id string) string {
		var st string
		escWaitFor(t, func() bool {
			res, _ := p.ListDeliveries(context.Background(), NotificationDeliveryQuery{})
			for _, d := range res.Deliveries {
				if d.ID == id && (d.Status == "sent" || d.Status == "failed") {
					st = d.Status
					return true
				}
			}
			return false
		})
		return st
	}
	if _, err := p.SendEvent(context.Background(), delivery.Event{ID: "before", Channel: "slack"}); err != nil {
		t.Fatal(err)
	}
	if st := status("before"); st != "failed" {
		t.Fatalf("before config: %s", st)
	}
	mu.Lock()
	configured = true
	mu.Unlock()
	if _, err := p.SendEvent(context.Background(), delivery.Event{ID: "after", Channel: "slack"}); err != nil {
		t.Fatal(err)
	}
	if st := status("after"); st != "sent" {
		t.Fatalf("after config: %s", st)
	}
}

type cfgChannel struct {
	name string
	ok   func() bool
}

func (c *cfgChannel) Name() string { return c.name }
func (c *cfgChannel) Send(context.Context, delivery.Event) error {
	if !c.ok() {
		return errors.New("not configured")
	}
	return nil
}

// CB-14: a destination refused by the egress guard says so, and names the
// setting, instead of leaving a bare "failed" row.
func TestEgressBlockedDeliveryCarriesAnExplanation(t *testing.T) {
	a := &escRecChannel{name: "webhook", fail: true, err: fmt.Errorf("send: %w: 127.0.0.1", egress.ErrBlockedDestination)}
	p := newDeliveryNotificationProviderForTest([]delivery.Channel{a}, 1, time.Millisecond, nil, nil)
	if _, err := p.SendEvent(context.Background(), delivery.Event{ID: "n9", Channel: "webhook", Target: "http://127.0.0.1:9/h", Subject: "s", Message: "m"}); err != nil {
		t.Fatal(err)
	}
	escWaitFor(t, func() bool {
		res, _ := p.ListDeliveries(context.Background(), NotificationDeliveryQuery{})
		for _, d := range res.Deliveries {
			if d.ID == "n9" && d.Status == "failed" {
				return strings.Contains(d.FailureReason, "egress guard") && strings.Contains(d.FailureReason, "KRYPTKEEPER_EGRESS_DENY_PRIVATE")
			}
		}
		return false
	})
}
