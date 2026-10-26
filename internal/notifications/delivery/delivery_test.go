// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/egress"
)

type mockChannel struct {
	name     string
	sendFunc func(ctx context.Context, event Event) error
	sent     []Event
}

func (m *mockChannel) Name() string { return m.name }
func (m *mockChannel) Send(ctx context.Context, event Event) error {
	m.sent = append(m.sent, event)
	if m.sendFunc != nil {
		return m.sendFunc(ctx, event)
	}
	return nil
}

func TestDeliverSuccess(t *testing.T) {
	ch := &mockChannel{name: "email"}
	worker := newSyncWorker([]Channel{ch}, 3)

	result := worker.Deliver(context.Background(), Event{
		ID:      "evt-1",
		Channel: "email",
		Target:  "test@example.com",
		Subject: "Test Alert",
	})

	if result.Status != "sent" {
		t.Errorf("expected sent, got %s", result.Status)
	}
	if result.Attempts != 1 {
		t.Errorf("expected 1 attempt, got %d", result.Attempts)
	}
	if len(ch.sent) != 1 {
		t.Errorf("expected 1 event sent, got %d", len(ch.sent))
	}
}

func TestDeliverRetryThenSuccess(t *testing.T) {
	attempts := 0
	ch := &mockChannel{
		name: "slack",
		sendFunc: func(_ context.Context, _ Event) error {
			attempts++
			if attempts < 3 {
				return fmt.Errorf("transient error")
			}
			return nil
		},
	}
	worker := newSyncWorker([]Channel{ch}, 3)

	result := worker.Deliver(context.Background(), Event{
		ID:      "evt-retry",
		Channel: "slack",
		Target:  "#alerts",
	})

	if result.Status != "sent" {
		t.Errorf("expected sent after retries, got %s", result.Status)
	}
	if result.Attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", result.Attempts)
	}
}

func TestDeliverExhaustsRetries(t *testing.T) {
	ch := &mockChannel{
		name: "pagerduty",
		sendFunc: func(_ context.Context, _ Event) error {
			return fmt.Errorf("service unavailable")
		},
	}
	worker := newSyncWorker([]Channel{ch}, 2)

	result := worker.Deliver(context.Background(), Event{
		ID:      "evt-fail",
		Channel: "pagerduty",
		Target:  "service-key",
	})

	if result.Status != "failed" {
		t.Errorf("expected failed, got %s", result.Status)
	}
	if result.Attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", result.Attempts)
	}
	if result.Error == "" {
		t.Error("expected error message")
	}
}

func TestDeliverUnknownChannel(t *testing.T) {
	worker := newSyncWorker(nil, 3)

	result := worker.Deliver(context.Background(), Event{
		ID:      "evt-unknown",
		Channel: "sms",
	})

	if result.Status != "failed" {
		t.Errorf("expected failed for unknown channel, got %s", result.Status)
	}
	if result.Attempts != 0 {
		t.Errorf("expected 0 attempts for unknown channel, got %d", result.Attempts)
	}
}

func TestDeliverResultsRecorded(t *testing.T) {
	ch := &mockChannel{name: "email"}
	worker := newSyncWorker([]Channel{ch}, 1)

	worker.Deliver(context.Background(), Event{ID: "evt-a", Channel: "email"})
	worker.Deliver(context.Background(), Event{ID: "evt-b", Channel: "email"})

	results := worker.Results()
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
}

func TestThresholdEvaluator(t *testing.T) {
	now := time.Now()
	checkFunc := func(_ context.Context, within time.Duration) ([]CertExpiryRecord, error) {
		var certs []CertExpiryRecord
		// Cert expiring in 5 days.
		if within >= 7*24*time.Hour {
			certs = append(certs, CertExpiryRecord{
				Fingerprint: "fp-expiring-soon",
				CommonName:  "expiring.example.com",
				ValidUntil:  now.Add(5 * 24 * time.Hour),
				OwnerEmail:  "ops@example.com",
			})
		}
		// Cert expiring in 25 days.
		if within >= 30*24*time.Hour {
			certs = append(certs, CertExpiryRecord{
				Fingerprint: "fp-expiring-month",
				CommonName:  "month.example.com",
				ValidUntil:  now.Add(25 * 24 * time.Hour),
				OwnerEmail:  "sec@example.com",
			})
		}
		return certs, nil
	}

	evaluator := NewThresholdEvaluator(checkFunc, []time.Duration{
		30 * 24 * time.Hour,
		7 * 24 * time.Hour,
	})

	events, err := evaluator.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	// 30d threshold returns both certs (5d + 25d). 7d threshold returns 5d cert only.
	// Total: 3 events.
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	// The 5-day cert appears twice (once per threshold), both as critical.
	// The 25-day cert appears once from the 30d threshold, as high.
	criticalCount := 0
	highCount := 0
	for _, ev := range events {
		switch ev.Priority {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		}
	}
	if criticalCount != 2 {
		t.Errorf("expected 2 critical events (5d cert from both thresholds), got %d", criticalCount)
	}
	if highCount != 1 {
		t.Errorf("expected 1 high event (25d cert), got %d", highCount)
	}
}

func TestSMTPChannelNameAndSend(t *testing.T) {
	var gotAddr, gotFrom string
	var gotTo []string
	var gotMsg []byte
	ch := &SMTPChannel{
		Host: "smtp.example.com", Port: 587, From: "noreply@example.com",
		sendMail: func(addr string, _ smtp.Auth, from string, to []string, msg []byte) error {
			gotAddr, gotFrom, gotTo, gotMsg = addr, from, to, msg
			return nil
		},
	}
	if ch.Name() != "email" {
		t.Errorf("expected email, got %s", ch.Name())
	}
	err := ch.Send(context.Background(), Event{Target: "test@example.com", Subject: "test", Message: "body"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if gotAddr != "smtp.example.com:587" {
		t.Errorf("expected addr smtp.example.com:587, got %s", gotAddr)
	}
	if gotFrom != "noreply@example.com" {
		t.Errorf("expected from noreply@example.com, got %s", gotFrom)
	}
	if len(gotTo) != 1 || gotTo[0] != "test@example.com" {
		t.Errorf("expected to [test@example.com], got %v", gotTo)
	}
	if !strings.Contains(string(gotMsg), "Subject: test") || !strings.Contains(string(gotMsg), "body") {
		t.Errorf("expected message to contain subject and body, got %q", gotMsg)
	}
}

func TestSMTPChannelSendError(t *testing.T) {
	ch := &SMTPChannel{
		Host: "smtp.example.com", Port: 587, From: "noreply@example.com",
		sendMail: func(string, smtp.Auth, string, []string, []byte) error {
			return fmt.Errorf("connection refused")
		},
	}
	if err := ch.Send(context.Background(), Event{Target: "test@example.com", Subject: "test"}); err == nil {
		t.Error("expected error from failing sendMail, got nil")
	}
}

func TestSMTPChannelSanitizesHeaders(t *testing.T) {
	var gotMsg []byte
	ch := &SMTPChannel{
		Host: "smtp.example.com", Port: 587, From: "noreply@example.com",
		sendMail: func(_ string, _ smtp.Auth, _ string, _ []string, msg []byte) error {
			gotMsg = msg
			return nil
		},
	}
	err := ch.Send(context.Background(), Event{
		Target:  "test@example.com",
		Subject: "evil\r\nBcc: attacker@example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(string(gotMsg), "\r\nBcc:") {
		t.Errorf("expected injected header line to be neutralized, got %q", gotMsg)
	}
}

func TestSlackChannelNameAndSend(t *testing.T) {
	var gotMethod, gotContentType string
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ch := &SlackChannel{WebhookURL: srv.URL}
	if ch.Name() != "slack" {
		t.Errorf("expected slack, got %s", ch.Name())
	}
	err := ch.Send(context.Background(), Event{Target: "#alerts", Subject: "test", Message: "detail"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("expected POST, got %s", gotMethod)
	}
	if gotContentType != "application/json" {
		t.Errorf("expected application/json, got %s", gotContentType)
	}
	if gotBody["text"] != "test\ndetail" {
		t.Errorf("expected text %q, got %q", "test\ndetail", gotBody["text"])
	}
}

func TestSlackChannelSendNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ch := &SlackChannel{WebhookURL: srv.URL}
	if err := ch.Send(context.Background(), Event{Target: "#alerts", Subject: "test"}); err == nil {
		t.Error("expected error on 500 response, got nil")
	}
}

func TestPagerDutyChannelNameAndSend(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	ch := &PagerDutyChannel{RoutingKey: "test-routing-key", Endpoint: srv.URL}
	if ch.Name() != "pagerduty" {
		t.Errorf("expected pagerduty, got %s", ch.Name())
	}
	err := ch.Send(context.Background(), Event{Target: "on-call-team", Subject: "cert expiry", Priority: "critical"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if gotBody["routing_key"] != "test-routing-key" {
		t.Errorf("expected routing_key test-routing-key, got %v", gotBody["routing_key"])
	}
	if gotBody["event_action"] != "trigger" {
		t.Errorf("expected event_action trigger, got %v", gotBody["event_action"])
	}
	payload, _ := gotBody["payload"].(map[string]any)
	if payload["severity"] != "critical" {
		t.Errorf("expected severity critical, got %v", payload["severity"])
	}
}

// TestPagerDutyChannelSend_SummaryIncludesMessage covers the W19-27 fix:
// event.Message used to be silently dropped, so every PagerDuty alert
// carried the same static subject regardless of what triggered it (found
// live via tests/live/notifications/run.sh's echo receiver).
func TestPagerDutyChannelSend_SummaryIncludesMessage(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	ch := &PagerDutyChannel{RoutingKey: "key", Endpoint: srv.URL}
	err := ch.Send(context.Background(), Event{Subject: "cert expiry", Message: "fp abc123 expires in 3 days"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	payload, _ := gotBody["payload"].(map[string]any)
	summary, _ := payload["summary"].(string)
	if !strings.Contains(summary, "cert expiry") || !strings.Contains(summary, "fp abc123 expires in 3 days") {
		t.Fatalf("expected summary to contain both subject and message, got %q", summary)
	}
}

func TestPagerDutyChannelSendNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	ch := &PagerDutyChannel{RoutingKey: "key", Endpoint: srv.URL}
	if err := ch.Send(context.Background(), Event{Target: "on-call-team", Subject: "test"}); err == nil {
		t.Error("expected error on 400 response, got nil")
	}
}

func TestWebhookChannelNameAndSend(t *testing.T) {
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Custom")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ch := &WebhookChannel{URL: srv.URL, Headers: map[string]string{"X-Custom": "value"}}
	if ch.Name() != "webhook" {
		t.Errorf("expected webhook, got %s", ch.Name())
	}
	if err := ch.Send(context.Background(), Event{Target: srv.URL, Subject: "test"}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if gotHeader != "value" {
		t.Errorf("expected custom header 'value', got %q", gotHeader)
	}
}

func TestWebhookChannelSendNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	ch := &WebhookChannel{URL: srv.URL}
	if err := ch.Send(context.Background(), Event{Target: srv.URL, Subject: "test"}); err == nil {
		t.Error("expected error on 503 response, got nil")
	}
}

func TestNewRetrierDefaults(t *testing.T) {
	if NewRetrier(nil, Policy{}, nil, nil) == nil {
		t.Fatal("expected non-nil retrier")
	}
}

func TestNewThresholdEvaluatorDefaults(t *testing.T) {
	check := func(_ context.Context, _ time.Duration) ([]CertExpiryRecord, error) { return nil, nil }
	ev := NewThresholdEvaluator(check, nil)
	if ev == nil {
		t.Fatal("expected non-nil evaluator with default thresholds")
	}
}

func TestWebhookEgressGuard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	ev := Event{Subject: "t"}

	// Link-local / cloud metadata is refused regardless of policy.
	meta := &WebhookChannel{URL: "http://169.254.169.254/latest/meta-data/"}
	if err := meta.Send(context.Background(), ev); !errors.Is(err, egress.ErrBlockedDestination) {
		t.Fatalf("metadata target must be refused, got %v", err)
	}

	// Loopback is refused in production (seam off), and allowed with it on.
	egressAllowLoopback = false
	defer func() { egressAllowLoopback = true }()
	if err := (&WebhookChannel{URL: srv.URL}).Send(context.Background(), ev); !errors.Is(err, egress.ErrBlockedDestination) {
		t.Fatalf("loopback must be refused, got %v", err)
	}
}

func TestWebhookPrivateAllowedByDefaultDeniedBySwitch(t *testing.T) {
	// 10.255.255.1 is not routable here, so a permitted dial fails with a
	// timeout/unreachable error, not ErrBlockedDestination.
	egressAllowLoopback = false
	defer func() { egressAllowLoopback = true }()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	ch := &WebhookChannel{URL: "http://10.255.255.1:9/hook"}
	if err := ch.Send(ctx, Event{Subject: "t"}); errors.Is(err, egress.ErrBlockedDestination) {
		t.Fatalf("private target must be allowed by default, got %v", err)
	}
	t.Setenv(egress.EnvDenyPrivate, "true")
	if err := ch.Send(context.Background(), Event{Subject: "t"}); !errors.Is(err, egress.ErrBlockedDestination) {
		t.Fatalf("private target must be refused with %s, got %v", egress.EnvDenyPrivate, err)
	}
}

func TestWebhookRefusesCrossHostRedirect(t *testing.T) {
	hit := false
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	err := (&WebhookChannel{URL: srv.URL, Headers: map[string]string{"Authorization": "Bearer x"}}).Send(context.Background(), Event{Subject: "t"})
	if !errors.Is(err, egress.ErrBlockedDestination) || hit {
		t.Fatalf("cross-host redirect must be refused (hit=%v err=%v)", hit, err)
	}
}

func TestRedactURLsMasksTokens(t *testing.T) {
	got := RedactURLs(`Post "https://hooks.slack.com/services/T/B/SECRET": dial tcp: refused`)
	if strings.Contains(got, "SECRET") || !strings.Contains(got, "dial tcp") {
		t.Fatalf("RedactURLs = %q", got)
	}
}
