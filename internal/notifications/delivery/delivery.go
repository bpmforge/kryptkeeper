// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"kryptkeeper/internal/egress"
)

// egressAllowLoopback is a test seam: production never sets it, so webhook
// targets on 127.0.0.0/8 and ::1 are refused (SEMGREP-001).
var egressAllowLoopback bool

// AllowLoopbackForTest lets another package's tests point a channel at an
// httptest server on 127.0.0.1. It returns a restore func. Never call it
// outside tests.
//
// It panics outside `go test`: a production caller must never be able to
// reopen loopback to webhook delivery (CLAUDE.md: no new global state that
// production can flip).
func AllowLoopbackForTest() (restore func()) {
	if !testing.Testing() {
		panic("delivery.AllowLoopbackForTest called outside a test binary")
	}
	prev := egressAllowLoopback
	egressAllowLoopback = true
	return func() { egressAllowLoopback = prev }
}

// newHTTPClient builds the client shared by all HTTP-based channels (Slack,
// PagerDuty, generic webhook). Private space is reachable by default (an
// internal chat server is a normal target) unless
// KRYPTKEEPER_EGRESS_DENY_PRIVATE=true; link-local/metadata never is. The
// policy is read per call so the env switch needs no restart-order care.
func newHTTPClient() *http.Client {
	return egress.NewClient(egress.PolicyFromEnv(egress.Policy{
		AllowPrivate:          true,
		AllowLoopback:         egressAllowLoopback,
		MaxRedirects:          3,
		SameHostRedirectsOnly: true,
		Timeout:               10 * time.Second,
	}))
}

// Event represents a notification event to be delivered.
type Event struct {
	ID        string
	Channel   string // email, slack, pagerduty
	Target    string // email address, webhook URL, service key
	Subject   string
	Message   string
	Priority  string // critical, high, medium, low
	CreatedAt time.Time
}

// Result is the outcome of a delivery attempt.
type Result struct {
	EventID     string
	Channel     string
	Status      string // sent, failed
	Error       string
	DeliveredAt time.Time
	Attempts    int
}

// Channel is the interface for notification delivery channels.
type Channel interface {
	Name() string
	Send(ctx context.Context, event Event) error
}

// Worker processes notification events with retry and channel routing.
type Worker struct {
	channels   map[string]Channel
	maxRetries int
	retryDelay time.Duration
	mu         sync.Mutex
	results    []Result
}

// NewWorker creates a delivery worker with the given channels.
func NewWorker(channels []Channel, maxRetries int, retryDelay time.Duration) *Worker {
	if maxRetries <= 0 {
		maxRetries = 3
	}
	if retryDelay <= 0 {
		retryDelay = 5 * time.Second
	}
	channelMap := make(map[string]Channel)
	for _, ch := range channels {
		channelMap[ch.Name()] = ch
	}
	return &Worker{
		channels:   channelMap,
		maxRetries: maxRetries,
		retryDelay: retryDelay,
	}
}

// Deliver sends an event through the appropriate channel with retry.
func (w *Worker) Deliver(ctx context.Context, event Event) Result {
	ch, ok := w.channels[event.Channel]
	if !ok {
		result := Result{
			EventID:     event.ID,
			Channel:     event.Channel,
			Status:      "failed",
			Error:       fmt.Sprintf("unknown channel: %s", event.Channel),
			DeliveredAt: time.Now().UTC(),
			Attempts:    0,
		}
		w.recordResult(result)
		return result
	}

	var lastErr error
	for attempt := 1; attempt <= w.maxRetries; attempt++ {
		err := ch.Send(ctx, event)
		if err == nil {
			result := Result{
				EventID:     event.ID,
				Channel:     event.Channel,
				Status:      "sent",
				DeliveredAt: time.Now().UTC(),
				Attempts:    attempt,
			}
			w.recordResult(result)
			return result
		}
		lastErr = err
		log.Printf("delivery attempt %d/%d for event %s on channel %s failed: %v",
			attempt, w.maxRetries, event.ID, event.Channel, err)

		if attempt < w.maxRetries {
			select {
			case <-ctx.Done():
				break
			case <-time.After(w.retryDelay * time.Duration(attempt)):
			}
		}
	}

	result := Result{
		EventID:     event.ID,
		Channel:     event.Channel,
		Status:      "failed",
		Error:       lastErr.Error(),
		DeliveredAt: time.Now().UTC(),
		Attempts:    w.maxRetries,
	}
	w.recordResult(result)
	return result
}

// Results returns all delivery results.
func (w *Worker) Results() []Result {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]Result, len(w.results))
	copy(out, w.results)
	return out
}

func (w *Worker) recordResult(r Result) {
	w.mu.Lock()
	w.results = append(w.results, r)
	w.mu.Unlock()
}

// --- Built-in Channel Implementations ---

// SMTPChannel sends notifications via email.
type SMTPChannel struct {
	Host     string
	Port     int
	From     string
	Username string
	Password string

	// sendMail is injectable for tests; defaults to smtp.SendMail.
	sendMail func(addr string, a smtp.Auth, from string, to []string, msg []byte) error
}

func (c *SMTPChannel) Name() string { return "email" }

func (c *SMTPChannel) Send(ctx context.Context, event Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	var auth smtp.Auth
	if c.Username != "" {
		auth = smtp.PlainAuth("", c.Username, c.Password, c.Host)
	}
	msg := buildRFC5322Message(c.From, event.Target, event.Subject, event.Message)

	send := c.sendMail
	if send == nil {
		send = smtp.SendMail
	}
	if err := send(addr, auth, c.From, []string{event.Target}, msg); err != nil {
		return fmt.Errorf("smtp send to %s: %w", event.Target, err)
	}
	return nil
}

// buildRFC5322Message renders a minimal RFC 5322 email. Header values are
// sanitized to strip CR/LF so event data cannot inject extra headers.
func buildRFC5322Message(from, to, subject, body string) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "From: %s\r\n", sanitizeHeader(from))
	fmt.Fprintf(&buf, "To: %s\r\n", sanitizeHeader(to))
	fmt.Fprintf(&buf, "Subject: %s\r\n", sanitizeHeader(subject))
	fmt.Fprintf(&buf, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	buf.WriteString("\r\n")
	buf.WriteString(body)
	return buf.Bytes()
}

func sanitizeHeader(s string) string {
	replacer := strings.NewReplacer("\r", " ", "\n", " ")
	return replacer.Replace(s)
}

// SlackChannel sends notifications via Slack webhook.
type SlackChannel struct {
	WebhookURL string
}

func (c *SlackChannel) Name() string { return "slack" }

func (c *SlackChannel) Send(ctx context.Context, event Event) error {
	text := event.Subject
	if event.Message != "" {
		text = text + "\n" + event.Message
	}
	payload, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		return fmt.Errorf("marshal slack payload: %w", err)
	}
	return postJSON(ctx, c.WebhookURL, payload, nil)
}

// pagerDutyEventsURL is the default PagerDuty Events API v2 endpoint.
const pagerDutyEventsURL = "https://events.pagerduty.com/v2/enqueue"

// PagerDutyChannel sends notifications via PagerDuty Events API v2.
type PagerDutyChannel struct {
	RoutingKey string

	// Endpoint overrides the Events API URL; tests point this at an httptest.Server.
	Endpoint string
}

func (c *PagerDutyChannel) Name() string { return "pagerduty" }

func (c *PagerDutyChannel) Send(ctx context.Context, event Event) error {
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = pagerDutyEventsURL
	}
	// summary folds in event.Message the same way SlackChannel.Send folds it
	// into its "text" field above -- found missing entirely (W19-27, live
	// against tests/live/notifications/run.sh's echo receiver): every
	// PagerDuty alert reported the same static "Kryptkeeper notification"
	// summary regardless of what actually triggered it, since only
	// event.Subject was ever read.
	summary := event.Subject
	if event.Message != "" {
		summary = summary + ": " + event.Message
	}
	payload, err := json.Marshal(map[string]any{
		"routing_key":  c.RoutingKey,
		"event_action": "trigger",
		"payload": map[string]string{
			"summary":  summary,
			"source":   "kryptkeeper",
			"severity": pagerDutySeverity(event.Priority),
		},
	})
	if err != nil {
		return fmt.Errorf("marshal pagerduty payload: %w", err)
	}
	return postJSON(ctx, endpoint, payload, nil)
}

// pagerDutySeverity maps an internal priority to a PagerDuty Events API v2 severity.
func pagerDutySeverity(priority string) string {
	switch priority {
	case "critical":
		return "critical"
	case "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "info"
	}
}

// WebhookChannel posts the event as JSON to a generic HTTP endpoint.
type WebhookChannel struct {
	URL     string
	Headers map[string]string
}

func (c *WebhookChannel) Name() string { return "webhook" }

func (c *WebhookChannel) Send(ctx context.Context, event Event) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}
	return postJSON(ctx, c.URL, payload, c.Headers)
}

// postJSON POSTs a JSON body to url with the given extra headers, returning an
// error on transport failure or a non-2xx response so the worker's retry engages.
func postJSON(ctx context.Context, url string, body []byte, headers map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := newHTTPClient().Do(req)
	if err != nil {
		return fmt.Errorf("post %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("post %s: server returned %d", url, resp.StatusCode)
	}
	return nil
}

// --- Threshold Evaluator ---

// CertExpiryRecord represents a certificate's expiry state.
type CertExpiryRecord struct {
	Fingerprint string
	CommonName  string
	ValidUntil  time.Time
	TeamID      string
	OwnerEmail  string
}

// ExpiryCheckFunc returns certificates expiring within the given window.
type ExpiryCheckFunc func(ctx context.Context, within time.Duration) ([]CertExpiryRecord, error)

// ThresholdEvaluator checks for expiring certificates and generates events.
type ThresholdEvaluator struct {
	checkFunc  ExpiryCheckFunc
	thresholds []time.Duration // e.g., 90d, 30d, 7d
}

// NewThresholdEvaluator creates a threshold evaluator.
func NewThresholdEvaluator(checkFunc ExpiryCheckFunc, thresholds []time.Duration) *ThresholdEvaluator {
	if len(thresholds) == 0 {
		thresholds = []time.Duration{
			90 * 24 * time.Hour,
			30 * 24 * time.Hour,
			7 * 24 * time.Hour,
		}
	}
	return &ThresholdEvaluator{checkFunc: checkFunc, thresholds: thresholds}
}

// Evaluate checks all thresholds and returns events for matching certificates.
func (te *ThresholdEvaluator) Evaluate(ctx context.Context) ([]Event, error) {
	var events []Event
	for _, threshold := range te.thresholds {
		certs, err := te.checkFunc(ctx, threshold)
		if err != nil {
			return nil, fmt.Errorf("check threshold %v: %w", threshold, err)
		}
		for _, cert := range certs {
			daysLeft := int(time.Until(cert.ValidUntil).Hours() / 24)
			priority := "low"
			if daysLeft <= 7 {
				priority = "critical"
			} else if daysLeft <= 30 {
				priority = "high"
			}

			events = append(events, Event{
				ID:        fmt.Sprintf("expiry-%s-%d", cert.Fingerprint, int(threshold.Hours()/24)),
				Channel:   "email",
				Target:    cert.OwnerEmail,
				Subject:   fmt.Sprintf("Certificate %s expires in %d days", cert.CommonName, daysLeft),
				Message:   fmt.Sprintf("Certificate %s (fingerprint: %s) expires on %s", cert.CommonName, cert.Fingerprint, cert.ValidUntil.Format(time.RFC3339)),
				Priority:  priority,
				CreatedAt: time.Now().UTC(),
			})
		}
	}
	return events, nil
}
