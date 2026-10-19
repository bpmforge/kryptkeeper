// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"kryptkeeper/internal/notifications/delivery"
)

// RC5 A1: the file and db providers only record; rule alerts through them
// were audited as sent and put on cooldown while nothing was delivered.

type auditCapture struct {
	mu      sync.Mutex
	entries []AuditEntry
}

func (*auditCapture) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{}, nil
}
func (a *auditCapture) AppendEntry(_ context.Context, e AuditEntry) error {
	a.mu.Lock()
	a.entries = append(a.entries, e)
	a.mu.Unlock()
	return nil
}
func (a *auditCapture) outcomes(action string) []AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []AuditEntry
	for _, e := range a.entries {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

func newNonDeliveringTestProviders(t *testing.T) map[string]NotificationProvider {
	t.Helper()
	dbp := newRuleTestStore(t)
	if _, err := dbp.store.(*sqliteNotificationStore).db.Exec(`CREATE TABLE notification_deliveries (
		id TEXT PRIMARY KEY, notification_policy_id TEXT, channel TEXT NOT NULL, target TEXT NOT NULL,
		subject TEXT, message TEXT, status TEXT NOT NULL DEFAULT 'queued', error_detail TEXT, retry_of_id TEXT,
		triggered_by TEXT NOT NULL DEFAULT 'system',
		queued_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
		delivered_at TEXT, acknowledged_at TEXT, acknowledged_note TEXT,
		created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')))`); err != nil {
		t.Fatal(err)
	}
	return map[string]NotificationProvider{
		notificationProviderFile: newFileNotificationProvider(),
		notificationProviderDB:   dbp,
	}
}

func TestNonDeliveringProvidersAreNotMarkedSent(t *testing.T) {
	for name, p := range newNonDeliveringTestProviders(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			if p.Delivers() {
				t.Fatalf("%s must report Delivers()==false", name)
			}
			rule, err := p.CreateRule(ctx, "60d", 60, "email", "ops@example.com")
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			audit := &auditCapture{}
			cooldown := newFreshRenewalAlertCooldownStore(t)
			s := &RenewalScheduler{
				certProvider: &reportCertProvider{items: []CertificateItem{
					{FingerprintSHA256: "fp-a", CommonName: "a.example.com", OwnerEmail: "owner@example.com",
						ValidUntil: now.Add(45 * 24 * time.Hour).Format(time.RFC3339)},
				}},
				notifProvider: p, auditProvider: audit,
				thresholdDays: 30, pollInterval: 24 * time.Hour, cooldown: time.Hour,
				cooldownStore: cooldown,
			}
			s.runScan()

			if sent := successEntries(audit.outcomes("renewal_notification_sent")); len(sent) != 0 {
				t.Fatalf("alert audited as sent through a non-delivering provider: %+v", sent)
			}
			skipped := audit.outcomes("renewal_notification_sent")
			if len(skipped) != 1 || skipped[0].Outcome != "skipped" ||
				!strings.Contains(skipped[0].ChangeSummary, "rule_id="+rule.ID) ||
				!strings.Contains(skipped[0].ChangeSummary, "notification provider "+name+" does not deliver") {
				t.Fatalf("want one skipped audit naming rule and provider, got %+v", skipped)
			}
			if _, ok, _ := cooldown.LastAlertedAt(ctx, crossingKey("fp-a", rule.ID)); ok {
				t.Fatal("cooldown written for an alert that was never sent")
			}
			if s.status.LastNotifications != 0 {
				t.Fatalf("notifications counted: %d", s.status.LastNotifications)
			}
		})
	}
}

func TestOwnerReminderNotMarkedSentByNonDeliveringProvider(t *testing.T) {
	audit := &auditCapture{}
	cooldown := newFreshRenewalAlertCooldownStore(t)
	s := &RenewalScheduler{
		notifProvider: newFileNotificationProvider(), auditProvider: audit,
		cooldown: time.Hour, cooldownStore: cooldown,
	}
	now := time.Now().UTC()
	cert := CertificateItem{FingerprintSHA256: "fp-o", OwnerEmail: "owner@example.com"}
	if s.handleRenewalCandidate(context.Background(), cert, now.Add(10*24*time.Hour), now, time.Hour) {
		t.Fatal("reminder reported notified through a non-delivering provider")
	}
	if _, ok, _ := cooldown.LastAlertedAt(context.Background(), "fp-o"); ok {
		t.Fatal("owner-reminder cooldown written")
	}
	if got := audit.outcomes("renewal_notification_sent"); len(got) != 1 || got[0].Outcome != "skipped" {
		t.Fatalf("want one skipped audit, got %+v", got)
	}
}

func successEntries(es []AuditEntry) []AuditEntry {
	var out []AuditEntry
	for _, e := range es {
		if e.Outcome == "success" {
			out = append(out, e)
		}
	}
	return out
}

func TestDeliveryProviderDelivers(t *testing.T) {
	p := newDeliveryNotificationProvider([]delivery.Channel{&captureChannel{name: "slack"}}, 1, nil)
	if !p.Delivers() || p.Name() != notificationProviderDelivery {
		t.Fatalf("delivery provider must deliver, got Delivers=%v Name=%q", p.Delivers(), p.Name())
	}
	res, err := p.TestDelivery(context.Background(), "slack", "#a", "m")
	if err != nil || !res.Dispatched || res.Note != "" {
		t.Fatalf("want dispatched, got %+v, %v", res, err)
	}
}

func TestTestDeliveryResultSaysNotDeliveredForRecordOnlyProviders(t *testing.T) {
	for name, p := range newNonDeliveringTestProviders(t) {
		res, err := p.TestDelivery(context.Background(), "email", "a@example.com", "hi")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.Dispatched || !strings.Contains(res.Note, "not delivered") || !strings.Contains(res.Note, name) {
			t.Errorf("%s: want Dispatched=false with a not-delivered note, got %+v", name, res)
		}
	}
}

func TestTestDeliveryEndpointReportsNotDispatched(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	mux := http.NewServeMux()
	registerNotificationHandlers(mux, NewAuthenticatorFromEnv(), newFileNotificationProvider(), stubAuditProvider{}, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/test-delivery",
		strings.NewReader(`{"channel":"email","target":"a@example.com","message":"hi"}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Data struct {
			Delivery struct {
				Dispatched bool   `json:"dispatched"`
				Note       string `json:"note"`
			} `json:"delivery"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Data.Delivery.Dispatched || !strings.Contains(body.Data.Delivery.Note, "not delivered") {
		t.Fatalf("response must say not delivered, got %s", rec.Body.String())
	}
}

func TestWarnIfRulesCannotDeliver(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })
	ctx := context.Background()

	p := newFileNotificationProvider()
	s := &RenewalScheduler{notifProvider: p}
	s.warnIfRulesCannotDeliver(ctx)
	if buf.Len() != 0 {
		t.Fatalf("no rules: expected no warning, got %q", buf.String())
	}
	if _, err := p.CreateRule(ctx, "r", 30, "email", "a@example.com"); err != nil {
		t.Fatal(err)
	}
	s.warnIfRulesCannotDeliver(ctx)
	if out := buf.String(); !strings.Contains(out, "WARN") || !strings.Contains(out, `"file"`) {
		t.Fatalf("want WARN-level line naming provider, got %q", out)
	}

	buf.Reset()
	d := &RenewalScheduler{notifProvider: newDeliveryNotificationProvider(nil, 1, p.(notificationRuleStore))}
	d.warnIfRulesCannotDeliver(ctx)
	if buf.Len() != 0 {
		t.Fatalf("delivering provider must not warn, got %q", buf.String())
	}
}

// Skips must not become audit spam: N ticks write a bounded number of rows.
func TestSkippedAuditIsBoundedAcrossTicks(t *testing.T) {
	p := newFileNotificationProvider()
	if _, err := p.CreateRule(context.Background(), "60d", 60, "email", "ops@example.com"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	audit := &auditCapture{}
	s := &RenewalScheduler{
		certProvider: &reportCertProvider{items: []CertificateItem{
			{FingerprintSHA256: "fp-a", ValidUntil: now.Add(45 * 24 * time.Hour).Format(time.RFC3339)},
			{FingerprintSHA256: "fp-b", ValidUntil: now.Add(10 * 24 * time.Hour).Format(time.RFC3339), OwnerEmail: "o@example.com"},
		}},
		notifProvider: p, auditProvider: audit, thresholdDays: 30,
		pollInterval: time.Hour, cooldown: time.Hour, ruleSendCap: 1,
		cooldownStore: newFreshRenewalAlertCooldownStore(t),
	}
	for i := 0; i < 20; i++ {
		s.runScan()
	}
	// fp-a rule, fp-b rule, fp-b owner reminder: one row each, not 20 each.
	if got := len(audit.outcomes("renewal_notification_sent")); got != 3 {
		t.Fatalf("want 3 skipped audit rows over 20 ticks, got %d", got)
	}
}
