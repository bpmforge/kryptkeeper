// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"kryptkeeper/internal/notifications/delivery"
)

type captureChannel struct {
	name string
	mu   sync.Mutex
	got  []delivery.Event
}

func (c *captureChannel) Name() string { return c.name }
func (c *captureChannel) Send(_ context.Context, e delivery.Event) error {
	c.mu.Lock()
	c.got = append(c.got, e)
	c.mu.Unlock()
	return nil
}
func (c *captureChannel) targets() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.got))
	for _, e := range c.got {
		out = append(out, e.Target)
	}
	return out
}
func (c *captureChannel) reset() {
	c.mu.Lock()
	c.got = nil
	c.mu.Unlock()
}

func newRuleTestStore(t *testing.T) *dbNotificationProvider {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`CREATE TABLE notification_rules (
		id TEXT PRIMARY KEY, name TEXT NOT NULL,
		threshold_days INTEGER NOT NULL CHECK (threshold_days > 0),
		channel TEXT NOT NULL CHECK (channel IN ('email','slack','pagerduty','webhook')),
		target TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
		created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
		tenant TEXT NOT NULL DEFAULT '')`); err != nil {
		t.Fatal(err)
	}
	return &dbNotificationProvider{store: &sqliteNotificationStore{db: db}}
}

func TestDeliveryProviderPersistsRules(t *testing.T) {
	ctx := context.Background()
	p := newDeliveryNotificationProvider(nil, 1, newRuleTestStore(t))

	r, err := p.CreateRule(ctx, "30d", 30, "slack", "#ops")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := p.ListRules(ctx)
	if err != nil || len(rules) != 1 || rules[0].ID != r.ID {
		t.Fatalf("created rule not listed: %v %v", rules, err)
	}
	if _, err := p.UpdateRule(ctx, r.ID, false, "#other"); err != nil {
		t.Fatal(err)
	}
	rules, _ = p.ListRules(ctx)
	if rules[0].Enabled || rules[0].Target != "#other" {
		t.Fatalf("update not persisted: %+v", rules[0])
	}
	if err := p.DeleteRule(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	if rules, _ = p.ListRules(ctx); len(rules) != 0 {
		t.Fatalf("rule not deleted: %v", rules)
	}
}

func TestDeliveryProviderWithoutRuleStoreRefusesRules(t *testing.T) {
	p := newDeliveryNotificationProvider(nil, 1, nil)
	if _, err := p.CreateRule(context.Background(), "x", 1, "slack", "#a"); !errors.Is(err, errNotificationRulesUnavailable) {
		t.Fatalf("want errNotificationRulesUnavailable, got %v", err)
	}
}

// A rule created through the provider must change what the renewal scheduler
// delivers: a cert 45 days out is outside the 30d renewal window, so only the
// rule (threshold 60) can cause the Slack alert.
func TestRuleCreatedViaProviderDrivesDelivery(t *testing.T) {
	ctx := context.Background()
	slack := &captureChannel{name: "slack"}
	p := newDeliveryNotificationProvider([]delivery.Channel{slack}, 1, newRuleTestStore(t))

	now := time.Now().UTC()
	certs := &reportCertProvider{items: []CertificateItem{
		{FingerprintSHA256: "fp-a", CommonName: "a.example.com", ValidUntil: now.Add(45 * 24 * time.Hour).Format(time.RFC3339)},
		{FingerprintSHA256: "fp-b", CommonName: "b.example.com", ValidUntil: now.Add(90 * 24 * time.Hour).Format(time.RFC3339)},
	}}
	newSched := func() *RenewalScheduler {
		return &RenewalScheduler{
			certProvider: certs, notifProvider: p, auditProvider: stubAuditProvider{},
			thresholdDays: 30, pollInterval: 24 * time.Hour, cooldown: time.Hour,
			cooldownStore: newFreshRenewalAlertCooldownStore(t),
		}
	}
	waitTargets := func(n int) []string {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if got := slack.targets(); len(got) >= n {
				return got
			}
			time.Sleep(10 * time.Millisecond)
		}
		return slack.targets()
	}

	s := newSched()
	s.runScan()
	time.Sleep(50 * time.Millisecond)
	if got := slack.targets(); len(got) != 0 {
		t.Fatalf("no rules yet, expected no deliveries, got %v", got)
	}

	rule, err := p.CreateRule(ctx, "60d", 60, "slack", "#expiry")
	if err != nil {
		t.Fatal(err)
	}
	s.runScan()
	if got := waitTargets(1); len(got) != 1 || got[0] != "#expiry" {
		t.Fatalf("expected exactly one alert (fp-a only) to #expiry, got %v", got)
	}

	s.runScan() // cooldown: no repeat
	time.Sleep(50 * time.Millisecond)
	if got := slack.targets(); len(got) != 1 {
		t.Fatalf("cooldown should suppress repeat, got %v", got)
	}

	if _, err := p.UpdateRule(ctx, rule.ID, false, "#expiry"); err != nil {
		t.Fatal(err)
	}
	slack.reset()
	newSched().runScan() // fresh cooldown store: only the disabled flag can suppress
	time.Sleep(50 * time.Millisecond)
	if got := slack.targets(); len(got) != 0 {
		t.Fatalf("disabled rule must not deliver, got %v", got)
	}
}

func TestNotificationRulesAPIWithDeliveryProvider(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	mux := http.NewServeMux()
	registerNotificationHandlers(mux, NewAuthenticatorFromEnv(),
		newDeliveryNotificationProvider(nil, 1, newRuleTestStore(t)), stubAuditProvider{}, nil)

	call := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer test-token")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	if rec := call(http.MethodPost, "/api/v1/notifications/rules", `{"name":"x","threshold_days":0,"channel":"email","target":"a@b.c"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("zero threshold: want 400, got %d", rec.Code)
	}
	if rec := call(http.MethodPost, "/api/v1/notifications/rules", `{"name":"x","threshold_days":5,"channel":"sms","target":"1"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad channel: want 400, got %d", rec.Code)
	}
	if rec := call(http.MethodPost, "/api/v1/notifications/rules", `{"name":"x","threshold_days":5,"channel":"email","target":"a@b.c"}`); rec.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d: %s", rec.Code, rec.Body.String())
	}
	rec := call(http.MethodGet, "/api/v1/notifications/rules", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"total":1`) {
		t.Fatalf("created rule must be listed, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestNotificationRulesAPIWithoutStoreIs503NotCreated(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	mux := http.NewServeMux()
	registerNotificationHandlers(mux, NewAuthenticatorFromEnv(),
		newDeliveryNotificationProvider(nil, 1, nil), stubAuditProvider{}, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/rules",
		strings.NewReader(`{"name":"x","threshold_days":5,"channel":"email","target":"a@b.c"}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 when rules cannot be stored, got %d", rec.Code)
	}
}
