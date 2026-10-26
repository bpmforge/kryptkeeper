// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/notifications/delivery"
)

func TestOwnerlessCertUsesOwnerlessQueueBeforeGlobalInbox(t *testing.T) {
	now := time.Now().UTC()
	slack := &recChannel{name: "slack"}
	h := newRoutedHarness(t, []CertificateItem{ownedCert(now, "")}, []NotificationRule{routedRule("slack")}, slack)
	h.addRoute(t, "r1", ownerlessQueueTeam, "slack", "#nobody-owns-this")
	h.addRoute(t, "r2", globalInboxTeam, "slack", "#global")
	h.addRoute(t, "r3", "platform-eng", "slack", "#platform-alerts")
	h.sched.runScan()
	waitUntil(t, "ownerless send", func() bool { return len(slack.got()) >= 1 })
	time.Sleep(50 * time.Millisecond)
	if got := targetsOf(slack.got()); len(got) != 1 || got[0] != "#nobody-owns-this" {
		t.Fatalf("want only the ownerless queue, got %v", got)
	}
}

func TestOwnerlessQueueDoesNotReceiveOwnedCertificates(t *testing.T) {
	now := time.Now().UTC()
	slack := &recChannel{name: "slack"}
	// The team has no route of its own: it falls back to the global inbox, and
	// the ownerless queue stays out of it.
	h := newRoutedHarness(t, []CertificateItem{ownedCert(now, "platform-eng")}, []NotificationRule{routedRule("slack")}, slack)
	h.addRoute(t, "r1", ownerlessQueueTeam, "slack", "#nobody-owns-this")
	h.addRoute(t, "r2", globalInboxTeam, "slack", "#global")
	h.sched.runScan()
	waitUntil(t, "global send", func() bool { return len(slack.got()) >= 1 })
	time.Sleep(50 * time.Millisecond)
	if got := targetsOf(slack.got()); len(got) != 1 || got[0] != "#global" {
		t.Fatalf("want only #global, got %v", got)
	}
}

func ownerlessMux(t *testing.T, items []CertificateItem) (*http.ServeMux, *recordingAuditProvider) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	audit := &recordingAuditProvider{}
	mux := http.NewServeMux()
	registerOwnerlessHandler(mux, NewAuthenticatorFromEnv(), &reportCertProvider{items: items}, audit)
	return mux, audit
}

func TestOwnerlessListingExpiringSoonestFirst(t *testing.T) {
	now := time.Now().UTC()
	mk := func(fp string, left time.Duration, team string) CertificateItem {
		c := lifetimeCert(now, 400*day, left)
		c.FingerprintSHA256, c.CommonName, c.OwnerTeam = fp, fp+".example.com", team
		return c
	}
	revoked := mk("fp-revoked", 3*day, "")
	at := now.Format(time.RFC3339)
	revoked.RevokedAt = &at
	mux, audit := ownerlessMux(t, []CertificateItem{
		mk("fp-late", 25*day, ""),
		mk("fp-soon", 5*day, ""),
		mk("fp-expired", -2*day, ""),
		mk("fp-far", 200*day, ""),
		mk("fp-owned", 4*day, "platform-eng"),
		revoked,
	})

	rec := routeReq(mux, "test-token", http.MethodGet, "/api/v1/notifications/ownerless", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Data struct {
			Items []ownerlessCertificate `json:"items"`
		} `json:"data"`
		Meta struct {
			Total      int `json:"total"`
			WithinDays int `json:"within_days"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	var fps []string
	for _, it := range got.Data.Items {
		fps = append(fps, it.FingerprintSHA256)
	}
	if want := "fp-expired,fp-soon,fp-late"; strings.Join(fps, ",") != want {
		t.Fatalf("items = %v, want %s (owned, revoked and out-of-window rows excluded)", fps, want)
	}
	if got.Data.Items[0].DaysLeft >= 0 || got.Meta.Total != 3 || got.Meta.WithinDays != 30 {
		t.Fatalf("meta/days: %+v %+v", got.Meta, got.Data.Items[0])
	}

	rec = routeReq(mux, "test-token", http.MethodGet, "/api/v1/notifications/ownerless?within_days=7&limit=1", nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if len(got.Data.Items) != 1 || got.Meta.Total != 2 {
		t.Fatalf("limit/window: items=%d total=%d", len(got.Data.Items), got.Meta.Total)
	}

	for _, bad := range []string{"within_days=0", "within_days=abc", "limit=9999"} {
		if rec := routeReq(mux, "test-token", http.MethodGet, "/api/v1/notifications/ownerless?"+bad, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", bad, rec.Code)
		}
	}
	if rec := routeReq(mux, "wrong", http.MethodGet, "/api/v1/notifications/ownerless", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("bad token: want 401, got %d", rec.Code)
	}
	if rec := routeReq(mux, "test-token", http.MethodPost, "/api/v1/notifications/ownerless", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: want 405, got %d", rec.Code)
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if len(audit.entries) == 0 || audit.entries[0].Action != "notification.ownerless.list" {
		t.Fatalf("listing wrote no audit row: %+v", audit.entries)
	}
}

// W32-31: each final outcome is audited exactly once, and a delivery that
// recovers on a later attempt is audited as a success, not as a failure.
func TestSettledDeliveriesAreAuditedOnce(t *testing.T) {
	flaky := &escRecChannel{name: "slack", failFirst: 1}
	audit := &recordingAuditProvider{}
	p := newDeliveryNotificationProviderForTest([]delivery.Channel{flaky}, 3, time.Millisecond, nil, nil)
	p.audit = audit

	ctx := context.Background()
	if _, err := p.SendEvent(ctx, delivery.Event{ID: "ok-after-retry", Channel: "slack", Target: "#a"}); err != nil {
		t.Fatal(err)
	}
	escWaitFor(t, func() bool { audit.mu.Lock(); defer audit.mu.Unlock(); return len(audit.entries) == 1 })

	bad := &escRecChannel{name: "email", fail: true, err: errors.New("550 mailbox unavailable")}
	p2 := newDeliveryNotificationProviderForTest([]delivery.Channel{bad}, 3, time.Millisecond, nil, nil)
	audit2 := &recordingAuditProvider{}
	p2.audit = audit2
	if _, err := p2.SendEvent(ctx, delivery.Event{ID: "never", Channel: "email", Target: "x@example.com"}); err != nil {
		t.Fatal(err)
	}
	escWaitFor(t, func() bool { audit2.mu.Lock(); defer audit2.mu.Unlock(); return len(audit2.entries) == 1 })
	time.Sleep(50 * time.Millisecond)

	audit.mu.Lock()
	e := audit.entries[0]
	audit.mu.Unlock()
	if e.Action != "notification.delivery.settled" || e.Outcome != AuditOutcomeSuccess || e.ResourceID != "ok-after-retry" {
		t.Fatalf("recovered delivery audit: %+v", e)
	}
	audit2.mu.Lock()
	defer audit2.mu.Unlock()
	if len(audit2.entries) != 1 || audit2.entries[0].Outcome != AuditOutcomeFailure || !strings.Contains(audit2.entries[0].ChangeSummary, "attempts=3") {
		t.Fatalf("failed delivery audit: %+v", audit2.entries)
	}
	if strings.Contains(audit2.entries[0].ChangeSummary, "x@example.com") {
		t.Fatalf("audit detail leaked the target: %s", audit2.entries[0].ChangeSummary)
	}
	if bad.attempts() != 3 {
		t.Fatalf("attempts = %d, want 3", bad.attempts())
	}
}
