// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/notifications/itsm"
)

// itsmRulesHarness mounts the notification rules API next to the ITSM API on
// one migrated database, so an itsm rule is created through the real routes
// and stored under the real (migrated) CHECK constraint.
func newITSMRulesHarness(t *testing.T) (*itsmHarness, *dbNotificationProvider) {
	t.Helper()
	h := newITSMHarness(t)
	prov := &dbNotificationProvider{store: &sqliteNotificationStore{db: h.db}}
	registerNotificationHandlers(h.mux, h.auth, prov, h.audit, newITSMConnectionVisible(h.svc))
	return h, prov
}

func TestNotificationRules_ITSMChannel(t *testing.T) {
	h, _ := newITSMRulesHarness(t)
	conn := h.createConn(t, h.adminKey)

	rec := h.call(http.MethodPost, "/api/v1/notifications/rules", h.adminKey, map[string]any{
		"name": "itsm rule", "threshold_days": 30, "channel": "itsm", "target": conn,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create itsm rule: %d %s", rec.Code, rec.Body.String())
	}
	var created struct{ Data NotificationRule }
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.Data.Channel != "itsm" || created.Data.Target != conn {
		t.Fatalf("created rule %+v %v", created.Data, err)
	}
	if e, ok := h.lastAudit("notification.rules.create"); !ok || e.Outcome != AuditOutcomeSuccess {
		t.Errorf("success not audited: %+v", e)
	}

	for name, target := range map[string]string{"unknown connection": "no-such-conn", "empty target": ""} {
		rec = h.call(http.MethodPost, "/api/v1/notifications/rules", h.adminKey, map[string]any{
			"name": "x", "threshold_days": 30, "channel": "itsm", "target": target,
		})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", name, rec.Code)
		}
		if e, ok := h.lastAudit("notification.rules.create"); !ok || e.Outcome != AuditOutcomeFailure {
			t.Errorf("%s: failure not audited: %+v", name, e)
		}
	}

	// Retargeting an itsm rule is validated the same way.
	upd := func(target string) int {
		return h.call(http.MethodPut, "/api/v1/notifications/rules/"+created.Data.ID, h.adminKey, map[string]any{"enabled": true, "target": target}).Code
	}
	if c := upd("no-such-conn"); c != http.StatusBadRequest {
		t.Errorf("retarget to unknown connection: %d", c)
	}
	if c := upd(conn); c != http.StatusOK {
		t.Errorf("retarget to own connection: %d", c)
	}
}

func TestNotificationRules_ITSMChannelOtherTenantConnection400(t *testing.T) {
	h, _ := newITSMRulesHarness(t)
	t.Setenv("MULTI_TENANCY", "on")
	if _, err := h.creds.Create(context.Background(), "cred-a", "a", "api_token", "tenant-a", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	_, tokA, err := h.auth.CreateAPIKey("ka", "ka", "pki-admin", []string{"*"}, "", "tenant-a", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, tokB, err := h.auth.CreateAPIKey("kb", "kb", "pki-admin", []string{"*"}, "", "tenant-b", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec := h.call(http.MethodPost, "/api/v1/itsm/connections", tokA, map[string]any{"kind": "jira", "name": "a", "base_url": "https://a.example", "credential_ref": "cred-a"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("tenant-a connection: %d %s", rec.Code, rec.Body.String())
	}
	var conn struct{ Data itsm.Connection }
	_ = json.Unmarshal(rec.Body.Bytes(), &conn)

	body := map[string]any{"name": "x", "threshold_days": 30, "channel": "itsm", "target": conn.Data.ID}
	if rec := h.call(http.MethodPost, "/api/v1/notifications/rules", tokB, body); rec.Code != http.StatusBadRequest {
		t.Errorf("tenant-b used tenant-a's connection: %d %s", rec.Code, rec.Body.String())
	}
	if e, ok := h.lastAudit("notification.rules.create"); !ok || e.Outcome != AuditOutcomeFailure {
		t.Errorf("denial not audited: %+v", e)
	}
	if rec := h.call(http.MethodPost, "/api/v1/notifications/rules", tokA, body); rec.Code != http.StatusCreated {
		t.Errorf("owner tenant: %d %s", rec.Code, rec.Body.String())
	}
}

func TestNotificationRules_ITSMChannelWithoutITSMService400(t *testing.T) {
	mux := newNotifRulesTestMux(t) // registers with no ITSM check
	req := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/rules",
		strings.NewReader(`{"name":"x","threshold_days":5,"channel":"itsm","target":"conn-1"}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400 (no ITSM service)", rec.Code)
	}
}

// listingProvider answers ListRules from the real (migrated) rule store and
// routes itsm deliveries into a real itsm.Channel, as the delivery worker does.
type listingProvider struct {
	*itsmRoutingProvider
	store *dbNotificationProvider
}

func (p listingProvider) ListRules(ctx context.Context) ([]NotificationRule, error) {
	return p.store.ListRules(ctx)
}

// The end-to-end path the ticket exists for: an itsm rule made through the
// API makes a new approval produce an itsm event (and link row).
func TestNotificationRules_ITSMRuleFeedsApprovalProducer(t *testing.T) {
	h, prov := newITSMRulesHarness(t)
	t.Setenv("MULTI_TENANCY", "on")
	// The approval's CA belongs to tenant acme, so the rule and connection must too.
	if _, err := h.creds.Create(context.Background(), "cred-acme", "acme", "api_token", "acme", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	_, tok, err := h.auth.CreateAPIKey("acme", "acme", "pki-admin", []string{"*"}, "", "acme", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec := h.call(http.MethodPost, "/api/v1/itsm/connections", tok, map[string]any{"kind": "jira", "name": "acme", "base_url": "https://a.example", "credential_ref": "cred-acme"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("connection: %d %s", rec.Code, rec.Body.String())
	}
	var cr struct{ Data itsm.Connection }
	_ = json.Unmarshal(rec.Body.Bytes(), &cr)
	conn := cr.Data.ID
	if rec := h.call(http.MethodPost, "/api/v1/notifications/rules", tok, map[string]any{
		"name": "itsm", "threshold_days": 30, "channel": "itsm", "target": conn,
	}); rec.Code != http.StatusCreated {
		t.Fatalf("rule: %d %s", rec.Code, rec.Body.String())
	}
	_, _, raw, _, _ := certApprovalEnv(t)
	routing := &itsmRoutingProvider{delivers: true, channel: itsm.Channel{Svc: h.svc}}
	store := withApprovalPendingNotifier(raw, listingProvider{routing, prov})
	seedApproval(t, store, "apr-e2e", "someone")

	if len(routing.delivered) != 1 || routing.delivered[0] != "itsm:"+conn {
		t.Fatalf("delivered %v, want one itsm delivery to the connection", routing.delivered)
	}
	rows, err := h.svc.Store().ListEvents(context.Background(), "", 10)
	if err != nil || len(rows) != 1 || rows[0].Class != "approval_pending" || !strings.Contains(rows[0].Fingerprint, "apr-e2e") {
		t.Fatalf("events %+v %v", rows, err)
	}
}
