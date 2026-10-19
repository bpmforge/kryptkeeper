// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"kryptkeeper/internal/notifications/delivery"
)

// recChannel records every event it is asked to send.
type recChannel struct {
	name   string
	mu     sync.Mutex
	events []delivery.Event
}

func (c *recChannel) Name() string { return c.name }
func (c *recChannel) Send(_ context.Context, ev delivery.Event) error {
	c.mu.Lock()
	c.events = append(c.events, ev)
	c.mu.Unlock()
	return nil
}
func (c *recChannel) got() []delivery.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]delivery.Event(nil), c.events...)
}

// fixedRules is a read-only notificationRuleStore.
type fixedRules struct{ rules []NotificationRule }

func (f fixedRules) ListRules(context.Context) ([]NotificationRule, error) { return f.rules, nil }
func (fixedRules) CreateRule(context.Context, string, int, string, string) (NotificationRule, error) {
	return NotificationRule{}, errors.New("read-only")
}
func (fixedRules) UpdateRule(context.Context, string, bool, string) (NotificationRule, error) {
	return NotificationRule{}, errors.New("read-only")
}
func (fixedRules) DeleteRule(context.Context, string) error { return errors.New("read-only") }

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// routedHarness wires a real delivery provider, sqlite stores and a scheduler.
type routedHarness struct {
	sched    *RenewalScheduler
	provider *deliveryNotificationProvider
	routes   *sqlNotificationTeamRouteStore
	opts     *sqliteNotificationRuleOptionsStore
}

func newRoutedHarness(t *testing.T, certs []CertificateItem, rules []NotificationRule, channels ...delivery.Channel) *routedHarness {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "routed.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	cd := &sqliteRenewalAlertCooldownStore{db: db}
	opts := &sqliteNotificationRuleOptionsStore{db: db}
	routes := &sqlNotificationTeamRouteStore{db: db, ph: func(int) string { return "?" }}
	for _, ensure := range []func(context.Context) error{cd.EnsureSchema, opts.EnsureSchema, routes.EnsureSchema} {
		if err := ensure(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	provider := newDeliveryNotificationProvider(channels, 1, fixedRules{rules: rules})
	sched := newRuleScheduler(&reportCertProvider{items: certs}, provider, cd, opts)
	sched.teamRoutes = routes
	return &routedHarness{sched: sched, provider: provider, routes: routes, opts: opts}
}

func (h *routedHarness) addRoute(t *testing.T, id, team, channel, target string) {
	t.Helper()
	if err := h.routes.Create(context.Background(), NotificationTeamRoute{ID: id, OwnerTeam: team, Channel: channel, Target: target}); err != nil {
		t.Fatal(err)
	}
}

func routedRule(channel string) NotificationRule {
	return NotificationRule{ID: "rr", Name: "routed", ThresholdDays: 30, Channel: channel, Target: routedRuleTarget, Enabled: true}
}

func ownedCert(now time.Time, team string) CertificateItem {
	c := lifetimeCert(now, 90*day, 20*day)
	c.OwnerTeam = team
	c.RiskScore = 73
	c.Grade = "B"
	return c
}

func targetsOf(evs []delivery.Event) []string {
	var out []string
	for _, e := range evs {
		out = append(out, e.Target)
	}
	return out
}

func TestRoutedRuleSendsOnlyToTeamRoute(t *testing.T) {
	now := time.Now().UTC()
	slack := &recChannel{name: "slack"}
	h := newRoutedHarness(t, []CertificateItem{ownedCert(now, "platform-eng")}, []NotificationRule{routedRule("slack")}, slack)
	h.addRoute(t, "r1", "platform-eng", "slack", "#platform-alerts")
	h.addRoute(t, "r2", globalInboxTeam, "slack", "#global")
	h.sched.runScan()
	waitUntil(t, "team send", func() bool { return len(slack.got()) >= 1 })
	time.Sleep(50 * time.Millisecond)
	if got := targetsOf(slack.got()); len(got) != 1 || got[0] != "#platform-alerts" {
		t.Fatalf("want only #platform-alerts, got %v", got)
	}
}

func TestRoutedRuleFallsBackToGlobalInbox(t *testing.T) {
	now := time.Now().UTC()
	slack := &recChannel{name: "slack"}
	h := newRoutedHarness(t, []CertificateItem{ownedCert(now, "")}, []NotificationRule{routedRule("slack")}, slack)
	h.addRoute(t, "r1", "platform-eng", "slack", "#platform-alerts")
	h.addRoute(t, "r2", globalInboxTeam, "slack", "#global")
	h.sched.runScan()
	waitUntil(t, "global send", func() bool { return len(slack.got()) >= 1 })
	time.Sleep(50 * time.Millisecond)
	if got := targetsOf(slack.got()); len(got) != 1 || got[0] != "#global" {
		t.Fatalf("want only #global, got %v", got)
	}
}

func TestRoutedRuleIgnoresRoutesOnOtherChannels(t *testing.T) {
	now := time.Now().UTC()
	slack := &recChannel{name: "slack"}
	h := newRoutedHarness(t, []CertificateItem{ownedCert(now, "platform-eng")}, []NotificationRule{routedRule("slack")}, slack)
	h.addRoute(t, "r1", "platform-eng", "email", "ops@example.com")
	h.sched.runScan()
	time.Sleep(50 * time.Millisecond)
	if got := slack.got(); len(got) != 0 {
		t.Fatalf("an email route must not serve a slack rule, got %v", targetsOf(got))
	}
}

func TestNoOwnerNoGlobalQueuesDashboard(t *testing.T) {
	now := time.Now().UTC()
	slack := &recChannel{name: "slack"}
	h := newRoutedHarness(t, []CertificateItem{ownedCert(now, "")}, []NotificationRule{routedRule("slack")}, slack)
	for i := 0; i < 2; i++ { // the second tick must not queue again
		h.sched.runScan()
	}
	time.Sleep(50 * time.Millisecond)
	if got := slack.got(); len(got) != 0 {
		t.Fatalf("nothing may be sent externally, got %v", targetsOf(got))
	}
	res, err := h.provider.ListDeliveries(context.Background(), NotificationDeliveryQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Deliveries) != 1 || res.Deliveries[0].Channel != "dashboard" || res.Deliveries[0].Status != "queued" {
		t.Fatalf("want exactly one queued dashboard row, got %+v", res.Deliveries)
	}
	sum, _ := h.provider.GetSummary(context.Background())
	if sum.PendingNotifications != 1 {
		t.Fatalf("pending_notifications = %d, want 1", sum.PendingNotifications)
	}
}

func TestExplicitTargetRuleUnchangedByRouting(t *testing.T) {
	now := time.Now().UTC()
	slack := &recChannel{name: "slack"}
	rule := NotificationRule{ID: "rx", Name: "x", ThresholdDays: 30, Channel: "slack", Target: "#explicit", Enabled: true}
	h := newRoutedHarness(t, []CertificateItem{ownedCert(now, "platform-eng")}, []NotificationRule{rule}, slack)
	h.addRoute(t, "r1", "platform-eng", "slack", "#platform-alerts")
	h.sched.runScan()
	waitUntil(t, "explicit send", func() bool { return len(slack.got()) >= 1 })
	time.Sleep(50 * time.Millisecond)
	if got := targetsOf(slack.got()); len(got) != 1 || got[0] != "#explicit" {
		t.Fatalf("want only #explicit, got %v", got)
	}
}

func TestExpiryEmailBodyFields(t *testing.T) {
	t.Setenv("KRYPTKEEPER_BASE_URL", "https://kk.example.com/")
	now := time.Now().UTC()
	cert := ownedCert(now, "platform-eng")
	email := &recChannel{name: "email"}
	h := newRoutedHarness(t, []CertificateItem{cert}, []NotificationRule{routedRule("email")}, email)
	h.addRoute(t, "r1", "platform-eng", "email", "team@example.com")
	h.sched.runScan()
	waitUntil(t, "email send", func() bool { return len(email.got()) >= 1 })
	ev := email.got()[0]
	for _, want := range []string{
		"CN: " + cert.CommonName,
		"Expires: " + cert.ValidUntil,
		"Risk score: 73",
		"Grade: B",
		"Link: https://kk.example.com/certificates/" + cert.FingerprintSHA256,
	} {
		if !strings.Contains(ev.Message, want) {
			t.Errorf("body missing %q:\n%s", want, ev.Message)
		}
	}
	if !strings.Contains(ev.Subject, cert.CommonName) {
		t.Errorf("subject %q lacks the CN", ev.Subject)
	}
	if strings.Contains(strings.ToUpper(ev.Message), "PRIVATE KEY") {
		t.Error("body must carry no key material")
	}
}

func TestBuildExpiryEventPriorityAndLink(t *testing.T) {
	now := time.Now().UTC()
	cert := ownedCert(now, "")
	if ev := buildExpiryEvent(cert, now.Add(3*day), now, false, ""); ev.Priority != "high" || strings.Contains(ev.Message, "Link:") {
		t.Errorf("3 days left, no base URL: priority=%q msg=%q", ev.Priority, ev.Message)
	}
	if ev := buildExpiryEvent(cert, now.Add(20*day), now, false, ""); ev.Priority != "medium" {
		t.Errorf("20 days left: priority=%q", ev.Priority)
	}
	ev := buildExpiryEvent(cert, now.Add(-day), now, true, "")
	if ev.Priority != "critical" || !strings.HasPrefix(ev.Subject, "Certificate EXPIRED: ") {
		t.Errorf("expired: priority=%q subject=%q", ev.Priority, ev.Subject)
	}
}

func TestPagerDutyExpiredCarriesCNAndExpiry(t *testing.T) {
	defer delivery.AllowLoopbackForTest()()
	var mu sync.Mutex
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		body = b
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	now := time.Now().UTC()
	cert := ownedCert(now, "platform-eng")
	until := now.Add(-2 * day)
	cert.ValidFrom = until.Add(-90 * day).Format(time.RFC3339)
	cert.ValidUntil = until.Format(time.RFC3339)
	rule := routedRule("pagerduty")
	h := newRoutedHarness(t, []CertificateItem{cert}, []NotificationRule{rule}, &delivery.PagerDutyChannel{RoutingKey: "rk", Endpoint: srv.URL})
	if err := h.opts.Set(context.Background(), NotificationRuleOption{RuleID: rule.ID, ThresholdPct: intPtr(0)}); err != nil {
		t.Fatal(err)
	}
	h.addRoute(t, "r1", "platform-eng", "pagerduty", "unused-service")
	h.sched.runScan()
	waitUntil(t, "pagerduty post", func() bool { mu.Lock(); defer mu.Unlock(); return body != nil })

	mu.Lock()
	defer mu.Unlock()
	var got struct {
		Payload struct {
			Summary  string `json:"summary"`
			Severity string `json:"severity"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.Payload.Summary, cert.CommonName) || !strings.Contains(got.Payload.Summary, cert.ValidUntil) {
		t.Errorf("summary lacks CN or expiry: %q", got.Payload.Summary)
	}
	if got.Payload.Severity != "critical" {
		t.Errorf("severity = %q, want critical", got.Payload.Severity)
	}
}

// --- handlers ---

func newTeamRouteMux(t *testing.T) (*http.ServeMux, *Authenticator) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	registerNotificationHandlers(mux, auth, newFileNotificationProvider(), stubAuditProvider{}, nil)
	return mux, auth
}

func routeReq(mux *http.ServeMux, tok, method, path string, body any) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestTeamRouteCRUDAndConflict(t *testing.T) {
	mux, _ := newTeamRouteMux(t)
	const path = "/api/v1/notifications/team-routes"
	body := map[string]string{"owner_team": "platform-eng", "channel": "slack", "target": "#platform-alerts"}
	rec := routeReq(mux, "test-token", http.MethodPost, path, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Data NotificationTeamRoute `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.Data.ID == "" {
		t.Fatalf("create body: %v %s", err, rec.Body.String())
	}
	if rec := routeReq(mux, "test-token", http.MethodPost, path, body); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate: want 409, got %d", rec.Code)
	}
	for name, bad := range map[string]map[string]string{
		"bad channel": {"owner_team": "a", "channel": "sms", "target": "x"},
		"no team":     {"owner_team": "", "channel": "slack", "target": "x"},
		"no target":   {"owner_team": "a", "channel": "slack", "target": ""},
		"long team":   {"owner_team": strings.Repeat("a", 121), "channel": "slack", "target": "x"},
		"long target": {"owner_team": "a", "channel": "slack", "target": strings.Repeat("a", 321)},
	} {
		if rec := routeReq(mux, "test-token", http.MethodPost, path, bad); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", name, rec.Code)
		}
	}
	rec = routeReq(mux, "test-token", http.MethodGet, path, nil)
	var list struct {
		Data struct {
			Items []NotificationTeamRoute `json:"items"`
		} `json:"data"`
		Meta struct {
			Total int `json:"total"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || list.Meta.Total != 1 || len(list.Data.Items) != 1 {
		t.Fatalf("list: %v %s", err, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "tenant") {
		t.Error("tenant must not be serialised")
	}
	if rec := routeReq(mux, "test-token", http.MethodDelete, path+"/"+created.Data.ID, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	if rec := routeReq(mux, "test-token", http.MethodDelete, path+"/"+created.Data.ID, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("second delete: want 404, got %d", rec.Code)
	}
}

func TestTeamRouteViewerForbiddenAndAudited(t *testing.T) {
	mux, auth := newTeamRouteMux(t)
	_, viewer, err := auth.CreateAPIKey("v", "v-p", "viewer", []string{}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	const path = "/api/v1/notifications/team-routes"
	if rec := routeReq(mux, viewer, http.MethodPost, path, map[string]string{"owner_team": "a", "channel": "slack", "target": "x"}); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer create: want 403, got %d", rec.Code)
	}
	if rec := routeReq(mux, viewer, http.MethodDelete, path+"/route-x", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer delete: want 403, got %d", rec.Code)
	}
}

func TestTeamRouteTenantIsolation(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	mux, auth := newTeamRouteMux(t)
	_, acme, err := auth.CreateAPIKey("a", "a-p", "pki-admin", []string{"*"}, "", "acme", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, globex, err := auth.CreateAPIKey("g", "g-p", "pki-admin", []string{"*"}, "", "globex", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	const path = "/api/v1/notifications/team-routes"
	rec := routeReq(mux, acme, http.MethodPost, path, map[string]string{"owner_team": "a", "channel": "slack", "target": "#a"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("acme create: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Data NotificationTeamRoute `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	rec = routeReq(mux, globex, http.MethodGet, path, nil)
	if strings.Contains(rec.Body.String(), "#a") {
		t.Fatalf("globex sees acme's route: %s", rec.Body.String())
	}
	if rec := routeReq(mux, globex, http.MethodDelete, path+"/"+created.Data.ID, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("globex delete of acme route: want 404, got %d", rec.Code)
	}
	if rec := routeReq(mux, acme, http.MethodDelete, path+"/"+created.Data.ID, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("acme delete: %d", rec.Code)
	}
}

func TestRoutedRuleAcceptedByRulePost(t *testing.T) {
	mux, _ := newTeamRouteMux(t)
	rec := routeReq(mux, "test-token", http.MethodPost, "/api/v1/notifications/rules", map[string]any{
		"name": "routed", "channel": "slack", "target": routedRuleTarget, "threshold_days": 30,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestResolveTeamRoutesTenantScoped(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	idx := teamRouteIndex{
		teamRouteKey("t", "slack"):             {{ID: "1", OwnerTeam: "t", Channel: "slack", Target: "#other", Tenant: "globex"}},
		teamRouteKey(globalInboxTeam, "slack"): {{ID: "2", OwnerTeam: globalInboxTeam, Channel: "slack", Target: "#g", Tenant: "acme"}},
	}
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	t.Setenv(dbModeEnv, dbModeSQLite)
	tenants := NewTenantStoreFromEnv()
	if tenants == nil {
		t.Fatal("tenant store unavailable")
	}
	for _, id := range []string{"acme", "globex"} {
		if _, err := tenants.CreateTenant(context.Background(), id, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := tenants.SetCATenant(context.Background(), "ca1", "acme"); err != nil {
		t.Fatal(err)
	}
	prev := activeTenantStore
	defer setActiveTenantStore(prev)
	setActiveTenantStore(tenants)
	got := resolveTeamRoutes(context.Background(), idx, CertificateItem{OwnerTeam: "t", CAID: "ca1"}, "slack")
	if len(got) != 1 || got[0].Target != "#g" {
		t.Fatalf("another tenant's team route must neither serve nor shadow the global inbox, got %+v", got)
	}
}
