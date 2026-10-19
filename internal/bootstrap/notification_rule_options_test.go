// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const day = 24 * time.Hour

func lifetimeCert(now time.Time, lifetime, remaining time.Duration) CertificateItem {
	until := now.Add(remaining)
	return CertificateItem{
		FingerprintSHA256: "fp-life", CommonName: "life.example.com", TemplateID: "t1",
		ValidFrom:  until.Add(-lifetime).Format(time.RFC3339),
		ValidUntil: until.Format(time.RFC3339),
	}
}

func intPtr(v int) *int { return &v }

func TestRuleCrossed90DayDaysRule(t *testing.T) {
	now := time.Now().UTC()
	if ruleCrossed(nil, 30, lifetimeCert(now, 90*day, 31*day), now) {
		t.Error("31 days left must not cross a 30-day rule")
	}
	if !ruleCrossed(nil, 30, lifetimeCert(now, 90*day, 30*day-time.Minute), now) {
		t.Error("30 days left must cross a 30-day rule")
	}
}

func TestRuleCrossed47DayPctRule(t *testing.T) {
	now := time.Now().UTC()
	opt := &NotificationRuleOption{ThresholdPct: intPtr(10)}
	// 10% of 47 days is 4.7 days.
	if !ruleCrossed(opt, 1, lifetimeCert(now, 47*day, 4*day+14*time.Hour), now) {
		t.Error("4.6 days left must cross 10%")
	}
	if ruleCrossed(opt, 1, lifetimeCert(now, 47*day, 5*day), now) {
		t.Error("5 days left must not cross 10%")
	}
}

func TestAbsoluteDaysNeverExceedsLifetime(t *testing.T) {
	start := time.Now().UTC()
	for _, days := range []int{60, 90, 47} {
		for d := 0; d <= 47; d++ {
			now := start.Add(time.Duration(d) * day)
			cert := lifetimeCert(start, 47*day, 47*day)
			if ruleCrossed(nil, days, cert, now) {
				t.Fatalf("%d-day rule crossed a 47-day cert on day %d", days, d)
			}
		}
	}
}

func TestExpiredRuleWindow(t *testing.T) {
	now := time.Now().UTC()
	opt := &NotificationRuleOption{ThresholdPct: intPtr(0)}
	if !ruleCrossed(opt, 1, lifetimeCert(now, 90*day, -2*day), now) {
		t.Error("expired 2 days ago must cross the EXPIRED rule")
	}
	if ruleCrossed(opt, 1, lifetimeCert(now, 90*day, -30*day), now) {
		t.Error("expired 30 days ago is outside the window")
	}
	if ruleCrossed(opt, 1, lifetimeCert(now, 90*day, day), now) {
		t.Error("unexpired cert must not cross the EXPIRED rule")
	}
	if ruleCrossed(&NotificationRuleOption{ThresholdPct: intPtr(50)}, 1, lifetimeCert(now, 90*day, -day), now) {
		t.Error("only the EXPIRED rule may match an expired cert")
	}
	if ruleCrossed(nil, 30, lifetimeCert(now, 90*day, -day), now) {
		t.Error("a days rule must not match an expired cert")
	}
}

// ruleRecorder is a delivering provider with canned rules that records the
// target of every send.
type ruleRecorder struct {
	NotificationProvider
	rules   []NotificationRule
	mu      sync.Mutex
	targets []string
}

func (p *ruleRecorder) Delivers() bool { return true }
func (p *ruleRecorder) Name() string   { return "recorder" }
func (p *ruleRecorder) ListRules(context.Context) ([]NotificationRule, error) {
	return p.rules, nil
}
func (p *ruleRecorder) TestDelivery(_ context.Context, _, target, _ string) (NotificationTestDeliveryResult, error) {
	p.mu.Lock()
	p.targets = append(p.targets, target)
	p.mu.Unlock()
	return NotificationTestDeliveryResult{Status: "queued", Dispatched: true}, nil
}
func (p *ruleRecorder) sent() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.targets...)
}

func openRuleSchedulerStores(t *testing.T, dbPath string) (*sqliteRenewalAlertCooldownStore, *sqliteNotificationRuleOptionsStore) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	cd := &sqliteRenewalAlertCooldownStore{db: db}
	op := &sqliteNotificationRuleOptionsStore{db: db}
	if err := cd.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := op.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	return cd, op
}

func newRuleScheduler(certs CertificateProvider, p NotificationProvider, cd renewalAlertCooldownStore, op NotificationRuleOptionsStore) *RenewalScheduler {
	return &RenewalScheduler{
		certProvider: certs, notifProvider: p, auditProvider: stubAuditProvider{},
		thresholdDays: 30, pollInterval: day, cooldown: day,
		cooldownStore: cd, ruleOptions: op,
	}
}

func TestNoDuplicatesAfterRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "restart.db")
	now := time.Now().UTC()
	certs := &reportCertProvider{items: []CertificateItem{lifetimeCert(now, 90*day, 20*day)}}
	p := &ruleRecorder{rules: []NotificationRule{
		{ID: "r30", Name: "30d", ThresholdDays: 30, Channel: "slack", Target: "#rule", Enabled: true},
	}}

	cd1, op1 := openRuleSchedulerStores(t, dbPath)
	newRuleScheduler(certs, p, cd1, op1).runScan()
	if got := len(p.sent()); got != 1 {
		t.Fatalf("first tick: want 1 send, got %d", got)
	}
	cd2, op2 := openRuleSchedulerStores(t, dbPath)
	newRuleScheduler(certs, p, cd2, op2).runScan()
	if got := len(p.sent()); got != 1 {
		t.Fatalf("after restart inside the cooldown: want 1 send total, got %d", got)
	}
	// Once per crossing: not even after the old 24h cooldown would have lapsed.
	if err := cd2.RecordAlerted(context.Background(), crossingKey("fp-life", "r30"), now.Add(-3*day)); err != nil {
		t.Fatal(err)
	}
	newRuleScheduler(certs, p, cd2, op2).runScan()
	if got := len(p.sent()); got != 1 {
		t.Fatalf("a crossing must never re-fire for the same fingerprint, got %d sends", got)
	}
}

func TestTemplateOverrideSuppressesGlobalRule(t *testing.T) {
	now := time.Now().UTC()
	certs := &reportCertProvider{items: []CertificateItem{lifetimeCert(now, 90*day, 20*day)}}
	p := &ruleRecorder{rules: []NotificationRule{
		{ID: "rg", Name: "global", ThresholdDays: 30, Channel: "slack", Target: "#global", Enabled: true},
		{ID: "rt", Name: "t1", ThresholdDays: 30, Channel: "slack", Target: "#t1", Enabled: true},
	}}
	cd, op := openRuleSchedulerStores(t, filepath.Join(t.TempDir(), "tmpl.db"))
	if err := op.Set(context.Background(), NotificationRuleOption{RuleID: "rt", TemplateID: "t1"}); err != nil {
		t.Fatal(err)
	}
	newRuleScheduler(certs, p, cd, op).runScan()
	if got := p.sent(); len(got) != 1 || got[0] != "#t1" {
		t.Fatalf("only the template rule should send, got %v", got)
	}

	// A cert of another template is not affected by the t1 rule.
	other := lifetimeCert(now, 90*day, 20*day)
	other.FingerprintSHA256, other.TemplateID = "fp-other", "t2"
	p2 := &ruleRecorder{rules: p.rules}
	newRuleScheduler(&reportCertProvider{items: []CertificateItem{other}}, p2, cd, op).runScan()
	if got := p2.sent(); len(got) != 1 || got[0] != "#global" {
		t.Fatalf("a t2 cert should get the global rule only, got %v", got)
	}
}

func TestExpiredRuleFiresThroughScheduler(t *testing.T) {
	now := time.Now().UTC()
	recent := lifetimeCert(now, 90*day, -2*day)
	old := lifetimeCert(now, 90*day, -30*day)
	old.FingerprintSHA256 = "fp-old"
	p := &ruleRecorder{rules: []NotificationRule{
		{ID: "rx", Name: "expired", ThresholdDays: 1, Channel: "slack", Target: "#exp", Enabled: true},
	}}
	cd, op := openRuleSchedulerStores(t, filepath.Join(t.TempDir(), "exp.db"))
	if err := op.Set(context.Background(), NotificationRuleOption{RuleID: "rx", ThresholdPct: intPtr(0)}); err != nil {
		t.Fatal(err)
	}
	newRuleScheduler(&reportCertProvider{items: []CertificateItem{recent, old}}, p, cd, op).runScan()
	if got := p.sent(); len(got) != 1 {
		t.Fatalf("want exactly the recently expired cert alerted, got %v", got)
	}
}

func newRuleOptionsHandlerMux(t *testing.T) *http.ServeMux {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("KRYPTKEEPER_DATA_DIR", t.TempDir())
	mux := http.NewServeMux()
	registerNotificationHandlers(mux, NewAuthenticatorFromEnv(), newFileNotificationProvider(), stubAuditProvider{}, nil)
	return mux
}

func doRuleReq(mux *http.ServeMux, method, path string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestCreateRulePctAndTemplate(t *testing.T) {
	mux := newRuleOptionsHandlerMux(t)
	rec := doRuleReq(mux, http.MethodPost, "/api/v1/notifications/rules", map[string]any{
		"name": "ten", "channel": "slack", "target": "#x", "threshold_pct": 10, "template_id": "tpl-web",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Data["threshold_pct"] != float64(10) || created.Data["template_id"] != "tpl-web" {
		t.Fatalf("options not echoed: %v", created.Data)
	}
	if _, leaked := created.Data["threshold_days"]; leaked {
		t.Fatalf("placeholder threshold_days leaked: %v", created.Data)
	}

	rec = doRuleReq(mux, http.MethodGet, "/api/v1/notifications/rules", nil)
	var list struct {
		Data struct {
			Items []map[string]any `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Data.Items) != 1 || list.Data.Items[0]["threshold_pct"] != float64(10) || list.Data.Items[0]["template_id"] != "tpl-web" {
		t.Fatalf("GET did not round-trip: %v", list.Data.Items)
	}
	if _, leaked := list.Data.Items[0]["threshold_days"]; leaked {
		t.Fatalf("GET leaked placeholder: %v", list.Data.Items[0])
	}
}

func TestCreateRuleRejectsBothOrNeither(t *testing.T) {
	mux := newRuleOptionsHandlerMux(t)
	base := func() map[string]any {
		return map[string]any{"name": "n", "channel": "slack", "target": "#x"}
	}
	cases := map[string]func(m map[string]any){
		"neither":      func(m map[string]any) {},
		"both":         func(m map[string]any) { m["threshold_days"] = 30; m["threshold_pct"] = 10 },
		"days+default": func(m map[string]any) { m["threshold_days"] = 30; m["use_defaults"] = true },
		"pct too high": func(m map[string]any) { m["threshold_pct"] = 101 },
		"pct negative": func(m map[string]any) { m["threshold_pct"] = -1 },
		"long tpl":     func(m map[string]any) { m["threshold_pct"] = 5; m["template_id"] = string(make([]byte, 129)) },
	}
	for name, mutate := range cases {
		m := base()
		mutate(m)
		if rec := doRuleReq(mux, http.MethodPost, "/api/v1/notifications/rules", m); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", name, rec.Code)
		}
	}
}

func TestCreateRuleUseDefaultsCreatesFour(t *testing.T) {
	mux := newRuleOptionsHandlerMux(t)
	rec := doRuleReq(mux, http.MethodPost, "/api/v1/notifications/rules", map[string]any{
		"name": "Std", "channel": "email", "target": "ops@example.com", "use_defaults": true,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data map[string]any `json:"data"`
		Meta struct {
			Created []string `json:"created"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Meta.Created) != 4 || resp.Data["threshold_pct"] != float64(50) {
		t.Fatalf("want four ids and the 50%% rule as data, got %+v", resp)
	}
	opts, err := newNotificationRuleOptionsStoreFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	stored, err := opts.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var pcts []int
	for _, id := range resp.Meta.Created {
		o, ok := stored[id]
		if !ok || o.ThresholdPct == nil {
			t.Fatalf("rule %s has no pct option", id)
		}
		pcts = append(pcts, *o.ThresholdPct)
	}
	for i, want := range defaultThresholdPcts {
		if pcts[i] != want {
			t.Fatalf("pcts = %v, want %v", pcts, defaultThresholdPcts)
		}
	}
}

func TestDeleteRuleRemovesOption(t *testing.T) {
	mux := newRuleOptionsHandlerMux(t)
	rec := doRuleReq(mux, http.MethodPost, "/api/v1/notifications/rules", map[string]any{
		"name": "x", "channel": "slack", "target": "#x", "threshold_pct": 25,
	})
	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.Data.ID == "" {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doRuleReq(mux, http.MethodDelete, "/api/v1/notifications/rules/"+resp.Data.ID, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	opts, err := newNotificationRuleOptionsStoreFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	stored, err := opts.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := stored[resp.Data.ID]; ok {
		t.Fatal("option row survived rule deletion")
	}
}

// TestDefaultPctsFireOnceEach drives the whole path: use_defaults through the
// handler, then a 47-day cert swept across its lifetime.
func TestDefaultPctsFireOnceEach(t *testing.T) {
	mux := newRuleOptionsHandlerMux(t)
	if rec := doRuleReq(mux, http.MethodPost, "/api/v1/notifications/rules", map[string]any{
		"name": "Std", "channel": "slack", "target": "#rule", "use_defaults": true,
	}); rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	opts, err := newNotificationRuleOptionsStoreFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := opts.List(context.Background())
	if len(stored) != 4 {
		t.Fatalf("want 4 option rows, got %d", len(stored))
	}
	var rules []NotificationRule
	for id := range stored {
		rules = append(rules, NotificationRule{ID: id, Name: id, ThresholdDays: 1, Channel: "slack", Target: "#rule", Enabled: true})
	}
	p := &ruleRecorder{rules: rules}
	cd, _ := openRuleSchedulerStores(t, filepath.Join(t.TempDir(), "sweep.db"))
	certs := &reportCertProvider{}
	s := newRuleScheduler(certs, p, cd, opts)

	now := time.Now().UTC()
	for d := 0; d <= 50; d++ {
		from := now.Add(-time.Duration(d)*day - time.Minute)
		certs.items = []CertificateItem{{
			FingerprintSHA256: "fp-47", CommonName: "short.example.com",
			ValidFrom: from.Format(time.RFC3339), ValidUntil: from.Add(47 * day).Format(time.RFC3339),
		}}
		s.runScan()
	}
	if got := len(p.sent()); got != 4 {
		t.Fatalf("want 4 sends (50/25/10/EXPIRED once each), got %d", got)
	}
	for id := range stored {
		if _, ok, _ := cd.LastAlertedAt(context.Background(), crossingKey("fp-47", id)); !ok {
			t.Errorf("rule %s never recorded a crossing", id)
		}
	}
}
