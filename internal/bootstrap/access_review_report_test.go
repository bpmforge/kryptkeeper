// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// memAuditProvider is an in-memory AuditProvider with the exact-match filters
// the real providers apply (Action/ActorID/ResourceType/ResourceID/Outcome,
// After/Before bounds), honouring Limit/Offset. Shared by the governance
// tests (access review, break-glass).
type memAuditProvider struct {
	mu      sync.Mutex
	entries []AuditEntry
}

func (m *memAuditProvider) AppendEntry(_ context.Context, e AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, e)
	return nil
}

func (m *memAuditProvider) ListEntries(_ context.Context, q AuditListQuery) (AuditListResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var matched []AuditEntry
	for _, e := range m.entries {
		if q.Action != "" && e.Action != q.Action {
			continue
		}
		if q.ActorID != "" && e.ActorID != q.ActorID {
			continue
		}
		if q.ResourceID != "" && e.ResourceID != q.ResourceID {
			continue
		}
		if q.Outcome != "" && e.Outcome != q.Outcome {
			continue
		}
		if q.After != "" && e.Timestamp < q.After {
			continue
		}
		if q.Before != "" && e.Timestamp > q.Before {
			continue
		}
		matched = append(matched, e)
	}
	sort.SliceStable(matched, func(i, j int) bool { return matched[i].Timestamp < matched[j].Timestamp })
	total := len(matched)
	if q.Offset >= total {
		return AuditListResult{Entries: []AuditEntry{}, Total: total, Limit: q.Limit}, nil
	}
	matched = matched[q.Offset:]
	if q.Limit > 0 && len(matched) > q.Limit {
		matched = matched[:q.Limit]
	}
	return AuditListResult{Entries: matched, Total: total, Limit: q.Limit}, nil
}

func (m *memAuditProvider) actions(action string) []AuditEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []AuditEntry
	for _, e := range m.entries {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

var arNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func arTS(d time.Duration) string { return arNow.Add(-d).Format(time.RFC3339) }

func arAdmin() AuthPrincipal {
	return AuthPrincipal{ID: "root", Role: "pki-admin", Tenant: DefaultTenant, SuperAdmin: true}
}

func newARAuth(t *testing.T) *Authenticator {
	t.Helper()
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	return newReportsTestAuth(t)
}

func TestAccessReportListsEveryUserAndKey(t *testing.T) {
	auth := newARAuth(t)
	for _, n := range []string{"k1", "k2"} {
		if _, _, err := auth.CreateAPIKeyAs("alice", n, n+"-p", "pki-operator", []string{"*"}, "", "", arNow); err != nil {
			t.Fatal(err)
		}
	}
	users := &stubUserProvider{users: []UserRecord{
		{ID: "u1", Email: "a@x", Role: "pki-admin", Status: "active", CreatedAt: arTS(time.Hour)},
		{ID: "u2", Email: "b@x", Role: "viewer", Status: "active", CreatedAt: arTS(time.Hour)},
		{ID: "u3", Email: "c@x", Role: "auditor", Status: "deactivated", CreatedAt: arTS(time.Hour)},
	}}
	rep, err := BuildAccessReport(context.Background(), accessReviewDeps{auth: auth, users: users, audit: &memAuditProvider{}}, arAdmin(), arNow.AddDate(0, 0, -90), arNow, arNow, 90)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Principals) != 5 || rep.Totals.Users != 3 || rep.Totals.APIKeys != 2 {
		t.Fatalf("principals=%d totals=%+v", len(rep.Principals), rep.Totals)
	}
	for _, p := range rep.Principals {
		if p.Role == "" || p.Tenant == "" || p.Source == "" {
			t.Errorf("incomplete row: %+v", p)
		}
	}
	for _, p := range rep.Principals {
		if p.ID == "u1" && !p.ApproverCapable {
			t.Error("pki-admin must be approver-capable")
		}
		if p.ID == "u2" && p.ApproverCapable {
			t.Error("viewer must not be approver-capable")
		}
		if p.ID == "u3" && p.Status != "inactive" {
			t.Errorf("deactivated user status = %q", p.Status)
		}
	}
	// The report must never serialise secret material.
	raw, _ := json.Marshal(rep)
	if !json.Valid(raw) {
		t.Fatal("report not serialisable")
	}
	for _, banned := range []string{"secret_verifier", "SecretVerifier"} {
		if strings.Contains(string(raw), banned) {
			t.Errorf("report leaks %s", banned)
		}
	}
}

func TestAccessReportFlagsDormant(t *testing.T) {
	day := 24 * time.Hour
	users := &stubUserProvider{users: []UserRecord{
		{ID: "idle100", Role: "viewer", Status: "active", CreatedAt: arTS(400 * day), LastSeenAt: arTS(100 * day)},
		{ID: "idle10", Role: "viewer", Status: "active", CreatedAt: arTS(400 * day), LastSeenAt: arTS(10 * day)},
		{ID: "idle90", Role: "viewer", Status: "active", CreatedAt: arTS(400 * day), LastSeenAt: arTS(90 * day)},
		{ID: "idle90s", Role: "viewer", Status: "active", CreatedAt: arTS(400 * day), LastSeenAt: arTS(90*day + time.Second)},
		{ID: "off", Role: "viewer", Status: "deactivated", CreatedAt: arTS(400 * day), LastSeenAt: arTS(300 * day)},
		{ID: "never", Role: "viewer", Status: "active", CreatedAt: arTS(120 * day)},
	}}
	dormant := func(days int) map[string]bool {
		rep, err := BuildAccessReport(context.Background(), accessReviewDeps{auth: nil, users: users, audit: &memAuditProvider{}}, arAdmin(), arNow.AddDate(0, 0, -90), arNow, arNow, days)
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]bool{}
		for _, p := range rep.Principals {
			m[p.ID] = p.Dormant
		}
		return m
	}
	m := dormant(90)
	want := map[string]bool{"idle100": true, "idle10": false, "idle90": false, "idle90s": true, "off": false, "never": true}
	for id, w := range want {
		if m[id] != w {
			t.Errorf("90d: %s dormant=%v want %v", id, m[id], w)
		}
	}
	if m := dormant(30); !m["idle90"] || m["idle10"] {
		t.Errorf("30d line wrong: %v", m)
	}

	// Keys: a never-used key created 120d ago is dormant; env moves the line.
	auth := newARAuth(t)
	if _, _, err := auth.CreateAPIKeyAs("alice", "old", "old-p", "viewer", []string{"*"}, "", "", arNow.AddDate(0, 0, -120)); err != nil {
		t.Fatal(err)
	}
	rep, _ := BuildAccessReport(context.Background(), accessReviewDeps{auth: auth, users: &stubUserProvider{}, audit: &memAuditProvider{}}, arAdmin(), arNow.AddDate(0, 0, -90), arNow, arNow, 90)
	if len(rep.Principals) != 1 || !rep.Principals[0].Dormant || rep.Totals.Dormant != 1 {
		t.Fatalf("old never-used key not dormant: %+v", rep.Principals)
	}
}

func TestAccessReportEnvMovesDormantLine(t *testing.T) {
	t.Setenv(envAccessReviewDormantDays, "30")
	auth := newARAuth(t)
	users := &stubUserProvider{users: []UserRecord{{ID: "u", Role: "viewer", Status: "active", CreatedAt: arTS(1000 * time.Hour), LastSeenAt: arTS(40 * 24 * time.Hour)}}}
	mux := http.NewServeMux()
	registerAccessReviewReportHandler(mux, auth, users, nil, &memAuditProvider{}, nil, nil)
	rec := httptest.NewRecorder()
	// created/last-seen are fixed in the past relative to arNow; the handler
	// uses the wall clock, so the user is ancient either way: assert the
	// echoed line instead.
	mux.ServeHTTP(rec, bearerReq("reports-test-token", http.MethodGet, "/api/v1/admin/access-review/report", nil))
	var resp struct {
		Data AccessReviewReport `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != 200 || resp.Data.DormantDays != 30 {
		t.Fatalf("code=%d dormant_days=%d", rec.Code, resp.Data.DormantDays)
	}
}

func TestAccessReportSourceFromAudit(t *testing.T) {
	audit := &memAuditProvider{entries: []AuditEntry{
		{Timestamp: arTS(time.Hour), Action: "scim.users.create", ResourceID: "scimu", Outcome: AuditOutcomeSuccess},
		{Timestamp: arTS(time.Hour), Action: "scim.users.create", ResourceID: "failed", Outcome: AuditOutcomeFailure},
		{Timestamp: arTS(time.Hour), Action: "auth.oidc.callback", ActorID: "ssou", Outcome: AuditOutcomeSuccess},
		{Timestamp: arTS(time.Hour), Action: "auth.saml.acs", ActorID: "samlu", Outcome: AuditOutcomeSuccess},
		{Timestamp: arTS(time.Hour), Action: "auth.oidc.callback", ActorID: "deniedu", Outcome: AuditOutcomeDenied},
	}}
	users := &stubUserProvider{users: []UserRecord{
		{ID: "scimu", Role: "viewer", Status: "active"}, {ID: "ssou", Role: "viewer", Status: "active"},
		{ID: "samlu", Role: "viewer", Status: "active"}, {ID: "deniedu", Role: "viewer", Status: "active"},
		{ID: "failed", Role: "viewer", Status: "active"}, {ID: "plain", Role: "viewer", Status: "active"},
	}}
	rep, err := BuildAccessReport(context.Background(), accessReviewDeps{users: users, audit: audit}, arAdmin(), arNow.AddDate(0, 0, -90), arNow, arNow, 90)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range rep.Principals {
		got[p.ID] = p.Source
	}
	want := map[string]string{"scimu": "scim", "ssou": "sso", "samlu": "sso", "deniedu": "local", "failed": "local", "plain": "local"}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s source=%q want %q", id, got[id], w)
		}
	}
}

func TestAccessReportRoleChangesFromAudit(t *testing.T) {
	audit := &memAuditProvider{}
	for i, a := range accessReviewRoleChangeActions {
		audit.entries = append(audit.entries, AuditEntry{Timestamp: arTS(time.Duration(len(accessReviewRoleChangeActions)-i) * time.Hour), Action: a, ActorID: "actor-" + a, ResourceType: "user", ResourceID: "r" + a, Outcome: AuditOutcomeSuccess})
	}
	audit.entries = append(audit.entries,
		AuditEntry{Timestamp: arTS(200 * 24 * time.Hour), Action: "users.update", ActorID: "old", Outcome: AuditOutcomeSuccess},
		AuditEntry{Timestamp: arTS(time.Minute), Action: "users.update", ActorID: "failer", Outcome: AuditOutcomeFailure},
		AuditEntry{Timestamp: arTS(time.Minute), Action: "role.access", ActorID: "other", Outcome: AuditOutcomeSuccess},
	)
	rep, err := BuildAccessReport(context.Background(), accessReviewDeps{users: &stubUserProvider{}, audit: audit}, arAdmin(), arNow.AddDate(0, 0, -90), arNow, arNow, 90)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.RoleChanges) != len(accessReviewRoleChangeActions) || rep.Totals.RoleChanges != len(rep.RoleChanges) {
		t.Fatalf("changes=%d want %d", len(rep.RoleChanges), len(accessReviewRoleChangeActions))
	}
	for i, c := range rep.RoleChanges {
		if c.Actor == "" || c.Timestamp == "" || c.Actor == "old" || c.Actor == "failer" {
			t.Errorf("bad row %+v", c)
		}
		if i > 0 && rep.RoleChanges[i-1].Timestamp > c.Timestamp {
			t.Error("not ascending")
		}
	}
}

func TestAccessReportRoleChangesPaginate(t *testing.T) {
	audit := &memAuditProvider{}
	for i := 0; i < 250; i++ {
		audit.entries = append(audit.entries, AuditEntry{Timestamp: arTS(time.Duration(i+1) * time.Minute), Action: "users.update", ActorID: "a", Outcome: AuditOutcomeSuccess})
	}
	rep, err := BuildAccessReport(context.Background(), accessReviewDeps{users: &stubUserProvider{}, audit: audit}, arAdmin(), arNow.AddDate(0, 0, -90), arNow, arNow, 90)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.RoleChanges) != 250 || rep.Truncated {
		t.Fatalf("got %d truncated=%v", len(rep.RoleChanges), rep.Truncated)
	}
}

func TestAccessReportHandlerAuthz(t *testing.T) {
	auth := newARAuth(t)
	_, viewerTok, err := auth.CreateAPIKeyAs("alice", "v", "viewer-p", "viewer", []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, auditorTok, err := auth.CreateAPIKeyAs("alice", "a", "auditor-p", "auditor", []string{"*"}, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	audit := &memAuditProvider{}
	mux := http.NewServeMux()
	registerAccessReviewReportHandler(mux, auth, &stubUserProvider{}, nil, audit, nil, nil)
	do := func(tok, method, path string) int {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, bearerReq(tok, method, path, nil))
		return rec.Code
	}
	const p = "/api/v1/admin/access-review/report"
	if c := do("", http.MethodGet, p); c != 401 {
		t.Errorf("no token = %d", c)
	}
	if c := do(viewerTok, http.MethodGet, p); c != 403 {
		t.Errorf("viewer = %d", c)
	}
	if c := do(auditorTok, http.MethodGet, p); c != 200 {
		t.Errorf("auditor = %d", c)
	}
	if c := do("reports-test-token", http.MethodGet, p); c != 200 {
		t.Errorf("admin = %d", c)
	}
	if c := do("reports-test-token", http.MethodPost, p); c != 405 {
		t.Errorf("post = %d", c)
	}
	if c := do("reports-test-token", http.MethodGet, p+"?period_days=0"); c != 400 {
		t.Errorf("period_days=0 = %d", c)
	}
	if c := do("reports-test-token", http.MethodGet, p+"?dormant_days=abc"); c != 400 {
		t.Errorf("dormant_days=abc = %d", c)
	}
	if n := len(audit.actions("access_review.report")); n < 3 {
		t.Errorf("expected audit rows for report reads, got %d", n)
	}
}

func TestAccessReportTenantScoped(t *testing.T) {
	t.Setenv("MULTI_TENANCY", "on")
	auth := newARAuth(t)
	if _, _, err := auth.CreateAPIKeyAs("alice", "a-key", "a-p", "viewer", []string{"*"}, "", "acme", arNow); err != nil {
		t.Fatal(err)
	}
	if _, _, err := auth.CreateAPIKeyAs("alice", "b-key", "b-p", "viewer", []string{"*"}, "", "globex", arNow); err != nil {
		t.Fatal(err)
	}
	users := &stubUserProvider{users: []UserRecord{
		{ID: "ua", Role: "viewer", Status: "active", Tenant: "acme"},
		{ID: "ub", Role: "viewer", Status: "active", Tenant: "globex"},
	}}
	audit := &memAuditProvider{entries: []AuditEntry{
		{Timestamp: arTS(time.Hour), Action: "users.update", ActorID: "a-admin", Outcome: AuditOutcomeSuccess, Tenant: "acme"},
		{Timestamp: arTS(time.Hour), Action: "users.update", ActorID: "b-admin", Outcome: AuditOutcomeSuccess, Tenant: "globex"},
		{Timestamp: arTS(time.Hour), Action: "users.update", ActorID: "g-admin", Outcome: AuditOutcomeSuccess},
	}}
	tenantA := AuthPrincipal{ID: "ta", Role: "auditor", Tenant: "acme", TenantScoped: true}
	rep, err := BuildAccessReport(context.Background(), accessReviewDeps{auth: auth, users: users, audit: audit}, tenantA, arNow.AddDate(0, 0, -90), arNow, arNow, 90)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range rep.Principals {
		if p.Tenant != "acme" {
			t.Errorf("tenant-A caller saw %+v", p)
		}
	}
	if len(rep.Principals) != 2 || rep.Totals.Users != 1 || rep.Totals.APIKeys != 1 {
		t.Errorf("principals=%+v totals=%+v", rep.Principals, rep.Totals)
	}
	if len(rep.RoleChanges) != 1 || rep.RoleChanges[0].Actor != "a-admin" {
		t.Errorf("role changes leak across tenants: %+v", rep.RoleChanges)
	}
	// An unscoped super-admin sees everything, with each row's real tenant.
	all, _ := BuildAccessReport(context.Background(), accessReviewDeps{auth: auth, users: users, audit: audit}, arAdmin(), arNow.AddDate(0, 0, -90), arNow, arNow, 90)
	if len(all.Principals) != 4 || len(all.RoleChanges) != 3 {
		t.Errorf("super-admin view: %d principals, %d changes", len(all.Principals), len(all.RoleChanges))
	}
}
