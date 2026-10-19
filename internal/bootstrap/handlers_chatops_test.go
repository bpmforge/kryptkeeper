// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"kryptkeeper/internal/notifications/chatops"
)

const chatopsTestSecret = "slack-test-secret"

type chatopsEnv struct {
	delegEnv
	users *stubUserProvider
	store chatops.IdentityStore
}

func newChatopsEnv(t *testing.T) chatopsEnv {
	t.Helper()
	t.Setenv(slackSigningEnv, chatopsTestSecret)
	e := newDelegEnv(t, "")
	users := &stubUserProvider{users: []UserRecord{
		{ID: "appr-a", Role: "pki-admin", Status: "active"},
		{ID: "proposer-x", Role: "pki-admin", Status: "active"},
		{ID: "viewer-v", Role: "pki-viewer", Status: "active"},
		{ID: "gone-g", Role: "pki-admin", Status: "deactivated"},
	}}
	e.auth.userProvider = users
	store := chatopsSQLStore(e.st.db, e.st.ph)
	if store == nil {
		t.Fatal("identity store unavailable")
	}
	RegisterChatopsHandlers(e.mux, e.auth, store, e.audit)
	ce := chatopsEnv{e, users, store}
	ce.mapUser(t, "T1", "U1", "appr-a")
	ce.mapUser(t, "T1", "U2", "proposer-x")
	ce.mapUser(t, "T1", "U3", "viewer-v")
	ce.mapUser(t, "T1", "U4", "gone-g")
	return ce
}

func (e chatopsEnv) mapUser(t *testing.T, team, ext, user string) {
	t.Helper()
	err := e.store.Upsert(t.Context(), chatops.Mapping{Identity: chatops.Identity{Platform: "slack", Workspace: team, ExternalID: ext},
		KryptkeeperUser: user, Tenant: DefaultTenant, CreatedAt: "t"})
	if err != nil {
		t.Fatal(err)
	}
}

func slackBody(team, user, action, value string) string {
	js, _ := json.Marshal(map[string]any{"type": "block_actions", "team": map[string]string{"id": team},
		"user": map[string]string{"id": user, "username": "ann"}, "response_url": "https://hooks.slack.com/x",
		"actions": []map[string]string{{"action_id": action, "value": value}}})
	return "payload=" + url.QueryEscape(string(js))
}

func slackSig(secret, ts, body string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("v0:" + ts + ":" + body))
	return "v0=" + hex.EncodeToString(m.Sum(nil))
}

func slackReq(secret string, at time.Time, body string) *http.Request {
	ts := strconv.FormatInt(at.Unix(), 10)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/chatops/slack/interactions", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-Slack-Request-Timestamp", ts)
	r.Header.Set("X-Slack-Signature", slackSig(secret, ts, body))
	return r
}

func (e chatopsEnv) slack(r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, r)
	return rec
}

func (e chatopsEnv) actionStatus(t *testing.T, id string) string {
	t.Helper()
	a, ok, err := e.st.Get(t.Context(), id)
	if err != nil || !ok {
		t.Fatalf("get %s: %v %v", id, ok, err)
	}
	return a.Status
}

func TestForgedOrReplayedRejected10of10(t *testing.T) {
	e := newChatopsEnv(t)
	a := e.propose(t, "someone-else", "")
	body := slackBody("T1", "U1", chatops.ActionApprove, "action:"+a.ID)
	now := time.Now()
	good := func() *http.Request { return slackReq(chatopsTestSecret, now, body) }
	mut := func(f func(r *http.Request)) func() *http.Request {
		return func() *http.Request { r := good(); f(r); return r }
	}
	unmapped := slackBody("T1", "U9", chatops.ActionApprove, "action:"+a.ID)
	cases := []struct {
		name string
		req  func() *http.Request
	}{
		{"wrong secret", func() *http.Request { return slackReq("other", now, body) }},
		{"truncated sig", mut(func(r *http.Request) { r.Header.Set("X-Slack-Signature", r.Header.Get("X-Slack-Signature")[:20]) })},
		{"no sig", mut(func(r *http.Request) { r.Header.Del("X-Slack-Signature") })},
		{"no timestamp", mut(func(r *http.Request) { r.Header.Del("X-Slack-Request-Timestamp") })},
		{"ts -6m", func() *http.Request { return slackReq(chatopsTestSecret, now.Add(-6*time.Minute), body) }},
		{"ts +6m", func() *http.Request { return slackReq(chatopsTestSecret, now.Add(6*time.Minute), body) }},
		{"tampered body", func() *http.Request {
			r := good()
			r.Body = http.NoBody
			r2 := httptest.NewRequest(http.MethodPost, r.URL.Path, strings.NewReader(body+"%20"))
			r2.Header = r.Header
			return r2
		}},
		{"wrong version", mut(func(r *http.Request) {
			r.Header.Set("X-Slack-Signature", "v1="+strings.TrimPrefix(r.Header.Get("X-Slack-Signature"), "v0="))
		})},
		{"empty secret", func() *http.Request { t.Setenv(slackSigningEnv, ""); return slackReq("", now, body) }},
	}
	for _, c := range cases {
		if rec := e.slack(c.req()); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d %s", c.name, rec.Code, rec.Body.String())
		}
	}
	t.Setenv(slackSigningEnv, chatopsTestSecret)
	// A validly signed request replayed: first (unmapped user, so no state change) is 403, the replay 401.
	if rec := e.slack(slackReq(chatopsTestSecret, now, unmapped)); rec.Code != http.StatusForbidden {
		t.Fatalf("first use: %d", rec.Code)
	}
	if rec := e.slack(slackReq(chatopsTestSecret, now, unmapped)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("replay: %d", rec.Code)
	}
	if got := e.actionStatus(t, a.ID); got != "pending" {
		t.Fatalf("state changed: %s", got)
	}
	if e.ran.Load() != 0 {
		t.Fatal("executor ran")
	}
	if n := len(e.audit.all("chatops.signature_failed", AuditOutcomeDenied)); n != 10 {
		t.Fatalf("signature_failed rows = %d, want 10", n)
	}
	for _, row := range e.audit.all("chatops.signature_failed", AuditOutcomeDenied) {
		if strings.Contains(row.ChangeSummary, "payload") || strings.Contains(row.ChangeSummary, "hooks.slack.com") {
			t.Errorf("audit leaks body: %q", row.ChangeSummary)
		}
	}
}

func TestUnmappedSlackUser403(t *testing.T) {
	e := newChatopsEnv(t)
	a := e.propose(t, "someone-else", "")
	rec := e.slack(slackReq(chatopsTestSecret, time.Now(), slackBody("T1", "U404", chatops.ActionApprove, "action:"+a.ID)))
	if rec.Code != http.StatusForbidden || e.actionStatus(t, a.ID) != "pending" || e.ran.Load() != 0 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if len(e.audit.all("chatops.interaction", AuditOutcomeDenied)) != 1 {
		t.Fatalf("audit: %+v", e.audit.entries)
	}
}

func TestRefusalsLeaveStatePending(t *testing.T) {
	e := newChatopsEnv(t)
	for _, c := range []struct{ name, user, proposer string }{
		{"proposer clicking own request", "U2", "proposer-x"},
		{"deprovisioned user", "U4", "someone-else"},
		{"no approve role", "U3", "someone-else"},
	} {
		a := e.propose(t, c.proposer, "")
		rec := e.slack(slackReq(chatopsTestSecret, time.Now(), slackBody("T1", c.user, chatops.ActionApprove, "action:"+a.ID)))
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: %d %s", c.name, rec.Code, rec.Body.String())
		}
		if e.actionStatus(t, a.ID) != "pending" {
			t.Errorf("%s: state changed", c.name)
		}
		time.Sleep(1100 * time.Millisecond) // distinct timestamp => distinct signature
	}
	if e.ran.Load() != 0 {
		t.Fatal("executor ran")
	}
}

func TestTenantMismatchedMappingRefused(t *testing.T) {
	e := newChatopsEnv(t)
	err := e.store.Upsert(t.Context(), chatops.Mapping{Identity: chatops.Identity{Platform: "slack", Workspace: "T1", ExternalID: "U7"},
		KryptkeeperUser: "appr-a", Tenant: "acme", CreatedAt: "t"})
	if err != nil {
		t.Fatal(err)
	}
	a := e.propose(t, "someone-else", "")
	if rec := e.slack(slackReq(chatopsTestSecret, time.Now(), slackBody("T1", "U7", chatops.ActionApprove, "action:"+a.ID))); rec.Code != http.StatusForbidden {
		t.Fatalf("%d", rec.Code)
	}
	if e.actionStatus(t, a.ID) != "pending" {
		t.Fatal("state changed")
	}
}

func TestApproveFromSlackUsesRealPath(t *testing.T) {
	e := newChatopsEnv(t)
	a := e.propose(t, "someone-else", "")
	rec := e.slack(slackReq(chatopsTestSecret, time.Now(), slackBody("T1", "U1", chatops.ActionApprove, "action:"+a.ID)))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"approved"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if e.ran.Load() != 1 || e.actionStatus(t, a.ID) != "approved" {
		t.Fatalf("ran=%d status=%s", e.ran.Load(), e.actionStatus(t, a.ID))
	}
	rows := e.audit.all("action.approve", AuditOutcomeSuccess)
	if len(rows) != 1 || !strings.Contains(rows[0].ChangeSummary, "channel=chatops") ||
		!strings.Contains(rows[0].ChangeSummary, "external_id=slack:T1/U1") || rows[0].ActorID != "appr-a" {
		t.Fatalf("rows: %+v", rows)
	}
}

func TestApproveCertApprovalFromSlackUsesRealPath(t *testing.T) {
	t.Setenv(slackSigningEnv, chatopsTestSecret)
	mux, auth, store, audit, _ := certApprovalEnv(t)
	auth.userProvider = &stubUserProvider{users: []UserRecord{{ID: "u-approver", Role: "pki-admin", Status: "active", Tenant: "acme"}}}
	ids := &memIdentityStore{m: map[chatops.Identity]chatops.Mapping{}}
	id := chatops.Identity{Platform: "slack", Workspace: "T1", ExternalID: "U1"}
	ids.m[id] = chatops.Mapping{Identity: id, KryptkeeperUser: "u-approver", Tenant: "acme"}
	RegisterChatopsHandlers(mux, auth, ids, audit)
	seedApproval(t, store, "apr-slack", "someone-else")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, slackReq(chatopsTestSecret, time.Now(), slackBody("T1", "U1", chatops.ActionApprove, "approval:apr-slack")))
	// Certificate issuance itself is not wired in this harness (the inner handler answers 5xx, mapped
	// to 502); what matters is that the real handler ran as the mapped user and audited the channel.
	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	rows := rowsFor(audit, "approval.approve")
	if len(rows) == 0 || !strings.Contains(rows[0].ChangeSummary, `"channel":"chatops"`) ||
		!strings.Contains(rows[0].ChangeSummary, `"external_id":"slack:T1/U1"`) || rows[0].ActorID != "u-approver" {
		t.Fatalf("rows: %+v", rows)
	}
}

func TestRejectFromSlack(t *testing.T) {
	e := newChatopsEnv(t)
	a := e.propose(t, "someone-else", "")
	rec := e.slack(slackReq(chatopsTestSecret, time.Now(), slackBody("T1", "U1", chatops.ActionReject, "action:"+a.ID)))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"rejected"`) || e.actionStatus(t, a.ID) != "rejected" || e.ran.Load() != 0 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	rows := e.audit.all("action.reject", AuditOutcomeSuccess)
	if len(rows) != 1 || !strings.Contains(rows[0].ChangeSummary, "channel=chatops") {
		t.Fatalf("rows: %+v", rows)
	}
}

func TestAlreadyDecided409(t *testing.T) {
	e := newChatopsEnv(t)
	a := e.propose(t, "someone-else", "")
	now := time.Now()
	if rec := e.slack(slackReq(chatopsTestSecret, now, slackBody("T1", "U1", chatops.ActionApprove, "action:"+a.ID))); rec.Code != http.StatusOK {
		t.Fatalf("first: %d", rec.Code)
	}
	rec := e.slack(slackReq(chatopsTestSecret, now.Add(-time.Minute), slackBody("T1", "U1", chatops.ActionApprove, "action:"+a.ID)))
	if rec.Code != http.StatusConflict || e.ran.Load() != 1 {
		t.Fatalf("second: %d %s ran=%d", rec.Code, rec.Body.String(), e.ran.Load())
	}
}

func TestIdentityMapAdminOnly_TenantScoped(t *testing.T) {
	e := newChatopsEnv(t)
	e.users.users = append(e.users.users, UserRecord{ID: "other-tenant-u", Role: "pki-admin", Status: "active", Tenant: "acme"})
	admin := mintAdminToken(t, e.auth, "admin-1", "")
	if _, viewer, err := e.auth.CreateAPIKey("v-key", "viewer-v", "pki-viewer", []string{"*"}, "", "", time.Now()); err != nil {
		t.Fatal(err)
	} else if rec := e.do(viewer, http.MethodGet, "/api/v1/chatops/identity-map", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer: %d", rec.Code)
	}
	if rec := e.do("bogus", http.MethodGet, "/api/v1/chatops/identity-map", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon: %d", rec.Code)
	}
	put := `{"platform":"slack","workspace":"T2","external_id":"U9","kryptkeeper_user":"appr-a"}`
	if rec := e.do(admin, http.MethodPut, "/api/v1/chatops/identity-map", put); rec.Code != http.StatusOK {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	for _, bad := range []string{
		`{"platform":"slack","workspace":"T2","external_id":"U9","kryptkeeper_user":"nobody"}`,
		`{"platform":"slack","workspace":"T2","external_id":"U9","kryptkeeper_user":"other-tenant-u"}`,
		`{"platform":"discord","workspace":"T2","external_id":"U9","kryptkeeper_user":"appr-a"}`,
		`{"platform":"slack","workspace":"T2","external_id":"U/9","kryptkeeper_user":"appr-a"}`,
	} {
		if rec := e.do(admin, http.MethodPut, "/api/v1/chatops/identity-map", bad); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, rec.Code)
		}
	}
	if rec := e.do(admin, http.MethodGet, "/api/v1/chatops/identity-map", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "U9") {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	// A mapping owned by another tenant is invisible to delete and refused on overwrite.
	other := chatops.Identity{Platform: "slack", Workspace: "T3", ExternalID: "U5"}
	if err := e.store.Upsert(t.Context(), chatops.Mapping{Identity: other, KryptkeeperUser: "other-tenant-u", Tenant: "acme", CreatedAt: "t"}); err != nil {
		t.Fatal(err)
	}
	if rec := e.do(admin, http.MethodDelete, "/api/v1/chatops/identity-map?platform=slack&workspace=T3&external_id=U5", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant delete: %d", rec.Code)
	}
	if rec := e.do(admin, http.MethodPut, "/api/v1/chatops/identity-map", `{"platform":"slack","workspace":"T3","external_id":"U5","kryptkeeper_user":"appr-a"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant overwrite: %d", rec.Code)
	}
	if rec := e.do(admin, http.MethodDelete, "/api/v1/chatops/identity-map?platform=slack&workspace=T2&external_id=U9", ""); rec.Code != http.StatusOK {
		t.Fatalf("delete: %d", rec.Code)
	}
	if len(e.audit.all("chatops.identity_map.set", AuditOutcomeSuccess)) != 1 || len(e.audit.all("chatops.identity_map.delete", AuditOutcomeSuccess)) != 1 {
		t.Fatalf("audit rows: %+v", e.audit.entries)
	}
}

// memIdentityStore is a map-backed IdentityStore for the certificate-approval test.
type memIdentityStore struct {
	m map[chatops.Identity]chatops.Mapping
}

func (s *memIdentityStore) Lookup(_ context.Context, id chatops.Identity) (chatops.Mapping, bool, error) {
	m, ok := s.m[id]
	return m, ok, nil
}
func (s *memIdentityStore) Upsert(_ context.Context, m chatops.Mapping) error {
	s.m[m.Identity] = m
	return nil
}
func (s *memIdentityStore) Delete(_ context.Context, id chatops.Identity) error {
	delete(s.m, id)
	return nil
}
func (s *memIdentityStore) List(context.Context, string) ([]chatops.Mapping, error) { return nil, nil }
