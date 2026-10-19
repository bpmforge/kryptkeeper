// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"kryptkeeper/internal/notifications/delivery"
)

type fakeCfg struct{ vals map[string]string }

func (f fakeCfg) EnsureSchema(context.Context) error { return nil }
func (f fakeCfg) Get(_ context.Context, k string) (ConfigEntry, bool, error) {
	v, ok := f.vals[k]
	return ConfigEntry{Key: k, Value: v, HasValue: ok}, ok, nil
}
func (f fakeCfg) List(context.Context) ([]ConfigEntry, error) { return nil, nil }
func (f fakeCfg) Set(context.Context, string, string, string) error {
	return nil
}
func (f fakeCfg) Delete(context.Context, string) error { return nil }
func (f fakeCfg) Resolve(_ context.Context, k string) ([]byte, error) {
	if v, ok := f.vals[k]; ok {
		return []byte(v), nil
	}
	return nil, errConfigOverrideNotFound
}

type hit struct{ Method, Host, Path, Body string }

// stubWorld records every outbound request; a RoundTripper sends all hosts to
// one httptest server so https Teams service URLs work without real DNS.
type stubWorld struct {
	mu       sync.Mutex
	hits     []hit
	slackErr bool
	srv      *httptest.Server
}

func newStubWorld(t *testing.T) *stubWorld {
	w := &stubWorld{}
	w.srv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.mu.Lock()
		w.hits = append(w.hits, hit{r.Method, r.Header.Get("X-Orig-Host"), r.URL.Path, string(b)})
		fail := w.slackErr
		w.mu.Unlock()
		switch {
		case strings.Contains(r.URL.Path, "oauth2"):
			_, _ = rw.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
		case strings.HasPrefix(r.URL.Path, "/slack/"):
			if fail {
				rw.WriteHeader(500)
				return
			}
			_, _ = rw.Write([]byte(`{"ok":true,"channel":"C1","ts":"111.222"}`))
		default:
			_, _ = rw.Write([]byte(`{"id":"act-9"}`))
		}
	}))
	t.Cleanup(w.srv.Close)
	return w
}

func (w *stubWorld) RoundTrip(r *http.Request) (*http.Response, error) {
	u, _ := url.Parse(w.srv.URL)
	r2 := r.Clone(r.Context())
	r2.Header.Set("X-Orig-Host", r.URL.Host)
	r2.URL.Scheme, r2.URL.Host = "http", u.Host
	return http.DefaultTransport.RoundTrip(r2)
}

func (w *stubWorld) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.hits)
}

func (w *stubWorld) find(sub string) []hit {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []hit
	for _, h := range w.hits {
		if strings.Contains(h.Path, sub) {
			out = append(out, h)
		}
	}
	return out
}

func chatopsPostEnv(t *testing.T, cfg map[string]string) (*chatopsApprovalNotifier, *stubWorld, *sqliteApprovalStore, *dbPendingActionStore) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "post.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	apr := &sqliteApprovalStore{db: db}
	if err := apr.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	act := &dbPendingActionStore{db: db, ph: sqlitePlaceholder}
	if err := act.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	refs := &chatopsRefStore{db: db, ph: sqlitePlaceholder}
	if err := refs.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	w := newStubWorld(t)
	n := newChatopsApprovalNotifier(fakeCfg{cfg}, refs)
	n.httpClient = &http.Client{Transport: w}
	n.slackBaseURL = "https://slack.test/slack"
	n.teamsTokenURL = "https://login.test/oauth2/token"
	approvalLifecycle.Store(n.hooks())
	t.Cleanup(func() { approvalLifecycle.Store(nil) })
	return n, w, apr, act
}

var fullCfg = map[string]string{
	cfgSlackBotToken:     "test-slack-bot-token",
	cfgSlackTeamChannels: `{"platform":"C1","other":"C2"}`,
	cfgTeamsAppID:        "app-id",
	cfgTeamsAppPassword:  "app-pw-secret",
	cfgTeamsTeamChannels: `{"platform":{"service_url":"https://smba.test","conversation_id":"19:abc"}}`,
}

func seedTeamApproval(t *testing.T, s ApprovalStore, id, team string) {
	t.Helper()
	if err := s.Create(context.Background(), ApprovalRequest{ID: id, TemplateID: "tpl", CAID: "ca", Requester: "alice", TeamID: team,
		Status: "pending", RequestedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
}

func TestChatopsPost_PendingPostsToOwnerTeamOnly(t *testing.T) {
	n, w, apr, _ := chatopsPostEnv(t, fullCfg)
	seedTeamApproval(t, apr, "apr-1", "platform")
	n.drain()
	sl := w.find("chat.postMessage")
	if len(sl) != 1 || !strings.Contains(sl[0].Body, `"channel":"C1"`) || strings.Contains(sl[0].Body, "C2") {
		t.Fatalf("slack hits: %+v", sl)
	}
	if !strings.Contains(sl[0].Body, `approval:apr-1`) {
		t.Fatalf("button value missing: %s", sl[0].Body)
	}
	tm := w.find("/v3/conversations/")
	if len(tm) != 1 || tm[0].Host != "smba.test" || !strings.Contains(tm[0].Path, "19:abc") || !strings.Contains(tm[0].Body, "apr-1") {
		t.Fatalf("teams hits: %+v", tm)
	}
	if len(w.find("oauth2")) != 1 {
		t.Fatalf("want one token call")
	}
}

func TestChatopsPost_UnmappedOrUnconfiguredMakesNoHTTP(t *testing.T) {
	n, w, apr, act := chatopsPostEnv(t, fullCfg)
	seedTeamApproval(t, apr, "apr-a", "no-such-team")
	seedTeamApproval(t, apr, "apr-b", "")
	if _, err := act.Create(context.Background(), PendingAction{ActionType: "revoke", ProposedBy: "alice"}); err != nil {
		t.Fatal(err)
	}
	n.drain()
	if w.count() != 0 {
		t.Fatalf("unmapped team must not call out: %+v", w.hits)
	}
	n2, w2, apr2, _ := chatopsPostEnv(t, map[string]string{})
	seedTeamApproval(t, apr2, "apr-c", "platform")
	n2.drain()
	if w2.count() != 0 {
		t.Fatalf("unconfigured must not call out: %+v", w2.hits)
	}
}

func TestChatopsPost_MalformedMapMakesNoHTTP(t *testing.T) {
	cfg := map[string]string{cfgSlackBotToken: "x", cfgSlackTeamChannels: `["not","an","object"]`}
	n, w, apr, _ := chatopsPostEnv(t, cfg)
	seedTeamApproval(t, apr, "apr-d", "platform")
	n.drain()
	if w.count() != 0 {
		t.Fatal("malformed map must not fall back to any channel")
	}
}

func TestChatopsPost_FailureNeverFailsApprovalCreate(t *testing.T) {
	n, w, apr, _ := chatopsPostEnv(t, fullCfg)
	w.slackErr = true
	if err := apr.Create(context.Background(), ApprovalRequest{ID: "apr-e", TemplateID: "t", CAID: "c", Requester: "alice", TeamID: "platform",
		RequestedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatalf("create must succeed: %v", err)
	}
	n.drain()
	if _, err := apr.Get(context.Background(), "apr-e"); err != nil {
		t.Fatal(err)
	}
}

func TestChatopsPost_DecidedUpdatesAnyChannel(t *testing.T) {
	n, w, apr, _ := chatopsPostEnv(t, fullCfg)
	seedTeamApproval(t, apr, "apr-2", "platform")
	n.drain()
	ch, _ := NewApprovalChannel(ChannelChatOps, "slack:T1/U1")
	ctx := WithApprovalChannel(context.Background(), ch)
	if err := apr.Decide(ctx, "apr-2", "bob", "approved", ""); err != nil {
		t.Fatal(err)
	}
	n.drain()
	up := w.find("chat.update")
	if len(up) != 1 || !strings.Contains(up[0].Body, "Approved") || !strings.Contains(up[0].Body, "bob") ||
		!strings.Contains(up[0].Body, "slack:T1/U1") || !strings.Contains(up[0].Body, "111.222") {
		t.Fatalf("slack update: %+v", up)
	}
	var put *hit
	for _, h := range w.find("/activities/act-9") {
		if h.Method == http.MethodPut {
			h := h
			put = &h
		}
	}
	if put == nil || !strings.Contains(put.Body, "Approved by bob") {
		t.Fatalf("teams update: %+v", w.hits)
	}
}

func TestChatopsPost_ExpiryAndPendingActionRejectUpdate(t *testing.T) {
	n, w, apr, act := chatopsPostEnv(t, fullCfg)
	seedTeamApproval(t, apr, "apr-3", "platform")
	a, err := act.Create(context.Background(), PendingAction{ActionType: "revoke", ProposedBy: "alice", Params: json.RawMessage(`{"owner_team":"platform"}`)})
	if err != nil {
		t.Fatal(err)
	}
	n.drain()
	if err := apr.Decide(context.Background(), "apr-3", expirySweeper, "rejected", "expired"); err != nil {
		t.Fatal(err)
	}
	n.drain()
	if err := act.Decide(context.Background(), a.ID, statusExecuting, "bob", nil); err != nil {
		t.Fatal(err)
	}
	n.drain()
	if len(w.find("chat.update")) != 1 {
		t.Fatalf("executing claim must not update, got %d", len(w.find("chat.update")))
	}
	n.drain()
	up := w.find("chat.update")
	if len(up) == 0 || !strings.Contains(up[0].Body, "Expired") || !strings.Contains(up[0].Body, "Nothing was changed") {
		t.Fatalf("expiry update: %+v", up)
	}
	if len(w.find("chat.postMessage")) != 2 {
		t.Fatalf("pending action with owner_team should also post")
	}
	if err := act.Decide(context.Background(), a.ID, "approved", "bob", nil); err != nil {
		t.Fatal(err)
	}
	n.drain()
	if got := w.find("chat.update"); len(got) != 2 || !strings.Contains(got[1].Body, "Approved") {
		t.Fatalf("action approve update: %+v", got)
	}
}

func TestChatopsPost_UpdateWithoutRecordedMessageIsNoop(t *testing.T) {
	n, w, apr, _ := chatopsPostEnv(t, map[string]string{})
	seedTeamApproval(t, apr, "apr-4", "platform")
	if err := apr.Decide(context.Background(), "apr-4", "bob", "rejected", "no"); err != nil {
		t.Fatal(err)
	}
	n.drain()
	if w.count() != 0 {
		t.Fatalf("no ref, no HTTP: %+v", w.hits)
	}
}

func TestChatopsRefStore_RoundTripAndSlackAdapter(t *testing.T) {
	n, _, _, _ := chatopsPostEnv(t, nil)
	ctx := context.Background()
	sr := slackRefs{s: n.refs, team: "platform"}
	if _, ok, _ := sr.Get(ctx, "approval:x"); ok {
		t.Fatal("unexpected ref")
	}
	if err := sr.Put(ctx, "approval:x", delivery.MessageRef{Channel: "C1", TS: "1.2"}); err != nil {
		t.Fatal(err)
	}
	if err := sr.Put(ctx, "approval:x", delivery.MessageRef{Channel: "C1", TS: "3.4"}); err != nil {
		t.Fatal(err)
	}
	got, ok, err := sr.Get(ctx, "approval:x")
	if err != nil || !ok || got.TS != "3.4" {
		t.Fatalf("got %+v %v %v", got, ok, err)
	}
	m, _, _ := n.refs.get(ctx, "slack", "approval:x")
	if m.Team != "platform" {
		t.Fatalf("team not stored: %+v", m)
	}
}

func TestChatopsConfigKeysRegistered_SecretsFlagged(t *testing.T) {
	want := map[string]bool{
		cfgSlackBotToken: true, cfgSlackTeamChannels: false, cfgTeamsAppID: false,
		cfgTeamsAppPassword: true, cfgTeamsTeamChannels: false,
	}
	for _, d := range configRegistry {
		if sec, ok := want[d.Key]; ok {
			if d.Secret != sec {
				t.Fatalf("%s Secret=%v want %v", d.Key, d.Secret, sec)
			}
			delete(want, d.Key)
		}
	}
	if len(want) != 0 {
		t.Fatalf("unregistered: %v", want)
	}
}

func TestChatopsTeamChannelParsers(t *testing.T) {
	if r, err := slackTeamChannels(""); r != nil || err != nil {
		t.Fatal("empty is nil,nil")
	}
	if _, err := slackTeamChannels("[1]"); err == nil {
		t.Fatal("array must error")
	}
	r, err := teamsTeamChannels(`{"a":{"service_url":"https://x","conversation_id":"c"}}`)
	if err != nil || r["a"].ConversationID != "c" {
		t.Fatalf("%v %v", r, err)
	}
	if _, err := teamsTeamChannels("nope"); err == nil {
		t.Fatal("garbage must error")
	}
}

func TestChatopsEnvFallbackForSecret(t *testing.T) {
	t.Setenv("SLACK_BOT_TOKEN", " env-token ")
	if got := configString(context.Background(), nil, cfgSlackBotToken, "SLACK_BOT_TOKEN", true); got != "env-token" {
		t.Fatalf("got %q", got)
	}
}
