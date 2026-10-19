// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type slackStub struct {
	mu   sync.Mutex
	reqs []stubReq
	srv  *httptest.Server
	fail func(n int, w http.ResponseWriter) bool
}

type stubReq struct {
	Path string
	Auth string
	Body map[string]any
	Raw  string
}

func newSlackStub(t *testing.T) *slackStub {
	t.Helper()
	st := &slackStub{}
	st.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		st.mu.Lock()
		st.reqs = append(st.reqs, stubReq{r.URL.Path, r.Header.Get("Authorization"), m, string(b)})
		n := len(st.reqs)
		st.mu.Unlock()
		if st.fail != nil && st.fail(n, w) {
			return
		}
		ch, _ := m["channel"].(string)
		_, _ = w.Write([]byte(`{"ok":true,"channel":"` + ch + `","ts":"1700.01"}`))
	}))
	t.Cleanup(st.srv.Close)
	return st
}

func (st *slackStub) client(r TeamChannelResolver) *SlackInteractive {
	return &SlackInteractive{BotToken: "test-slack-bot", BaseURL: st.srv.URL, Resolver: r, Refs: &MemRefStore{}}
}

func buttons(t *testing.T, body map[string]any) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, b := range body["blocks"].([]any) {
		blk := b.(map[string]any)
		if blk["type"] == "actions" {
			for _, e := range blk["elements"].([]any) {
				out = append(out, e.(map[string]any))
			}
		}
	}
	return out
}

func TestPostApproval_OwnerTeamChannelOnly(t *testing.T) {
	st := newSlackStub(t)
	s := st.client(MapResolver{"a": "CA1", "b": "CB1"})
	ref, err := s.PostApproval(context.Background(), ApprovalPending{Kind: "approval", ID: "abc", OwnerTeam: "a", Summary: "Renew x"})
	if err != nil {
		t.Fatal(err)
	}
	if len(st.reqs) != 1 || st.reqs[0].Path != "/chat.postMessage" || st.reqs[0].Body["channel"] != "CA1" {
		t.Fatalf("unexpected requests: %+v", st.reqs)
	}
	if ref.Channel != "CA1" || ref.TS == "" {
		t.Fatalf("ref=%+v", ref)
	}
	bs := buttons(t, st.reqs[0].Body)
	if len(bs) != 2 || bs[0]["action_id"] != "kk_approve" || bs[1]["action_id"] != "kk_reject" ||
		bs[0]["value"] != "approval:abc" || bs[1]["value"] != "approval:abc" {
		t.Fatalf("buttons=%+v", bs)
	}
}

func TestPostApproval_UnmappedTeamNoHTTP(t *testing.T) {
	st := newSlackStub(t)
	s := st.client(MapResolver{"a": "CA1"})
	for _, team := range []string{"zzz", ""} {
		if _, err := s.PostApproval(context.Background(), ApprovalPending{Kind: "approval", ID: "1", OwnerTeam: team}); err != ErrNoTeamChannel {
			t.Fatalf("team %q: err=%v", team, err)
		}
	}
	if len(st.reqs) != 0 {
		t.Fatalf("expected 0 requests, got %d", len(st.reqs))
	}
}

func TestButtonContractPinned(t *testing.T) {
	if slackActionApprove != "kk_approve" || slackActionReject != "kk_reject" {
		t.Fatal("action ids drifted from chatops contract")
	}
	st := newSlackStub(t)
	s := st.client(MapResolver{"a": "C1"})
	if _, err := s.PostApproval(context.Background(), ApprovalPending{Kind: "action", ID: "7", OwnerTeam: "a"}); err != nil {
		t.Fatal(err)
	}
	if v := buttons(t, st.reqs[0].Body)[0]["value"]; v != "action:7" {
		t.Fatalf("value=%v", v)
	}
}

func TestUpdateOutcome_Approved(t *testing.T) {
	st := newSlackStub(t)
	s := st.client(MapResolver{"a": "CA1"})
	ctx := context.Background()
	if _, err := s.PostApproval(ctx, ApprovalPending{Kind: "approval", ID: "abc", OwnerTeam: "a"}); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	if err := s.UpdateOutcome(ctx, "approval:abc", Outcome{Result: "approved", By: "alice", ExternalBy: "slack:T1/U1", At: at}); err != nil {
		t.Fatal(err)
	}
	u := st.reqs[1]
	if u.Path != "/chat.update" || u.Body["channel"] != "CA1" || u.Body["ts"] != "1700.01" {
		t.Fatalf("update=%+v", u)
	}
	txt := u.Body["text"].(string)
	for _, want := range []string{"Approved", "alice", "slack:T1/U1", "2026-10-16T12:00:00Z"} {
		if !strings.Contains(txt, want) {
			t.Fatalf("text %q missing %q", txt, want)
		}
	}
	if len(buttons(t, u.Body)) != 0 || strings.Contains(u.Raw, `"actions"`) {
		t.Fatal("buttons must be removed")
	}
}

func TestUpdateOutcome_ExpiredExplains(t *testing.T) {
	st := newSlackStub(t)
	s := st.client(MapResolver{"a": "C1"})
	ctx := context.Background()
	_, _ = s.PostApproval(ctx, ApprovalPending{Kind: "approval", ID: "e", OwnerTeam: "a"})
	st.reqs = nil
	if err := s.UpdateOutcome(ctx, "approval:e", Outcome{Result: "expired", At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	txt := st.reqs[0].Body["text"].(string)
	if len(st.reqs) != 1 || st.reqs[0].Path != "/chat.update" || !strings.Contains(txt, "Expired") || !strings.Contains(txt, "Nothing was changed") {
		t.Fatalf("reqs=%+v", st.reqs)
	}
}

func TestUpdateOutcome_UnknownKey(t *testing.T) {
	st := newSlackStub(t)
	if err := st.client(MapResolver{}).UpdateOutcome(context.Background(), "approval:nope", Outcome{Result: "approved"}); err != ErrNoMessage {
		t.Fatalf("err=%v", err)
	}
	if len(st.reqs) != 0 {
		t.Fatal("no HTTP expected")
	}
}

func TestSlackErrorNotLeaked(t *testing.T) {
	st := newSlackStub(t)
	st.fail = func(_ int, w http.ResponseWriter) bool {
		_, _ = w.Write([]byte(`{"ok":false,"error":"channel_not_found"}`))
		return true
	}
	s := st.client(MapResolver{"a": "C1"})
	_, err := s.PostApproval(context.Background(), ApprovalPending{Kind: "approval", ID: "1", OwnerTeam: "a"})
	if err == nil || !strings.Contains(err.Error(), "channel_not_found") || strings.Contains(err.Error(), "test-slack-bot") {
		t.Fatalf("err=%v", err)
	}
}

func TestEscapesMrkdwn(t *testing.T) {
	st := newSlackStub(t)
	s := st.client(MapResolver{"a": "C1"})
	_, err := s.PostApproval(context.Background(), ApprovalPending{Kind: "approval", ID: "1", OwnerTeam: "a", Summary: "<!channel> a&b", Requester: "<@U1>"})
	if err != nil {
		t.Fatal(err)
	}
	raw := st.reqs[0].Body["blocks"].([]any)[0].(map[string]any)["text"].(map[string]any)["text"].(string)
	if strings.Contains(raw, "<!channel>") || !strings.Contains(raw, "&lt;!channel&gt; a&amp;b") || strings.Contains(raw, "<@U1>") {
		t.Fatalf("unescaped: %s", raw)
	}
}

func TestSummaryTruncated(t *testing.T) {
	st := newSlackStub(t)
	s := st.client(MapResolver{"a": "C1"})
	_, _ = s.PostApproval(context.Background(), ApprovalPending{Kind: "approval", ID: "1", OwnerTeam: "a", Summary: strings.Repeat("x", 2000)})
	if strings.Contains(st.reqs[0].Raw, strings.Repeat("x", 501)) {
		t.Fatal("summary not truncated")
	}
}

func TestRetryOn429(t *testing.T) {
	st := newSlackStub(t)
	st.fail = func(n int, w http.ResponseWriter) bool {
		if n == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return true
		}
		return false
	}
	s := st.client(MapResolver{"a": "C1"})
	if _, err := s.PostApproval(context.Background(), ApprovalPending{Kind: "approval", ID: "1", OwnerTeam: "a"}); err != nil {
		t.Fatal(err)
	}
	if len(st.reqs) != 2 {
		t.Fatalf("requests=%d", len(st.reqs))
	}
}

func TestAuthHeaderSent(t *testing.T) {
	st := newSlackStub(t)
	s := st.client(MapResolver{"a": "C1"})
	_, _ = s.PostApproval(context.Background(), ApprovalPending{Kind: "approval", ID: "1", OwnerTeam: "a"})
	if st.reqs[0].Auth != "Bearer test-slack-bot" {
		t.Fatalf("auth=%q", st.reqs[0].Auth)
	}
}
