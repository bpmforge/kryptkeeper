// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package jira

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	kkdb "kryptkeeper/internal/db"
	"kryptkeeper/internal/egress"
	"kryptkeeper/internal/notifications/itsm"

	_ "modernc.org/sqlite"
)

const (
	testEmail = "svc@example.com"
	testToken = "ATATT-secret-token"
)

type issue struct {
	Key, Status, Category string
	Labels                []string
	Fields                map[string]any
	Comments              []map[string]any
	Author                string // accountId of last status change
	NoAuthor              bool
}

type stub struct {
	mu          sync.Mutex
	issues      map[string]*issue
	creates     int
	transitions []string // transition ids posted
	forceCode   int
	create502   bool // store the issue, then answer 502
	noDoneTrans bool
	last        *http.Request
	lastBody    map[string]any
}

func newStub() (*stub, *Connector, *httptest.Server) {
	s := &stub{issues: map[string]*issue{}}
	srv := httptest.NewServer(s)
	c, err := New(srv.URL+"/", Config{Email: testEmail, APIToken: testToken, ProjectKey: "KK",
		ApprovedStatus: "Approved", RejectedStatus: "Rejected"}, testClient())
	if err != nil {
		panic(err)
	}
	return s, c, srv
}

func testClient() *http.Client {
	return egress.NewClient(egress.Policy{AllowLoopback: true, Timeout: 5 * time.Second})
}

func (s *stub) setStatus(key, name, cat, author string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.issues[key]
	i.Status, i.Category, i.Author = name, cat, author
}

func (s *stub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.last = r.Clone(context.Background())
	if u, p, ok := r.BasicAuth(); !ok || u != testEmail || p != testToken {
		http.Error(w, "unauthorized", 401)
		return
	}
	var body map[string]any
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	s.lastBody = body
	if s.forceCode != 0 {
		w.WriteHeader(s.forceCode)
		_, _ = w.Write([]byte(`{"errorMessages":["forced ` + strings.Repeat("x", 500) + `"]}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	p := r.URL.Path
	switch {
	case r.Method == http.MethodGet && p == "/rest/api/3/search/jql":
		jql := r.URL.Query().Get("jql")
		res := []map[string]string{}
		for _, i := range s.issues {
			for _, l := range i.Labels {
				if strings.Contains(jql, `labels = "`+l+`"`) && len(res) == 0 {
					res = append(res, map[string]string{"key": i.Key})
				}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"issues": res})
	case r.Method == http.MethodPost && p == "/rest/api/3/issue":
		s.creates++
		key := fmt.Sprintf("KK-%d", s.creates)
		f, _ := body["fields"].(map[string]any)
		i := &issue{Key: key, Status: "To Do", Category: "new", Fields: f}
		for _, l := range f["labels"].([]any) {
			i.Labels = append(i.Labels, l.(string))
		}
		s.issues[key] = i
		if s.create502 {
			http.Error(w, "bad gateway", 502)
			return
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]string{"key": key})
	case strings.HasPrefix(p, "/rest/api/3/issue/"):
		rest := strings.TrimPrefix(p, "/rest/api/3/issue/")
		key, sub, _ := strings.Cut(rest, "/")
		i, ok := s.issues[key]
		if !ok {
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"errorMessages":["Issue does not exist"]}`))
			return
		}
		switch {
		case sub == "" && r.Method == http.MethodGet:
			out := map[string]any{"key": key, "fields": map[string]any{"status": map[string]any{
				"name": i.Status, "statusCategory": map[string]string{"key": i.Category}}}}
			if r.URL.Query().Get("expand") == "changelog" {
				author := map[string]string{"accountId": i.Author}
				if i.NoAuthor {
					author = map[string]string{}
				}
				out["changelog"] = map[string]any{"histories": []any{
					map[string]any{"created": "2026-10-01T10:00:00.000+0000", "author": map[string]string{"accountId": "someone-else"},
						"items": []any{map[string]string{"field": "status", "toString": "In Review"}}},
					map[string]any{"created": "2026-10-02T10:00:00.000+0000", "author": author,
						"items": []any{map[string]string{"field": "status", "toString": i.Status}}},
				}}
			}
			_ = json.NewEncoder(w).Encode(out)
		case sub == "comment" && r.Method == http.MethodPost:
			i.Comments = append(i.Comments, body)
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{}`))
		case sub == "transitions" && r.Method == http.MethodGet:
			ts := []any{map[string]any{"id": "11", "name": "Start", "to": map[string]any{"name": "In Progress", "statusCategory": map[string]string{"key": "indeterminate"}}}}
			if !s.noDoneTrans {
				ts = append(ts, map[string]any{"id": "31", "name": "Close it", "to": map[string]any{"name": "Done", "statusCategory": map[string]string{"key": "done"}}})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"transitions": ts})
		case sub == "transitions" && r.Method == http.MethodPost:
			id := body["transition"].(map[string]any)["id"].(string)
			s.transitions = append(s.transitions, id)
			if id == "31" {
				i.Status, i.Category = "Done", "done"
			}
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	default:
		w.WriteHeader(404)
	}
}

func event(id string) itsm.Event {
	return itsm.Event{ID: id, Class: "renewal_failed", CN: "api.example.com", Serial: "0A1B2C", Risk: "high",
		DeepLink: "https://kk.example/certs/0A1B2C", Fingerprint: "fp-1", NotAfter: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)}
}

func adfText(t *testing.T, v any) string {
	t.Helper()
	doc, ok := v.(map[string]any)
	if !ok || doc["type"] != "doc" || doc["version"] != float64(1) {
		t.Fatalf("not an ADF doc: %v", v)
	}
	var sb strings.Builder
	for _, p := range doc["content"].([]any) {
		for _, n := range p.(map[string]any)["content"].([]any) {
			sb.WriteString(n.(map[string]any)["text"].(string) + "\n")
		}
	}
	return sb.String()
}

func TestCreate_SendsProjectTypeLabelADFAndBasicAuth(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	ref, err := c.Create(context.Background(), event("ev-1"))
	if err != nil {
		t.Fatal(err)
	}
	if s.last.URL.Path != "/rest/api/3/issue" || s.last.Method != http.MethodPost {
		t.Fatalf("%s %s", s.last.Method, s.last.URL.Path)
	}
	if u, p, _ := s.last.BasicAuth(); u != testEmail || p != testToken {
		t.Fatal("basic auth missing")
	}
	f := s.lastBody["fields"].(map[string]any)
	if f["project"].(map[string]any)["key"] != "KK" || f["issuetype"].(map[string]any)["name"] != "Task" {
		t.Fatalf("fields %v", f)
	}
	if f["summary"] != "Certificate renewal failed: api.example.com" {
		t.Fatalf("summary %v", f["summary"])
	}
	if l := fmt.Sprint(f["labels"]); l != "[kk-ev-1 kryptkeeper]" {
		t.Fatalf("labels %s", l)
	}
	d := adfText(t, f["description"])
	for _, want := range []string{"CN: api.example.com", "Serial: 0A1B2C", "Expires: 2026-11-01T12:00:00Z", "Risk: high", "Link: https://kk.example/certs/0A1B2C"} {
		if !strings.Contains(d, want) {
			t.Fatalf("description missing %q: %q", want, d)
		}
	}
	if ref.Key != "KK-1" || ref.URL != srv.URL+"/browse/KK-1" {
		t.Fatalf("ref %+v", ref)
	}
	ev := event("ev-2")
	ev.Class = "other"
	if _, err := c.Create(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s.lastBody["fields"].(map[string]any)["summary"].(string), "Certificate alert: ") {
		t.Fatalf("body %v", s.lastBody)
	}
}

func TestCreate_LabelSanitised(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	if _, err := c.Create(context.Background(), event("renew 42/api.example.com:rsa")); err != nil {
		t.Fatal(err)
	}
	labels := s.lastBody["fields"].(map[string]any)["labels"].([]any)
	if labels[0] != "kk-renew_42_api_example_com_rsa" {
		t.Fatalf("label %v", labels[0])
	}
}

func TestFind_ByLabel(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	ctx := context.Background()
	if ref, err := c.Find(ctx, "ev-1"); err != nil || ref != nil {
		t.Fatalf("empty: %v %v", ref, err)
	}
	made, _ := c.Create(ctx, event("ev-1"))
	ref, err := c.Find(ctx, "ev-1")
	if err != nil || ref == nil || ref.Key != made.Key {
		t.Fatalf("hit: %v %v", ref, err)
	}
	if q := s.last.URL.Query(); q.Get("jql") != `project = "KK" AND labels = "kk-ev-1"` || q.Get("maxResults") != "1" {
		t.Fatalf("query %v", q)
	}
	if ref, _ := c.Find(ctx, "ev-2"); ref != nil {
		t.Fatalf("other event matched: %v", ref)
	}
}

func newService(t *testing.T, c *Connector, srvURL string, now func() time.Time) *itsm.Service {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "itsm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	store := itsm.NewStore(db, false)
	if _, err := store.CreateConnection(context.Background(), itsm.Connection{ID: "c1", Kind: "jira", Name: "J", BaseURL: srvURL, CredentialRef: "r", Enabled: true}, time.Now()); err != nil {
		t.Fatal(err)
	}
	return itsm.NewService(itsm.Config{Store: store, Now: now, Conns: func(context.Context, string) (itsm.Connector, error) { return c, nil }})
}

func TestFind_AdoptsCreatedButUnackedIssue(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	ctx := context.Background()
	svc := newService(t, c, srv.URL, nil)
	s.create502 = true
	if err := svc.Submit(ctx, "c1", event("ev-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if s.creates != 1 {
		t.Fatalf("creates=%d", s.creates)
	}
	// The retry path calls Find first and adopts the stored issue.
	s.create502 = false
	ref, err := c.Find(ctx, "ev-1")
	if err != nil || ref == nil || ref.Key != "KK-1" {
		t.Fatalf("not adopted: %v %v", ref, err)
	}
	if s.creates != 1 {
		t.Fatalf("Find must not create: %d", s.creates)
	}
}

func TestCreate_Exactly1IssueAcross5Retries(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	ctx := context.Background()
	svc := newService(t, c, srv.URL, nil)
	for i := 0; i < 5; i++ {
		if err := svc.Submit(ctx, "c1", event("ev-1")); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Drain(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if s.creates != 1 || len(s.issues) != 1 {
		t.Fatalf("issues=%d creates=%d, want 1", len(s.issues), s.creates)
	}
}

func TestExists_404IsFalse(t *testing.T) {
	_, c, srv := newStub()
	defer srv.Close()
	ctx := context.Background()
	if ok, err := c.Exists(ctx, itsm.TicketRef{Key: "KK-99"}); ok || err != nil {
		t.Fatalf("missing: %v %v", ok, err)
	}
	ref, _ := c.Create(ctx, event("ev-1"))
	if ok, err := c.Exists(ctx, ref); !ok || err != nil {
		t.Fatalf("present: %v %v", ok, err)
	}
}

func TestResolve_CommentsThenTransitions(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	ref, _ := c.Create(context.Background(), event("ev-1"))
	if err := c.Resolve(context.Background(), ref, "Replaced cert verified"); err != nil {
		t.Fatal(err)
	}
	i := s.issues[ref.Key]
	if len(i.Comments) != 1 || !strings.Contains(adfText(t, i.Comments[0]["body"]), "Replaced cert verified") {
		t.Fatalf("comments %v", i.Comments)
	}
	if len(s.transitions) != 1 || s.transitions[0] != "31" || i.Category != "done" {
		t.Fatalf("transitions %v status %s", s.transitions, i.Status)
	}
}

func TestResolve_DoneStatusNamePreferred(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	c.cfg.DoneStatus = "close IT"
	ref, _ := c.Create(context.Background(), event("ev-1"))
	if err := c.Resolve(context.Background(), ref, "x"); err != nil || len(s.transitions) != 1 || s.transitions[0] != "31" {
		t.Fatalf("%v %v", err, s.transitions)
	}
}

func TestResolve_AlreadyDoneIsSuccess(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	ref, _ := c.Create(context.Background(), event("ev-1"))
	s.setStatus(ref.Key, "Done", "done", "u1")
	if err := c.Resolve(context.Background(), ref, "x"); err != nil {
		t.Fatal(err)
	}
	if len(s.transitions) != 0 {
		t.Fatalf("transitioned a done issue: %v", s.transitions)
	}
}

func TestResolve_NoDoneTransitionPermanent(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	ref, _ := c.Create(context.Background(), event("ev-1"))
	s.noDoneTrans = true
	err := c.Resolve(context.Background(), ref, "x")
	if !errors.Is(err, itsm.ErrPermanent) || !strings.Contains(err.Error(), "no done transition") {
		t.Fatalf("%v", err)
	}
}

func TestApproval_PendingApprovedRejected(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	ctx := context.Background()
	ref, _ := c.Create(ctx, event("ev-1"))
	st, _, err := c.Approval(ctx, ref)
	if err != nil || st != itsm.ApprovalPending {
		t.Fatalf("pending: %v %v", st, err)
	}
	s.setStatus(ref.Key, "approved", "indeterminate", "acc-1") // case-insensitive
	if st, _, err = c.Approval(ctx, ref); err != nil || st != itsm.ApprovalApproved {
		t.Fatalf("approved: %v %v", st, err)
	}
	s.setStatus(ref.Key, "Rejected", "done", "acc-2")
	if st, _, err = c.Approval(ctx, ref); err != nil || st != itsm.ApprovalRejected {
		t.Fatalf("rejected: %v %v", st, err)
	}
	c.cfg.RejectedStatus = ""
	if st, _, _ = c.Approval(ctx, ref); st != itsm.ApprovalPending {
		t.Fatalf("unset rejected status must stay pending: %v", st)
	}
}

func TestApproval_ApproverFromChangelog(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	ref, _ := c.Create(context.Background(), event("ev-1"))
	s.setStatus(ref.Key, "Approved", "indeterminate", "acc-77")
	_, who, err := c.Approval(context.Background(), ref)
	if err != nil || who != "acc-77" {
		t.Fatalf("approver %q %v", who, err)
	}
}

func TestApproval_NoAuthorPermanent(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	ref, _ := c.Create(context.Background(), event("ev-1"))
	s.setStatus(ref.Key, "Approved", "indeterminate", "")
	s.issues[ref.Key].NoAuthor = true
	_, _, err := c.Approval(context.Background(), ref)
	if !errors.Is(err, itsm.ErrPermanent) || !strings.Contains(err.Error(), "approver unknown") {
		t.Fatalf("%v", err)
	}
}

// W32-12's Bridge is not on this branch; this drives the same poll contract:
// the connector must report the flip on the poll after it happens.
func TestApprovalSurfacedWithin2Polls(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	ctx := context.Background()
	ref, _ := c.Create(ctx, event("ev-1"))
	var got itsm.ApprovalState
	var who string
	for poll := 1; poll <= 2; poll++ {
		st, w, err := c.Approval(ctx, ref)
		if err != nil {
			t.Fatal(err)
		}
		if st == itsm.ApprovalApproved {
			got, who = st, w
			break
		}
		if poll == 1 {
			s.setStatus(ref.Key, "Approved", "indeterminate", "acc-9")
		}
	}
	if got != itsm.ApprovalApproved || who != "acc-9" {
		t.Fatalf("not surfaced by poll 2: %q %q", got, who)
	}
}

func TestResolveWithin5MinutesOfRecovery(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	ctx := context.Background()
	clock := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	svc := newService(t, c, srv.URL, func() time.Time { return clock })
	if err := svc.Submit(ctx, "c1", event("ev-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(4*time.Minute + 59*time.Second) // recovery + 4m59s
	n, err := svc.ResolveByFingerprint(ctx, "fp-1", "renewed")
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if len(s.transitions) != 1 || s.issues["KK-1"].Category != "done" {
		t.Fatalf("transitions %v", s.transitions)
	}
}

func TestErrors_5xx429Temporary_4xxPermanent(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	for code, want := range map[int]error{500: itsm.ErrTemporary, 503: itsm.ErrTemporary, 429: itsm.ErrTemporary, 408: itsm.ErrTemporary,
		400: itsm.ErrPermanent, 401: itsm.ErrPermanent, 403: itsm.ErrPermanent, 422: itsm.ErrPermanent} {
		s.forceCode = code
		_, err := c.Create(context.Background(), event("ev-x"))
		if !errors.Is(err, want) {
			t.Errorf("%d: got %v, want %v", code, err, want)
		}
		if err != nil && len(err.Error()) > 300 {
			t.Errorf("%d: error not truncated (%d bytes)", code, len(err.Error()))
		}
	}
	srv.Close()
	if _, err := c.Find(context.Background(), "ev"); !errors.Is(err, itsm.ErrTemporary) {
		t.Errorf("network error: %v", err)
	}
}

func TestErrors_NeverContainToken(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	for _, code := range []int{401, 403, 500} {
		s.forceCode = code
		_, err := c.Create(context.Background(), event("ev-x"))
		if err == nil || strings.Contains(err.Error(), testToken) || strings.Contains(strings.ToLower(err.Error()), "basic ") {
			t.Fatalf("%d: %v", code, err)
		}
	}
	srv.Close()
	_, err := c.Find(context.Background(), "ev")
	if err == nil || strings.Contains(err.Error(), testToken) {
		t.Fatalf("net error leaks: %v", err)
	}
}

func TestNew_RejectsPlainHTTPNonLoopbackAndMissingProject(t *testing.T) {
	cfg := Config{Email: "e", APIToken: "t", ProjectKey: "KK"}
	hc := http.DefaultClient
	for _, u := range []string{"http://x.atlassian.net", "ftp://x", "", "not a url"} {
		if _, err := New(u, cfg, hc); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
	for _, u := range []string{"https://x.atlassian.net/", "http://127.0.0.1:8080", "http://localhost:1"} {
		if _, err := New(u, cfg, hc); err != nil {
			t.Errorf("%q rejected: %v", u, err)
		}
	}
	for _, pk := range []string{"", `K" OR 1=1`} {
		bad := cfg
		bad.ProjectKey = pk
		if _, err := New("https://x.atlassian.net", bad, hc); err == nil {
			t.Errorf("project %q accepted", pk)
		}
	}
	c, _ := New("https://x.atlassian.net/", cfg, hc)
	if c.baseURL != "https://x.atlassian.net" || c.cfg.IssueType != "Task" {
		t.Errorf("baseURL %q issuetype %q", c.baseURL, c.cfg.IssueType)
	}
}

func TestFactory_ParsesCredentialJSON(t *testing.T) {
	good := `{"email":"e","api_token":"t","project_key":"KK","approved_status":"Approved"}`
	if _, err := Factory("https://x.atlassian.net", []byte(good), http.DefaultClient); err != nil {
		t.Fatal(err)
	}
	if _, err := Factory("https://x.atlassian.net", []byte(`nope`), http.DefaultClient); err == nil {
		t.Fatal("bad json accepted")
	}
}

func TestCreate_EventTicketTypeOverridesIssueType(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	ev := event("ev-9")
	ev.TicketType = "Bug"
	if _, err := c.Create(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if got := s.lastBody["fields"].(map[string]any)["issuetype"].(map[string]any)["name"]; got != "Bug" {
		t.Fatalf("issuetype %v", got)
	}
}
