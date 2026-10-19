// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package servicenow

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
	"kryptkeeper/internal/notifications/itsm"

	_ "modernc.org/sqlite"
)

const (
	testUser = "svc-kk"
	testPass = "hunter2-secret"
)

type stub struct {
	mu        sync.Mutex
	byCorr    map[string]map[string]string // correlation_id -> incident
	bySys     map[string]map[string]string
	posts     int
	last      *http.Request
	lastBody  map[string]string
	forceCode int
	patchCode int               // forced status for PATCH only
	approvers map[string]string // sysapproval sys_id -> approving sys_user sys_id
}

func newStub() (*stub, *Connector, *httptest.Server) {
	s := &stub{byCorr: map[string]map[string]string{}, bySys: map[string]map[string]string{}}
	srv := httptest.NewServer(s)
	c, err := New(srv.URL+"/", Credentials{testUser, testPass}, srv.Client())
	if err != nil {
		panic(err)
	}
	return s, c, srv
}

func (s *stub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.last = r.Clone(context.Background())
	u, p, ok := r.BasicAuth()
	if !ok || u != testUser || p != testPass {
		http.Error(w, "unauthorized", 401)
		return
	}
	var body map[string]string
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	s.lastBody = body
	if s.forceCode != 0 {
		http.Error(w, "forced "+strings.Repeat("x", 500), s.forceCode)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	base, pfx, num := "/api/now/table/incident", "sys", "INC"
	if strings.HasPrefix(r.URL.Path, "/api/now/table/change_request") {
		base, pfx, num = "/api/now/table/change_request", "chg", "CHG"
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/now/table/sysapproval_approver":
		res := []map[string]any{}
		for sys, who := range s.approvers {
			if strings.Contains(r.URL.Query().Get("sysparm_query"), "sysapproval="+sys+"^state=approved") {
				res = append(res, map[string]any{"approver": map[string]string{"link": "x", "value": who}})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"result": res})
	case r.Method == http.MethodGet && r.URL.Path == base:
		q := strings.TrimPrefix(r.URL.Query().Get("sysparm_query"), "correlation_id=")
		res := []map[string]string{}
		if inc, ok := s.byCorr[q]; ok && strings.HasPrefix(inc["sys_id"], pfx) {
			res = append(res, inc)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"result": res})
	case r.Method == http.MethodPost && r.URL.Path == base:
		s.posts++
		sys := fmt.Sprintf("%s%03d", pfx, s.posts)
		inc := map[string]string{"sys_id": sys, "number": fmt.Sprintf("%s%04d", num, s.posts), "state": "1"}
		for k, v := range body {
			inc[k] = v
		}
		s.byCorr[body["correlation_id"]] = inc
		s.bySys[sys] = inc
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"result": inc})
	case strings.HasPrefix(r.URL.Path, base+"/"):
		inc, ok := s.bySys[strings.TrimPrefix(r.URL.Path, base+"/")]
		if ok && !strings.HasPrefix(inc["sys_id"], pfx) {
			ok = false // right sys_id, wrong table
		}
		if !ok {
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"error":{"message":"No Record found"}}`))
			return
		}
		if r.Method == http.MethodPatch {
			if s.patchCode != 0 {
				http.Error(w, `{"error":{"message":"state transition not allowed"}}`, s.patchCode)
				return
			}
			for k, v := range body {
				inc[k] = v
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"result": inc})
	default:
		w.WriteHeader(404)
	}
}

func event(id string) itsm.Event {
	return itsm.Event{ID: id, Class: "renewal_failed", CN: "api.example.com", Serial: "0A1B2C", Risk: "high",
		DeepLink: "https://kk.example/certs/0A1B2C", Fingerprint: "fp-1", NotAfter: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)}
}

func TestCreate_PostsMappedFields(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	ref, err := c.Create(context.Background(), event("ev-1"))
	if err != nil {
		t.Fatal(err)
	}
	if s.last.URL.Path != "/api/now/table/incident" || s.last.Method != http.MethodPost {
		t.Fatalf("path/method %s %s", s.last.Method, s.last.URL.Path)
	}
	if u, p, _ := s.last.BasicAuth(); u != testUser || p != testPass {
		t.Fatal("basic auth missing")
	}
	b := s.lastBody
	if b["correlation_id"] != "ev-1" || b["correlation_display"] != "Kryptkeeper" || b["category"] != "software" {
		t.Fatalf("body %v", b)
	}
	if b["short_description"] != "Certificate renewal failed: api.example.com" || b["urgency"] != "2" || b["impact"] != "2" {
		t.Fatalf("body %v", b)
	}
	for _, want := range []string{"CN: api.example.com", "Serial: 0A1B2C", "Expires: 2026-11-01T12:00:00Z", "Risk: high", "Link: https://kk.example/certs/0A1B2C"} {
		if !strings.Contains(b["description"], want) {
			t.Fatalf("description missing %q: %q", want, b["description"])
		}
	}
	if ref.Key != "sys001" || !strings.Contains(ref.URL, "sys_id=sys001") || !strings.Contains(ref.URL, "&number=INC0001") {
		t.Fatalf("ref %+v", ref)
	}
	ev := event("ev-2")
	ev.Risk, ev.Class = "low", "other"
	if _, err := c.Create(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if s.lastBody["urgency"] != "3" || !strings.HasPrefix(s.lastBody["short_description"], "Certificate alert: ") {
		t.Fatalf("body %v", s.lastBody)
	}
}

func TestFind_ByCorrelationID(t *testing.T) {
	_, c, srv := newStub()
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
}

func TestCreate_Exactly1IncidentAcross5Retries(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "itsm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	store := itsm.NewStore(db, false)
	ctx := context.Background()
	if _, err := store.CreateConnection(ctx, itsm.Connection{ID: "c1", Kind: "servicenow", Name: "SN", BaseURL: srv.URL, CredentialRef: "r", Enabled: true}, time.Now()); err != nil {
		t.Fatal(err)
	}
	svc := itsm.NewService(itsm.Config{Store: store, Conns: func(context.Context, string) (itsm.Connector, error) { return c, nil }})
	for i := 0; i < 5; i++ {
		if err := svc.Submit(ctx, "c1", event("ev-1")); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Drain(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if s.posts != 1 || len(s.bySys) != 1 {
		t.Fatalf("incidents=%d posts=%d, want 1", len(s.bySys), s.posts)
	}
}

func TestResolve_PatchesStateSixWithCloseNotes(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	ref, _ := c.Create(context.Background(), event("ev-1"))
	if err := c.Resolve(context.Background(), ref, "Replaced cert verified"); err != nil {
		t.Fatal(err)
	}
	if s.last.Method != http.MethodPatch || s.last.URL.Path != "/api/now/table/incident/"+ref.Key {
		t.Fatalf("%s %s", s.last.Method, s.last.URL.Path)
	}
	b := s.lastBody
	if b["state"] != "6" || b["close_code"] != "Solved (Permanently)" || b["close_notes"] != "Replaced cert verified" || b["work_notes"] != "Replaced cert verified" {
		t.Fatalf("body %v", b)
	}
}

func TestResolve_AlreadyResolvedIsSuccess(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	ref, _ := c.Create(context.Background(), event("ev-1"))
	s.bySys[ref.Key]["state"] = "7"
	s.patchCode = http.StatusBadRequest
	if err := c.Resolve(context.Background(), ref, "x"); err != nil {
		t.Fatalf("closed incident should be success: %v", err)
	}
	s.bySys[ref.Key]["state"] = "2"
	if err := c.Resolve(context.Background(), ref, "x"); !errors.Is(err, itsm.ErrPermanent) {
		t.Fatalf("in-progress + 400 should be permanent: %v", err)
	}
}

func TestExists_404IsFalse(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	ctx := context.Background()
	if ok, err := c.Exists(ctx, itsm.TicketRef{Key: "nope"}); ok || err != nil {
		t.Fatalf("missing: %v %v", ok, err)
	}
	ref, _ := c.Create(ctx, event("ev-1"))
	s.bySys[ref.Key]["state"] = "8"
	if ok, err := c.Exists(ctx, ref); !ok || err != nil {
		t.Fatalf("canceled still exists: %v %v", ok, err)
	}
}

func TestErrors_5xxIsTemporary_4xxIsPermanent_429IsTemporary(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	for code, want := range map[int]error{500: itsm.ErrTemporary, 503: itsm.ErrTemporary, 429: itsm.ErrTemporary, 408: itsm.ErrTemporary,
		400: itsm.ErrPermanent, 401: itsm.ErrPermanent, 403: itsm.ErrPermanent, 422: itsm.ErrPermanent} {
		s.forceCode = code
		_, err := c.Create(context.Background(), event("ev-x"))
		if !errors.Is(err, want) {
			t.Errorf("%d: got %v, want %v", code, err, want)
		}
		if err != nil && len(err.Error()) > 400 {
			t.Errorf("%d: error not truncated (%d bytes)", code, len(err.Error()))
		}
	}
	srv.Close()
	if _, err := c.Find(context.Background(), "ev"); !errors.Is(err, itsm.ErrTemporary) {
		t.Errorf("network error: %v", err)
	}
}

func TestErrors_NeverContainCredentials(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	for _, code := range []int{401, 403, 500} {
		s.forceCode = code
		_, err := c.Create(context.Background(), event("ev-x"))
		if err == nil || strings.Contains(err.Error(), testPass) || strings.Contains(err.Error(), testUser) || strings.Contains(strings.ToLower(err.Error()), "basic ") {
			t.Fatalf("%d: %v", code, err)
		}
	}
	srv.Close()
	_, err := c.Find(context.Background(), "ev")
	if err == nil || strings.Contains(err.Error(), testPass) {
		t.Fatalf("net error leaks: %v", err)
	}
}

func TestNew_RejectsPlainHTTPNonLoopback(t *testing.T) {
	cr := Credentials{"u", "p"}
	hc := http.DefaultClient
	for _, u := range []string{"http://dev1.service-now.com", "ftp://x", "", "not a url"} {
		if _, err := New(u, cr, hc); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
	for _, u := range []string{"https://dev1.service-now.com/", "http://127.0.0.1:8080", "http://localhost:1"} {
		if _, err := New(u, cr, hc); err != nil {
			t.Errorf("%q rejected: %v", u, err)
		}
	}
	c, _ := New("https://dev1.service-now.com/", cr, hc)
	if c.baseURL != "https://dev1.service-now.com" {
		t.Errorf("slash not trimmed: %s", c.baseURL)
	}
}

func TestFactory_ParsesCredentialJSON(t *testing.T) {
	if _, err := Factory("https://x.service-now.com", []byte(`{"username":"u","password":"p"}`), http.DefaultClient); err != nil {
		t.Fatal(err)
	}
	if _, err := Factory("https://x.service-now.com", []byte(`nope`), http.DefaultClient); err == nil {
		t.Fatal("bad json accepted")
	}
}

func TestChangeRequest_UsesChangeTableEndToEnd(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	ctx := context.Background()
	ev := event("ev-chg")
	ev.TicketType = "change_request"
	ref, err := c.Create(ctx, ev)
	if err != nil {
		t.Fatal(err)
	}
	if s.last.URL.Path != "/api/now/table/change_request" || s.lastBody["correlation_id"] != "ev-chg" {
		t.Fatalf("create hit %s body %v", s.last.URL.Path, s.lastBody)
	}
	if _, ok := s.lastBody["category"]; ok {
		t.Fatalf("change_request body must not carry the incident category: %v", s.lastBody)
	}
	if !strings.Contains(ref.URL, "uri=change_request.do?sys_id="+ref.Key) || !strings.HasPrefix(ref.Key, "chg") {
		t.Fatalf("ref %+v", ref)
	}
	found, err := c.Find(ctx, "ev-chg")
	if err != nil || found == nil || found.Key != ref.Key || tableOf(*found).name != "change_request" {
		t.Fatalf("find %v %v", found, err)
	}
	if ok, err := c.Exists(ctx, ref); !ok || err != nil || s.last.URL.Path != "/api/now/table/change_request/"+ref.Key {
		t.Fatalf("exists %v %v %s", ok, err, s.last.URL.Path)
	}
	s.approvers = map[string]string{ref.Key: "user42"}
	s.bySys[ref.Key]["approval"] = "approved"
	if st, who, err := c.Approval(ctx, ref); err != nil || st != itsm.ApprovalApproved || who != "user42" {
		t.Fatalf("approval %v %q %v", st, who, err)
	}
	if err := c.Resolve(ctx, ref, "Replaced cert verified"); err != nil {
		t.Fatal(err)
	}
	if s.last.Method != http.MethodPatch || s.last.URL.Path != "/api/now/table/change_request/"+ref.Key {
		t.Fatalf("resolve hit %s %s", s.last.Method, s.last.URL.Path)
	}
	b := s.lastBody
	if b["state"] != "3" || b["close_code"] != "successful" || b["close_notes"] != "Replaced cert verified" {
		t.Fatalf("body %v", b)
	}
}

func TestChangeRequest_AlreadyClosedIsSuccess_IncidentUnaffected(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	ctx := context.Background()
	ev := event("ev-chg")
	ev.TicketType = "change_request"
	ref, _ := c.Create(ctx, ev)
	s.bySys[ref.Key]["state"] = "4"
	s.patchCode = http.StatusBadRequest
	if err := c.Resolve(ctx, ref, "x"); err != nil {
		t.Fatalf("canceled change should be success: %v", err)
	}
	// "6" closes an incident but is not a closed state for a change.
	s.bySys[ref.Key]["state"] = "6"
	if err := c.Resolve(ctx, ref, "x"); !errors.Is(err, itsm.ErrPermanent) {
		t.Fatalf("state 6 on a change + 400 should be permanent: %v", err)
	}
}

func TestFind_ChangeTableForbiddenIsNoMatch(t *testing.T) {
	_, c, srv := newStub()
	defer srv.Close()
	// An integration user without change_request read access must still
	// create incidents: the secondary search treats 403/404 as "no match".
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "change_request") {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"result":[]}`))
	})
	if ref, err := c.Find(context.Background(), "ev-1"); err != nil || ref != nil {
		t.Fatalf("want nil,nil got %v %v", ref, err)
	}
}
