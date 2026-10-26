// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestReportScheduleStore(t *testing.T) *dbReportScheduleStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "rsched.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := &dbReportScheduleStore{db: db, ph: sqlitePlaceholder}
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	return s
}

func TestReportScheduleStoreCRUD(t *testing.T) {
	s := newTestReportScheduleStore(t)
	ctx := context.Background()
	created, err := s.Create(ctx, ReportSchedule{
		Report: "inventory", Format: "csv", Cadence: "weekly", Recipients: []string{"a@x.com", "b@x.com"}, Enabled: true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !strings.HasPrefix(created.ID, "rsc-") || len(created.ID) != 4+24 {
		t.Fatalf("unexpected id %q", created.ID)
	}
	list, err := s.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v len=%d", err, len(list))
	}
	if got := list[0]; got.Report != "inventory" || got.Format != "csv" || len(got.Recipients) != 2 || !got.Enabled || got.LastSentAt != "" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	when := time.Now().UTC().Format(time.RFC3339)
	if err := s.MarkSent(ctx, created.ID, when); err != nil {
		t.Fatalf("mark sent: %v", err)
	}
	if list, _ = s.List(ctx); list[0].LastSentAt != when {
		t.Fatalf("last_sent_at = %q, want %q", list[0].LastSentAt, when)
	}
	if err := s.Delete(ctx, created.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := s.Delete(ctx, created.ID); !errors.Is(err, errReportScheduleNotFound) {
		t.Fatalf("second delete = %v, want not found", err)
	}
	if list, _ = s.List(ctx); len(list) != 0 {
		t.Fatalf("expected empty list, got %d", len(list))
	}
}

func TestValidateReportSchedule(t *testing.T) {
	ok := func() ReportSchedule {
		return ReportSchedule{Report: "executive-summary", Format: "pdf", Cadence: "weekly", Recipients: []string{"a@x.com"}}
	}
	many := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("u%d@x.com", i)
		}
		return out
	}
	cases := []struct {
		name   string
		mutate func(*ReportSchedule)
		wantOK bool
	}{
		{"exec pdf", func(*ReportSchedule) {}, true},
		{"inventory csv", func(s *ReportSchedule) { s.Report, s.Format = "inventory", "csv" }, true},
		{"inventory xlsx", func(s *ReportSchedule) { s.Report, s.Format = "inventory", "xlsx" }, true},
		{"findings xlsx", func(s *ReportSchedule) { s.Report, s.Format = "findings", "xlsx" }, true},
		{"default cadence", func(s *ReportSchedule) { s.Cadence = "" }, true},
		{"inventory pdf", func(s *ReportSchedule) { s.Report, s.Format = "inventory", "pdf" }, false},
		{"exec csv", func(s *ReportSchedule) { s.Format = "csv" }, false},
		{"unknown report", func(s *ReportSchedule) { s.Report = "nope" }, false},
		{"bad cadence", func(s *ReportSchedule) { s.Cadence = "hourly" }, false},
		{"zero recipients", func(s *ReportSchedule) { s.Recipients = nil }, false},
		{"20 recipients", func(s *ReportSchedule) { s.Recipients = many(20) }, true},
		{"21 recipients", func(s *ReportSchedule) { s.Recipients = many(21) }, false},
		{"bad email", func(s *ReportSchedule) { s.Recipients = []string{"not-an-email"} }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := ok()
			tc.mutate(&s)
			err := validateReportSchedule(&s)
			if (err == nil) != tc.wantOK {
				t.Fatalf("err=%v wantOK=%v", err, tc.wantOK)
			}
			if err != nil && strings.Contains(err.Error(), "not-an-email") {
				t.Fatalf("error echoes recipient: %v", err)
			}
		})
	}
	s := ok()
	s.Cadence = ""
	_ = validateReportSchedule(&s)
	if s.Cadence != "monthly" {
		t.Fatalf("default cadence = %q", s.Cadence)
	}
}

func TestReportScheduleHandlers(t *testing.T) {
	auth := newReportsTestAuth(t)
	store := newTestReportScheduleStore(t)
	audit := &recordingAuditProvider{}
	mux := http.NewServeMux()
	RegisterReportScheduleHandlers(mux, auth, store, audit)

	actions := func() []string {
		audit.mu.Lock()
		defer audit.mu.Unlock()
		var out []string
		for _, e := range audit.entries {
			out = append(out, e.Action+"/"+string(e.Outcome))
		}
		return out
	}
	has := func(want string) bool {
		for _, a := range actions() {
			if a == want {
				return true
			}
		}
		return false
	}

	// 401 unauthenticated.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/reports/schedules", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth GET: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/reports/schedules", strings.NewReader("{}")))
	if rec.Code != http.StatusUnauthorized || !has("report.schedule_create/"+string(AuditOutcomeDenied)) {
		t.Fatalf("unauth POST: %d audit=%v", rec.Code, actions())
	}

	// 400 on matrix violation, audited as failure.
	bad, _ := json.Marshal(ReportSchedule{Report: "inventory", Format: "pdf", Recipients: []string{"a@x.com"}})
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/reports/schedules", bad))
	if rec.Code != http.StatusBadRequest || !has("report.schedule_create/"+string(AuditOutcomeFailure)) {
		t.Fatalf("matrix violation: %d audit=%v", rec.Code, actions())
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/reports/schedules", []byte("{")))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad JSON: %d", rec.Code)
	}

	// 201 create.
	good := []byte(`{"report":"executive-summary","format":"pdf","cadence":"weekly","recipients":["board@x.com"]}`) // enabled omitted: defaults on
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodPost, "/api/v1/reports/schedules", good))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Data ReportSchedule `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created.Data.ID == "" || !created.Data.Enabled {
		t.Fatalf("created = %+v", created.Data)
	}
	if !has("report.schedule_create/" + string(AuditOutcomeSuccess)) {
		t.Fatalf("missing create audit: %v", actions())
	}
	for _, e := range audit.entries {
		if strings.Contains(fmt.Sprint(e), "board@x.com") {
			t.Fatalf("audit entry leaks recipient: %+v", e)
		}
	}

	// GET lists it.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodGet, "/api/v1/reports/schedules", nil))
	var list struct {
		Data []ReportSchedule `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if rec.Code != http.StatusOK || len(list.Data) != 1 || list.Data[0].ID != created.Data.ID {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}

	// DELETE: unknown id 404 (audited), real id removes.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodDelete, "/api/v1/reports/schedules/rsc-missing", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete unknown: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(http.MethodDelete, "/api/v1/reports/schedules/"+created.Data.ID, nil))
	if rec.Code != http.StatusOK || !has("report.schedule_delete/"+string(AuditOutcomeSuccess)) {
		t.Fatalf("delete: %d audit=%v", rec.Code, actions())
	}
	if l, _ := store.List(context.Background()); len(l) != 0 {
		t.Fatalf("schedule not removed")
	}
}

// smtpSink is a minimal in-process SMTP server that captures DATA payloads.
type smtpSink struct {
	ln   net.Listener
	mu   sync.Mutex
	msgs []string
}

func newSMTPSink(t *testing.T) *smtpSink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &smtpSink{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *smtpSink) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	say := func(line string) { _, _ = io.WriteString(c, line+"\r\n") }
	say("220 sink ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			say("250 sink")
		case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"):
			say("250 OK")
		case cmd == "DATA":
			say("354 go ahead")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			s.mu.Lock()
			s.msgs = append(s.msgs, b.String())
			s.mu.Unlock()
			say("250 queued")
		case cmd == "QUIT":
			say("221 bye")
			return
		default:
			say("250 OK")
		}
	}
}

func (s *smtpSink) messages() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.msgs...)
}

func (s *smtpSink) env(t *testing.T) {
	host, port, _ := net.SplitHostPort(s.ln.Addr().String())
	t.Setenv("SMTP_HOST", host)
	t.Setenv("SMTP_PORT", port)
	t.Setenv("SMTP_FROM", "noreply@example.com")
	t.Setenv("SMTP_USERNAME", "")
}

func newTestReportScheduler(t *testing.T, store ReportScheduleStore, mailer *EvidenceMailer) *ReportScheduler {
	return &ReportScheduler{
		certProvider: &reportCertProvider{items: buildTestCerts()},
		caProvider:   &reportCAProvider{},
		store:        store,
		mailer:       mailer,
		pollInterval: time.Hour,
		maxAttempts:  3,
		stop:         make(chan struct{}),
	}
}

func TestReportSchedulerWeeklyBoardPDFMailedWithAttachment(t *testing.T) {
	sink := newSMTPSink(t)
	sink.env(t)
	store := newTestReportScheduleStore(t)
	if _, err := store.Create(context.Background(), ReportSchedule{
		Report: "executive-summary", Format: "pdf", Cadence: "weekly", Recipients: []string{"board@example.com"}, Enabled: true,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	s := newTestReportScheduler(t, store, NewEvidenceMailerFromEnv())
	s.scan()

	msgs := sink.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 captured message, got %d", len(msgs))
	}
	m := msgs[0]
	for _, want := range []string{"Content-Type: application/pdf", `filename="executive-summary-`, "JVBERi0"} { // base64 of "%PDF-"
		if !strings.Contains(m, want) {
			t.Fatalf("message missing %q", want)
		}
	}
	if list, _ := store.List(context.Background()); list[0].LastSentAt == "" {
		t.Fatal("expected MarkSent after delivery")
	}

	if api := strings.TrimRight(os.Getenv("KK_MAILPIT_API"), "/"); api != "" {
		resp, err := http.Get(api + "/api/v1/messages") //nolint:gosec,noctx // test-only Mailpit probe
		if err != nil {
			t.Fatalf("mailpit: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("mailpit status %d", resp.StatusCode)
		}
	} else {
		t.Log("KK_MAILPIT_API not set: skipping the Mailpit half of the assertion")
	}
}

func TestReportSchedulerCSVAttachmentType(t *testing.T) {
	sink := newSMTPSink(t)
	sink.env(t)
	store := newTestReportScheduleStore(t)
	if _, err := store.Create(context.Background(), ReportSchedule{
		Report: "inventory", Format: "csv", Cadence: "weekly", Recipients: []string{"ops@example.com"}, Enabled: true,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	newTestReportScheduler(t, store, NewEvidenceMailerFromEnv()).scan()
	msgs := sink.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	for _, want := range []string{"Content-Type: text/csv", `filename="inventory-`, `.csv"`} {
		if !strings.Contains(msgs[0], want) {
			t.Fatalf("message missing %q", want)
		}
	}
}

func TestReportSchedulerRetriesThenEmitsFailureEvent(t *testing.T) {
	newSched := func(t *testing.T) (*ReportScheduler, *dbReportScheduleStore) {
		t.Setenv("SMTP_HOST", "smtp.example.com")
		t.Setenv("SMTP_FROM", "noreply@example.com")
		store := newTestReportScheduleStore(t)
		if _, err := store.Create(context.Background(), ReportSchedule{
			Report: "findings", Format: "xlsx", Cadence: "weekly", Recipients: []string{"ops@example.com"}, Enabled: true,
		}); err != nil {
			t.Fatalf("create: %v", err)
		}
		return newTestReportScheduler(t, store, NewEvidenceMailerFromEnv()), store
	}

	t.Run("always fails", func(t *testing.T) {
		s, store := newSched(t)
		calls := 0
		s.send = func(_ []string, _, _ string, _ []byte, _, _ string) error {
			calls++
			return errors.New("451 temporary failure for ops@example.com")
		}
		var events []string
		s.alerts = func(_ context.Context, event, detail string) { events = append(events, event+"|"+detail) }
		s.scan()
		if calls != 3 {
			t.Fatalf("attempts = %d, want 3", calls)
		}
		if len(events) != 1 || !strings.HasPrefix(events[0], "report.delivery_failed|") {
			t.Fatalf("events = %v", events)
		}
		if strings.Contains(events[0], "ops@example.com") {
			t.Fatalf("alert detail leaks recipient: %s", events[0])
		}
		if list, _ := store.List(context.Background()); list[0].LastSentAt != "" {
			t.Fatal("LastSentAt must stay empty after failed delivery")
		}
	})

	t.Run("recovers on third attempt", func(t *testing.T) {
		s, store := newSched(t)
		calls := 0
		s.send = func(_ []string, _, _ string, _ []byte, _, ct string) error {
			calls++
			if calls < 3 {
				return errors.New("transient")
			}
			if ct != reportContentTypeXLSX {
				return fmt.Errorf("content type %q", ct)
			}
			return nil
		}
		events := 0
		s.alerts = func(context.Context, string, string) { events++ }
		s.scan()
		if calls != 3 || events != 0 {
			t.Fatalf("calls=%d events=%d", calls, events)
		}
		if list, _ := store.List(context.Background()); list[0].LastSentAt == "" {
			t.Fatal("expected MarkSent after eventual success")
		}
	})
}

func TestReportSchedulerSkipsWhenNotLeader(t *testing.T) {
	store := newTestReportScheduleStore(t)
	if _, err := store.Create(context.Background(), ReportSchedule{
		Report: "inventory", Format: "csv", Cadence: "weekly", Recipients: []string{"a@x.com"}, Enabled: true,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	mailer, sent := newTestEnabledMailer(t)
	mailer.send = func(string, smtp.Auth, string, []string, []byte) error { *sent++; return nil }

	db := newTestHADB(t)
	now := time.Now().UTC()
	peer := newTestHACoordinatorAt(t, db, "replica-peer", now)
	if ok, err := peer.TryAcquire(context.Background(), haLockReportScheduler, 5*time.Minute); err != nil || !ok {
		t.Fatalf("setup: peer acquire ok=%v err=%v", ok, err)
	}
	s := newTestReportScheduler(t, store, mailer)
	s.haCoordinator = newTestHACoordinatorAt(t, db, "replica-self", now)
	s.scan()
	if *sent != 0 {
		t.Fatalf("non-leader sent %d message(s)", *sent)
	}
}
