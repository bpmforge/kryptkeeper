// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"kryptkeeper/internal/metrics"
)

// ctxAuditProvider fails the append if its context was already cancelled, as a
// real DB driver does, and records what it was given.
type ctxAuditProvider struct {
	mu      sync.Mutex
	entries []AuditEntry
	fail    error
}

func (p *ctxAuditProvider) ListEntries(context.Context, AuditListQuery) (AuditListResult, error) {
	return AuditListResult{}, nil
}

func (p *ctxAuditProvider) AppendEntry(ctx context.Context, e AuditEntry) error {
	if p.fail != nil {
		return p.fail
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.entries = append(p.entries, e)
	return nil
}

func (p *ctxAuditProvider) snapshot() []AuditEntry {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]AuditEntry(nil), p.entries...)
}

func TestAuditAppendSurvivesCancelledRequestContext(t *testing.T) {
	p := &ctxAuditProvider{}
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "/x", nil).WithContext(ctx)
	cancel() // client disconnected right after the action ran

	emitAuditEvent(req, p, "alice", "certificate.revoke", "certificate", "fp1", "success")

	got := p.snapshot()
	if len(got) != 1 || got[0].Action != "certificate.revoke" {
		t.Fatalf("audit row dropped after client disconnect: %+v", got)
	}
}

func TestAuditAppendFailureIncrementsMetric(t *testing.T) {
	p := WithSIEMForwarding(&ctxAuditProvider{fail: errors.New("db down")}, NewSIEMRouterFromEnv())
	before := metrics.AuditAppendFailures.Load()
	emitAuditEvent(httptest.NewRequest(http.MethodPost, "/x", nil), p, "alice", "ca.suspend", "ca", "ca-1", "success")
	if d := metrics.AuditAppendFailures.Load() - before; d != 1 {
		t.Fatalf("audit_append_failures delta = %d, want 1", d)
	}
	err := emitAuditEventDetailErr(httptest.NewRequest(http.MethodPost, "/x", nil), p, "alice", "ca.suspend", "ca", "ca-1", "success", "")
	if err == nil {
		t.Fatal("emitAuditEventDetailErr must return the append error")
	}
}

// approvedFailingStore executes fine but cannot record the approval.
type approvedFailingStore struct {
	PendingActionStore
	approvedTries int
}

func (s *approvedFailingStore) Decide(ctx context.Context, id, status, by string, result json.RawMessage) error {
	if status == "approved" {
		s.approvedTries++
		return errors.New(`pq: connection refused at 10.1.2.3:5432 secret-dsn`)
	}
	return s.PendingActionStore.Decide(ctx, id, status, by, result)
}

func pendingTestAuth(t *testing.T) *Authenticator {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "pa-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	return NewAuthenticatorFromEnv()
}

func TestApproveDecideFailureAfterExecutionIsAuditedAndGeneric(t *testing.T) {
	auth := pendingTestAuth(t)
	token := mintAdminToken(t, auth, "approver-three", "")

	inner := newTestPendingStore(t)
	created, err := inner.Create(context.Background(), PendingAction{
		ActionType: "revoke", Params: json.RawMessage(`{"fingerprint":"fp1","reason_code":1}`), ProposedBy: "mcp:agent",
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &approvedFailingStore{PendingActionStore: inner}
	certs := &recordingCertProvider{reportCertProvider: &reportCertProvider{}}
	audit := &ctxAuditProvider{}
	mux := http.NewServeMux()
	registerPendingActionHandlers(mux, auth, certs, store, audit, nil)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, bearerReq(token, http.MethodPost, "/api/v1/pending-actions/"+created.ID+"/approve", nil))

	if certs.revoked != 1 {
		t.Fatalf("setup: action should have executed once, got %d", certs.revoked)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, leak := range []string{"pq:", "10.1.2.3", "secret-dsn", "connection refused"} {
		if strings.Contains(body, leak) {
			t.Fatalf("response leaks raw error %q: %s", leak, body)
		}
	}
	if store.approvedTries != 2 {
		t.Fatalf("Decide(approved) should be retried once, tries=%d", store.approvedTries)
	}
	rows := audit.snapshot()
	if len(rows) != 1 || rows[0].Action != "action.approve" || rows[0].Outcome != "executed" || rows[0].ResourceID != created.ID {
		t.Fatalf("want one action.approve/executed audit row, got %+v", rows)
	}
	if !strings.Contains(rows[0].ChangeSummary, "decision failed") {
		t.Fatalf("audit detail should note the failed decision write: %q", rows[0].ChangeSummary)
	}
	if strings.Contains(rows[0].ChangeSummary, "10.1.2.3") {
		t.Fatalf("audit detail leaks raw error: %q", rows[0].ChangeSummary)
	}
}

type rejectFailingStore struct{ PendingActionStore }

func (s *rejectFailingStore) Decide(ctx context.Context, id, status, by string, result json.RawMessage) error {
	if status == "rejected" {
		return errors.New("secret-dsn unreachable")
	}
	return s.PendingActionStore.Decide(ctx, id, status, by, result)
}

func TestRejectDecideFailureDoesNotLeakError(t *testing.T) {
	auth := pendingTestAuth(t)
	token := mintAdminToken(t, auth, "approver-four", "")
	inner := newTestPendingStore(t)
	created, _ := inner.Create(context.Background(), PendingAction{
		ActionType: "revoke", Params: json.RawMessage(`{"fingerprint":"fp1"}`), ProposedBy: "mcp:agent",
	})
	store := &rejectFailingStore{PendingActionStore: inner}
	mux := http.NewServeMux()
	registerPendingActionHandlers(mux, auth, &reportCertProvider{}, store, &ctxAuditProvider{}, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, bearerReq(token, http.MethodPost, "/api/v1/pending-actions/"+created.ID+"/reject", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("want 409, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "secret-dsn") {
		t.Fatalf("reject response leaks raw error: %s", rec.Body.String())
	}
}

func TestAuditEventReachesSIEMWebhook(t *testing.T) {
	got := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv("SIEM_WEBHOOK_URL", srv.URL)
	t.Setenv("SIEM_SYSLOG_ADDR", "")
	t.Setenv("SIEM_FORMAT", "json")

	router := NewSIEMRouterFromEnv()
	inner := &ctxAuditProvider{}
	provider := WithSIEMForwarding(inner, router)

	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.Header.Set("User-Agent", "secret-ua")
	emitAuditEventDetail(req, provider, "alice", "certificate.revoke", "certificate", "fp1", "success", "private-change-summary")

	select {
	case body := <-got:
		var ev SIEMEvent
		if err := json.Unmarshal([]byte(body), &ev); err != nil {
			t.Fatalf("decode %q: %v", body, err)
		}
		if ev.EventType != "cert.revoked" || ev.ResourceID != "fp1" || ev.ActorID != "alice" {
			t.Fatalf("unexpected event: %+v", ev)
		}
		for _, leak := range []string{"secret-ua", "private-change-summary"} {
			if strings.Contains(body, leak) {
				t.Fatalf("SIEM payload carries %q: %s", leak, body)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("audit event never reached the SIEM webhook")
	}
	if len(inner.snapshot()) != 1 {
		t.Fatal("audit row must still be appended")
	}
}

func TestSIEMNotForwardedWhenAuditAppendFails(t *testing.T) {
	called := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called <- struct{}{} }))
	defer srv.Close()
	t.Setenv("SIEM_WEBHOOK_URL", srv.URL)
	t.Setenv("SIEM_SYSLOG_ADDR", "")
	provider := WithSIEMForwarding(&ctxAuditProvider{fail: errors.New("down")}, NewSIEMRouterFromEnv())
	emitAuditEvent(httptest.NewRequest(http.MethodPost, "/x", nil), provider, "alice", "certificate.revoke", "certificate", "fp1", "success")
	select {
	case <-called:
		t.Fatal("SIEM must only see entries that were durably appended")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestSIEMFullQueueDoesNotBlock(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)
	t.Setenv("SIEM_WEBHOOK_URL", srv.URL)
	t.Setenv("SIEM_SYSLOG_ADDR", "")
	router := NewSIEMRouterFromEnv()
	router.queueSize = 2

	before := metrics.SIEMEventsDropped.Load()
	start := time.Now()
	for i := 0; i < 50; i++ {
		router.Emit(SIEMEvent{EventType: "cert.issued", Timestamp: "2026-01-01T00:00:00Z"})
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Emit blocked on a stuck sink: %v", elapsed)
	}
	if dropped := metrics.SIEMEventsDropped.Load() - before; dropped < 40 {
		t.Fatalf("expected most events dropped with a stuck sink, dropped=%d", dropped)
	}
}

func TestSIEMWebhookUsesEgressGuard(t *testing.T) {
	t.Setenv("SIEM_WEBHOOK_URL", "http://169.254.169.254/latest/meta-data")
	t.Setenv("SIEM_SYSLOG_ADDR", "")
	res := NewSIEMRouterFromEnv().Test("admin")
	if res.WebhookOK || !strings.Contains(res.WebhookError, "egress") {
		t.Fatalf("metadata address must be refused by the egress guard: %+v", res)
	}
}

func TestWithSIEMForwardingDoesNotDoubleWrap(t *testing.T) {
	router := NewSIEMRouterFromEnv()
	once := WithSIEMForwarding(&ctxAuditProvider{}, router)
	twice := WithSIEMForwarding(once, router)
	if _, ok := twice.(siemAuditProvider).AuditProvider.(*ctxAuditProvider); !ok {
		t.Fatalf("provider was wrapped twice: %T", twice.(siemAuditProvider).AuditProvider)
	}
}
