// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package itsm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"kryptkeeper/internal/egress"
	"kryptkeeper/internal/notifications/delivery"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// fakeConnector is an in-memory ticketing system keyed by correlation id.
type fakeConnector struct {
	mu         sync.Mutex
	tickets    map[string]TicketRef // correlation id -> ref
	creates    int
	finds      int
	resolved   []string
	down       bool  // every call fails temporarily
	permanent  error // Create fails with this
	attemptLog []time.Time
	clock      *fakeClock
}

func newFake(clock *fakeClock) *fakeConnector {
	return &fakeConnector{tickets: map[string]TicketRef{}, clock: clock}
}

func (f *fakeConnector) Kind() string { return "jira" }

func (f *fakeConnector) Find(_ context.Context, id string) (*TicketRef, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finds++
	f.attemptLog = append(f.attemptLog, f.clock.now()) // one Find per attempt
	if f.down {
		return nil, fmt.Errorf("%w: down", ErrTemporary)
	}
	if r, ok := f.tickets[id]; ok {
		return &r, nil
	}
	return nil, nil
}

func (f *fakeConnector) Create(_ context.Context, ev Event) (TicketRef, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return TicketRef{}, fmt.Errorf("%w: down", ErrTemporary)
	}
	if f.permanent != nil {
		return TicketRef{}, f.permanent
	}
	f.creates++
	r := TicketRef{Key: fmt.Sprintf("T-%d", f.creates), URL: "https://itsm.example/T-" + ev.ID}
	f.tickets[ev.ID] = r
	return r, nil
}

func (f *fakeConnector) Exists(_ context.Context, ref TicketRef) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.tickets {
		if r.Key == ref.Key {
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeConnector) Resolve(_ context.Context, ref TicketRef, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolved = append(f.resolved, ref.Key)
	return nil
}

func (f *fakeConnector) deleteExternally(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, r := range f.tickets {
		if r.Key == key {
			delete(f.tickets, id)
		}
	}
}

type harness struct {
	svc    *Service
	conn   *fakeConnector
	clock  *fakeClock
	audits []AuditRecord
	alerts []string
}

func newHarness(t *testing.T, classes ...string) *harness {
	t.Helper()
	h := &harness{clock: &fakeClock{t: time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)}}
	h.conn = newFake(h.clock)
	store := newTestStore(t)
	var ecs []EventClass
	for _, c := range classes {
		ecs = append(ecs, EventClass{Class: c, TicketType: "Bug"})
	}
	if _, err := store.CreateConnection(context.Background(), Connection{ID: "c1", Kind: "jira", Name: "J", BaseURL: "https://x", CredentialRef: "r", EventClasses: ecs, Enabled: true}, h.clock.now()); err != nil {
		t.Fatal(err)
	}
	h.svc = NewService(Config{
		Store: store,
		Conns: func(context.Context, string) (Connector, error) { return h.conn, nil },
		Now:   h.clock.now,
		Audit: func(_ context.Context, r AuditRecord) { h.audits = append(h.audits, r) },
		Alert: func(_ context.Context, class, detail string) { h.alerts = append(h.alerts, class+":"+detail) },
	})
	return h
}

func (h *harness) auditCount(action, outcome string) int {
	n := 0
	for _, a := range h.audits {
		if a.Action == action && a.Outcome == outcome {
			n++
		}
	}
	return n
}

func TestSubmit_SameEventFiveRetries_OneTicket(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if err := h.svc.Submit(ctx, "c1", Event{ID: "ev-1", Class: "expiry", CN: "a.example"}); err != nil {
			t.Fatal(err)
		}
		if _, err := h.svc.Drain(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if h.conn.creates != 1 {
		t.Fatalf("Create called %d times, want 1", h.conn.creates)
	}
	row, _ := h.svc.Store().GetEvent(ctx, "ev-1")
	if row.Status != StatusCreated || row.TicketKey != "T-1" || row.TicketURL == "" {
		t.Fatalf("ticket key not stored against the event: %+v", row)
	}
}

func TestSubmit_ClassFilterAndValidation(t *testing.T) {
	h := newHarness(t, "expiry")
	ctx := context.Background()
	if err := h.svc.Submit(ctx, "c1", Event{ID: "e1", Class: "other"}); err != nil {
		t.Fatal(err)
	}
	if rows, _ := h.svc.Store().ListEvents(ctx, "", 10); len(rows) != 0 {
		t.Fatal("event outside subscribed classes must be dropped")
	}
	if err := h.svc.Submit(ctx, "c1", Event{Class: "expiry"}); err == nil {
		t.Fatal("empty id must be rejected")
	}
	if err := h.svc.Submit(ctx, "missing", Event{ID: "e2", Class: "expiry"}); err == nil {
		t.Fatal("unknown connection must be rejected")
	}
}

func TestDrain_AdoptsExistingTicketViaFind(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.conn.tickets["ev-1"] = TicketRef{Key: "T-99", URL: "https://itsm.example/T-99"}
	_ = h.svc.Submit(ctx, "c1", Event{ID: "ev-1", Class: "expiry"})
	if _, err := h.svc.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	row, _ := h.svc.Store().GetEvent(ctx, "ev-1")
	if h.conn.creates != 0 || row.TicketKey != "T-99" || row.Status != StatusCreated {
		t.Fatalf("existing ticket must be adopted: creates=%d row=%+v", h.conn.creates, row)
	}
}

func TestReconcile_ExternalDeleteRecreatedOnceAndFlagged(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_ = h.svc.Submit(ctx, "c1", Event{ID: "ev-1", Class: "expiry"})
	_, _ = h.svc.Drain(ctx)

	h.conn.deleteExternally("T-1")
	if err := h.svc.Reconcile(ctx, "ev-1"); err != nil {
		t.Fatal(err)
	}
	row, _ := h.svc.Store().GetEvent(ctx, "ev-1")
	if !row.Recreated || row.TicketKey != "T-2" || h.conn.creates != 2 {
		t.Fatalf("recreate once and flag: %+v creates=%d", row, h.conn.creates)
	}

	h.conn.deleteExternally("T-2")
	if err := h.svc.Reconcile(ctx, "ev-1"); err != nil {
		t.Fatal(err)
	}
	row, _ = h.svc.Store().GetEvent(ctx, "ev-1")
	if h.conn.creates != 2 || row.TicketKey != "T-2" {
		t.Fatalf("must not recreate a second time: %+v creates=%d", row, h.conn.creates)
	}
	if len(h.alerts) != 1 || h.alerts[0] != AlertTicketDeletedAgain+":ev-1" {
		t.Fatalf("alerts=%v", h.alerts)
	}
	var recreated bool
	for _, a := range h.audits {
		if a.Action == ActionTicketCreate && a.ChangeSummary != "" && len(a.ChangeSummary) >= 31 && a.ChangeSummary[:31] == "recreated_after_external_delete" {
			recreated = true
		}
	}
	if !recreated {
		t.Fatalf("recreate not audited: %+v", h.audits)
	}
}

func TestDrain_OneHourOutage_ZeroLoss(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.conn.down = true
	const n = 20
	for i := 0; i < n; i++ {
		_ = h.svc.Submit(ctx, "c1", Event{ID: fmt.Sprintf("ev-%02d", i), Class: "expiry"})
	}
	start := h.clock.now()
	for m := 0; m <= 60; m++ {
		if _, err := h.svc.Drain(ctx); err != nil {
			t.Fatal(err)
		}
		h.clock.advance(time.Minute)
	}
	// Attempts happen at 0, 5, 15, 35 minutes (BackoffDelay 5,10,20) and the
	// next is at 75: nothing was attempted between.
	seen := map[time.Duration]bool{}
	for _, at := range h.conn.attemptLog {
		seen[at.Sub(start)] = true
	}
	for _, want := range []time.Duration{0, 5 * time.Minute, 15 * time.Minute, 35 * time.Minute} {
		if !seen[want] {
			t.Errorf("expected an attempt at +%v, saw %v", want, seen)
		}
	}
	if len(seen) != 4 {
		t.Errorf("attempts must follow BackoffDelay, saw offsets %v", seen)
	}
	if len(h.alerts) != 1 || h.alerts[0] != AlertUnreachable+":c1" {
		t.Fatalf("unreachable alert must fire once: %v", h.alerts)
	}
	if pending, _ := h.svc.Store().ListEvents(ctx, StatusPending, 100); len(pending) != n {
		t.Fatalf("no event may be lost during the outage: %d pending", len(pending))
	}

	h.conn.down = false
	h.clock.advance(15 * time.Minute) // now +76m, past the 75m retry
	done, err := h.svc.Drain(ctx)
	if err != nil || done != n {
		t.Fatalf("drain after recovery: done=%d err=%v", done, err)
	}
	if created, _ := h.svc.Store().ListEvents(ctx, StatusCreated, 100); len(created) != n {
		t.Fatalf("%d tickets, want %d", len(created), n)
	}
	if failed, _ := h.svc.Store().ListEvents(ctx, StatusFailed, 100); len(failed) != 0 {
		t.Fatalf("%d failed", len(failed))
	}
	if h.conn.creates != n {
		t.Fatalf("creates=%d want %d (no duplicates)", h.conn.creates, n)
	}
	// Reachable again, so a second outage alerts again.
	h.conn.down = true
	_ = h.svc.Submit(ctx, "c1", Event{ID: "late", Class: "expiry"})
	_, _ = h.svc.Drain(ctx)
	if len(h.alerts) != 2 {
		t.Fatalf("alert must re-arm after recovery: %v", h.alerts)
	}
}

func TestDrain_PermanentError_Fails(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.conn.permanent = fmt.Errorf("%w: 403 forbidden", ErrPermanent)
	_ = h.svc.Submit(ctx, "c1", Event{ID: "ev-1", Class: "expiry"})
	if done, err := h.svc.Drain(ctx); err != nil || done != 0 {
		t.Fatalf("done=%d err=%v", done, err)
	}
	row, _ := h.svc.Store().GetEvent(ctx, "ev-1")
	if row.Status != StatusFailed || row.LastError == "" {
		t.Fatalf("%+v", row)
	}
	if h.auditCount(ActionTicketCreate, OutcomeFailure) != 1 {
		t.Fatalf("failure not audited: %+v", h.audits)
	}
	h.clock.advance(24 * time.Hour)
	_, _ = h.svc.Drain(ctx)
	if len(h.conn.attemptLog) != 1 {
		t.Fatal("a failed row must not be retried")
	}
}

func TestDrain_ConnectorSourceErrorKeepsRowQueued(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.svc.conns = func(context.Context, string) (Connector, error) { return nil, errors.New("credential store offline") }
	_ = h.svc.Submit(ctx, "c1", Event{ID: "ev-1", Class: "expiry"})
	_, _ = h.svc.Drain(ctx)
	row, _ := h.svc.Store().GetEvent(ctx, "ev-1")
	if row.Status != StatusPending || row.Attempts != 1 {
		t.Fatalf("%+v", row)
	}
}

func TestResolveByFingerprint_ResolvesCreatedOnly(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for _, e := range []Event{
		{ID: "a", Class: "expiry", Fingerprint: "fp1"},
		{ID: "b", Class: "expiry", Fingerprint: "fp1"},
		{ID: "c", Class: "expiry", Fingerprint: "fp2"},
	} {
		_ = h.svc.Submit(ctx, "c1", e)
	}
	_, _ = h.svc.Drain(ctx)
	// "d" shares fp1 but is still pending (not yet ticketed).
	h.conn.down = true
	_ = h.svc.Submit(ctx, "c1", Event{ID: "d", Class: "expiry", Fingerprint: "fp1"})
	_, _ = h.svc.Drain(ctx)
	h.conn.down = false

	n, err := h.svc.ResolveByFingerprint(ctx, "fp1", "replaced certificate verified")
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if len(h.conn.resolved) != 2 {
		t.Fatalf("resolved=%v", h.conn.resolved)
	}
	for id, want := range map[string]string{"a": StatusResolved, "b": StatusResolved, "c": StatusCreated, "d": StatusPending} {
		row, _ := h.svc.Store().GetEvent(ctx, id)
		if row.Status != want {
			t.Errorf("%s: status %s want %s", id, row.Status, want)
		}
	}
	if h.auditCount(ActionTicketResolve, OutcomeSuccess) != 2 {
		t.Fatalf("audits=%+v", h.audits)
	}
	if n, _ := h.svc.ResolveByFingerprint(ctx, "fp1", "again"); n != 0 {
		t.Fatalf("second call must resolve nothing, got %d", n)
	}
}

func TestChannel_SendSubmitsIdempotently(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ch := Channel{Svc: h.svc}
	ev := delivery.Event{ID: "n-1", Target: "c1", Subject: "a.example expires", Message: `{"class":"expiry","fingerprint":"fp9","serial":"01"}`, Priority: "high"}
	for i := 0; i < 3; i++ {
		if err := ch.Send(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	rows, _ := h.svc.Store().ListEvents(ctx, "", 10)
	if len(rows) != 1 || rows[0].Class != "expiry" || rows[0].Fingerprint != "fp9" {
		t.Fatalf("%+v", rows)
	}
	if err := (Channel{}).Send(ctx, ev); err == nil {
		t.Fatal("unconfigured channel must error")
	}
}

func TestChannel_ProducerEventIDIsStableAcrossDeliveries(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ch := Channel{Svc: h.svc}
	msg := `{"class":"renewal_failed","event_id":"renewal_failed:fp1:100","fingerprint":"fp1","not_after":"2026-11-01T12:00:00Z"}`
	for _, id := range []string{"notif-1", "notif-2", "notif-3"} { // each delivery has a fresh id
		if err := ch.Send(ctx, delivery.Event{ID: id, Target: "c1", Message: msg}); err != nil {
			t.Fatal(err)
		}
	}
	rows, _ := h.svc.Store().ListEvents(ctx, "", 10)
	if len(rows) != 1 || rows[0].EventID != "renewal_failed:fp1:100:c1" || !strings.Contains(rows[0].Payload, "2026-11-01T12:00:00Z") {
		t.Fatalf("%+v", rows)
	}
}

func TestConnectorUsesEgressClient(t *testing.T) {
	hc := NewHTTPClient()
	resp, err := hc.Get("http://169.254.169.254/latest/meta-data/")
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("metadata address must be refused")
	}
	if !errors.Is(err, egress.ErrBlockedDestination) {
		t.Fatalf("want egress refusal, got %v", err)
	}
	var _ *http.Client = hc
}

func TestConnectorSource_ResolvesCredentialAndKind(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	var gotSecret string
	src := NewConnectorSource(h.svc.Store(), credFunc(func(_ context.Context, id string) ([]byte, error) {
		if id != "r" {
			return nil, errors.New("unknown")
		}
		return []byte("s3cret"), nil
	}), NewHTTPClient(), map[string]Factory{"jira": func(base string, cred []byte, _ *http.Client) (Connector, error) {
		gotSecret = string(cred)
		return h.conn, nil
	}}, nil)
	if _, err := src(ctx, "c1"); err != nil || gotSecret != "s3cret" {
		t.Fatalf("err=%v secret=%q", err, gotSecret)
	}
	if _, err := src(ctx, "missing"); err == nil {
		t.Fatal("unknown connection")
	}
	bad := NewConnectorSource(h.svc.Store(), credFunc(func(context.Context, string) ([]byte, error) { return []byte("s3cret"), errors.New("boom") }), nil, map[string]Factory{"jira": nil}, nil)
	if _, err := bad(ctx, "c1"); err == nil || containsStr(err.Error(), "s3cret") {
		t.Fatalf("err=%v", err)
	}
	none := NewConnectorSource(h.svc.Store(), nil, nil, nil, nil)
	if _, err := none(ctx, "c1"); err == nil {
		t.Fatal("kind without factory")
	}
}

type credFunc func(ctx context.Context, id string) ([]byte, error)

func (f credFunc) Resolve(ctx context.Context, id string) ([]byte, error) { return f(ctx, id) }

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestSubmit_StampsTicketTypeFromEventClass(t *testing.T) {
	h := newHarness(t, "expiry")
	if err := h.svc.Submit(context.Background(), "c1", Event{ID: "e1", Class: "expiry"}); err != nil {
		t.Fatal(err)
	}
	row, err := h.svc.Store().GetEvent(context.Background(), "e1")
	if err != nil || !strings.Contains(row.Payload, `"ticket_type":"Bug"`) {
		t.Fatalf("payload %q err=%v", row.Payload, err)
	}
}

func TestTestConnection_UsesFindOnly(t *testing.T) {
	h := newHarness(t)
	if err := h.svc.TestConnection(context.Background(), "c1"); err != nil || h.conn.finds != 1 || h.conn.creates != 0 {
		t.Fatalf("err=%v finds=%d creates=%d", err, h.conn.finds, h.conn.creates)
	}
	h.conn.down = true
	if err := h.svc.TestConnection(context.Background(), "c1"); !errors.Is(err, ErrTemporary) {
		t.Fatalf("err=%v", err)
	}
}

func TestReconcileAll_RecreatesDeletedAndSkipsHealthy(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for _, id := range []string{"ev-1", "ev-2"} {
		_ = h.svc.Submit(ctx, "c1", Event{ID: id, Class: "expiry"})
	}
	_, _ = h.svc.Drain(ctx)
	h.conn.deleteExternally("T-1")
	n, err := h.svc.ReconcileAll(ctx)
	if err != nil || n != 2 || h.conn.creates != 3 {
		t.Fatalf("n=%d err=%v creates=%d", n, err, h.conn.creates)
	}
	deleted, healthy := 0, 0
	for _, id := range []string{"ev-1", "ev-2"} {
		row, _ := h.svc.Store().GetEvent(ctx, id)
		if row.Recreated {
			deleted++
		} else {
			healthy++
		}
	}
	if deleted != 1 || healthy != 1 {
		t.Fatalf("recreated=%d untouched=%d", deleted, healthy)
	}
}

func TestReconcileIfDue_FirstCallStartsClockThenHourly(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_ = h.svc.Submit(ctx, "c1", Event{ID: "ev-1", Class: "expiry"})
	_, _ = h.svc.Drain(ctx)
	h.conn.deleteExternally("T-1")

	if n, _ := h.svc.reconcileIfDue(ctx); n != 0 {
		t.Fatalf("first call reconciled %d", n)
	}
	h.clock.advance(59 * time.Minute)
	if n, _ := h.svc.reconcileIfDue(ctx); n != 0 || h.conn.creates != 1 {
		t.Fatalf("ran early: n=%d creates=%d", n, h.conn.creates)
	}
	h.clock.advance(time.Minute)
	if n, err := h.svc.reconcileIfDue(ctx); n != 1 || err != nil || h.conn.creates != 2 {
		t.Fatalf("due pass: n=%d err=%v creates=%d", n, err, h.conn.creates)
	}
	if n, _ := h.svc.reconcileIfDue(ctx); n != 0 {
		t.Fatalf("ran again without waiting an interval: %d", n)
	}
}

func TestRun_ReconcilesOnItsInterval(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = h.svc.Submit(ctx, "c1", Event{ID: "ev-1", Class: "expiry"})
	_, _ = h.svc.Drain(ctx)
	h.conn.deleteExternally("T-1")
	h.svc.reconcileEvery = time.Nanosecond
	h.svc.lastReconcile = h.clock.now().Add(-time.Hour)
	done := make(chan struct{})
	var logMu sync.Mutex
	var runErrs []string
	logf := func(format string, args ...any) {
		logMu.Lock()
		runErrs = append(runErrs, fmt.Sprintf(format, args...))
		logMu.Unlock()
	}
	go func() { h.svc.Run(ctx, 5*time.Millisecond, logf); close(done) }()
	// Wait for the persisted outcome, not the connector call: the recreate
	// is written to the store after the second create, and a loaded CI
	// runner can cancel in between.
	deadline := time.Now().Add(20 * time.Second)
	var row EventRow
	for time.Now().Before(deadline) {
		row, _ = h.svc.Store().GetEvent(context.Background(), "ev-1")
		if row.Recreated {
			break
		}
		// Poll gently: every read contends with Run's writes on SQLite.
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	<-done
	if !row.Recreated {
		logMu.Lock()
		defer logMu.Unlock()
		t.Fatalf("Run never reconciled: %+v; Run errors: %v", row, runErrs)
	}
}

func TestReconcile_DeletedAgainAlertsAndAuditsOnce(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_ = h.svc.Submit(ctx, "c1", Event{ID: "ev-1", Class: "expiry"})
	_, _ = h.svc.Drain(ctx)
	h.conn.deleteExternally("T-1")
	_ = h.svc.Reconcile(ctx, "ev-1") // recreated
	h.conn.deleteExternally("T-2")
	for i := 0; i < 3; i++ { // hourly reconcile passes
		if _, err := h.svc.ReconcileAll(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if len(h.alerts) != 1 {
		t.Fatalf("alerts=%v, want exactly one", h.alerts)
	}
	n := 0
	for _, a := range h.audits {
		if a.ChangeSummary == deletedAgainMarker {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("deleted-again audit rows=%d, want 1", n)
	}
	row, _ := h.svc.Store().GetEvent(ctx, "ev-1")
	if row.Status != StatusCreated || row.LastError != deletedAgainMarker {
		t.Fatalf("row %+v", row)
	}
}
