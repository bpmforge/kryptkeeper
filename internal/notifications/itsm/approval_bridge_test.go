// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package itsm

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"kryptkeeper/internal/notifications/delivery"
)

type approvalFake struct {
	fakeConnectorBase
	mu    sync.Mutex
	state ApprovalState
	who   string
	err   error
}

// fakeConnectorBase satisfies Connector; only Kind and Approval matter here.
type fakeConnectorBase struct{}

func (fakeConnectorBase) Kind() string                                     { return "jira" }
func (fakeConnectorBase) Find(context.Context, string) (*TicketRef, error) { return nil, nil }
func (fakeConnectorBase) Create(context.Context, Event) (TicketRef, error) { return TicketRef{}, nil }
func (fakeConnectorBase) Exists(context.Context, TicketRef) (bool, error)  { return true, nil }
func (fakeConnectorBase) Resolve(context.Context, TicketRef, string) error { return nil }

func (f *approvalFake) Approval(context.Context, TicketRef) (ApprovalState, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state, f.who, f.err
}

func (f *approvalFake) set(st ApprovalState, who string) {
	f.mu.Lock()
	f.state, f.who = st, who
	f.mu.Unlock()
}

type fakeActor struct {
	mu      sync.Mutex
	calls   []string // approval id + ":" + user id + ":" + external id
	outcome Outcome
	err     error
}

func (a *fakeActor) Approve(_ context.Context, approvalID, userID, channel, ext string) (Outcome, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if channel != ChannelName {
		return OutcomeRefused, nil
	}
	a.calls = append(a.calls, approvalID+":"+userID+":"+ext)
	if a.err != nil {
		return "", a.err
	}
	return a.outcome, nil
}

type mapFake map[string]string

func (m mapFake) Lookup(_ context.Context, kind, ext string) (string, bool, error) {
	u, ok := m[kind+"/"+ext]
	return u, ok, nil
}

type bridgeEnv struct {
	store *Store
	conn  *approvalFake
	actor *fakeActor
	b     *Bridge
	audit []AuditRecord
	now   time.Time
}

func newBridgeEnv(t *testing.T, pm PrincipalMap) *bridgeEnv {
	t.Helper()
	ctx := context.Background()
	e := &bridgeEnv{store: newTestStore(t), conn: &approvalFake{state: ApprovalPending}, actor: &fakeActor{outcome: OutcomeApproved},
		now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	if _, err := e.store.CreateConnection(ctx, Connection{ID: "c1", Kind: "jira", Name: "J", BaseURL: "https://x.example", CredentialRef: "r", Enabled: true}, e.now); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.InsertEvent(ctx, EventRow{EventID: "ev1", ConnectionID: "c1", Class: "approval_pending", Payload: "{}"}, e.now); err != nil {
		t.Fatal(err)
	}
	row, _ := e.store.GetEvent(ctx, "ev1")
	row.Status, row.TicketKey = StatusCreated, "KK-1"
	if err := e.store.SaveEvent(ctx, row, e.now); err != nil {
		t.Fatal(err)
	}
	if pm == nil {
		pm = mapFake{"jira/acct-1": "u-approver"}
	}
	e.b = NewBridge(BridgeConfig{
		Links: e.store, Events: e.store, Actor: e.actor, Principals: pm, Now: func() time.Time { return e.now },
		Conns: func(context.Context, string) (Connector, error) { return e.conn, nil },
		Audit: func(_ context.Context, r AuditRecord) { e.audit = append(e.audit, r) },
	})
	if err := e.b.Link(ctx, "ev1", "apr-1"); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *bridgeEnv) linkStatus(t *testing.T) string {
	t.Helper()
	st, err := e.store.LinkStatus(context.Background(), "ev1")
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestBridge_ApprovesWithinTwoIntervals(t *testing.T) {
	e := newBridgeEnv(t, nil)
	ctx := context.Background()
	if err := e.b.Tick(ctx); err != nil || len(e.actor.calls) != 0 {
		t.Fatalf("pending tick acted: %v %v", err, e.actor.calls)
	}
	e.conn.set(ApprovalApproved, "acct-1") // flips between tick 1 and tick 2
	e.now = e.now.Add(60 * time.Second)
	if err := e.b.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if len(e.actor.calls) != 1 || e.actor.calls[0] != "apr-1:u-approver:acct-1" || e.linkStatus(t) != LinkDone {
		t.Fatalf("calls=%v status=%s", e.actor.calls, e.linkStatus(t))
	}
	last := e.audit[len(e.audit)-1]
	if last.Action != ActionApprovalApprove || last.Outcome != OutcomeSuccess || !strings.Contains(last.ChangeSummary, "approval=apr-1") {
		t.Fatalf("audit %+v", last)
	}
}

func TestBridge_RefusedByActorIsTerminalAndAudited(t *testing.T) {
	e := newBridgeEnv(t, nil)
	e.actor.outcome = OutcomeRefused // proposer, missing capability, cross-tenant: all surface as refused
	e.conn.set(ApprovalApproved, "acct-1")
	for i := 0; i < 3; i++ {
		_ = e.b.Tick(context.Background())
	}
	if len(e.actor.calls) != 1 || e.linkStatus(t) != LinkRefused {
		t.Fatalf("calls=%v status=%s", e.actor.calls, e.linkStatus(t))
	}
	if r := e.audit[len(e.audit)-1]; r.Outcome != OutcomeFailure || !strings.Contains(r.ChangeSummary, "outcome=refused") {
		t.Fatalf("audit %+v", r)
	}
}

func TestBridge_UnmappedApproverRefused(t *testing.T) {
	e := newBridgeEnv(t, nil)
	e.conn.set(ApprovalApproved, "stranger")
	_ = e.b.Tick(context.Background())
	if len(e.actor.calls) != 0 || e.linkStatus(t) != LinkRefused {
		t.Fatalf("calls=%v status=%s", e.actor.calls, e.linkStatus(t))
	}
	if r := e.audit[len(e.audit)-1]; !strings.Contains(r.ChangeSummary, "unmapped_approver") {
		t.Fatalf("audit %+v", r)
	}
}

func TestBridge_ReopenAfterApprovalDoesNotUndo(t *testing.T) {
	e := newBridgeEnv(t, nil)
	ctx := context.Background()
	e.conn.set(ApprovalApproved, "acct-1")
	_ = e.b.Tick(ctx)
	e.conn.set(ApprovalPending, "")
	_ = e.b.Tick(ctx)
	e.conn.set(ApprovalRejected, "acct-1")
	_ = e.b.Tick(ctx)
	if len(e.actor.calls) != 1 || e.linkStatus(t) != LinkDone {
		t.Fatalf("calls=%v status=%s", e.actor.calls, e.linkStatus(t))
	}
	// The Actor interface has no revoke or reject method, so nothing can have been undone.
	for _, r := range e.audit {
		if r.Action == ActionApprovalRejectedExternal {
			t.Fatalf("done link polled again: %+v", r)
		}
	}
}

func TestBridge_AlreadyDecided409IsDoneNotRetried(t *testing.T) {
	e := newBridgeEnv(t, nil)
	e.actor.outcome = OutcomeAlreadyDecided
	e.conn.set(ApprovalApproved, "acct-1")
	for i := 0; i < 3; i++ {
		_ = e.b.Tick(context.Background())
	}
	if len(e.actor.calls) != 1 || e.linkStatus(t) != LinkDone {
		t.Fatalf("calls=%v status=%s", e.actor.calls, e.linkStatus(t))
	}
}

func TestBridge_ActorErrorLeavesWaitingThenRetries(t *testing.T) {
	e := newBridgeEnv(t, nil)
	e.actor.err = errors.New("approve route answered Service Unavailable")
	e.conn.set(ApprovalApproved, "acct-1")
	_ = e.b.Tick(context.Background())
	if e.linkStatus(t) != LinkWaiting {
		t.Fatalf("status=%s", e.linkStatus(t))
	}
	e.actor.err = nil
	_ = e.b.Tick(context.Background())
	if e.linkStatus(t) != LinkDone || len(e.actor.calls) != 2 {
		t.Fatalf("status=%s calls=%v", e.linkStatus(t), e.actor.calls)
	}
}

func TestBridge_ExternalRejectionReportedOnceAndStaysWaiting(t *testing.T) {
	e := newBridgeEnv(t, nil)
	e.conn.set(ApprovalRejected, "acct-1")
	for i := 0; i < 3; i++ {
		_ = e.b.Tick(context.Background())
	}
	n := 0
	for _, r := range e.audit {
		if r.Action == ActionApprovalRejectedExternal {
			n++
		}
	}
	if n != 1 || e.linkStatus(t) != LinkWaiting || len(e.actor.calls) != 0 {
		t.Fatalf("n=%d status=%s calls=%v", n, e.linkStatus(t), e.actor.calls)
	}
}

func TestBridge_TicketNotCreatedYetIsSkipped(t *testing.T) {
	e := newBridgeEnv(t, nil)
	ctx := context.Background()
	row, _ := e.store.GetEvent(ctx, "ev1")
	row.Status = StatusPending
	_ = e.store.SaveEvent(ctx, row, e.now)
	e.conn.set(ApprovalApproved, "acct-1")
	_ = e.b.Tick(ctx)
	if len(e.actor.calls) != 0 || e.linkStatus(t) != LinkWaiting {
		t.Fatalf("calls=%v", e.actor.calls)
	}
}

func TestStore_LinkAndMappingRoundTrip(t *testing.T) {
	ctx := context.Background()
	e := newBridgeEnv(t, nil)
	s := e.store
	// A repeated Link cannot reset a decided link.
	if err := s.SetLinkStatus(ctx, "ev1", LinkDone, e.now); err != nil {
		t.Fatal(err)
	}
	_ = s.AddLink(ctx, "ev1", "apr-1", e.now)
	if st, _ := s.LinkStatus(ctx, "ev1"); st != LinkDone {
		t.Fatalf("status %s", st)
	}
	if err := s.SetLinkStatus(ctx, "ev1", LinkRefused, e.now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("decided link changed: %v", err)
	}
	m := Mapping{Kind: "jira", ExternalID: "acct-9", UserID: "u1", Tenant: "default"}
	if err := s.UpsertMapping(ctx, m); err != nil {
		t.Fatal(err)
	}
	m.UserID = "u2"
	_ = s.UpsertMapping(ctx, m)
	got, ok, err := s.LookupMapping(ctx, "jira", "acct-9")
	if err != nil || !ok || got.UserID != "u2" {
		t.Fatalf("%+v %v %v", got, ok, err)
	}
	if l, _ := s.ListMappings(ctx, "other"); len(l) != 0 {
		t.Fatalf("tenant leak: %v", l)
	}
	if err := s.DeleteMapping(ctx, "jira", "acct-9"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteMapping(ctx, "jira", "acct-9"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("%v", err)
	}
}

func TestChannel_ApprovalIDLinksTicket(t *testing.T) {
	h := newHarness(t, "approval_pending")
	ctx := context.Background()
	ch := Channel{Svc: h.svc}
	send := func(id, msg string) {
		t.Helper()
		if err := ch.Send(ctx, delivery.Event{ID: id, Target: "c1", Subject: "csr", Message: msg}); err != nil {
			t.Fatal(err)
		}
	}
	send("n-1", `{"class":"approval_pending","approval_id":"apr-7"}`)
	send("n-2", `{"class":"expiry","approval_id":"apr-8"}`) // class not subscribed: dropped, nothing to link
	send("n-3", `{"class":"approval_pending"}`)             // no approval id: no link
	links, _ := h.svc.Store().WaitingLinks(ctx, 10)
	if len(links) != 1 || links[0].EventID != "n-1:c1" || links[0].ApprovalID != "apr-7" {
		t.Fatalf("links %+v", links)
	}
}
