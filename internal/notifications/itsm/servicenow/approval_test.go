// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package servicenow

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	kkdb "kryptkeeper/internal/db"

	"kryptkeeper/internal/notifications/itsm"
)

func newApprovalIncident(t *testing.T, s *stub, c *Connector) itsm.TicketRef {
	t.Helper()
	ref, err := c.Create(context.Background(), event("ev-ap"))
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func TestApproval_MapsApprovalField(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	ctx := context.Background()
	ref := newApprovalIncident(t, s, c)
	s.approvers = map[string]string{ref.Key: "user-9"}
	cases := map[string]itsm.ApprovalState{
		"":              itsm.ApprovalPending,
		"not requested": itsm.ApprovalPending,
		"requested":     itsm.ApprovalPending,
		"Approved":      itsm.ApprovalApproved,
		"rejected":      itsm.ApprovalRejected,
	}
	for field, want := range cases {
		s.bySys[ref.Key]["approval"] = field
		got, who, err := c.Approval(ctx, ref)
		if err != nil || got != want {
			t.Fatalf("approval=%q: got %v %v want %v", field, got, err, want)
		}
		if want == itsm.ApprovalApproved && who != "user-9" {
			t.Fatalf("approver %q", who)
		}
		if want == itsm.ApprovalPending && who != "" {
			t.Fatalf("pending carries approver %q", who)
		}
	}
}

func TestApproval_ApprovedWithoutApproverPermanent(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	ref := newApprovalIncident(t, s, c)
	s.bySys[ref.Key]["approval"] = "approved"
	_, _, err := c.Approval(context.Background(), ref)
	if !errors.Is(err, itsm.ErrPermanent) || !strings.Contains(err.Error(), "approver unknown") {
		t.Fatalf("%v", err)
	}
}

func TestApproval_ErrorMapping(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	ctx := context.Background()
	ref := newApprovalIncident(t, s, c)
	for code, want := range map[int]error{500: itsm.ErrTemporary, 429: itsm.ErrTemporary, 401: itsm.ErrPermanent, 403: itsm.ErrPermanent} {
		s.forceCode = code
		_, _, err := c.Approval(ctx, ref)
		if !errors.Is(err, want) {
			t.Fatalf("status %d: %v want %v", code, err, want)
		}
		if strings.Contains(err.Error(), testPass) || strings.Contains(err.Error(), "Basic ") {
			t.Fatalf("credentials leaked: %v", err)
		}
	}
	s.forceCode = 0
	if _, _, err := c.Approval(ctx, itsm.TicketRef{Key: "missing"}); !errors.Is(err, itsm.ErrPermanent) {
		t.Fatalf("404: %v", err)
	}
	if _, _, err := c.Approval(ctx, itsm.TicketRef{Key: "a^b=c"}); !errors.Is(err, itsm.ErrPermanent) {
		t.Fatalf("query injection key accepted: %v", err)
	}
}

func TestApproval_NetworkErrorTemporary(t *testing.T) {
	s, c, srv := newStub()
	ref := newApprovalIncident(t, s, c)
	srv.Close()
	if _, _, err := c.Approval(context.Background(), ref); !errors.Is(err, itsm.ErrTemporary) {
		t.Fatalf("%v", err)
	}
}

func TestApproval_NeverReturnsUpstreamBody(t *testing.T) {
	s, c, srv := newStub()
	defer srv.Close()
	ref := newApprovalIncident(t, s, c)
	s.bySys[ref.Key]["approval"] = "approved"
	s.bySys[ref.Key]["short_description"] = "SECRET-UPSTREAM-TEXT"
	s.approvers = map[string]string{ref.Key: "u1"}
	st, who, err := c.Approval(context.Background(), ref)
	if err != nil || st != itsm.ApprovalApproved || strings.Contains(who, "SECRET") {
		t.Fatalf("%v %v %q", st, err, who)
	}
}

type recActor struct {
	mu    sync.Mutex
	calls []string
}

func (a *recActor) Approve(_ context.Context, approvalID, userID, channel, ext string) (itsm.Outcome, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, approvalID+":"+userID+":"+channel+":"+ext)
	return itsm.OutcomeApproved, nil
}

type pmap map[string]string

func (m pmap) Lookup(_ context.Context, kind, ext string) (string, bool, error) {
	u, ok := m[kind+"/"+ext]
	return u, ok, nil
}

// The bridge used to skip ServiceNow tickets (no ApprovalConnector); the real
// connector now drives an approval end to end.
func TestBridge_ApprovesServiceNowTicket(t *testing.T) {
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
	now := time.Now()
	if _, err := store.CreateConnection(ctx, itsm.Connection{ID: "c1", Kind: "servicenow", Name: "SN", BaseURL: srv.URL, CredentialRef: "r", Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	conns := func(context.Context, string) (itsm.Connector, error) { return c, nil }
	svc := itsm.NewService(itsm.Config{Store: store, Conns: conns})
	ev := event("ev-ap")
	ev.Class = "approval_pending"
	if err := svc.Submit(ctx, "c1", ev); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	actor := &recActor{}
	b := itsm.NewBridge(itsm.BridgeConfig{Links: store, Events: store, Conns: conns, Actor: actor, Principals: pmap{"servicenow/user-9": "u-hub"}})
	if err := b.Link(ctx, "ev-ap", "apr-1"); err != nil {
		t.Fatal(err)
	}
	if err := b.Tick(ctx); err != nil || len(actor.calls) != 0 {
		t.Fatalf("pending acted: %v %v", err, actor.calls)
	}
	sys := store0Key(t, s)
	s.bySys[sys]["approval"] = "approved"
	s.approvers = map[string]string{sys: "user-9"}
	if err := b.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if len(actor.calls) != 1 || actor.calls[0] != "apr-1:u-hub:itsm:user-9" {
		t.Fatalf("calls %v", actor.calls)
	}
}

func store0Key(t *testing.T, s *stub) string {
	t.Helper()
	for k := range s.bySys {
		return k
	}
	t.Fatal("no incident")
	return ""
}
