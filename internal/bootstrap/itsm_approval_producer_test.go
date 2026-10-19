// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	kkdb "kryptkeeper/internal/db"
	"kryptkeeper/internal/notifications/delivery"
	"kryptkeeper/internal/notifications/itsm"
)

// itsmRoutingProvider routes TestDelivery on the itsm channel into a real
// itsm.Channel, as the delivery worker does in production.
type itsmRoutingProvider struct {
	NotificationProvider
	rules     []NotificationRule
	channel   itsm.Channel
	delivers  bool
	delivered []string // channel:target
	n         int
}

func (p *itsmRoutingProvider) Delivers() bool { return p.delivers }
func (p *itsmRoutingProvider) ListRules(context.Context) ([]NotificationRule, error) {
	return p.rules, nil
}
func (p *itsmRoutingProvider) TestDelivery(ctx context.Context, channel, target, message string) (NotificationTestDeliveryResult, error) {
	p.n++
	p.delivered = append(p.delivered, channel+":"+target)
	if channel == "itsm" {
		err := p.channel.Send(ctx, delivery.Event{ID: "n-" + string(rune('0'+p.n)), Channel: channel, Target: target, Subject: "Kryptkeeper notification", Message: message})
		return NotificationTestDeliveryResult{}, err
	}
	return NotificationTestDeliveryResult{}, nil
}

func newItsmService(t *testing.T) *itsm.Service {
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
	if _, err := store.CreateConnection(context.Background(), itsm.Connection{ID: "conn-1", Kind: "servicenow", Name: "SN", BaseURL: "https://x.example", CredentialRef: "r", Enabled: true}, time.Now()); err != nil {
		t.Fatal(err)
	}
	return itsm.NewService(itsm.Config{Store: store})
}

func TestApprovalPending_CreatesItsmLinkRow(t *testing.T) {
	_, _, raw, _, _ := certApprovalEnv(t)
	svc := newItsmService(t)
	prov := &itsmRoutingProvider{delivers: true, channel: itsm.Channel{Svc: svc}, rules: []NotificationRule{
		{ID: "r1", Channel: "itsm", Target: "conn-1", Enabled: true, Tenant: "acme"},
		{ID: "r2", Channel: "email", Target: "a@b.example", Enabled: true, Tenant: "acme"},
		{ID: "r3", Channel: "itsm", Target: "conn-1", Enabled: false, Tenant: "acme"},
		{ID: "r4", Channel: "itsm", Target: "conn-other", Enabled: true, Tenant: "globex"}, // another tenant's connection
	}}
	store := withApprovalPendingNotifier(raw, prov)
	if delegationStoreForApprovals(store) == nil {
		t.Fatal("delegation lost behind the notifying wrapper")
	}
	seedApproval(t, store, "apr-77", "someone")

	if len(prov.delivered) != 1 || prov.delivered[0] != "itsm:conn-1" {
		t.Fatalf("delivered %v, want only the enabled itsm rule", prov.delivered)
	}
	rows, err := svc.Store().ListEvents(context.Background(), "", 10)
	if err != nil || len(rows) != 1 || rows[0].Class != "approval_pending" || rows[0].Fingerprint != "approval:apr-77" {
		t.Fatalf("events %+v %v", rows, err)
	}
	links, err := svc.Store().WaitingLinks(context.Background(), 10)
	if err != nil || len(links) != 1 || links[0].ApprovalID != "apr-77" || links[0].EventID != rows[0].EventID {
		t.Fatalf("link row missing: %+v %v", links, err)
	}
}

func TestApprovalPending_NotAnnouncedWhenCreateFailsOrNotDelivering(t *testing.T) {
	_, _, raw, _, _ := certApprovalEnv(t)
	svc := newItsmService(t)
	rules := []NotificationRule{{ID: "r1", Channel: "itsm", Target: "conn-1", Enabled: true, Tenant: "acme"}}
	quiet := &itsmRoutingProvider{delivers: false, channel: itsm.Channel{Svc: svc}, rules: rules}
	seedApproval(t, withApprovalPendingNotifier(raw, quiet), "apr-q", "someone")
	if len(quiet.delivered) != 0 {
		t.Fatalf("record-only provider announced: %v", quiet.delivered)
	}
	loud := &itsmRoutingProvider{delivers: true, channel: itsm.Channel{Svc: svc}, rules: rules}
	wrapped := withApprovalPendingNotifier(&failingCreateStore{raw}, loud)
	if err := wrapped.Create(context.Background(), ApprovalRequest{ID: "apr-f"}); err == nil {
		t.Fatal("expected create error")
	}
	if len(loud.delivered) != 0 {
		t.Fatalf("failed create announced: %v", loud.delivered)
	}
}

type failingCreateStore struct{ ApprovalStore }

func (failingCreateStore) Create(context.Context, ApprovalRequest) error { return errors.New("boom") }

func TestApprovalPendingMessage_Shape(t *testing.T) {
	t.Setenv("KRYPTKEEPER_BASE_URL", "https://kk.example/")
	m := approvalPendingMessage(ApprovalRequest{ID: "apr-1", CSRPEM: "not pem"})
	for _, want := range []string{`"class":"approval_pending"`, `"approval_id":"apr-1"`, `"deep_link":"https://kk.example/approvals"`, `"cn":"approval request apr-1"`} {
		if !strings.Contains(m, want) {
			t.Errorf("%s missing from %s", want, m)
		}
	}
}
