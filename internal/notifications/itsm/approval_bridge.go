// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package itsm

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/logging"
)

// W32-12: an approver can approve in the ITSM and the hub applies the same
// approval path as the UI, as a mapped hub user. This package cannot import
// internal/bootstrap (cycle), so the decision is delegated to an Actor that
// bootstrap implements over the real approve route.

// Outcome is what the hub did with an approval attempt.
type Outcome string

const (
	OutcomeApproved       Outcome = "approved"
	OutcomeRefused        Outcome = "refused"
	OutcomeAlreadyDecided Outcome = "already_decided"
	OutcomeNotFound       Outcome = "not_found"
)

// ChannelName is the acting channel stamped on approvals decided here.
const ChannelName = "itsm"

// Audit actions for the bridge. Summaries carry ids only: ticket text is untrusted.
const (
	ActionApprovalApprove          = "itsm.approval.approve"
	ActionApprovalRejectedExternal = "itsm.approval.rejected_external"
)

const (
	defaultBridgeInterval = 60 * time.Second
	waitingBatch          = 200
	maxExternalIDLen      = 200 // matches the hub's approval channel limit
)

// Actor applies an approval as a hub user through the hub's own gates. A
// refusal (role, proposer, tenant, inactive user) is an Outcome, not an error;
// an error means "try again next tick".
type Actor interface {
	Approve(ctx context.Context, approvalID, userID, channel, externalID string) (Outcome, error)
}

// PrincipalMap resolves an external approver to a hub user id.
type PrincipalMap interface {
	Lookup(ctx context.Context, kind, externalID string) (userID string, ok bool, err error)
}

// LinkStore persists approval links; *Store implements it.
type LinkStore interface {
	AddLink(ctx context.Context, eventID, approvalID string, now time.Time) error
	WaitingLinks(ctx context.Context, limit int) ([]Link, error)
	SetLinkStatus(ctx context.Context, eventID, status string, now time.Time) error
}

// EventReader reads the ticket an event produced; *Store implements it.
type EventReader interface {
	GetEvent(ctx context.Context, eventID string) (EventRow, error)
}

// BridgeConfig wires a Bridge. Audit may be nil.
type BridgeConfig struct {
	Links      LinkStore
	Events     EventReader
	Conns      ConnectorSource
	Actor      Actor
	Principals PrincipalMap
	Audit      func(ctx context.Context, rec AuditRecord)
	Now        func() time.Time
	Interval   time.Duration // default 60s
}

// Bridge polls waiting links and maps an ITSM approval onto the hub approval.
type Bridge struct {
	cfg BridgeConfig

	mu       sync.Mutex
	reported map[string]bool // event ids whose external rejection was already audited
}

// NewBridge returns a Bridge.
func NewBridge(cfg BridgeConfig) *Bridge {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Interval <= 0 {
		cfg.Interval = defaultBridgeInterval
	}
	return &Bridge{cfg: cfg, reported: map[string]bool{}}
}

// Link registers eventID's ticket as the decider of approvalID. Called when
// the approval-pending ticket is created.
func (b *Bridge) Link(ctx context.Context, eventID, approvalID string) error {
	if strings.TrimSpace(eventID) == "" || strings.TrimSpace(approvalID) == "" {
		return errors.New("itsm: event id and approval id are required")
	}
	return b.cfg.Links.AddLink(ctx, eventID, approvalID, b.cfg.Now())
}

func (b *Bridge) record(ctx context.Context, action, eventID, tenant, outcome, summary string) {
	if b.cfg.Audit != nil {
		b.cfg.Audit(ctx, AuditRecord{Action: action, ResourceID: eventID, Outcome: outcome, Tenant: tenant, ChangeSummary: summary})
	}
}

// Tick makes one poll pass over the waiting links. A failure on one link is
// logged and leaves it waiting; it never stops the others.
func (b *Bridge) Tick(ctx context.Context) error {
	links, err := b.cfg.Links.WaitingLinks(ctx, waitingBatch)
	if err != nil {
		return err
	}
	for _, l := range links {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := b.poll(ctx, l); err != nil {
			logging.Warnf("itsm approval: link %s: %v", l.EventID, err)
		}
	}
	return nil
}

func (b *Bridge) poll(ctx context.Context, l Link) error {
	ev, err := b.cfg.Events.GetEvent(ctx, l.EventID)
	if err != nil {
		return err
	}
	if ev.Status != StatusCreated {
		return nil // no ticket yet
	}
	conn, err := b.cfg.Conns(ctx, ev.ConnectionID)
	if err != nil {
		return err
	}
	ac, ok := conn.(ApprovalConnector)
	if !ok {
		return nil // this connector kind cannot report approvals
	}
	state, ext, err := ac.Approval(ctx, TicketRef{Key: ev.TicketKey, URL: ev.TicketURL})
	if err != nil {
		return err
	}
	switch state {
	case ApprovalApproved:
		return b.applyApproval(ctx, l, ev, conn.Kind(), ext)
	case ApprovalRejected:
		// A rejection is not mapped to a hub reject: report it once, keep waiting.
		b.mu.Lock()
		first := !b.reported[l.EventID]
		b.reported[l.EventID] = true
		b.mu.Unlock()
		if first {
			b.record(ctx, ActionApprovalRejectedExternal, l.EventID, ev.Tenant, OutcomeSuccess, "approval="+l.ApprovalID+" ticket="+ev.TicketKey)
		}
	default:
		b.mu.Lock()
		delete(b.reported, l.EventID) // reopened: a later rejection is news again
		b.mu.Unlock()
	}
	return nil
}

func (b *Bridge) applyApproval(ctx context.Context, l Link, ev EventRow, kind, ext string) error {
	summary := func(outcome string) string {
		return "approval=" + l.ApprovalID + " ticket=" + ev.TicketKey + " outcome=" + outcome
	}
	finish := func(status, auditOutcome, outcome string) error {
		if err := b.cfg.Links.SetLinkStatus(ctx, l.EventID, status, b.cfg.Now()); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		b.record(ctx, ActionApprovalApprove, l.EventID, ev.Tenant, auditOutcome, summary(outcome))
		return nil
	}
	if ext == "" || len(ext) > maxExternalIDLen {
		return finish(LinkRefused, OutcomeFailure, "unmapped_approver")
	}
	userID, ok, err := b.cfg.Principals.Lookup(ctx, kind, ext)
	if err != nil {
		return err
	}
	if !ok {
		return finish(LinkRefused, OutcomeFailure, "unmapped_approver")
	}
	out, err := b.cfg.Actor.Approve(ctx, l.ApprovalID, userID, ChannelName, ext)
	if err != nil {
		b.record(ctx, ActionApprovalApprove, l.EventID, ev.Tenant, OutcomeFailure, summary("error"))
		return err
	}
	switch out {
	case OutcomeApproved:
		return finish(LinkDone, OutcomeSuccess, string(out))
	case OutcomeAlreadyDecided:
		return finish(LinkDone, OutcomeFailure, string(out))
	}
	return finish(LinkRefused, OutcomeFailure, string(out))
}

// Run ticks every Interval until ctx is done.
func (b *Bridge) Run(ctx context.Context) {
	t := time.NewTicker(b.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := b.Tick(ctx); err != nil && ctx.Err() == nil {
				logging.Warnf("itsm approval: tick: %v", err)
			}
		}
	}
}
