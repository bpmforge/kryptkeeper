// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package itsm

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"kryptkeeper/internal/notifications/delivery"
)

// Channel exposes the Service as a delivery.Channel named "itsm", so
// /notifications/rules route events to it. The rule's target is the
// connection id.
type Channel struct{ Svc *Service }

func (c Channel) Name() string { return "itsm" }

// Send enqueues the event. The delivery worker's retries reuse delivery
// Event.ID, which is what makes them idempotent; the connection id is part of
// the stored id so one event can fan out to several connections.
//
// Message may carry a JSON object with optional class, cn, serial, risk,
// deep_link, fingerprint, not_after, event_id and approval_id fields (approval_id makes the ticket
// decide that approval, W32-12); plain text is ignored. Subject is the
// fallback for cn.
func (c Channel) Send(ctx context.Context, e delivery.Event) error {
	if c.Svc == nil {
		return errors.New("itsm: not configured")
	}
	ev := Event{ID: e.ID + ":" + e.Target, Class: "notification", CN: e.Subject, Risk: e.Priority}
	var extra struct {
		Class       string `json:"class"`
		CN          string `json:"cn"`
		Serial      string `json:"serial"`
		Risk        string `json:"risk"`
		DeepLink    string `json:"deep_link"`
		Fingerprint string `json:"fingerprint"`
		ApprovalID  string `json:"approval_id"`
		// EventID is a producer-chosen stable id (one per failure episode or
		// certificate window), so a re-announced event leaves one ticket.
		EventID  string `json:"event_id"`
		NotAfter string `json:"not_after"` // RFC3339
	}
	if json.Unmarshal([]byte(e.Message), &extra) == nil {
		if extra.Class != "" {
			ev.Class = extra.Class
		}
		if extra.CN != "" {
			ev.CN = extra.CN
		}
		if extra.Risk != "" {
			ev.Risk = extra.Risk
		}
		ev.Serial, ev.DeepLink, ev.Fingerprint = extra.Serial, extra.DeepLink, extra.Fingerprint
		if extra.EventID != "" {
			ev.ID = extra.EventID + ":" + e.Target
		}
		if t, err := time.Parse(time.RFC3339, extra.NotAfter); err == nil {
			ev.NotAfter = t
		}
	}
	if err := c.Svc.Submit(ctx, e.Target, ev); err != nil {
		return err
	}
	return c.linkApproval(ctx, ev.ID, extra.ApprovalID)
}

// linkApproval lets the ticket decide approvalID (W32-12). An event the
// connection dropped (class not subscribed) has no row to link, so it is skipped.
func (c Channel) linkApproval(ctx context.Context, eventID, approvalID string) error {
	if approvalID == "" {
		return nil
	}
	if _, err := c.Svc.Store().GetEvent(ctx, eventID); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	return c.Svc.Store().AddLink(ctx, eventID, approvalID, c.Svc.now())
}
