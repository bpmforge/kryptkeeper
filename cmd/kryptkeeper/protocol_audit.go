// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"kryptkeeper/internal/logging"
	"strings"
	"time"

	"kryptkeeper/internal/bootstrap"
)

// appendProtocolAudit writes one enrollment-protocol outcome (WSTEP, XCEP,
// EST) to the hub's audit log. The protocol packages each define their own
// small event type; this is the one place they become audit rows.
func appendProtocolAudit(ctx context.Context, audit bootstrap.AuditProvider, action, actor, outcome, sourceIP, detail string) {
	appendProtocolAuditFor(ctx, audit, "protocol", strings.SplitN(action, ".", 2)[0], action, actor, outcome, sourceIP, detail)
}

// appendProtocolAuditFor is appendProtocolAudit with an explicit resource,
// for outcomes that concern one object (a template) rather than the protocol.
func appendProtocolAuditFor(ctx context.Context, audit bootstrap.AuditProvider, resourceType, resourceID, action, actor, outcome, sourceIP, detail string) {
	if audit == nil {
		return
	}
	actorType, actorID := "user", actor
	if actorID == "" {
		actorType, actorID = "system", "anonymous"
	}
	if err := audit.AppendEntry(ctx, bootstrap.AuditEntry{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Action:        action,
		ActorType:     actorType,
		ActorID:       actorID,
		ResourceType:  resourceType,
		ResourceID:    resourceID,
		Outcome:       bootstrap.AuditOutcome(outcome),
		SourceIP:      sourceIP,
		ChangeSummary: detail,
	}); err != nil {
		logging.Warnf("audit append failed action=%s outcome=%s: %v", action, outcome, err)
	}
}
