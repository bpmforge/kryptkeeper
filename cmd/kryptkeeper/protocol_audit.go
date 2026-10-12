// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log"
	"strings"
	"time"

	"kryptkeeper/internal/bootstrap"
)

// appendProtocolAudit writes one enrollment-protocol outcome (WSTEP, XCEP,
// EST) to the hub's audit log. The protocol packages each define their own
// small event type; this is the one place they become audit rows.
func appendProtocolAudit(ctx context.Context, audit bootstrap.AuditProvider, action, actor, outcome, sourceIP, detail string) {
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
		ResourceType:  "protocol",
		ResourceID:    strings.SplitN(action, ".", 2)[0],
		Outcome:       bootstrap.AuditOutcome(outcome),
		SourceIP:      sourceIP,
		ChangeSummary: detail,
	}); err != nil {
		log.Printf("audit append failed action=%s outcome=%s: %v", action, outcome, err)
	}
}
