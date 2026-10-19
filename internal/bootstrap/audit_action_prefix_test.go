// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"testing"
	"time"
)

// CB-05: the /audit action filter matches an exact action or its dot-bounded
// family, while internal callers keep exact semantics through Action.
func TestAuditActionPrefixFilter(t *testing.T) {
	audit := realSQLiteAuditProvider(t)
	ctx := context.Background()
	for _, a := range []string{"certificate.issue", "certificate.revoke", "certificate", "certificates.import", "role.create", "role_x.create"} {
		if err := audit.AppendEntry(ctx, AuditEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339), Action: a, ActorType: "user",
			ActorID: "alice", ResourceType: "test", ResourceID: a, Outcome: AuditOutcomeSuccess,
		}); err != nil {
			t.Fatalf("append %q: %v", a, err)
		}
	}
	count := func(q AuditListQuery) int {
		res, err := audit.ListEntries(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		return res.Total
	}
	if got := count(AuditListQuery{ActionPrefix: "certificate", Limit: 50}); got != 3 {
		t.Errorf("prefix certificate = %d, want 3 (issue, revoke, bare)", got)
	}
	if got := count(AuditListQuery{ActionPrefix: "certificate.issue", Limit: 50}); got != 1 {
		t.Errorf("exact via prefix = %d, want 1", got)
	}
	if got := count(AuditListQuery{ActionPrefix: "role_x", Limit: 50}); got != 1 {
		t.Errorf("LIKE metacharacter must be literal: role_x = %d, want 1", got)
	}
	if got := count(AuditListQuery{Action: "certificate", Limit: 50}); got != 1 {
		t.Errorf("Action stays exact: %d, want 1", got)
	}
}
