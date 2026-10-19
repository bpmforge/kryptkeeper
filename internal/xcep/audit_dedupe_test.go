// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package xcep

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"kryptkeeper/internal/wstep"
)

func dedupeServer(rows *int) (*Server, *time.Time) {
	srv := NewServer(func() ([]Template, error) { return nil, nil }, "").
		WithAuditFunc(func(context.Context, wstep.AuditEvent) { *rows++ })
	now := time.Now()
	srv.now = func() time.Time { return now }
	return srv, &now
}

func serve(srv *Server, principal string) {
	srv.auditServed(httptest.NewRequest("POST", "/xcep", nil), wstep.Identity{Method: "kerberos", Principal: principal}, nil)
}

// S-08: the dedupe map used to be walked in full for every new principal.
func TestAuditSeenIsPrunedOncePerWindowNotPerPrincipal(t *testing.T) {
	rows := 0
	srv, now := dedupeServer(&rows)
	serve(srv, "WS0$@CORP") // first call prunes (zero lastPrune) and starts the interval
	for i := 0; i < 100; i++ {
		srv.auditSeen[fmt.Sprintf("old%d", i)] = now.Add(-time.Hour) // already expired
	}
	serve(srv, "WS1$@CORP")
	if len(srv.auditSeen) != 102 {
		t.Fatalf("a new principal inside the interval must not walk the map: %d entries", len(srv.auditSeen))
	}

	*now = now.Add(policyAuditWindow + time.Second)
	serve(srv, "WS2$@CORP")
	if len(srv.auditSeen) != 1 {
		t.Fatalf("the prune after the interval must drop every expired entry: %d left", len(srv.auditSeen))
	}
}

func TestAuditSeenIsBoundedAndStillAudits(t *testing.T) {
	rows := 0
	srv, now := dedupeServer(&rows)
	for i := 0; i < auditSeenMax; i++ {
		srv.auditSeen[fmt.Sprintf("p%d", i)] = *now // all live
	}
	serve(srv, "extra@CORP")
	serve(srv, "extra@CORP")
	if len(srv.auditSeen) != auditSeenMax {
		t.Fatalf("map grew past its bound: %d", len(srv.auditSeen))
	}
	if rows != 2 {
		t.Fatalf("an unremembered principal is audited every poll, not dropped silently: %d rows", rows)
	}

	*now = now.Add(policyAuditWindow + time.Second) // everything expires: the cap frees up
	serve(srv, "extra@CORP")
	if len(srv.auditSeen) != 1 {
		t.Fatalf("expired entries must be reclaimed at the cap: %d", len(srv.auditSeen))
	}
}
