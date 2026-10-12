// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/clientip"
	"kryptkeeper/internal/metrics"
)

// auditAppendTimeout bounds one audit write. The write is detached from the
// request context (see appendAuditEntry), so without a bound a hung audit DB
// would pin the handler goroutine.
const auditAppendTimeout = 5 * time.Second

func emitAuditEvent(r *http.Request, auditProvider AuditProvider, principal, action, resourceType, resourceID string, outcome AuditOutcome) {
	emitAuditEventDetail(r, auditProvider, principal, action, resourceType, resourceID, outcome, "")
}

// emitAuditEventDetail records an audit row and only logs/counts a failure:
// the ~800 call sites run AFTER the action has already taken effect, so there
// is nothing left to roll back. Known limitation: if the audit store is down,
// the audited action can still complete and its row is lost (visible only via
// kryptkeeper_audit_append_failures_total and the ERROR log). Paths that need
// the outcome (approvals) use emitAuditEventDetailErr instead.
func emitAuditEventDetail(r *http.Request, auditProvider AuditProvider, principal, action, resourceType, resourceID string, outcome AuditOutcome, changeSummary string) {
	if err := emitAuditEventDetailErr(r, auditProvider, principal, action, resourceType, resourceID, outcome, changeSummary); err != nil {
		return // already logged and counted
	}
}

// emitAuditEventDetailErr is emitAuditEventDetail returning the append error.
func emitAuditEventDetailErr(r *http.Request, auditProvider AuditProvider, principal, action, resourceType, resourceID string, outcome AuditOutcome, changeSummary string) error {
	if auditProvider == nil {
		return nil
	}
	actorID := strings.TrimSpace(principal)
	actorType := "user"
	if actorID == "" {
		actorID = "anonymous"
		actorType = "system"
	}
	if actorID == "bootstrap" {
		actorType = "system"
	}

	entry := AuditEntry{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Action:        action,
		ActorType:     actorType,
		ActorID:       actorID,
		ResourceType:  resourceType,
		ResourceID:    resourceID,
		TraceID:       strings.TrimSpace(r.Header.Get("X-Request-Id")),
		Outcome:       outcome,
		SourceIP:      extractSourceIP(r),
		UserAgent:     strings.TrimSpace(r.Header.Get("User-Agent")),
		SessionID:     strings.TrimSpace(r.Header.Get("X-Session-Id")),
		ChangeSummary: strings.TrimSpace(changeSummary),
		Tenant:        auditRequestTenant(r),
	}
	// A client that disconnects right after the action must not cancel the
	// audit write, or the row for an action that already happened is lost.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), auditAppendTimeout)
	defer cancel()
	if err := auditProvider.AppendEntry(ctx, entry); err != nil {
		log.Printf("ERROR audit append failed action=%s resource_type=%s resource_id=%s actor_id=%s trace_id=%s: %v",
			action, resourceType, resourceID, actorID, entry.TraceID, err)
		return err
	}
	return nil
}

// siemAuditProvider is the process's single audit-write choke point. It is
// applied once, where the provider is constructed (main), so every writer —
// HTTP handlers, protocol servers, schedulers, ceremonies — is counted and
// forwarded to the SIEM. After a durable append it forwards through
// SIEMRouter's bounded non-blocking queue, so the SIEM never sees an event
// the audit log lacks. Failed appends increment
// kryptkeeper_audit_append_failures_total.
type siemAuditProvider struct {
	AuditProvider
	router *SIEMRouter
}

func (p siemAuditProvider) AppendEntry(ctx context.Context, entry AuditEntry) error {
	if err := p.AuditProvider.AppendEntry(ctx, entry); err != nil {
		metrics.AuditAppendFailures.Inc()
		return err
	}
	p.router.EmitFromAuditEntry(entry)
	return nil
}

// WithSIEMForwarding wraps auditProvider exactly once; an already-wrapped
// provider is returned unchanged so a second call cannot double-forward.
func WithSIEMForwarding(auditProvider AuditProvider, router *SIEMRouter) AuditProvider {
	if auditProvider == nil || router == nil {
		return auditProvider
	}
	if _, already := auditProvider.(siemAuditProvider); already {
		return auditProvider
	}
	return siemAuditProvider{AuditProvider: auditProvider, router: router}
}

// auditRequestTenant derives the tenant an audited action ran under directly
// from the request's X-Tenant header. This intentionally duplicates
// resolvePrincipalTenancy's header handling (auth.go) rather than sharing it:
// audit call sites only ever pass a plain actor-ID string, never the resolved
// AuthPrincipal, and auth.go is W3-01's write_scope (cross-lane) — if the two
// ever diverge, this needs to be updated to match.
func auditRequestTenant(r *http.Request) string {
	if !multiTenancyEnabled() {
		return DefaultTenant
	}
	header := strings.TrimSpace(r.Header.Get("X-Tenant"))
	if header == "" || header == "*" {
		return DefaultTenant
	}
	return header
}

// extractSourceIP is the audit record's source address. It goes through the
// same trusted-proxy resolver as the rate limiters (OWASP-001): forwarding
// headers from an untrusted peer are client-controlled, and audit rows must
// not be forgeable that way.
func extractSourceIP(r *http.Request) string {
	if ip := clientip.FromEnv().ClientIP(r); ip != "" {
		return ip
	}
	return r.RemoteAddr
}
