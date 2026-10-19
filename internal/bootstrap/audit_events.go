// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/clientip"
	"kryptkeeper/internal/logging"
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
		ChangeSummary: strings.TrimSpace(decisionChannelSummary(r.Context(), action, changeSummary)),
		Tenant:        auditRequestTenant(r),
	}
	// A client that disconnects right after the action must not cancel the
	// audit write, or the row for an action that already happened is lost.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), auditAppendTimeout)
	defer cancel()
	if err := auditProvider.AppendEntry(ctx, entry); err != nil {
		logging.Errorf("audit append failed action=%s resource_type=%s resource_id=%s actor_id=%s trace_id=%s: %v",
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

// auditTenantHolder carries the tenant of the principal that authenticated this
// request. It is installed by withAuditTenant and filled by
// AuthenticatePrincipalDetails, so audit rows are stamped from the RESOLVED
// principal. The raw X-Tenant header is attacker-controlled for anonymous and
// tenant-bound callers (it would let an unauthenticated probe file rows under
// another tenant), so it is never consulted here.
type auditTenantHolder struct {
	mu     sync.Mutex
	tenant string
}

type auditTenantCtxKey struct{}

// withAuditTenant installs a per-request auditTenantHolder.
func withAuditTenant(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := &auditTenantHolder{}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), auditTenantCtxKey{}, h)))
	})
}

// recordAuditTenant is called once a principal has been fully authenticated and
// its tenancy resolved. A no-op when the request carries no holder.
func recordAuditTenant(r *http.Request, tenant string) {
	h, _ := r.Context().Value(auditTenantCtxKey{}).(*auditTenantHolder)
	if h == nil {
		return
	}
	h.mu.Lock()
	h.tenant = tenant
	h.mu.Unlock()
}

// auditRequestTenant is the tenant to stamp on an audit row: the resolved
// principal's tenant, or DefaultTenant for unauthenticated/failed requests (and
// when multi-tenancy is off).
func auditRequestTenant(r *http.Request) string {
	if !multiTenancyEnabled() {
		return DefaultTenant
	}
	h, _ := r.Context().Value(auditTenantCtxKey{}).(*auditTenantHolder)
	if h == nil {
		return DefaultTenant
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if t := strings.TrimSpace(h.tenant); t != "" {
		return t
	}
	return DefaultTenant
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

// configKeyAuditAction maps a config key to an extra, domain-specific audit
// action emitted beside config.set/config.reset (SLO objective changes must
// be findable without scanning every config write).
func configKeyAuditAction(key string) (action string, ok bool) {
	if key == "metrics.bearer_token" {
		return "config.metrics_auth.update", true
	}
	if strings.HasPrefix(key, "slo.") {
		return "slo.objective.update", true
	}
	return "", false
}

// Acting channels recorded on approval decisions.
const (
	ChannelUI       = "ui"
	ChannelITSM     = "itsm"
	ChannelChatOps  = "chatops"
	maxChannelIDLen = 200
)

// ApprovalChannel names the surface that made an approval decision and the
// external identity behind it (e.g. "slack:T012/U034", "servicenow:INC0012345").
type ApprovalChannel struct{ Name, ExternalID string }

type approvalChannelKey struct{}
type injectedPrincipalKey struct{}

// NewApprovalChannel validates a non-ui channel. Only in-process bridges may
// build one; the zero value means the ui channel.
func NewApprovalChannel(name, externalID string) (ApprovalChannel, error) {
	if name != ChannelITSM && name != ChannelChatOps {
		return ApprovalChannel{}, errors.New("approval channel must be itsm or chatops")
	}
	if externalID == "" || len(externalID) > maxChannelIDLen {
		return ApprovalChannel{}, errors.New("approval channel external id must be 1-200 characters")
	}
	return ApprovalChannel{Name: name, ExternalID: externalID}, nil
}

// WithApprovalChannel returns ctx carrying the acting channel.
func WithApprovalChannel(ctx context.Context, ch ApprovalChannel) context.Context {
	return context.WithValue(ctx, approvalChannelKey{}, ch)
}

// ApprovalChannelFrom returns the acting channel; the zero value is ui.
func ApprovalChannelFrom(ctx context.Context) ApprovalChannel {
	if ctx != nil {
		if ch, ok := ctx.Value(approvalChannelKey{}).(ApprovalChannel); ok && ch.Name != "" {
			return ch
		}
	}
	return ApprovalChannel{Name: ChannelUI}
}

// WithInjectedPrincipal lets an in-process bridge act as an already-mapped
// user through the real handlers. It is honoured only together with a non-ui
// channel (see authenticateDecider). HTTP clients cannot set context values.
func WithInjectedPrincipal(ctx context.Context, pd AuthPrincipal) context.Context {
	return context.WithValue(ctx, injectedPrincipalKey{}, pd)
}

// authenticateDecider returns the injected principal when the context also
// carries a non-ui channel, otherwise the normal bearer authentication.
func authenticateDecider(a *Authenticator, r *http.Request, now time.Time) (AuthPrincipal, error) {
	if r != nil {
		ctx := r.Context()
		if ApprovalChannelFrom(ctx).Name != ChannelUI {
			if pd, ok := ctx.Value(injectedPrincipalKey{}).(AuthPrincipal); ok {
				return pd, nil
			}
		}
	}
	return a.AuthenticatePrincipalDetails(r, now)
}

// decisionChannelSummary stamps the acting channel onto approve/reject audit
// summaries. JSON actions get leading keys; text actions get key=value suffixes.
func decisionChannelSummary(ctx context.Context, action, base string) string {
	ch := ApprovalChannelFrom(ctx)
	base = strings.TrimSpace(base)
	switch action {
	case "approval.approve", "approval.reject":
		name, _ := json.Marshal(ch.Name)
		lead := `"channel":` + string(name)
		if ch.Name != ChannelUI {
			id, _ := json.Marshal(ch.ExternalID)
			lead += `,"external_id":` + string(id)
		}
		switch {
		case base == "":
			return "{" + lead + "}"
		case strings.HasPrefix(base, "{"):
			if strings.TrimSpace(base[1:]) == "}" {
				return "{" + lead + "}"
			}
			return "{" + lead + "," + base[1:]
		}
		return base
	case "action.approve", "action.reject":
		out := base + " channel=" + ch.Name
		if ch.Name != ChannelUI {
			out += " external_id=" + ch.ExternalID
		}
		return strings.TrimSpace(out)
	}
	return base
}
