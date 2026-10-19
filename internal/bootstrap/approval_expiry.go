// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
)

const (
	approvalTTLEnv = "APPROVAL_TTL_HOURS"
	// expirySweeper is recorded as decided_by / approved_by on an expired row.
	expirySweeper = "system:expiry"
	// approvalExpiryInterval stays below one minute so an expired item is
	// rejected within the board's 1-minute bound.
	approvalExpiryInterval = 30 * time.Second
	defaultApprovalTTL     = 72 * time.Hour
	approvalExpiryPageSize = 100
)

// ApprovalTTL reads APPROVAL_TTL_HOURS. Unset is the 72h default; a
// non-numeric or non-positive value also yields 72h with one log line, so a
// typo can never switch expiry off or make everything expire instantly.
func ApprovalTTL() time.Duration {
	raw := strings.TrimSpace(os.Getenv(approvalTTLEnv))
	if raw == "" {
		return defaultApprovalTTL
	}
	h, err := strconv.ParseFloat(raw, 64)
	if err != nil || h <= 0 || h > 24*365*10 {
		logging.Infof("approval expiry: invalid %s=%q, using %s", approvalTTLEnv, raw, defaultApprovalTTL)
		return defaultApprovalTTL
	}
	return time.Duration(h * float64(time.Hour))
}

// ApprovalExpiredEvent describes one auto-rejected item for notification.
type ApprovalExpiredEvent struct {
	Kind          string // "pending_action" | "certificate_approval"
	ID            string
	ActionType    string
	Proposer      string
	Tenant        string
	ApproverRoles []string
	ExpiredAt     time.Time
}

// ApprovalExpiryNotifier is the hook a real notification router plugs into.
// There is no generic notification-event bus yet, so production passes nil and
// relies on the approval.expired audit row (which the SIEM router forwards).
type ApprovalExpiryNotifier interface {
	NotifyApprovalExpired(ctx context.Context, ev ApprovalExpiredEvent) error
}

// ApprovalExpiryJob auto-rejects pending items older than TTL. Safe to run on
// several nodes at once: the pending-guarded Decide lets exactly one win.
type ApprovalExpiryJob struct {
	Actions   PendingActionStore
	Approvals ApprovalStore // may be nil
	Audit     AuditProvider
	Notifier  ApprovalExpiryNotifier // may be nil
	TTL       time.Duration
	Now       func() time.Time // test seam; default time.Now
	Interval  time.Duration    // default approvalExpiryInterval
	// Tenants resolves a certificate approval's tenant via its CA; may be nil.
	Tenants TenantStore
}

func (j *ApprovalExpiryJob) now() time.Time {
	if j.Now != nil {
		return j.Now()
	}
	return time.Now()
}

// approverRolesForExpiry is the set that could have decided the item.
func approverRolesForExpiry() []string { return []string{"pki-admin", "pki-operator"} }

// RunOnce expires every stale pending item and returns how many were expired.
func (j *ApprovalExpiryJob) RunOnce(ctx context.Context) (int, error) {
	ttl := j.TTL
	if ttl <= 0 {
		ttl = defaultApprovalTTL
	}
	now := j.now()
	cutoff := now.Add(-ttl)
	expired := 0
	var errs []error

	if j.Actions != nil {
		list, err := j.Actions.List(ctx, "pending")
		if err != nil {
			errs = append(errs, fmt.Errorf("list pending actions: %w", err))
		}
		for _, a := range list {
			created, perr := time.Parse(time.RFC3339, a.CreatedAt)
			if perr != nil || !created.Before(cutoff) {
				continue
			}
			result, _ := json.Marshal(map[string]any{"expired": true, "reason": "not approved within " + ttl.String()}) // static map: cannot fail
			// Only "rejected" is pending-guarded in Decide, so an approver
			// who already claimed the row (executing) wins and we skip.
			if derr := j.Actions.Decide(ctx, a.ID, "rejected", expirySweeper, result); derr != nil {
				continue
			}
			expired++
			tenant := a.Tenant
			if tenant == "" {
				tenant = DefaultTenant
			}
			j.record(ctx, "action.expire", "pending-action", a.ID, tenant,
				fmt.Sprintf("proposer=%s type=%s ttl=%s", a.ProposedBy, a.ActionType, ttl),
				ApprovalExpiredEvent{Kind: "pending_action", ID: a.ID, ActionType: a.ActionType, Proposer: a.ProposedBy, Tenant: tenant, ExpiredAt: now})
		}
	}

	if j.Approvals != nil {
		var stale []ApprovalRequest
		for offset := 0; ; offset += approvalExpiryPageSize {
			page, _, err := j.Approvals.List(ctx, "pending", approvalExpiryPageSize, offset)
			if err != nil {
				errs = append(errs, fmt.Errorf("list pending approvals: %w", err))
				break
			}
			for _, r := range page {
				if t, perr := time.Parse(time.RFC3339, r.RequestedAt); perr == nil && t.Before(cutoff) {
					stale = append(stale, r)
				}
			}
			if len(page) < approvalExpiryPageSize {
				break
			}
		}
		for _, r := range stale {
			if derr := j.Approvals.Decide(ctx, r.ID, expirySweeper, "rejected", "expired after "+ttl.String()); derr != nil {
				if !errors.Is(derr, errApprovalDecided) {
					errs = append(errs, fmt.Errorf("expire approval %s: %w", r.ID, derr))
				}
				continue
			}
			expired++
			tenant := DefaultTenant
			if t := approvalTenant(ctx, j.Tenants, r); t != "" {
				tenant = t
			}
			j.record(ctx, "approval.expire", "approval", r.ID, tenant,
				fmt.Sprintf("requester=%s template=%s ttl=%s", r.Requester, r.TemplateID, ttl),
				ApprovalExpiredEvent{Kind: "certificate_approval", ID: r.ID, ActionType: "certificate.issue", Proposer: r.Requester, Tenant: tenant, ExpiredAt: now})
		}
	}
	return expired, errors.Join(errs...)
}

// record writes the expiry audit row, the approval.expired notification audit
// row (SIEM-forwarded) and calls the optional Notifier.
func (j *ApprovalExpiryJob) record(ctx context.Context, action, resourceType, id, tenant, summary string, ev ApprovalExpiredEvent) {
	ev.ApproverRoles = approverRolesForExpiry()
	if j.Audit != nil {
		ts := j.now().UTC().Format(time.RFC3339)
		for _, e := range []AuditEntry{
			{Timestamp: ts, Action: action, ActorType: "system", ActorID: expirySweeper, ResourceType: resourceType, ResourceID: id, Outcome: AuditOutcomeSuccess, Tenant: tenant, ChangeSummary: summary},
			{Timestamp: ts, Action: "approval.expired", ActorType: "system", ActorID: expirySweeper, ResourceType: resourceType, ResourceID: id, Outcome: AuditOutcomeSuccess, Tenant: tenant,
				ChangeSummary: fmt.Sprintf("notify proposer=%s approver_roles=%s", ev.Proposer, strings.Join(ev.ApproverRoles, ","))},
		} {
			if err := j.Audit.AppendEntry(ctx, e); err != nil {
				logging.Errorf("approval expiry: audit append failed action=%s id=%s: %v", e.Action, id, err)
			}
		}
	}
	if j.Notifier != nil {
		if err := j.Notifier.NotifyApprovalExpired(ctx, ev); err != nil {
			logging.Warnf("approval expiry: notifier failed for %s: %v", id, err)
		}
	}
}

// Start sweeps immediately, then every Interval until ctx is cancelled.
func (j *ApprovalExpiryJob) Start(ctx context.Context) {
	interval := j.Interval
	if interval <= 0 {
		interval = approvalExpiryInterval
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if _, err := j.RunOnce(ctx); err != nil {
				logging.Infof("approval expiry: sweep: %v", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// newApprovalExpiryJob builds the sweeper from the environment; nil when no
// source store is available. The tenant store is opened here rather than read
// from the handlers' process-wide registration: the sweeper starts before the
// handlers register, and without it every certificate-approval expiry audit
// row would be stamped with the default tenant instead of the CA's tenant.
func newApprovalExpiryJob(audit AuditProvider) *ApprovalExpiryJob {
	actions := NewPendingActionStoreFromEnv()
	approvals, _ := newApprovalStoreFromEnv() // nil store = source skipped; open errors are logged by the provider
	if actions == nil && approvals == nil {
		return nil
	}
	return &ApprovalExpiryJob{Actions: actions, Approvals: approvals, Audit: audit, TTL: ApprovalTTL(), Interval: approvalExpiryInterval, Tenants: NewTenantStoreFromEnv()}
}

// StartApprovalExpiry builds the stores from the environment and starts the
// sweeper; a missing store is skipped.
func StartApprovalExpiry(ctx context.Context, audit AuditProvider) {
	if job := newApprovalExpiryJob(audit); job != nil {
		job.Start(ctx)
	}
}
