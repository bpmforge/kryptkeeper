// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// W22-34: the access-review report joins users, API keys and the audit trail
// into one read-only document. It is also the snapshot W22-35 recertifies.

const (
	envAccessReviewDormantDays     = "ACCESS_REVIEW_DORMANT_DAYS"
	defaultAccessReviewDormantDays = 90
	defaultAccessReviewPeriodDays  = 90
	maxAccessReviewRoleChanges     = 5000
	accessReviewAuditPage          = 100
)

// accessReviewRoleChangeActions are the audit actions that change who holds
// access. Exact-match: both audit providers filter Action by equality.
var accessReviewRoleChangeActions = []string{
	"users.update", "users.invite", "users.deactivate",
	"role.create", "role.update", "role.delete",
	"api-key.create", "api-key.delete",
	"scim.users.update", "scim.users.deprovision",
}

// AccessReviewPrincipal is one user or API key in the report. It never carries
// key secret material.
type AccessReviewPrincipal struct {
	Kind            string `json:"kind"`
	ID              string `json:"id"`
	Name            string `json:"name"`
	Role            string `json:"role"`
	Tenant          string `json:"tenant"`
	Source          string `json:"source"`
	Status          string `json:"status"`
	CreatedAt       string `json:"created_at,omitempty"`
	CreatedBy       string `json:"created_by,omitempty"`
	LastActivityAt  string `json:"last_activity_at,omitempty"`
	Dormant         bool   `json:"dormant"`
	ApproverCapable bool   `json:"approver_capable"`
}

// AccessReviewRoleChange is one access-changing audit event in the period.
type AccessReviewRoleChange struct {
	Timestamp    string `json:"timestamp"`
	Action       string `json:"action"`
	Actor        string `json:"actor"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Outcome      string `json:"outcome"`
}

// AccessReviewTotals counts the report's rows.
type AccessReviewTotals struct {
	Users       int `json:"users"`
	APIKeys     int `json:"api_keys"`
	Dormant     int `json:"dormant"`
	RoleChanges int `json:"role_changes"`
}

// AccessReviewReport is the response body of GET /admin/access-review/report.
type AccessReviewReport struct {
	GeneratedAt string                   `json:"generated_at"`
	PeriodStart string                   `json:"period_start"`
	PeriodEnd   string                   `json:"period_end"`
	DormantDays int                      `json:"dormant_days"`
	Principals  []AccessReviewPrincipal  `json:"principals"`
	RoleChanges []AccessReviewRoleChange `json:"role_changes"`
	Totals      AccessReviewTotals       `json:"totals"`
	Truncated   bool                     `json:"truncated,omitempty"`
	// PrivilegedCredentials lists outbound credentials flagged high-impact
	// (W34-11), with the hosts they reach.
	PrivilegedCredentials *PrivilegedCredentialsSummary `json:"privileged_credentials,omitempty"`
}

type accessReviewDeps struct {
	auth  *Authenticator
	users UserProvider
	roles *CustomRoleStore
	audit AuditProvider
	// creds and targets feed the privileged-credentials section; nil omits it.
	creds   OutboundCredentialStore
	targets ManagedTargetStore
}

func accessReviewUsers(a *Authenticator) UserProvider {
	if a.userProvider != nil {
		return a.userProvider
	}
	return NewUserProviderFromEnv()
}

func accessReviewRoles(a *Authenticator) *CustomRoleStore {
	if a.roleStore != nil {
		return a.roleStore
	}
	return NewCustomRoleStoreFromEnv()
}

// roleHoldsPermission answers for fixed roles without a store, so a deployment
// (or test) with no custom-role table still resolves built-in roles.
func roleHoldsPermission(roles *CustomRoleStore, role, perm string) bool {
	if fixed := fixedRolePermissions(role); fixed != nil {
		for _, p := range fixed {
			if p == perm {
				return true
			}
		}
		return false
	}
	if roles == nil {
		return false
	}
	ok, err := roles.RoleHasPermission(role, perm)
	return err == nil && ok
}

// BuildAccessReport is a pure function of (deps, now): tests inject now.
func BuildAccessReport(ctx context.Context, d accessReviewDeps, pd AuthPrincipal, from, to, now time.Time, dormantDays int) (AccessReviewReport, error) {
	report := AccessReviewReport{
		GeneratedAt: now.UTC().Format(time.RFC3339),
		PeriodStart: from.UTC().Format(time.RFC3339),
		PeriodEnd:   to.UTC().Format(time.RFC3339),
		DormantDays: dormantDays,
		Principals:  []AccessReviewPrincipal{},
		RoleChanges: []AccessReviewRoleChange{},
	}

	users, err := d.users.ListUsers(ctx)
	if err != nil {
		return report, err
	}
	sources, err := accessReviewUserSources(ctx, d.audit)
	if err != nil {
		return report, err
	}
	for _, u := range users {
		p := AccessReviewPrincipal{
			Kind:            "user",
			ID:              u.ID,
			Name:            u.Email,
			Role:            u.Role,
			Tenant:          userTenant(u),
			Source:          "local",
			Status:          "inactive",
			CreatedAt:       u.CreatedAt,
			LastActivityAt:  u.LastSeenAt,
			ApproverCapable: roleHoldsPermission(d.roles, u.Role, "action.approve"),
		}
		if s, ok := sources[u.ID]; ok {
			p.Source = s
		}
		if u.Status == "active" {
			p.Status = "active"
		}
		report.Principals = append(report.Principals, p)
	}
	if d.auth != nil {
		for _, k := range d.auth.ListAPIKeys() {
			p := AccessReviewPrincipal{
				Kind:            "api_key",
				ID:              k.Kid,
				Name:            k.Name,
				Role:            k.Role,
				Tenant:          k.Tenant,
				Source:          "local",
				Status:          "inactive",
				CreatedAt:       k.CreatedAt,
				CreatedBy:       k.CreatedBy,
				LastActivityAt:  k.LastUsedAt,
				ApproverCapable: roleHoldsPermission(d.roles, k.Role, "action.approve"),
			}
			if p.Tenant == "" {
				p.Tenant = DefaultTenant
			}
			if k.Active {
				p.Status = "active"
			}
			report.Principals = append(report.Principals, p)
		}
	}

	// Scope before counting so a tenant reviewer's totals never hint at rows
	// of other tenants.
	visible := report.Principals[:0]
	for _, p := range report.Principals {
		if !tenantVisible(pd, p.Tenant) {
			continue
		}
		p.Dormant = accessReviewDormant(p, now, dormantDays)
		if p.Dormant {
			report.Totals.Dormant++
		}
		if p.Kind == "user" {
			report.Totals.Users++
		} else {
			report.Totals.APIKeys++
		}
		visible = append(visible, p)
	}
	report.Principals = visible

	changes, truncated, err := accessReviewRoleChanges(ctx, d.audit, pd, from, to)
	if err != nil {
		return report, err
	}
	report.RoleChanges = changes
	report.Truncated = truncated
	report.Totals.RoleChanges = len(changes)
	report.PrivilegedCredentials = buildPrivilegedCredentialsSummary(ctx, pd, d.creds, d.targets)
	return report, nil
}

// accessReviewDormant: only active accounts can be dormant; an account that
// never acted is aged from its creation. Exactly N days idle is not dormant.
func accessReviewDormant(p AccessReviewPrincipal, now time.Time, dormantDays int) bool {
	if p.Status != "active" {
		return false
	}
	ref := p.LastActivityAt
	if ref == "" {
		ref = p.CreatedAt
	}
	t, err := time.Parse(time.RFC3339, ref)
	if err != nil {
		return false
	}
	return now.Sub(t) > time.Duration(dormantDays)*24*time.Hour
}

// accessReviewUserSources derives how each account was provisioned from the
// audit trail (UserRecord carries no source): SCIM create wins over an SSO
// login, anything else is local.
func accessReviewUserSources(ctx context.Context, audit AuditProvider) (map[string]string, error) {
	out := map[string]string{}
	if audit == nil {
		return out, nil
	}
	scan := func(action string, f func(AuditEntry)) error {
		for offset := 0; ; {
			res, err := audit.ListEntries(ctx, AuditListQuery{Action: action, Outcome: AuditOutcomeSuccess, Order: "asc", Limit: accessReviewAuditPage, Offset: offset})
			if err != nil {
				return err
			}
			for _, e := range res.Entries {
				f(e)
			}
			offset += len(res.Entries)
			if len(res.Entries) == 0 || offset >= res.Total {
				return nil
			}
		}
	}
	for _, a := range []string{"auth.saml.acs", "auth.oidc.callback"} {
		if err := scan(a, func(e AuditEntry) {
			if e.ActorID != "" {
				out[e.ActorID] = "sso"
			}
		}); err != nil {
			return nil, err
		}
	}
	if err := scan("scim.users.create", func(e AuditEntry) {
		if e.ResourceID != "" {
			out[e.ResourceID] = "scim"
		}
	}); err != nil {
		return nil, err
	}
	return out, nil
}

func accessReviewRoleChanges(ctx context.Context, audit AuditProvider, pd AuthPrincipal, from, to time.Time) ([]AccessReviewRoleChange, bool, error) {
	changes := []AccessReviewRoleChange{}
	if audit == nil {
		return changes, false, nil
	}
	after, before := from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339)
	truncated := false
	for _, action := range accessReviewRoleChangeActions {
		for offset := 0; ; {
			res, err := audit.ListEntries(ctx, AuditListQuery{Action: action, Outcome: AuditOutcomeSuccess, After: after, Before: before, Order: "asc", Limit: accessReviewAuditPage, Offset: offset})
			if err != nil {
				return nil, false, err
			}
			for _, e := range res.Entries {
				if !tenantBypass(pd) && auditEntryTenantOrDefault(e.Tenant) != pd.Tenant {
					continue
				}
				if len(changes) >= maxAccessReviewRoleChanges {
					truncated = true
					break
				}
				changes = append(changes, AccessReviewRoleChange{Timestamp: e.Timestamp, Action: e.Action, Actor: e.ActorID, ResourceType: e.ResourceType, ResourceID: e.ResourceID, Outcome: string(e.Outcome)})
			}
			offset += len(res.Entries)
			if truncated || len(res.Entries) == 0 || offset >= res.Total {
				break
			}
		}
		if truncated {
			break
		}
	}
	sort.SliceStable(changes, func(i, j int) bool {
		if changes[i].Timestamp != changes[j].Timestamp {
			return changes[i].Timestamp < changes[j].Timestamp
		}
		return changes[i].Action < changes[j].Action
	})
	return changes, truncated, nil
}

// accessReviewIntParam reads an optional bounded integer query parameter.
func accessReviewIntParam(r *http.Request, name string, def, lo, hi int) (int, bool) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return def, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < lo || n > hi {
		return 0, false
	}
	return n, true
}

func registerAccessReviewReportHandler(mux *http.ServeMux, auth *Authenticator, users UserProvider, roles *CustomRoleStore, audit AuditProvider, creds OutboundCredentialStore, targets ManagedTargetStore) {
	mux.HandleFunc("/api/v1/admin/access-review/report", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, audit, "", "access_review.report", "access-review", "report", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		if !requireReadPermission(w, r, audit, pd, roles, "audit.read", "access_review.report", "access-review", "report") {
			return
		}
		periodDays, ok := accessReviewIntParam(r, "period_days", defaultAccessReviewPeriodDays, 1, 3660)
		if !ok {
			writeBadRequest(w, "period_days must be an integer between 1 and 3660")
			return
		}
		dormantDays, ok := accessReviewIntParam(r, "dormant_days", intFromEnvOrDefault(envAccessReviewDormantDays, defaultAccessReviewDormantDays), 1, 3650)
		if !ok {
			writeBadRequest(w, "dormant_days must be an integer between 1 and 3650")
			return
		}
		now := time.Now().UTC()
		report, err := BuildAccessReport(r.Context(), accessReviewDeps{auth: auth, users: users, roles: roles, audit: audit, creds: creds, targets: targets},
			pd, now.AddDate(0, 0, -periodDays), now, now, dormantDays)
		if err != nil {
			emitAuditEvent(r, audit, pd.ID, "access_review.report", "access-review", "report", AuditOutcomeFailure)
			writeServiceUnavailable(w, "access review data unavailable")
			return
		}
		emitAuditEvent(r, audit, pd.ID, "access_review.report", "access-review", "report", AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": report})
	})
}
