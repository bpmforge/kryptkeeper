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

const (
	inboxTypeCert   = "certificate_approval"
	inboxTypeAction = "pending_action"

	inboxDefaultLimit = 50
	inboxMaxLimit     = 200
	// inboxCertFetch bounds how many pending certificate approvals one inbox
	// request reads from the store.
	inboxCertFetch = 1000
)

// inboxItem is the common read-model row over certificate approvals and
// pending actions.
type inboxItem struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Summary    string `json:"summary"`
	Requester  string `json:"requester"`
	Tenant     string `json:"tenant"`
	CreatedAt  string `json:"created_at"`
	AgeSeconds int64  `json:"age_seconds"`
	ActionType string `json:"action_type,omitempty"`
}

// RegisterApprovalInbox mounts the unified approvals inbox. It must run after
// registerHandlers so the active tenant store is set and the source approve
// routes it re-dispatches to exist on mux.
func RegisterApprovalInbox(mux *http.ServeMux, auth *Authenticator, audit AuditProvider, templates TemplateProvider) {
	approvals, _ := newApprovalStoreFromEnv() // nil store = source skipped; open errors are logged by the provider
	actions := NewPendingActionStoreFromEnv()
	registerApprovalInboxHandlers(mux, auth, approvals, actions, activeTenantStore, audit, templates)
}

// templates may be nil; without one, a non-admin sees only the certificate
// approvals they raised.
func registerApprovalInboxHandlers(mux *http.ServeMux, auth *Authenticator, approvals ApprovalStore, actions PendingActionStore, tenants TenantStore, audit AuditProvider, templates TemplateProvider) {
	mux.HandleFunc("/api/v1/approvals/inbox", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		q := r.URL.Query()
		typ := strings.TrimSpace(q.Get("type"))
		if typ != "" && typ != inboxTypeCert && typ != inboxTypeAction {
			writeBadRequest(w, "type must be certificate_approval or pending_action")
			return
		}
		var minAge time.Duration
		if v := strings.TrimSpace(q.Get("min_age")); v != "" {
			d, derr := time.ParseDuration(v)
			if derr != nil || d < 0 {
				writeBadRequest(w, "min_age must be a non-negative duration such as 24h")
				return
			}
			minAge = d
		}
		limit := inboxDefaultLimit
		if v := q.Get("limit"); v != "" {
			if n, e := strconv.Atoi(v); e == nil && n > 0 {
				limit = n
			}
		}
		if limit > inboxMaxLimit {
			limit = inboxMaxLimit
		}
		offset := 0
		if v := q.Get("offset"); v != "" {
			if n, e := strconv.Atoi(v); e == nil && n >= 0 {
				offset = n
			}
		}
		// A tenant principal is always forced to its own tenant; the filter
		// is only a narrowing option for an unscoped caller.
		tenantFilter := ""
		if tenantBypass(pd) {
			tenantFilter = strings.TrimSpace(q.Get("tenant"))
		}

		now := time.Now()
		items, lerr := collectInbox(r.Context(), pd, approvals, actions, tenants, typ, now, templates)
		if lerr != nil {
			emitAuditEvent(r, audit, pd.ID, "approval.inbox.list", "approval", "inbox", AuditOutcomeFailure)
			writeServiceUnavailable(w, "approval stores unavailable")
			return
		}
		filtered := items[:0]
		for _, it := range items {
			if tenantFilter != "" && it.Tenant != tenantFilter {
				continue
			}
			if minAge > 0 && time.Duration(it.AgeSeconds)*time.Second < minAge {
				continue
			}
			filtered = append(filtered, it)
		}
		sort.SliceStable(filtered, func(i, j int) bool {
			if filtered[i].CreatedAt != filtered[j].CreatedAt {
				return filtered[i].CreatedAt < filtered[j].CreatedAt
			}
			return filtered[i].ID < filtered[j].ID
		})
		// Total is taken after every visibility filter so it can never reveal
		// how many items other tenants hold.
		total := len(filtered)
		page := pageSlice(filtered, offset, limit)
		emitAuditEvent(r, audit, pd.ID, "approval.inbox.list", "approval", "inbox", AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": page,
			"meta": map[string]int{"total": total, "limit": limit, "offset": offset},
		})
	})

	// POST /api/v1/approvals/inbox/{type}/{id}/{approve|reject} only
	// re-dispatches: every refusal (bootstrap, self, role, tenant, not
	// pending) must come from the source handler, never from a copy here.
	mux.HandleFunc("/api/v1/approvals/inbox/", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, audit, "", "approval.inbox.act", "approval", "inbox", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/approvals/inbox/"), "/")
		if len(parts) != 3 || !validInboxID(parts[1]) || (parts[2] != "approve" && parts[2] != "reject") {
			emitAuditEvent(r, audit, pd.ID, "approval.inbox.act", "approval", "inbox", AuditOutcomeFailure)
			writeNotFound(w, "unknown inbox item")
			return
		}
		var target string
		switch parts[0] {
		case inboxTypeCert:
			target = "/api/v1/approvals/" + parts[1] + "/" + parts[2]
		case inboxTypeAction:
			target = "/api/v1/pending-actions/" + parts[1] + "/" + parts[2]
		default:
			emitAuditEvent(r, audit, pd.ID, "approval.inbox.act", "approval", "inbox", AuditOutcomeFailure)
			writeNotFound(w, "unknown inbox item type")
			return
		}
		r2 := r.Clone(r.Context())
		r2.URL.Path = target
		r2.URL.RawPath = ""
		r2.RequestURI = target
		mux.ServeHTTP(w, r2)
	})
}

// validInboxID keeps a crafted id from steering the re-dispatch to another
// route: ids are generated hex/dash tokens.
func validInboxID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// collectInbox reads the pending rows of both stores and applies the same
// visibility rules as the source list handlers.
func collectInbox(ctx context.Context, pd AuthPrincipal, approvals ApprovalStore, actions PendingActionStore, tenants TenantStore, typ string, now time.Time, templates TemplateProvider) ([]inboxItem, error) {
	out := []inboxItem{}
	if approvals != nil && (typ == "" || typ == inboxTypeCert) {
		reqs, _, err := approvals.List(ctx, "pending", inboxCertFetch, 0)
		if err != nil {
			return nil, err
		}
		reqs = newApprovalRoleScope(templates).visibleTo(ctx, pd, reqs)
		// filterApprovalsByTenant passes everything through on a nil store;
		// a tenant principal must instead see nothing it cannot prove.
		if tenants == nil && !tenantBypass(pd) {
			reqs = nil
		}
		reqs = filterApprovalsByTenant(ctx, tenants, pd, reqs)
		for _, r := range reqs {
			tenant := DefaultTenant
			if t := approvalTenant(ctx, tenants, r); t != "" {
				tenant = t
			}
			summary := "issue from template " + r.TemplateID + " on CA " + r.CAID
			if r.Kind == approvalKindSSH {
				summary = "issue SSH certificate from template " + r.TemplateID
			}
			out = append(out, inboxItem{
				Type: inboxTypeCert, ID: r.ID, Requester: r.Requester, Tenant: tenant,
				Summary:   summary,
				CreatedAt: r.RequestedAt, AgeSeconds: ageSeconds(r.RequestedAt, now),
			})
		}
	}
	if actions != nil && (typ == "" || typ == inboxTypeAction) {
		list, err := actions.List(ctx, "pending")
		if err != nil {
			return nil, err
		}
		// Key/CA dual-control actions are decided only by pki-admin and
		// pki-operator; a role that cannot decide them (approver is certificate
		// requests only) sees just the ones it proposed.
		mayDecideActions := canApproveActions(pd.Role)
		for _, a := range filterPendingActionsByTenant(pd, list) {
			if !mayDecideActions && a.ProposedBy != pd.ID {
				continue
			}
			tenant := a.Tenant
			if tenant == "" {
				tenant = DefaultTenant
			}
			summary := strings.TrimSpace(a.ActionType + " " + a.Rationale)
			if len(summary) > 200 {
				summary = summary[:200]
			}
			out = append(out, inboxItem{
				Type: inboxTypeAction, ID: a.ID, Requester: a.ProposedBy, Tenant: tenant, Summary: summary,
				CreatedAt: a.CreatedAt, AgeSeconds: ageSeconds(a.CreatedAt, now), ActionType: a.ActionType,
			})
		}
	}
	return out, nil
}

func ageSeconds(rfc3339 string, now time.Time) int64 {
	t, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil || t.After(now) {
		return 0
	}
	return int64(now.Sub(t).Seconds())
}
