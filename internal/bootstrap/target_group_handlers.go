// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"kryptkeeper/internal/logging"
)

// W27-04: /api/v1/target-groups and /api/v1/target-policy. Writes are
// pki-admin (see authz_write_gate.go) and tenant-scoped like targets.

const targetGroupAuditAction = "target.update"

// defaultThresholdFallback is the documented RENEWAL_THRESHOLD_DAYS default,
// used for the policy view before the scheduler has ticked once.
const defaultThresholdFallback = 30

// schedulerDefaultThreshold is the default the scheduler is using now.
func schedulerDefaultThreshold() int {
	if st, ok := LatestRenewalStatus(); ok && st.ThresholdDays > 0 {
		return st.ThresholdDays
	}
	return defaultThresholdFallback
}

// groupTenantFor is the tenant a group is written under: the principal's, or
// the default tenant for a principal that bypasses tenant scoping (the same
// rule POST /targets stamps new targets with).
func groupTenantFor(pd AuthPrincipal) string {
	if tenantBypass(pd) {
		return DefaultTenant
	}
	return pd.Tenant
}

func groupVisibleToTenant(pd AuthPrincipal, g TargetGroup) bool {
	return tenantBypass(pd) || g.Tenant == pd.Tenant
}

// TargetPolicyRow is one target's effective renewal threshold and where it
// came from.
type TargetPolicyRow struct {
	TargetID      string `json:"target_id"`
	Name          string `json:"name"`
	Host          string `json:"host"`
	Group         string `json:"group"`
	OwnDays       int    `json:"own_days"`
	GroupDays     int    `json:"group_days"`
	DefaultDays   int    `json:"default_days"`
	EffectiveDays int    `json:"effective_days"`
	Source        string `json:"source"`
}

// RegisterTargetGroupHandlers mounts the group and effective-policy routes.
// A nil store answers 503, auditing the refusal.
func RegisterTargetGroupHandlers(mux *http.ServeMux, auth *Authenticator, targets ManagedTargetStore, groups TargetGroupStore, auditProvider AuditProvider) {
	authenticate := func(w http.ResponseWriter, r *http.Request) (AuthPrincipal, bool) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return AuthPrincipal{}, false
		}
		return pd, true
	}

	mux.HandleFunc("/api/v1/target-groups", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		pd, ok := authenticate(w, r)
		if !ok {
			return
		}
		if groups == nil {
			emitAuditEvent(r, auditProvider, pd.ID, "target.list", "target_group", "target-groups", AuditOutcomeFailure)
			writeServiceUnavailable(w, "target group store unavailable")
			return
		}
		all, err := groups.List(r.Context())
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "target.list", "target_group", "target-groups", AuditOutcomeFailure)
			writeServiceUnavailable(w, "list failed")
			return
		}
		out := make([]TargetGroup, 0, len(all))
		for _, g := range all {
			if groupVisibleToTenant(pd, g) {
				out = append(out, g)
			}
		}
		emitAuditEvent(r, auditProvider, pd.ID, "target.list", "target_group", "target-groups", AuditOutcomeSuccess)
		writeJSONData(w, out)
	})

	mux.HandleFunc("/api/v1/target-groups/{name}", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut && r.Method != http.MethodDelete {
			writeMethodNotAllowed(w, "PUT, DELETE")
			return
		}
		pd, ok := authenticate(w, r)
		if !ok {
			return
		}
		name := r.PathValue("name")
		audit := func(o AuditOutcome) {
			emitAuditEvent(r, auditProvider, pd.ID, targetGroupAuditAction, "target_group", name, o)
		}
		if groups == nil || (r.Method == http.MethodPut && targets == nil) {
			audit(AuditOutcomeFailure)
			writeServiceUnavailable(w, "target group store unavailable")
			return
		}
		tenant := groupTenantFor(pd)

		if r.Method == http.MethodDelete {
			switch err := groups.Delete(r.Context(), tenant, name); {
			case errors.Is(err, errTargetGroupNotFound):
				audit(AuditOutcomeFailure)
				writeNotFound(w, "target group not found")
			case err != nil:
				audit(AuditOutcomeFailure)
				writeServiceUnavailable(w, "delete failed")
			default:
				audit(AuditOutcomeSuccess)
				w.WriteHeader(http.StatusNoContent)
			}
			return
		}

		if err := validateGroupName(name); err != nil {
			audit(AuditOutcomeFailure)
			writeBadRequest(w, err.Error())
			return
		}
		var req struct {
			RenewalThresholdDays int      `json:"renewal_threshold_days"`
			TargetIDs            []string `json:"target_ids"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024)).Decode(&req); err != nil {
			audit(AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}
		if err := validateGroupThresholdDays(req.RenewalThresholdDays); err != nil {
			audit(AuditOutcomeFailure)
			writeBadRequest(w, err.Error())
			return
		}
		// Members must be targets of the group's own tenant. An unknown id and
		// another tenant's id answer the same, so ids cannot be probed.
		for _, id := range req.TargetIDs {
			t, err := targets.Get(r.Context(), id)
			if err != nil || t.Tenant != tenant {
				audit(AuditOutcomeFailure)
				writeBadRequest(w, "unknown target id: "+id)
				return
			}
		}
		saved, err := groups.Upsert(r.Context(), TargetGroup{Name: name, Tenant: tenant, RenewalThresholdDays: req.RenewalThresholdDays, TargetIDs: req.TargetIDs})
		if err != nil {
			audit(AuditOutcomeFailure)
			logging.Warnf("target group %q upsert failed: %v", name, err)
			writeServiceUnavailable(w, "save failed")
			return
		}
		audit(AuditOutcomeSuccess)
		writeJSONData(w, saved)
	})

	mux.HandleFunc("/api/v1/target-policy", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		pd, ok := authenticate(w, r)
		if !ok {
			return
		}
		if targets == nil {
			emitAuditEvent(r, auditProvider, pd.ID, "target.list", "target_policy", "target-policy", AuditOutcomeFailure)
			writeServiceUnavailable(w, "managed target store unavailable")
			return
		}
		items, err := targets.List(r.Context())
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "target.list", "target_policy", "target-policy", AuditOutcomeFailure)
			writeServiceUnavailable(w, "list failed")
			return
		}
		var all []TargetGroup
		if groups != nil {
			if all, err = groups.List(r.Context()); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.list", "target_policy", "target-policy", AuditOutcomeFailure)
				writeServiceUnavailable(w, "list failed")
				return
			}
		}
		groupOf := map[string]TargetGroup{}
		for _, g := range all {
			if groupVisibleToTenant(pd, g) {
				for _, id := range g.TargetIDs {
					groupOf[id] = g
				}
			}
		}
		def := schedulerDefaultThreshold()
		rows := []TargetPolicyRow{}
		for _, t := range filterManagedTargetsByTenant(pd, items) {
			g := groupOf[t.ID]
			days, src := effectiveTargetThreshold(t, g.RenewalThresholdDays, def)
			rows = append(rows, TargetPolicyRow{
				TargetID: t.ID, Name: t.Name, Host: t.Host, Group: g.Name,
				OwnDays: t.RenewalThresholdDays, GroupDays: g.RenewalThresholdDays, DefaultDays: def,
				EffectiveDays: days, Source: src,
			})
		}
		emitAuditEvent(r, auditProvider, pd.ID, "target.list", "target_policy", "target-policy", AuditOutcomeSuccess)
		writeJSONData(w, rows)
	})
}
