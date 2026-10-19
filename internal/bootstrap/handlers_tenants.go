// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// activeTenantStore is the process-wide tenant store used by list handlers that
// resolve tenancy without taking the store as a parameter. Set once in
// RegisterHandlers; nil with multi-tenancy on => tenant-scoped principals are
// denied (D-202); with it off nothing is filtered anyway.
var activeTenantStore TenantStore

func setActiveTenantStore(s TenantStore) { activeTenantStore = s }

// tenantBypass reports whether tenant read-filtering should be skipped entirely:
// multi-tenancy off, or an unscoped super-admin (identity super-admin who has
// not opted into a "view-as" tenant). A tenant-scoped super-admin IS filtered.
func tenantBypass(pd AuthPrincipal) bool {
	return !multiTenancyEnabled() || (pd.SuperAdmin && !pd.TenantScoped)
}

// tenantVisible reports whether a resource that belongs to effectiveTenant is
// visible to the principal.
func tenantVisible(pd AuthPrincipal, effectiveTenant string) bool {
	if tenantBypass(pd) {
		return true
	}
	return effectiveTenant == pd.Tenant
}

// caVisibleToTenant reports whether a CA (by its tenant mapping) is visible to a
// principal.
func caVisibleToTenant(ctx context.Context, store TenantStore, pd AuthPrincipal, caID string) bool {
	if tenantBypass(pd) {
		return true
	}
	if store == nil {
		return false // D-202: fail closed when the tenant store is unavailable
	}
	t, err := store.CATenant(ctx, caID)
	if err != nil {
		return false // deny by default on lookup failure
	}
	return t == pd.Tenant
}

// filterCAsByTenant returns only the CAs visible to the principal.
func filterCAsByTenant(ctx context.Context, store TenantStore, pd AuthPrincipal, items []CAListItem) []CAListItem {
	if tenantBypass(pd) {
		return items
	}
	if store == nil {
		return []CAListItem{} // D-202
	}
	out := make([]CAListItem, 0, len(items))
	for _, item := range items {
		if caVisibleToTenant(ctx, store, pd, item.ID) {
			out = append(out, item)
		}
	}
	return out
}

// filterCertificatesByTenant scopes certificates by their issuing CA's tenant.
func filterCertificatesByTenant(ctx context.Context, store TenantStore, pd AuthPrincipal, items []CertificateItem) []CertificateItem {
	if tenantBypass(pd) {
		return items
	}
	if store == nil {
		return []CertificateItem{} // D-202
	}
	out := make([]CertificateItem, 0, len(items))
	for _, item := range items {
		t, err := store.CATenant(ctx, item.CAID)
		if err != nil {
			continue // deny by default
		}
		if t == pd.Tenant {
			out = append(out, item)
		}
	}
	return out
}

// filterApprovalsByTenant scopes issuance approval requests by their CA's
// tenant; SSH rows (no CA) by their stored tenant, even with no store.
func filterApprovalsByTenant(ctx context.Context, store TenantStore, pd AuthPrincipal, items []ApprovalRequest) []ApprovalRequest {
	if tenantBypass(pd) {
		return items
	}
	out := make([]ApprovalRequest, 0, len(items))
	for _, item := range items {
		if item.Kind == approvalKindSSH {
			if approvalTenant(ctx, store, item) == pd.Tenant {
				out = append(out, item)
			}
			continue
		}
		if store == nil {
			continue // D-202: CA-backed rows need the store to prove tenancy
		}
		t, err := store.CATenant(ctx, item.CAID)
		if err != nil {
			continue // deny by default
		}
		if t == pd.Tenant {
			out = append(out, item)
		}
	}
	return out
}

// templateVisibleToTenant reports whether a template (by its tenant mapping)
// is visible to a principal (unmapped templates belong to the default tenant
// — a shared catalog entry).
func templateVisibleToTenant(ctx context.Context, store TenantStore, pd AuthPrincipal, templateID string) bool {
	if tenantBypass(pd) {
		return true
	}
	if store == nil {
		return false // D-202
	}
	t, err := store.TemplateTenant(ctx, templateID)
	if err != nil {
		return false // deny by default on lookup failure
	}
	return t == pd.Tenant
}

// filterTemplatesByTenant scopes templates by their explicit tenant mapping
// (unmapped templates belong to the default tenant — a shared catalog entry).
func filterTemplatesByTenant(ctx context.Context, store TenantStore, pd AuthPrincipal, items []TemplateItem) []TemplateItem {
	if tenantBypass(pd) {
		return items
	}
	if store == nil {
		return []TemplateItem{} // D-202
	}
	out := make([]TemplateItem, 0, len(items))
	for _, item := range items {
		t, err := store.TemplateTenant(ctx, item.ID)
		if err != nil {
			continue // deny by default
		}
		if t == pd.Tenant {
			out = append(out, item)
		}
	}
	return out
}

// filterPendingActionsByTenant scopes the proposal queue by the tenant stamped
// on each action at creation time (the proposer's tenant). No store lookup —
// the tenant travels with the row, so a failed lookup can't leak across tenants.
func filterPendingActionsByTenant(pd AuthPrincipal, items []PendingAction) []PendingAction {
	if tenantBypass(pd) {
		return items
	}
	out := make([]PendingAction, 0, len(items))
	for _, item := range items {
		t := item.Tenant
		if t == "" {
			t = DefaultTenant
		}
		if t == pd.Tenant {
			out = append(out, item)
		}
	}
	return out
}

// registerTenantHandlers mounts super-admin tenant CRUD + the resource→tenant
// mapping endpoints (CA and template).
func registerTenantHandlers(mux *http.ServeMux, auth *Authenticator, store TenantStore, auditProvider AuditProvider) {
	requireSuperAdmin := func(w http.ResponseWriter, r *http.Request) (AuthPrincipal, bool) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "tenant.admin", "tenant", "-", AuditOutcomeDenied)
			writeUnauthorized(w)
			return AuthPrincipal{}, false
		}
		if !pd.SuperAdmin {
			emitAuditEvent(r, auditProvider, pd.ID, "tenant.admin", "tenant", "-", AuditOutcomeDenied)
			writeForbidden(w, "tenant administration requires super-admin")
			return AuthPrincipal{}, false
		}
		if store == nil {
			writeServiceUnavailable(w, "tenant store unavailable")
			return AuthPrincipal{}, false
		}
		return pd, true
	}

	mux.HandleFunc("/api/v1/tenants", func(w http.ResponseWriter, r *http.Request) {
		pd, ok := requireSuperAdmin(w, r)
		if !ok {
			return
		}
		switch r.Method {
		case http.MethodGet:
			list, err := store.ListTenants(r.Context())
			if err != nil {
				writeServiceUnavailable(w, "list failed")
				return
			}
			writeJSONData(w, list)
		case http.MethodPost:
			var req struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "tenant.create", "tenant", "-", AuditOutcomeFailure)
				writeBadRequest(w, "invalid JSON")
				return
			}
			req.ID = strings.TrimSpace(req.ID)
			if req.ID == "" || req.Name == "" {
				emitAuditEvent(r, auditProvider, pd.ID, "tenant.create", "tenant", "-", AuditOutcomeFailure)
				writeBadRequest(w, "id and name are required")
				return
			}
			t, err := store.CreateTenant(r.Context(), req.ID, req.Name)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "tenant.create", "tenant", "-", AuditOutcomeFailure)
				writeServiceUnavailable(w, "create failed: "+err.Error())
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "tenant.create", "tenant", t.ID, AuditOutcomeSuccess)
			w.WriteHeader(http.StatusCreated)
			writeJSONData(w, t)
		default:
			writeMethodNotAllowed(w, "GET, POST")
		}
	})

	// POST /api/v1/tenants/ca-mapping — map a CA to a tenant (super-admin).
	mux.HandleFunc("/api/v1/tenants/ca-mapping", func(w http.ResponseWriter, r *http.Request) {
		pd, ok := requireSuperAdmin(w, r)
		if !ok {
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		var req struct {
			CAID     string `json:"ca_id"`
			TenantID string `json:"tenant_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CAID == "" || req.TenantID == "" {
			emitAuditEvent(r, auditProvider, pd.ID, "tenant.ca_map", "tenant", "-", AuditOutcomeFailure)
			writeBadRequest(w, "ca_id and tenant_id are required")
			return
		}
		if err := store.SetCATenant(r.Context(), req.CAID, req.TenantID); err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "tenant.ca_map", "tenant", "-", AuditOutcomeFailure)
			writeServiceUnavailable(w, "mapping failed")
			return
		}
		emitAuditEvent(r, auditProvider, pd.ID, "tenant.ca_map", "tenant", req.TenantID, AuditOutcomeSuccess)
		writeJSONData(w, map[string]string{"status": "mapped"})
	})

	// POST /api/v1/tenants/template-mapping — map a template to a tenant (super-admin).
	mux.HandleFunc("/api/v1/tenants/template-mapping", func(w http.ResponseWriter, r *http.Request) {
		pd, ok := requireSuperAdmin(w, r)
		if !ok {
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		var req struct {
			TemplateID string `json:"template_id"`
			TenantID   string `json:"tenant_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TemplateID == "" || req.TenantID == "" {
			emitAuditEvent(r, auditProvider, pd.ID, "tenant.template_map", "tenant", "-", AuditOutcomeFailure)
			writeBadRequest(w, "template_id and tenant_id are required")
			return
		}
		if err := store.SetTemplateTenant(r.Context(), req.TemplateID, req.TenantID); err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "tenant.template_map", "tenant", "-", AuditOutcomeFailure)
			writeServiceUnavailable(w, "mapping failed")
			return
		}
		emitAuditEvent(r, auditProvider, pd.ID, "tenant.template_map", "tenant", req.TenantID, AuditOutcomeSuccess)
		writeJSONData(w, map[string]string{"status": "mapped"})
	})

	// GET /api/v1/tenants/context — drives the UI tenant switcher. Available to
	// any authenticated principal: reports whether multi-tenancy is on, the
	// caller's resolved tenant/scope, and (super-admin only) the tenant list.
	mux.HandleFunc("/api/v1/tenants/context", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		resp := struct {
			Enabled    bool     `json:"enabled"`
			SuperAdmin bool     `json:"super_admin"`
			Tenant     string   `json:"tenant"`
			Scoped     bool     `json:"scoped"`
			Tenants    []Tenant `json:"tenants"`
		}{
			Enabled:    multiTenancyEnabled(),
			SuperAdmin: pd.SuperAdmin,
			Tenant:     pd.Tenant,
			Scoped:     pd.TenantScoped,
			Tenants:    []Tenant{},
		}
		if pd.SuperAdmin && store != nil {
			if list, lerr := store.ListTenants(r.Context()); lerr == nil {
				resp.Tenants = list
			}
		}
		writeJSONData(w, resp)
	})
}

// drainPages reads every page of an offset-paged list. Tenant filtering has
// to run over the whole set before total/cursor are computed, otherwise the
// provider's fleet-wide total leaks other tenants' row counts (L-20).
func drainPages[T any](fetch func(offset, limit int) (items []T, total int, err error)) ([]T, error) {
	const pageSize = 100
	var all []T
	for offset := 0; ; {
		items, total, err := fetch(offset, pageSize)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
		offset += len(items)
		if len(items) == 0 || offset >= total {
			return all, nil
		}
	}
}

// pageSlice returns the [offset, offset+limit) window of items.
func pageSlice[T any](items []T, offset, limit int) []T {
	if offset > len(items) {
		offset = len(items)
	}
	end := offset + limit
	if end > len(items) || end < offset {
		end = len(items)
	}
	return items[offset:end]
}

// denyNonSuperAdminGlobal refuses an operation on instance-global state (runtime
// config, plugins, ceremonies, SCEP, AD sync) unless the caller is an unscoped
// super-admin. With multi-tenancy off every principal passes, so single-tenant
// behaviour is unchanged. Returns true when it has written the 403.
func denyNonSuperAdminGlobal(w http.ResponseWriter, r *http.Request, audit AuditProvider, pd AuthPrincipal, action, resType, resID string) bool {
	if tenantBypass(pd) {
		return false
	}
	emitAuditEventDetail(r, audit, pd.ID, action, resType, resID, AuditOutcomeDenied, `{"reason":"global setting; super-admin only when multi-tenancy is on"}`)
	writeForbidden(w, "instance-wide setting: platform super-admin required when multi-tenancy is on")
	return true
}

// stampedTenantVisible reports whether a row that carries its own tenant column
// is visible to the principal. Rows predating tenancy hold "" and belong to
// DefaultTenant. Shared by every store-backed resource whose tenant travels
// with the row (credentials, connectors, inventory sources, notifications).
func stampedTenantVisible(pd AuthPrincipal, stamped string) bool {
	if tenantBypass(pd) {
		return true
	}
	if stamped == "" {
		stamped = DefaultTenant
	}
	return stamped == pd.Tenant
}
