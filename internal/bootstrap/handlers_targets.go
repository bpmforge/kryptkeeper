// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// RegisterTargetHandlers mounts the /api/v1/targets CRUD surface (W5-09,
// D-062, FR-P24). store may be nil (DB unavailable) -- every handler
// reports 503 in that case rather than silently no-op'ing.
func RegisterTargetHandlers(mux *http.ServeMux, auth *Authenticator, store ManagedTargetStore, tenantStore TenantStore, auditProvider AuditProvider, credentials OutboundCredentialStore, plugins *DeliveryPluginManager) {
	registerTargetHandlers(mux, auth, store, tenantStore, auditProvider, targetEgressDeps{credentials: credentials, plugins: plugins})
}

// targetVisibleToTenant reports whether a managed target belongs to the
// principal's tenant. Unlike CA/template (a separate mapping table,
// unmapped => DefaultTenant), tenant is a direct column stamped at create
// time -- no store lookup needed, mirroring filterPendingActionsByTenant's
// reasoning: the tenant travels with the row, so this can't leak across
// tenants via a failed lookup because there is no lookup.
func targetVisibleToTenant(pd AuthPrincipal, target ManagedTarget) bool {
	return tenantBypass(pd) || target.Tenant == pd.Tenant
}

func filterManagedTargetsByTenant(pd AuthPrincipal, items []ManagedTarget) []ManagedTarget {
	if tenantBypass(pd) {
		return items
	}
	out := make([]ManagedTarget, 0, len(items))
	for _, t := range items {
		if t.Tenant == pd.Tenant {
			out = append(out, t)
		}
	}
	return out
}

func registerTargetHandlers(mux *http.ServeMux, auth *Authenticator, store ManagedTargetStore, tenantStore TenantStore, auditProvider AuditProvider, egressDeps targetEgressDeps) {
	authenticate := func(w http.ResponseWriter, r *http.Request) (AuthPrincipal, bool) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return AuthPrincipal{}, false
		}
		return pd, true
	}

	mux.HandleFunc("/api/v1/targets", func(w http.ResponseWriter, r *http.Request) {
		pd, ok := authenticate(w, r)
		if !ok {
			return
		}
		if store == nil {
			emitAuditEvent(r, auditProvider, pd.ID, "target.list", "target", "targets", AuditOutcomeFailure)
			writeServiceUnavailable(w, "managed target store unavailable")
			return
		}

		switch r.Method {
		case http.MethodGet:
			items, err := store.List(r.Context())
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.list", "target", "targets", AuditOutcomeFailure)
				writeServiceUnavailable(w, "list failed")
				return
			}
			writeJSONData(w, filterManagedTargetsByTenant(pd, items))

		case http.MethodPost:
			var req struct {
				Name                 string `json:"name"`
				Host                 string `json:"host"`
				DiscoveryMode        string `json:"discovery_mode"`
				InstallMode          string `json:"install_mode"`
				RenewalMethod        string `json:"renewal_method"`
				RenewalThresholdDays int    `json:"renewal_threshold_days"`
				CredentialRef        string `json:"credential_ref"`
				Schedule             string `json:"schedule"`
				InstallServerType    string `json:"install_server_type"`
				InstallCertPath      string `json:"install_cert_path"`
				InstallKeyPath       string `json:"install_key_path"`
				InstallReloadMethod  string `json:"install_reload_method"`
				VerifyHostPort       string `json:"verify_host_port"`
				AutoRenew            bool   `json:"auto_renew"`
				// W20-20: install_mode "plugin" targets name their plugin
				// and its target_schema values.
				PluginID       string            `json:"plugin_id"`
				PluginSettings map[string]string `json:"plugin_settings"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&req); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.create", "target", "targets", AuditOutcomeFailure)
				writeBadRequest(w, "invalid request body")
				return
			}
			req.Name = strings.TrimSpace(req.Name)
			req.Host = strings.TrimSpace(req.Host)
			if req.Name == "" || req.Host == "" {
				emitAuditEvent(r, auditProvider, pd.ID, "target.create", "target", "targets", AuditOutcomeFailure)
				writeBadRequest(w, "name and host are required")
				return
			}
			if req.DiscoveryMode == "" {
				req.DiscoveryMode = "agent"
			}
			if req.InstallMode == "" {
				req.InstallMode = "agent"
			}
			if req.RenewalMethod == "" {
				req.RenewalMethod = "acme"
			}
			if err := validateManagedTargetModes(req.DiscoveryMode, req.InstallMode, req.RenewalMethod); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.create", "target", "targets", AuditOutcomeFailure)
				writeBadRequest(w, "invalid discovery_mode, install_mode, or renewal_method")
				return
			}
			if err := validateRenewalThresholdDays(req.RenewalThresholdDays); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.create", "target", "targets", AuditOutcomeFailure)
				writeBadRequest(w, err.Error())
				return
			}
			if err := validateVerifyHostPort(req.VerifyHostPort); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.create", "target", "targets", AuditOutcomeFailure)
				writeBadRequest(w, err.Error())
				return
			}
			if err := validatePluginTarget(req.InstallMode, req.PluginID); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.create", "target", "targets", AuditOutcomeFailure)
				writeBadRequest(w, err.Error())
				return
			}

			tenant := DefaultTenant
			if !tenantBypass(pd) {
				tenant = pd.Tenant
				if tenantStore != nil {
					exists, terr := tenantStore.TenantExists(r.Context(), tenant)
					if terr != nil {
						emitAuditEvent(r, auditProvider, pd.ID, "target.create", "target", "targets", AuditOutcomeFailure)
						writeServiceUnavailable(w, "tenant lookup failed")
						return
					}
					if !exists {
						emitAuditEvent(r, auditProvider, pd.ID, "target.create", "target", "targets", AuditOutcomeDenied)
						writeBadRequest(w, "unknown tenant")
						return
					}
				}
			}

			id, err := newManagedTargetID()
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.create", "target", "targets", AuditOutcomeFailure)
				writeServiceUnavailable(w, "id generation failed")
				return
			}
			now := time.Now().UTC().Format(time.RFC3339)
			newTarget := ManagedTarget{
				ID:                   id,
				Name:                 req.Name,
				Host:                 req.Host,
				DiscoveryMode:        req.DiscoveryMode,
				InstallMode:          req.InstallMode,
				RenewalMethod:        req.RenewalMethod,
				RenewalThresholdDays: req.RenewalThresholdDays,
				CredentialRef:        req.CredentialRef,
				Schedule:             req.Schedule,
				InstallServerType:    strings.TrimSpace(req.InstallServerType),
				InstallCertPath:      strings.TrimSpace(req.InstallCertPath),
				InstallKeyPath:       strings.TrimSpace(req.InstallKeyPath),
				InstallReloadMethod:  strings.TrimSpace(req.InstallReloadMethod),
				VerifyHostPort:       strings.TrimSpace(req.VerifyHostPort),
				AutoRenew:            req.AutoRenew,
				PluginID:             strings.TrimSpace(req.PluginID),
				PluginSettings:       req.PluginSettings,
				Tenant:               tenant,
				CreatedAt:            now,
				UpdatedAt:            now,
			}
			fields, stamp, allowed, need := authorizeTargetEgress(pd, auth.roleStore, ManagedTarget{}, newTarget, req.AutoRenew)
			if !allowed {
				refuseTargetEgress(w, r, auditProvider, pd, "target.create", "targets", fields, need)
				return
			}
			var armedBy string
			if stamp {
				var ok bool
				if armedBy, ok = armStamp(w, r, auditProvider, pd, "target.create", "targets"); !ok {
					return
				}
			}
			if err := egressDeps.validateTargetReferences(r.Context(), pd, ManagedTarget{}, newTarget); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.create", "target", "targets", AuditOutcomeFailure)
				writeTargetReferenceError(w, err)
				return
			}
			if stamp {
				newTarget.AutoRenewSetBy = armedBy
			}
			created, err := store.Create(r.Context(), newTarget)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.create", "target", "targets", AuditOutcomeFailure)
				writeServiceUnavailable(w, "create failed")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "target.create", "target", created.ID, AuditOutcomeSuccess)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			writeJSONData(w, created)

		default:
			writeMethodNotAllowed(w, "GET, POST")
		}
	})

	mux.HandleFunc("/api/v1/targets/", func(w http.ResponseWriter, r *http.Request) {
		pd, ok := authenticate(w, r)
		if !ok {
			return
		}
		if store == nil {
			emitAuditEvent(r, auditProvider, pd.ID, "target.get", "target", "", AuditOutcomeFailure)
			writeServiceUnavailable(w, "managed target store unavailable")
			return
		}

		tail := strings.TrimPrefix(r.URL.Path, "/api/v1/targets/")
		if tail == "" || strings.Contains(strings.TrimSuffix(tail, "/endpoints"), "/") {
			emitAuditEvent(r, auditProvider, pd.ID, "target.get", "target", tail, AuditOutcomeFailure)
			writeNotFound(w, "target not found")
			return
		}

		if strings.HasSuffix(tail, "/endpoints") {
			if r.Method != http.MethodGet {
				writeMethodNotAllowed(w, http.MethodGet)
				return
			}
			id := strings.TrimSuffix(tail, "/endpoints")
			target, err := store.Get(r.Context(), id)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.endpoints", "target", id, AuditOutcomeFailure)
				writeNotFound(w, "target not found")
				return
			}
			// NFR-P2 (acceptance #3): endpoints/agent_endpoints have no
			// tenant column of their own -- the ONLY thing enforcing
			// tenant scope on this join is that it's reachable solely
			// through a tenant-authorized target fetch. Do not expose an
			// endpoints view that bypasses this check.
			if !targetVisibleToTenant(pd, target) {
				emitAuditEvent(r, auditProvider, pd.ID, "target.endpoints", "target", id, AuditOutcomeDenied)
				writeForbidden(w, "forbidden")
				return
			}
			matches, err := store.MatchEndpoints(r.Context(), target.Host)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.endpoints", "target", id, AuditOutcomeFailure)
				writeServiceUnavailable(w, "endpoint match failed")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "target.endpoints", "target", id, AuditOutcomeSuccess)
			writeJSONData(w, matches)
			return
		}

		id := tail
		switch r.Method {
		case http.MethodGet:
			target, err := store.Get(r.Context(), id)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.get", "target", id, AuditOutcomeFailure)
				writeNotFound(w, "target not found")
				return
			}
			if !targetVisibleToTenant(pd, target) {
				emitAuditEvent(r, auditProvider, pd.ID, "target.get", "target", id, AuditOutcomeDenied)
				writeForbidden(w, "forbidden")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "target.get", "target", id, AuditOutcomeSuccess)
			writeJSONData(w, target)

		case http.MethodPatch:
			existing, err := store.Get(r.Context(), id)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.update", "target", id, AuditOutcomeFailure)
				writeNotFound(w, "target not found")
				return
			}
			if !targetVisibleToTenant(pd, existing) {
				emitAuditEvent(r, auditProvider, pd.ID, "target.update", "target", id, AuditOutcomeDenied)
				writeForbidden(w, "forbidden")
				return
			}
			var req struct {
				Name                 *string            `json:"name"`
				Host                 *string            `json:"host"`
				DiscoveryMode        *string            `json:"discovery_mode"`
				InstallMode          *string            `json:"install_mode"`
				RenewalMethod        *string            `json:"renewal_method"`
				RenewalThresholdDays *int               `json:"renewal_threshold_days"`
				CredentialRef        *string            `json:"credential_ref"`
				Schedule             *string            `json:"schedule"`
				InstallServerType    *string            `json:"install_server_type"`
				InstallCertPath      *string            `json:"install_cert_path"`
				InstallKeyPath       *string            `json:"install_key_path"`
				InstallReloadMethod  *string            `json:"install_reload_method"`
				VerifyHostPort       *string            `json:"verify_host_port"`
				AutoRenew            *bool              `json:"auto_renew"`
				PluginID             *string            `json:"plugin_id"`
				PluginSettings       *map[string]string `json:"plugin_settings"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&req); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.update", "target", id, AuditOutcomeFailure)
				writeBadRequest(w, "invalid request body")
				return
			}
			update := ManagedTargetUpdate{
				Name: req.Name, Host: req.Host, DiscoveryMode: req.DiscoveryMode,
				InstallMode: req.InstallMode, RenewalMethod: req.RenewalMethod,
				RenewalThresholdDays: req.RenewalThresholdDays,
				CredentialRef:        req.CredentialRef, Schedule: req.Schedule,
				InstallServerType: req.InstallServerType, InstallCertPath: req.InstallCertPath,
				InstallKeyPath: req.InstallKeyPath, InstallReloadMethod: req.InstallReloadMethod,
				VerifyHostPort: req.VerifyHostPort,
				AutoRenew:      req.AutoRenew,
				PluginID:       req.PluginID, PluginSettings: req.PluginSettings,
			}
			merged := existing
			mergeManagedTargetUpdate(&merged, update)
			reaffirm := req.AutoRenew != nil && *req.AutoRenew
			fields, stamp, allowed, need := authorizeTargetEgress(pd, auth.roleStore, existing, merged, reaffirm)
			if !allowed {
				refuseTargetEgress(w, r, auditProvider, pd, "target.update", id, fields, need)
				return
			}
			var armedBy string
			if stamp {
				var ok bool
				if armedBy, ok = armStamp(w, r, auditProvider, pd, "target.update", id); !ok {
					return
				}
			}
			if err := egressDeps.validateTargetReferences(r.Context(), pd, existing, merged); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.update", "target", id, AuditOutcomeFailure)
				writeTargetReferenceError(w, err)
				return
			}
			if stamp {
				update.AutoRenewSetBy = &armedBy
			}
			updated, err := store.Update(r.Context(), id, update)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.update", "target", id, AuditOutcomeFailure)
				if errors.Is(err, errManagedTargetInvalidMode) {
					writeBadRequest(w, "invalid discovery_mode, install_mode, or renewal_method")
					return
				}
				if errors.Is(err, errManagedTargetInvalidThreshold) || errors.Is(err, errManagedTargetPluginID) || errors.Is(err, errManagedTargetVerifyHostPort) {
					writeBadRequest(w, err.Error())
					return
				}
				if errors.Is(err, errManagedTargetNotFound) {
					writeNotFound(w, "target not found")
					return
				}
				writeBadRequest(w, err.Error())
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "target.update", "target", id, AuditOutcomeSuccess)
			writeJSONData(w, updated)

		case http.MethodDelete:
			existing, err := store.Get(r.Context(), id)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.delete", "target", id, AuditOutcomeFailure)
				writeNotFound(w, "target not found")
				return
			}
			if !targetVisibleToTenant(pd, existing) {
				emitAuditEvent(r, auditProvider, pd.ID, "target.delete", "target", id, AuditOutcomeDenied)
				writeForbidden(w, "forbidden")
				return
			}
			if err := store.Delete(r.Context(), id); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.delete", "target", id, AuditOutcomeFailure)
				writeServiceUnavailable(w, "delete failed")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "target.delete", "target", id, AuditOutcomeSuccess)
			w.WriteHeader(http.StatusNoContent)

		default:
			writeMethodNotAllowed(w, "GET, PATCH, DELETE")
		}
	})
}

func writeTargetReferenceError(w http.ResponseWriter, err error) {
	if errors.Is(err, errTargetStoreUnavailable) {
		writeServiceUnavailable(w, "outbound credential or delivery plugin store not configured")
		return
	}
	writeBadRequest(w, err.Error())
}
