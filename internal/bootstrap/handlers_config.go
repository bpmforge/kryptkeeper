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

// registerConfigHandlers mounts the /api/v1/config runtime-settings surface
// (W8-03, D-068, FR-P30). store may be nil (DB unavailable) -- every handler
// reports 503 in that case rather than silently no-op'ing, matching
// RegisterTargetHandlers' convention.
func registerConfigHandlers(mux *http.ServeMux, auth *Authenticator, store ConfigStore, auditProvider AuditProvider) {
	authenticate := func(w http.ResponseWriter, r *http.Request) (AuthPrincipal, bool) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return AuthPrincipal{}, false
		}
		return pd, true
	}

	mux.HandleFunc("/api/v1/config", func(w http.ResponseWriter, r *http.Request) {
		pd, ok := authenticate(w, r)
		if !ok {
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		// Reading effective settings (SSO issuer, SMTP host, discovery
		// provider) is an operational summary like dashboard/notification
		// reads -- gated the same way (handlers_dashboard.go,
		// handlers_notifications.go), not open to every authenticated
		// principal.
		if !canReadOperationalSummaries(pd) {
			emitAuditEvent(r, auditProvider, pd.ID, "config.list", "config", "config", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}
		// Effective settings expose instance-wide SSO/SMTP values and who set them.
		if denyNonSuperAdminGlobal(w, r, auditProvider, pd, "config.list", "config", "config") {
			return
		}
		if store == nil {
			emitAuditEvent(r, auditProvider, pd.ID, "config.list", "config", "config", AuditOutcomeFailure)
			writeServiceUnavailable(w, "config store unavailable")
			return
		}

		settings, err := EffectiveSettings(r.Context(), store)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "config.list", "config", "config", AuditOutcomeFailure)
			writeServiceUnavailable(w, "config lookup failed")
			return
		}
		emitAuditEvent(r, auditProvider, pd.ID, "config.list", "config", "config", AuditOutcomeSuccess)
		writeJSONData(w, settings)
	})

	mux.HandleFunc("/api/v1/config/", func(w http.ResponseWriter, r *http.Request) {
		pd, ok := authenticate(w, r)
		if !ok {
			return
		}

		key := strings.TrimPrefix(r.URL.Path, "/api/v1/config/")
		if key == "" || strings.Contains(key, "/") {
			writeNotFound(w, "config key not found")
			return
		}
		if _, known := lookupConfigKey(key); !known {
			writeNotFound(w, "config key not found")
			return
		}

		switch r.Method {
		case http.MethodPut:
			// Writing a runtime setting is an operational, instance-wide
			// change (SMTP credentials, SSO issuer, discovery provider) --
			// gated on admin role, matching handlers_cas.go's rotate-key
			// convention for consequential mutations.
			if !isAdminRole(pd.Role) {
				emitAuditEvent(r, auditProvider, pd.ID, "config.set", "config", key, AuditOutcomeDenied)
				writeForbidden(w, "admin role required")
				return
			}
			if denyNonSuperAdminGlobal(w, r, auditProvider, pd, "config.set", "config", key) {
				return
			}
			if store == nil {
				emitAuditEvent(r, auditProvider, pd.ID, "config.set", "config", key, AuditOutcomeFailure)
				writeServiceUnavailable(w, "config store unavailable")
				return
			}

			var req struct {
				Value string `json:"value"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, configValueMaxLen+1024)).Decode(&req); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "config.set", "config", key, AuditOutcomeFailure)
				writeBadRequest(w, "invalid request body")
				return
			}
			// W33-06: refuse (before anything is persisted) an SSO override
			// that could lock every login out.
			if err := auth.ssoOverrideGuard(r.Context(), key, req.Value); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "config.set", "config", key, AuditOutcomeFailure)
				writeConflict(w, err.Error())
				return
			}
			if err := store.Set(r.Context(), key, req.Value, pd.ID); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "config.set", "config", key, AuditOutcomeFailure)
				if errors.Is(err, errConfigUnknownKey) {
					writeNotFound(w, "config key not found")
					return
				}
				writeBadRequest(w, err.Error())
				return
			}
			// Never echo the value back -- a secret key's plaintext must
			// not appear in any API response, including the response to
			// the very request that set it (acceptance #2).
			emitAuditEvent(r, auditProvider, pd.ID, "config.set", "config", key, AuditOutcomeSuccess)
			if extra, ok := configKeyAuditAction(key); ok {
				detail := "updated"
				if def, _ := lookupConfigKey(key); !def.Secret {
					detail = "value=" + req.Value
				}
				emitAuditEventDetail(r, auditProvider, pd.ID, extra, "config", key, AuditOutcomeSuccess, detail)
			}
			w.WriteHeader(http.StatusNoContent)

		case http.MethodDelete:
			if !isAdminRole(pd.Role) {
				emitAuditEvent(r, auditProvider, pd.ID, "config.reset", "config", key, AuditOutcomeDenied)
				writeForbidden(w, "admin role required")
				return
			}
			if denyNonSuperAdminGlobal(w, r, auditProvider, pd, "config.reset", "config", key) {
				return
			}
			if store == nil {
				emitAuditEvent(r, auditProvider, pd.ID, "config.reset", "config", key, AuditOutcomeFailure)
				writeServiceUnavailable(w, "config store unavailable")
				return
			}
			if err := store.Delete(r.Context(), key); err != nil {
				if errors.Is(err, errConfigOverrideNotFound) {
					emitAuditEvent(r, auditProvider, pd.ID, "config.reset", "config", key, AuditOutcomeFailure)
					writeNotFound(w, "no override set for this key")
					return
				}
				emitAuditEvent(r, auditProvider, pd.ID, "config.reset", "config", key, AuditOutcomeFailure)
				writeServiceUnavailable(w, "reset failed")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "config.reset", "config", key, AuditOutcomeSuccess)
			if extra, ok := configKeyAuditAction(key); ok {
				emitAuditEventDetail(r, auditProvider, pd.ID, extra, "config", key, AuditOutcomeSuccess, "reset to default")
			}
			w.WriteHeader(http.StatusNoContent)

		default:
			writeMethodNotAllowed(w, "PUT, DELETE")
		}
	})
}
