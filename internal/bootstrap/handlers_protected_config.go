// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

func registerProtectedConfigHandler(auth *Authenticator, auditProvider AuditProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipal(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "protected.config.read", "protected_resource", "config", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		emitAuditEvent(r, auditProvider, principal, "protected.config.read", "protected_resource", "config", AuditOutcomeSuccess)

		resp := struct {
			Service  string `json:"service"`
			Resource string `json:"resource"`
			AuthMode string `json:"auth_mode"`
			Config   struct {
				OIDCEnabled      bool `json:"oidc_enabled"`
				DiscoveryEnabled bool `json:"discovery_enabled"`
				JWTModeEnabled   bool `json:"jwt_mode_enabled"`
			} `json:"config"`
		}{
			Service:  "kryptkeeper",
			Resource: "protected-config",
			AuthMode: auth.Mode(),
		}
		resp.Config.OIDCEnabled = auth.Mode() == "oidc"
		resp.Config.DiscoveryEnabled = auth.DiscoveryEnabled()
		resp.Config.JWTModeEnabled = auth.Mode() == "jwt"

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("failed to encode /api/v1/protected/config response: %v", err)
		}
	}
}
