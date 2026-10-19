// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"net/http"
	"time"

	"kryptkeeper/internal/logging"
)

func registerProtectedPingHandler(auth *Authenticator, auditProvider AuditProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipal(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "protected.ping.read", "protected_resource", "ping", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		emitAuditEvent(r, auditProvider, principal, "protected.ping.read", "protected_resource", "ping", AuditOutcomeSuccess)

		resp := struct {
			Service   string `json:"service"`
			Resource  string `json:"resource"`
			Status    string `json:"status"`
			Principal string `json:"principal"`
		}{
			Service:   "kryptkeeper",
			Resource:  "protected-ping",
			Status:    "ok",
			Principal: principal,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logging.Warnf("failed to encode /api/v1/protected/ping response: %v", err)
		}
	}
}
