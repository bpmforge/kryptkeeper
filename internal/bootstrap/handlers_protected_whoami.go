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

func registerProtectedWhoamiHandler(auth *Authenticator, auditProvider AuditProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		now := time.Now().UTC()
		pd, err := auth.AuthenticatePrincipalDetails(r, now)
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "protected.whoami.read", "protected_resource", "whoami", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		emitAuditEvent(r, auditProvider, pd.ID, "protected.whoami.read", "protected_resource", "whoami", AuditOutcomeSuccess)

		resp := struct {
			Service   string `json:"service"`
			Resource  string `json:"resource"`
			Principal string `json:"principal"`
			AuthMode  string `json:"auth_mode"`
			Timestamp string `json:"timestamp"`
			// Role/CanApproveActions (G-58): a token's own holder can always
			// see its own resolved role -- benign self-introspection, the
			// same trust boundary the rest of this endpoint already has.
			// CanApproveActions is computed via the SAME canApproveActions
			// function every approval endpoint enforces, not re-derived by
			// a caller from Role alone -- avoids the two-places-encode-the-
			// same-policy drift risk this session has flagged before
			// (G-64/G-65 class), and lets cmd/kryptkeeper-mcp refuse to
			// start on a misconfigured approver-capable token without
			// needing to know Kryptkeeper's role taxonomy at all.
			Role              string `json:"role"`
			CanApproveActions bool   `json:"can_approve_actions"`
		}{
			Service:           "kryptkeeper",
			Resource:          "protected-whoami",
			Principal:         pd.ID,
			AuthMode:          auth.Mode(),
			Timestamp:         now.Format(time.RFC3339),
			Role:              pd.Role,
			CanApproveActions: canApproveActions(pd.Role),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("failed to encode /api/v1/protected/whoami response: %v", err)
		}
	}
}
