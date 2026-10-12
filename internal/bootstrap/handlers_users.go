// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
)

// targetUserRefusal applies checkTargetRole to the user's current role. An
// unknown user passes; the handler answers 404 itself.
func targetUserRefusal(r *http.Request, userProvider UserProvider, roles *CustomRoleStore, caller AuthPrincipal, id string) *grantRefusal {
	users, err := userProvider.ListUsers(r.Context())
	if err != nil {
		return nil
	}
	for _, u := range users {
		if u.ID == id {
			return checkTargetRole(caller, roles, u.Role)
		}
	}
	return nil
}

func registerUserHandlers(mux *http.ServeMux, auth *Authenticator, userProvider UserProvider, roles *CustomRoleStore, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "users.list", "user", "users", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		// The directory lists every account's email and role, so it is held
		// to the same bar as the mutations beside it (user.manage); the
		// Users page is admin-only in the UI.
		if !roleMayManageRoles(roles, principal.Role) {
			emitAuditEvent(r, auditProvider, principal.ID, "users.list", "user", "users", AuditOutcomeDenied)
			writeForbidden(w, "your role is not authorized to list users")
			return
		}
		users, err := userProvider.ListUsers(r.Context())
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "users.list", "user", "users", AuditOutcomeFailure)
			writeServiceUnavailable(w, "users unavailable")
			return
		}
		emitAuditEvent(r, auditProvider, principal.ID, "users.list", "user", "users", AuditOutcomeSuccess)
		resp := struct {
			Data struct {
				Resource string       `json:"resource"`
				Items    []UserRecord `json:"items"`
			} `json:"data"`
			Meta struct {
				Total int `json:"total"`
			} `json:"meta"`
		}{}
		resp.Data.Resource = "users"
		resp.Data.Items = users
		resp.Meta.Total = len(users)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("failed to encode /api/v1/users response: %v", err)
		}
	})

	mux.HandleFunc("/api/v1/users/invite", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "users.invite", "user", "users", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		var req struct {
			Email string `json:"email"`
			Role  string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
			writeBadRequest(w, "email is required")
			return
		}
		if req.Role == "" {
			req.Role = "pki-operator"
		}
		if ref := checkRoleGrant(principal, roles, req.Role); ref != nil {
			refuseGrant(w, r, auditProvider, principal, "users.invite", "user", req.Email, ref)
			return
		}
		user, err := userProvider.InviteUser(r.Context(), req.Email, req.Role)
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "users.invite", "user", req.Email, AuditOutcomeFailure)
			writeServiceUnavailable(w, "user invitation unavailable")
			return
		}
		emitAuditEvent(r, auditProvider, principal.ID, "users.invite", "user", user.ID, AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(struct {
			Data UserRecord `json:"data"`
		}{Data: user}); err != nil {
			log.Printf("failed to encode POST /api/v1/users/invite response: %v", err)
		}
	})

	mux.HandleFunc("/api/v1/users/", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "users.action", "user", "users", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
		if id == "" || id == "invite" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodPatch || r.Method == http.MethodDelete {
			if ref := targetUserRefusal(r, userProvider, roles, principal, id); ref != nil {
				refuseGrant(w, r, auditProvider, principal, "users.update", "user", id, ref)
				return
			}
		}
		switch r.Method {
		case http.MethodPatch:
			var req struct {
				Role   string `json:"role"`
				Status string `json:"status"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeBadRequest(w, "invalid request body")
				return
			}
			if strings.TrimSpace(req.Role) != "" {
				if ref := checkRoleGrant(principal, roles, req.Role); ref != nil {
					refuseGrant(w, r, auditProvider, principal, "users.update", "user", id, ref)
					return
				}
			}
			user, err := userProvider.UpdateUser(r.Context(), id, req.Role, req.Status)
			if err != nil {
				emitAuditEvent(r, auditProvider, principal.ID, "users.update", "user", id, AuditOutcomeFailure)
				writeNotFound(w, "user not found")
				return
			}
			emitAuditEvent(r, auditProvider, principal.ID, "users.update", "user", id, AuditOutcomeSuccess)
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(struct {
				Data UserRecord `json:"data"`
			}{Data: user}); err != nil {
				log.Printf("failed to encode PATCH /api/v1/users/{id} response: %v", err)
			}
		case http.MethodDelete:
			if err := userProvider.DeactivateUser(r.Context(), id); err != nil {
				emitAuditEvent(r, auditProvider, principal.ID, "users.deactivate", "user", id, AuditOutcomeFailure)
				writeNotFound(w, "user not found")
				return
			}
			emitAuditEvent(r, auditProvider, principal.ID, "users.deactivate", "user", id, AuditOutcomeSuccess)
			w.WriteHeader(http.StatusNoContent)
		default:
			writeMethodNotAllowed(w, http.MethodPatch+", "+http.MethodDelete)
		}
	})
}
