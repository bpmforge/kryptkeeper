// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// W9-06: the M-of-N root-CA ceremony API. The approver identity is ALWAYS
// the authenticated principal — never a body field — so one person cannot
// replay N approvals through the API.
func RegisterCeremonyHandlers(mux *http.ServeMux, auth *Authenticator, mgr *ca.CeremonyManager, auditProvider AuditProvider) {
	if mgr == nil {
		return
	}

	authorize := func(w http.ResponseWriter, r *http.Request, action string) (string, bool) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", action, "ceremony", "-", AuditOutcomeDenied)
			writeUnauthorized(w)
			return "", false
		}
		if !isAdminRole(pd.Role) {
			emitAuditEvent(r, auditProvider, pd.ID, action, "ceremony", "-", AuditOutcomeDenied)
			writeForbidden(w, "admin role required for key ceremonies")
			return "", false
		}
		return pd.ID, true
	}

	writeCeremony := func(w http.ResponseWriter, status int, c ca.Ceremony) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(struct {
			Data ca.Ceremony `json:"data"`
		}{Data: c})
	}

	// POST /api/v1/ceremonies — start; GET — list.
	mux.HandleFunc("/api/v1/ceremonies", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			principal, ok := authorize(w, r, "ceremony.start")
			if !ok {
				return
			}
			var req struct {
				Name         string   `json:"name"`
				CommonName   string   `json:"common_name"`
				Algorithm    string   `json:"algorithm"`
				ValidityDays int      `json:"validity_days"`
				Approvers    []string `json:"approvers"`
				Quorum       int      `json:"quorum"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&req); err != nil {
				emitAuditEvent(r, auditProvider, principal, "ceremony.start", "ceremony", "-", AuditOutcomeFailure)
				writeBadRequest(w, "invalid request body")
				return
			}
			c, err := mgr.StartRootCACeremony(ca.RootCACeremonyParams{
				Name:         req.Name,
				CommonName:   req.CommonName,
				Algorithm:    keystore.Algorithm(strings.TrimSpace(req.Algorithm)),
				ValidityDays: req.ValidityDays,
				Initiator:    principal,
				Approvers:    req.Approvers,
				Quorum:       req.Quorum,
			})
			if err != nil {
				emitAuditEvent(r, auditProvider, principal, "ceremony.start", "ceremony", "-", AuditOutcomeFailure)
				writeBadRequest(w, err.Error())
				return
			}
			emitAuditEventDetail(r, auditProvider, principal, "ceremony.start", "ceremony", c.ID, AuditOutcomeSuccess,
				fmt.Sprintf(`{"id":%q,"ca_id":%q,"quorum":%d,"approvers":%d}`, c.ID, c.CAID, c.Quorum, len(c.Approvers)))
			writeCeremony(w, http.StatusCreated, c)

		case http.MethodGet:
			principal, ok := authorize(w, r, "ceremony.list")
			if !ok {
				return
			}
			list, err := mgr.List()
			if err != nil {
				emitAuditEvent(r, auditProvider, principal, "ceremony.list", "ceremony", "-", AuditOutcomeFailure)
				writeServiceUnavailable(w, "ceremonies unavailable")
				return
			}
			emitAuditEvent(r, auditProvider, principal, "ceremony.list", "ceremony", "-", AuditOutcomeSuccess)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(struct {
				Data []ca.Ceremony `json:"data"`
			}{Data: list})

		default:
			writeMethodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
		}
	})

	// GET /api/v1/ceremonies/{id}; POST /{id}/approve; POST /{id}/abort.
	mux.HandleFunc("/api/v1/ceremonies/", func(w http.ResponseWriter, r *http.Request) {
		tail := strings.TrimPrefix(r.URL.Path, "/api/v1/ceremonies/")

		if strings.HasSuffix(tail, "/approve") {
			id := strings.TrimSuffix(tail, "/approve")
			principal, ok := authorize(w, r, "ceremony.approve")
			if !ok {
				return
			}
			if r.Method != http.MethodPost {
				writeMethodNotAllowed(w, http.MethodPost)
				return
			}
			// The approver is the AUTHENTICATED principal, deliberately not
			// read from the body.
			c, err := mgr.Approve(id, principal)
			if err != nil {
				emitAuditEvent(r, auditProvider, principal, "ceremony.approve", "ceremony", id, AuditOutcomeFailure)
				writeBadRequest(w, err.Error())
				return
			}
			emitAuditEventDetail(r, auditProvider, principal, "ceremony.approve", "ceremony", id, AuditOutcomeSuccess,
				fmt.Sprintf(`{"id":%q,"approvals":%d,"quorum":%d,"status":%q}`, c.ID, len(c.Approvals), c.Quorum, c.Status))
			writeCeremony(w, http.StatusOK, c)
			return
		}

		if strings.HasSuffix(tail, "/abort") {
			id := strings.TrimSuffix(tail, "/abort")
			principal, ok := authorize(w, r, "ceremony.abort")
			if !ok {
				return
			}
			if r.Method != http.MethodPost {
				writeMethodNotAllowed(w, http.MethodPost)
				return
			}
			c, err := mgr.Abort(id)
			if err != nil {
				emitAuditEvent(r, auditProvider, principal, "ceremony.abort", "ceremony", id, AuditOutcomeFailure)
				writeBadRequest(w, err.Error())
				return
			}
			emitAuditEventDetail(r, auditProvider, principal, "ceremony.abort", "ceremony", id, AuditOutcomeSuccess,
				fmt.Sprintf(`{"id":%q,"ca_id":%q}`, c.ID, c.CAID))
			writeCeremony(w, http.StatusOK, c)
			return
		}

		principal, ok := authorize(w, r, "ceremony.get")
		if !ok {
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		id := tail
		if id == "" || strings.Contains(id, "/") {
			writeNotFound(w, "ceremony not found")
			return
		}
		c, found, err := mgr.Get(id)
		if err != nil {
			emitAuditEvent(r, auditProvider, principal, "ceremony.get", "ceremony", id, AuditOutcomeFailure)
			writeServiceUnavailable(w, "ceremony unavailable")
			return
		}
		if !found {
			writeNotFound(w, "ceremony not found")
			return
		}
		emitAuditEvent(r, auditProvider, principal, "ceremony.get", "ceremony", id, AuditOutcomeSuccess)
		writeCeremony(w, http.StatusOK, c)
	})
}
