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

func registerProtocolHandlers(mux *http.ServeMux, auth *Authenticator, protocolProvider ProtocolProvider, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/protocols/status", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "protocol.status", "protocol", "status", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		if !canReadOperationalSummaries(principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "protocol.status", "protocol", "status", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}

		status, err := protocolProvider.GetStatus(r.Context())
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "protocol.status", "protocol", "status", AuditOutcomeFailure)
			log.Printf("protocol status unavailable: %v", err)
			writeServiceUnavailable(w, "protocol status unavailable")
			return
		}

		emitAuditEvent(r, auditProvider, principal.ID, "protocol.status", "protocol", "status", AuditOutcomeSuccess)
		resp := struct {
			Data struct {
				Resource  string         `json:"resource"`
				Principal string         `json:"principal"`
				Protocols ProtocolStatus `json:"protocols"`
			} `json:"data"`
		}{}
		resp.Data.Resource = "protocol-status"
		resp.Data.Principal = principal.ID
		resp.Data.Protocols = status

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("failed to encode /api/v1/protocols/status response: %v", err)
		}
	})

	mux.HandleFunc("/api/v1/protocols/readiness", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "protocol.readiness", "protocol", "readiness", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		if !canReadOperationalSummaries(principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "protocol.readiness", "protocol", "readiness", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}

		readiness, err := protocolProvider.GetReadiness(r.Context())
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "protocol.readiness", "protocol", "readiness", AuditOutcomeFailure)
			log.Printf("protocol readiness unavailable: %v", err)
			writeServiceUnavailable(w, "protocol readiness unavailable")
			return
		}

		emitAuditEvent(r, auditProvider, principal.ID, "protocol.readiness", "protocol", "readiness", AuditOutcomeSuccess)
		resp := struct {
			Data struct {
				Resource  string            `json:"resource"`
				Principal string            `json:"principal"`
				Protocols ProtocolReadiness `json:"protocols"`
			} `json:"data"`
		}{}
		resp.Data.Resource = "protocol-readiness"
		resp.Data.Principal = principal.ID
		resp.Data.Protocols = readiness

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("failed to encode /api/v1/protocols/readiness response: %v", err)
		}
	})

	mux.HandleFunc("/api/v1/protocols/conformance", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "protocol.conformance", "protocol", "conformance", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		if !canReadOperationalSummaries(principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "protocol.conformance", "protocol", "conformance", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}

		conformance, err := protocolProvider.GetConformance(r.Context())
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "protocol.conformance", "protocol", "conformance", AuditOutcomeFailure)
			log.Printf("protocol conformance unavailable: %v", err)
			writeServiceUnavailable(w, "protocol conformance unavailable")
			return
		}

		emitAuditEvent(r, auditProvider, principal.ID, "protocol.conformance", "protocol", "conformance", AuditOutcomeSuccess)
		resp := struct {
			Data struct {
				Resource  string              `json:"resource"`
				Principal string              `json:"principal"`
				Suites    ProtocolConformance `json:"suites"`
			} `json:"data"`
		}{}
		resp.Data.Resource = "protocol-conformance"
		resp.Data.Principal = principal.ID
		resp.Data.Suites = conformance

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("failed to encode /api/v1/protocols/conformance response: %v", err)
		}
	})

	mux.HandleFunc("/api/v1/protocols/conformance/recheck", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}

		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "protocol.conformance.recheck", "protocol", "conformance-recheck", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if !canManageProtocols(principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "protocol.conformance.recheck", "protocol", "conformance-recheck", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}

		var req struct {
			Suite  string `json:"suite"`
			Reason string `json:"reason"`
		}
		reader := http.MaxBytesReader(w, r.Body, 8*1024)
		defer reader.Close()
		if err := json.NewDecoder(reader).Decode(&req); err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "protocol.conformance.recheck", "protocol", "conformance-recheck", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}

		req.Suite = strings.ToLower(strings.TrimSpace(req.Suite))
		req.Reason = strings.TrimSpace(req.Reason)
		switch req.Suite {
		case "acme", "est", "scep", "ocsp", "crl":
		default:
			emitAuditEvent(r, auditProvider, principal.ID, "protocol.conformance.recheck", "protocol", "conformance-recheck", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}
		if tooLong(req.Reason) {
			emitAuditEvent(r, auditProvider, principal.ID, "protocol.conformance.recheck", "protocol", "conformance-recheck", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}

		result, err := protocolProvider.TriggerConformanceRecheck(r.Context(), req.Suite, req.Reason)
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "protocol.conformance.recheck", "protocol", "conformance-recheck", AuditOutcomeFailure)
			log.Printf("protocol conformance recheck failed: %v", err)
			writeServiceUnavailable(w, "protocol conformance recheck unavailable")
			return
		}

		emitAuditEvent(r, auditProvider, principal.ID, "protocol.conformance.recheck", "protocol", req.Suite, AuditOutcomeSuccess)
		resp := struct {
			Data struct {
				Resource  string `json:"resource"`
				Principal string `json:"principal"`
				Suite     string `json:"suite"`
				JobID     string `json:"job_id"`
				Status    string `json:"status"`
				Reason    string `json:"reason"`
				QueuedAt  string `json:"queued_at"`
			} `json:"data"`
		}{}
		resp.Data.Resource = "protocol-conformance-recheck"
		resp.Data.Principal = principal.ID
		resp.Data.Suite = result.Suite
		resp.Data.JobID = result.JobID
		resp.Data.Status = result.Status
		resp.Data.Reason = result.Reason
		resp.Data.QueuedAt = result.QueuedAt

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("failed to encode /api/v1/protocols/conformance/recheck response: %v", err)
		}
	})
}
