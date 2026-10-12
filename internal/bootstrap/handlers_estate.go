// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

// W11-03: the takeover API — an unmanaged/external certificate becomes
// managed with a chosen renewal path, in one audited call. Lives under
// /api/v1/estate/ rather than /api/v1/certificates/{fp}/ because that
// suffix router is owned by parked review branches (same reasoning as
// W5-13's route). Takeover mutates ownership + estate bookkeeping only —
// no key or cert material moves — so it is audit-logged, not
// approval-gated; the NFR-P2 approval gate applies at the issuance the
// takeover leads to (spec decision 6).

type takeoverRenewalPath struct {
	Mode        string `json:"mode"` // internal | connector
	ConnectorID string `json:"connector_id,omitempty"`
}

type takeoverRequest struct {
	Fingerprint string              `json:"fingerprint"`
	OwnerEmail  string              `json:"owner_email,omitempty"`
	OwnerTeam   string              `json:"owner_team,omitempty"`
	ServiceName string              `json:"service_name,omitempty"`
	RenewalPath takeoverRenewalPath `json:"renewal_path"`
}

// RegisterEstateHandlers mounts POST /api/v1/estate/takeover.
func RegisterEstateHandlers(mux *http.ServeMux, auth *Authenticator, provider CertificateProvider, connectorStore ConnectorStore, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/estate/takeover", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "estate.takeover", "certificate", "takeover", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}

		body := http.MaxBytesReader(w, r.Body, 64*1024)
		defer body.Close()
		raw, err := io.ReadAll(body)
		if err != nil {
			if rejectOversizeBody(w, err) {
				return
			}
			writeBadRequestJSON(w, "invalid request body")
			return
		}
		var req takeoverRequest
		if err := json.Unmarshal(raw, &req); err != nil || req.Fingerprint == "" {
			emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover", "certificate", req.Fingerprint, AuditOutcomeFailure)
			writeBadRequestJSON(w, "fingerprint and renewal_path.mode are required")
			return
		}

		if _, err := authorizeCertificateResourceAccess(r.Context(), provider, pd, req.Fingerprint); err != nil {
			switch {
			case errors.Is(err, errCertificateNotFound):
				emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover", "certificate", req.Fingerprint, AuditOutcomeFailure)
				writeNotFound(w, "certificate not found")
			case errors.Is(err, errCertificateForbidden):
				emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover", "certificate", req.Fingerprint, AuditOutcomeDenied)
				writeForbidden(w, "forbidden")
			default:
				emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover", "certificate", req.Fingerprint, AuditOutcomeFailure)
				writeServiceUnavailable(w, "certificate unavailable")
			}
			return
		}

		// Resolve the renewal path BEFORE mutating anything: a takeover onto
		// a connector that does not exist must fail whole.
		update := EstateUpdate{ManagementState: "managed"}
		switch req.RenewalPath.Mode {
		case "internal":
			update.RenewalMethod = "api"
		case "connector":
			if req.RenewalPath.ConnectorID == "" {
				emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover", "certificate", req.Fingerprint, AuditOutcomeFailure)
				writeBadRequestJSON(w, "renewal_path.connector_id is required for mode connector")
				return
			}
			if connectorStore == nil {
				emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover", "certificate", req.Fingerprint, AuditOutcomeFailure)
				writeServiceUnavailable(w, "connector store not configured")
				return
			}
			rec, err := connectorStore.Get(r.Context(), req.RenewalPath.ConnectorID)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover", "certificate", req.Fingerprint, AuditOutcomeFailure)
				if errors.Is(err, errConnectorNotFound) {
					writeBadRequestJSON(w, "renewal_path.connector_id does not name a configured connector")
				} else {
					writeServiceUnavailable(w, "connector lookup failed")
				}
				return
			}
			// The upstream renewal method mirrors the connector type
			// (acme connectors renew via acme, etc.); internal-type
			// connectors are just the internal path with extra steps.
			if rec.Type == "internal" {
				update.RenewalMethod = "api"
			} else {
				update.RenewalMethod = rec.Type
			}
			update.RenewalConnectorID = rec.ID
		default:
			emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover", "certificate", req.Fingerprint, AuditOutcomeFailure)
			writeBadRequestJSON(w, "renewal_path.mode must be internal or connector")
			return
		}

		if req.OwnerEmail != "" || req.OwnerTeam != "" || req.ServiceName != "" {
			if _, err := provider.UpdateOwnership(r.Context(), req.Fingerprint, CertificateOwnershipRequest{
				OwnerEmail: req.OwnerEmail, OwnerTeam: req.OwnerTeam, ServiceName: req.ServiceName,
			}); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover", "certificate", req.Fingerprint, AuditOutcomeFailure)
				writeServiceUnavailable(w, "ownership update failed")
				return
			}
		}

		item, err := provider.UpdateEstate(r.Context(), req.Fingerprint, update)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover", "certificate", req.Fingerprint, AuditOutcomeFailure)
			if errors.Is(err, errCertificateInvalid) {
				writeBadRequestJSON(w, err.Error())
				return
			}
			writeServiceUnavailable(w, "estate update failed")
			return
		}

		emitAuditEvent(r, auditProvider, pd.ID, "estate.takeover", "certificate", req.Fingerprint, AuditOutcomeSuccess)
		writeJSONStatus(w, http.StatusOK, struct {
			Data CertificateItem `json:"data"`
		}{Data: item})
	})
}
