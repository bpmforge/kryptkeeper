// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"kryptkeeper/internal/logging"
	"net/http"
	"os"
	"strings"
	"time"

	"kryptkeeper/internal/wstep"
)

// SCEPEnabledFromEnv reports whether SCEP enrollment is switched on
// (KRYPTKEEPER_SCEP_ENABLED=true, W20-16). It also needs a database for
// its one-time challenges and an RSA CA; main logs when either is missing.
func SCEPEnabledFromEnv() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("KRYPTKEEPER_SCEP_ENABLED")), "true")
}

// microsoftIntegrationStatus is the response body for GET /api/v1/integrations/microsoft.
type microsoftIntegrationStatus struct {
	SCEPEnabled bool `json:"scep_enabled"`
	// SCEPOffReason says why SCEP is not serving when it was asked for or
	// cannot run (non-RSA CA, missing database, ...).
	SCEPOffReason  string `json:"scep_off_reason,omitempty"`
	SCEPEndpoint   string `json:"scep_endpoint,omitempty"`
	XCEPEnabled    bool   `json:"xcep_enabled"`
	XCEPEndpoint   string `json:"xcep_endpoint,omitempty"`
	WSTEPEnabled   bool   `json:"wstep_enabled"`
	WSTEPEndpoint  string `json:"wstep_endpoint,omitempty"`
	IntuneProtocol string `json:"intune_protocol"` // "SCEP" or "WSTEP+XCEP"
}

// siem is the same router instance the audit provider forwards through, so
// Status/Test report on exactly what live events use.
func registerIntegrationsHandlers(mux *http.ServeMux, auth *Authenticator, auditProvider AuditProvider, siem *SIEMRouter, scepOffReason string) {
	mux.HandleFunc("/api/v1/integrations/microsoft", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		principal, err := auth.AuthenticatePrincipal(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "integration.microsoft.get", "integration", "microsoft", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		baseURL := strings.TrimRight(os.Getenv("KRYPTKEEPER_BASE_URL"), "/")

		scepEnabled := SCEPEnabledFromEnv() && scepOffReason == ""
		wstepEnabled := wstep.EnabledFromEnv()
		status := microsoftIntegrationStatus{
			SCEPEnabled:   scepEnabled,
			SCEPOffReason: scepOffReason,
			XCEPEnabled:   wstepEnabled,
			WSTEPEnabled:  wstepEnabled,
			// SCEP is preferred for Intune BYOCA; XCEP+WSTEP handles Windows autoenrollment.
			IntuneProtocol: "SCEP",
		}
		if baseURL != "" {
			status.SCEPEndpoint = baseURL + "/scep"
			if wstepEnabled {
				status.XCEPEndpoint = baseURL + "/xcep"
				status.WSTEPEndpoint = baseURL + "/wstep"
			}
		}

		emitAuditEvent(r, auditProvider, principal, "integration.microsoft.get", "integration", "microsoft", AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(struct {
			Data microsoftIntegrationStatus `json:"data"`
		}{Data: status}); err != nil {
			logging.Warnf("failed to encode microsoft integration response: %v", err)
		}
	})

	// SIEM integration status (env-driven) and a synchronous test emission.
	mux.HandleFunc("/api/v1/integrations/siem", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		principal, err := auth.AuthenticatePrincipal(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "integration.siem.get", "integration", "siem", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		status := siem.Status()
		emitAuditEvent(r, auditProvider, principal, "integration.siem.get", "integration", "siem", AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(struct {
			Data SIEMStatus `json:"data"`
		}{Data: status}); err != nil {
			logging.Warnf("failed to encode siem integration response: %v", err)
		}
	})

	mux.HandleFunc("/api/v1/integrations/siem/test", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		principal, err := auth.AuthenticatePrincipal(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "integration.siem.test", "integration", "siem", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		router := siem
		if !router.Enabled() {
			emitAuditEvent(r, auditProvider, principal, "integration.siem.test", "integration", "siem", AuditOutcomeFailure)
			writeBadRequest(w, "no SIEM target configured")
			return
		}
		result := router.Test(principal)
		outcome := AuditOutcomeSuccess
		if (result.WebhookTested && !result.WebhookOK) || (result.SyslogTested && !result.SyslogOK) {
			outcome = AuditOutcomeFailure
		}
		emitAuditEvent(r, auditProvider, principal, "integration.siem.test", "integration", "siem", outcome)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(struct {
			Data SIEMTestResult `json:"data"`
		}{Data: result}); err != nil {
			logging.Warnf("failed to encode siem test response: %v", err)
		}
	})
}
