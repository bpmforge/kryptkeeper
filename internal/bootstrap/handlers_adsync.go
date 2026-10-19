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

	"kryptkeeper/internal/adsync"
)

// W17-10: make AD directory sync reachable now that adsync has a real
// LDAP client.
//
// Template sync WRITES into Active Directory's Configuration naming
// context, which every domain member reads — a genuinely high blast
// radius. So it is gated on the approver capability rather than plain
// admin, and every run is audited with its counts. The GPO check beside
// it is read-only and purely advisory.

type adsyncRequest struct {
	LDAPURL        string                `json:"ldap_url"`
	BindDN         string                `json:"bind_dn"`
	CredentialRef  string                `json:"credential_ref"`
	ConfigDN       string                `json:"config_dn"`
	ServiceName    string                `json:"service_name"`
	AllowCleartext bool                  `json:"allow_cleartext"`
	Templates      []adsync.TemplateSync `json:"templates"`
}

// newADSyncClient is a package var so tests inject a fake directory —
// unit tests must never need a domain controller.
var newADSyncClient = func(req adsyncRequest, password string) (adsync.LDAPClient, error) {
	return adsync.DialAndBind(req.LDAPURL, req.BindDN, password, req.AllowCleartext)
}

func registerADSyncHandlers(mux *http.ServeMux, auth *Authenticator, creds OutboundCredentialStore, auditProvider AuditProvider) {
	// POST /api/v1/adsync/templates — publish certificate templates into AD.
	mux.HandleFunc("/api/v1/adsync/templates", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "adsync.templates", "directory", "-", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		// Writing to the Configuration NC affects every domain member, so
		// this needs the approver capability, not merely admin.
		if !canApproveActions(pd.Role) {
			emitAuditEvent(r, auditProvider, pd.ID, "adsync.templates", "directory", "-", AuditOutcomeDenied)
			writeForbidden(w, "approver role required to write certificate templates into Active Directory")
			return
		}
		if denyNonSuperAdminGlobal(w, r, auditProvider, pd, "adsync.templates", "directory", "-") {
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}

		var req adsyncRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024)).Decode(&req); err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "adsync.templates", "directory", "-", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}
		if strings.TrimSpace(req.LDAPURL) == "" || strings.TrimSpace(req.ConfigDN) == "" || req.CredentialRef == "" {
			emitAuditEvent(r, auditProvider, pd.ID, "adsync.templates", "directory", "-", AuditOutcomeFailure)
			writeBadRequest(w, "ldap_url, config_dn and credential_ref are required")
			return
		}
		if len(req.Templates) == 0 {
			emitAuditEvent(r, auditProvider, pd.ID, "adsync.templates", "directory", "-", AuditOutcomeFailure)
			writeBadRequest(w, "at least one template is required")
			return
		}
		if creds == nil {
			emitAuditEvent(r, auditProvider, pd.ID, "adsync.templates", "directory", "-", AuditOutcomeFailure)
			writeServiceUnavailable(w, "outbound credential store not configured")
			return
		}
		secret, err := creds.Resolve(r.Context(), req.CredentialRef)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "adsync.templates", "directory", req.ConfigDN, AuditOutcomeFailure)
			writeBadRequest(w, fmt.Sprintf("credential %q: %v", req.CredentialRef, err))
			return
		}

		client, err := newADSyncClient(req, strings.TrimSpace(string(secret)))
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "adsync.templates", "directory", req.ConfigDN, AuditOutcomeFailure)
			writeServiceUnavailable(w, err.Error())
			return
		}
		defer func() { _ = client.Close() }()

		svc := adsync.NewService(client, req.ConfigDN, req.ServiceName)
		result, err := svc.SyncTemplates(r.Context(), req.Templates)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "adsync.templates", "directory", req.ConfigDN, AuditOutcomeFailure)
			writeServiceUnavailable(w, err.Error())
			return
		}
		// Per-template errors are reported, not swallowed: a sync that
		// half-applied must not read as a clean success.
		outcome := AuditOutcomeSuccess
		if len(result.Errors) > 0 {
			outcome = AuditOutcomeFailure
		}
		emitAuditEventDetail(r, auditProvider, pd.ID, "adsync.templates", "directory", req.ConfigDN, outcome,
			fmt.Sprintf(`{"created":%d,"updated":%d,"errors":%d}`, result.Created, result.Updated, len(result.Errors)))
		writeJSONData(w, result)
	})

	// POST /api/v1/adsync/gpo-check — advisory validation of a supplied
	// GPO config. POST because the config rides the body; it writes nothing.
	mux.HandleFunc("/api/v1/adsync/gpo-check", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "adsync.gpo_check", "directory", "-", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		var cfg adsync.GPOConfig
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&cfg); err != nil {
			writeBadRequest(w, "invalid request body")
			return
		}
		results := adsync.ValidateGPOConfig(cfg)
		emitAuditEvent(r, auditProvider, pd.ID, "adsync.gpo_check", "directory", "gpo", AuditOutcomeSuccess)
		writeJSONData(w, map[string]any{
			"checks":      results,
			"all_passing": adsync.GPOAllPassing(results),
		})
	})

}
