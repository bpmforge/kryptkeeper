// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

// API for credential sources (W38-07, D-324): where external credentials get
// their secrets from.
//
//	GET    /api/v1/credential-sources           list the caller's tenant's sources
//	POST   /api/v1/credential-sources           create one
//	DELETE /api/v1/credential-sources/{id}      delete one no credential uses
//	POST   /api/v1/credential-sources/{id}/test fetch a reference and report the field names
//
// Admin only, like credentials. Nothing here carries a secret in either
// direction: a source names the local credential that logs in to the manager
// (created through /api/v1/credentials), and the test call returns field
// names, never values.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/connectors"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
)

func newCredentialSourceID() (string, error) {
	id, err := newOutboundCredentialID()
	if err != nil {
		return "", err
	}
	return "csrc-" + strings.TrimPrefix(id, "cred-"), nil
}

func registerCredentialSourceHandlers(mux *http.ServeMux, auth *Authenticator, sources CredentialSourceStore, creds OutboundCredentialStore, auditProvider AuditProvider, plugins *DeliveryPluginManager) {
	authorize := func(w http.ResponseWriter, r *http.Request, action string) (AuthPrincipal, bool) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", action, "credential_source", "-", AuditOutcomeDenied)
			writeUnauthorized(w)
			return AuthPrincipal{}, false
		}
		// A source decides where a credential that reaches devices as root or
		// Administrator comes from: the same bar as creating the credential.
		if !isAdminRole(pd.Role) {
			emitAuditEvent(r, auditProvider, pd.ID, action, "credential_source", "-", AuditOutcomeDenied)
			writeForbidden(w, "admin role required for credential sources")
			return AuthPrincipal{}, false
		}
		return pd, true
	}
	unconfigured := func(w http.ResponseWriter) bool {
		if sources != nil && creds != nil {
			return false
		}
		writeServiceUnavailable(w, "credential sources need the hub database and the outbound credential store (set APP_CREDENTIAL_STORE_PASSPHRASE or KRYPTKEEPER_KEYSTORE_PASSPHRASE)")
		return true
	}

	mux.HandleFunc("/api/v1/credential-sources", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			pd, ok := authorize(w, r, "credential_source.list")
			if !ok || unconfigured(w) {
				return
			}
			all, err := sources.List(r.Context())
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "credential_source.list", "credential_source", "-", AuditOutcomeFailure)
				writeServiceUnavailable(w, "credential source store unavailable")
				return
			}
			visible := make([]CredentialSource, 0, len(all))
			for _, s := range all {
				if stampedTenantVisible(pd, s.Tenant) {
					visible = append(visible, s)
				}
			}
			writeJSONData(w, map[string]any{"items": visible})
		case http.MethodPost:
			createCredentialSource(w, r, authorize, unconfigured, sources, creds, auditProvider, plugins)
		default:
			writeMethodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
		}
	})

	mux.HandleFunc("/api/v1/credential-sources/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/api/v1/credential-sources/")
		if id, isTest := strings.CutSuffix(rest, "/test"); isTest {
			testCredentialSource(w, r, id, authorize, unconfigured, sources, creds, auditProvider)
			return
		}
		if r.Method != http.MethodDelete {
			writeMethodNotAllowed(w, http.MethodDelete)
			return
		}
		pd, ok := authorize(w, r, "credential_source.delete")
		if !ok || unconfigured(w) {
			return
		}
		if rest == "" || strings.Contains(rest, "/") {
			writeBadRequest(w, "credential source id required")
			return
		}
		src, err := sources.Get(r.Context(), rest)
		if err != nil || !stampedTenantVisible(pd, src.Tenant) {
			outcome := AuditOutcomeFailure
			if err == nil {
				outcome = AuditOutcomeDenied
			}
			emitAuditEvent(r, auditProvider, pd.ID, "credential_source.delete", "credential_source", rest, outcome)
			writeNotFound(w, "credential source not found")
			return
		}
		switch err := sources.Delete(r.Context(), rest); {
		case errors.Is(err, errCredentialSourceInUse):
			emitAuditEvent(r, auditProvider, pd.ID, "credential_source.delete", "credential_source", rest, AuditOutcomeFailure)
			writeConflict(w, "credentials still use this source; delete or repoint them first")
		case err != nil:
			emitAuditEvent(r, auditProvider, pd.ID, "credential_source.delete", "credential_source", rest, AuditOutcomeFailure)
			writeServiceUnavailable(w, "delete failed")
		default:
			emitAuditEvent(r, auditProvider, pd.ID, "credential_source.delete", "credential_source", rest, AuditOutcomeSuccess)
			w.WriteHeader(http.StatusNoContent)
		}
	})
}

type credentialSourceAuthorizer func(http.ResponseWriter, *http.Request, string) (AuthPrincipal, bool)

func createCredentialSource(w http.ResponseWriter, r *http.Request, authorize credentialSourceAuthorizer, unconfigured func(http.ResponseWriter) bool,
	sources CredentialSourceStore, creds OutboundCredentialStore, auditProvider AuditProvider, plugins *DeliveryPluginManager) {
	const action = "credential_source.create"
	pd, ok := authorize(w, r, action)
	if !ok || unconfigured(w) {
		return
	}
	var req struct {
		Name          string                 `json:"name"`
		Kind          string                 `json:"kind"`
		CredentialRef string                 `json:"credential_ref"`
		Config        CredentialSourceConfig `json:"config"`
	}
	decodeErr := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req)
	if rejectOversizeBody(w, decodeErr) {
		return
	}
	fail := func(msg string) {
		emitAuditEvent(r, auditProvider, pd.ID, action, "credential_source", strings.TrimSpace(req.Name), AuditOutcomeFailure)
		writeBadRequest(w, msg)
	}
	if decodeErr != nil {
		fail("name, kind, credential_ref and config are required")
		return
	}
	src := CredentialSource{Name: req.Name, Kind: req.Kind, Tenant: pd.Tenant, CredentialRef: strings.TrimSpace(req.CredentialRef), Config: req.Config}
	if err := src.Validate(); err != nil {
		fail(strings.TrimPrefix(err.Error(), errCredentialSourceInvalid.Error()+": "))
		return
	}
	if src.Kind == CredentialSourceVaultKV2 {
		if _, _, err := connectors.TLSMaterial("", "", src.Config.CACertPEM); err != nil {
			fail("config.ca_cert_pem is not a PEM certificate")
			return
		}
	}
	// The login is a local api_token credential of the same tenant: a secret
	// manager's own login is the one secret that has to live in the hub.
	login, err := creds.Get(r.Context(), src.CredentialRef)
	switch {
	case err != nil || normalizeTenant(login.Tenant) != normalizeTenant(pd.Tenant):
		fail(fmt.Sprintf("credential %q does not exist", src.CredentialRef))
		return
	case login.Source == CredentialSourceExternal:
		fail("a source's own login must be a local credential, not an external one")
		return
	case login.CredentialType != CredentialTypeAPIToken:
		fail(fmt.Sprintf("credential %q must be an %s credential holding the login (see docs/ops/CREDENTIAL_SOURCES.md)", src.CredentialRef, CredentialTypeAPIToken))
		return
	}
	if src.Kind == CredentialSourcePlugin {
		if plugins == nil {
			fail("plugins are off, so a plugin source cannot be used")
			return
		}
		if _, v, err := plugins.Enabled(r.Context(), src.Config.PluginID); err != nil {
			fail(fmt.Sprintf("plugin %q is not an enabled plugin", src.Config.PluginID))
			return
		} else if v.Kind != abi.KindCredentials {
			fail(fmt.Sprintf("plugin %q is a %s plugin, not a credentials plugin", src.Config.PluginID, v.Kind))
			return
		}
	}
	id, err := newCredentialSourceID()
	if err != nil {
		writeServiceUnavailable(w, "could not generate a source id")
		return
	}
	src.ID = id
	created, err := sources.Create(r.Context(), src)
	if err != nil {
		fail(strings.TrimPrefix(err.Error(), errCredentialSourceInvalid.Error()+": "))
		return
	}
	emitAuditEventDetail(r, auditProvider, pd.ID, action, "credential_source", created.ID, AuditOutcomeSuccess,
		fmt.Sprintf(`{"name":%q,"kind":%q,"credential_ref":%q}`, created.Name, created.Kind, created.CredentialRef))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(struct {
		Data CredentialSource `json:"data"`
	}{Data: created})
}

// testCredentialSource fetches a reference through a source and reports the
// field names. A failure is a 200 with ok=false and the clear reason: it is the
// answer the operator asked for, not a fault of this endpoint.
func testCredentialSource(w http.ResponseWriter, r *http.Request, id string, authorize credentialSourceAuthorizer, unconfigured func(http.ResponseWriter) bool,
	sources CredentialSourceStore, creds OutboundCredentialStore, auditProvider AuditProvider) {
	const action = "credential_source.test"
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	pd, ok := authorize(w, r, action)
	if !ok || unconfigured(w) {
		return
	}
	var req struct {
		CredentialType string            `json:"credential_type"`
		Reference      map[string]string `json:"reference"`
		Static         map[string]string `json:"static"`
	}
	decodeErr := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&req)
	if rejectOversizeBody(w, decodeErr) {
		return
	}
	src, err := sources.Get(r.Context(), id)
	if err != nil || !stampedTenantVisible(pd, src.Tenant) {
		outcome := AuditOutcomeFailure
		if err == nil {
			outcome = AuditOutcomeDenied
		}
		emitAuditEvent(r, auditProvider, pd.ID, action, "credential_source", id, outcome)
		writeNotFound(w, "credential source not found")
		return
	}
	ref := ExternalReference{Reference: req.Reference, Static: req.Static}
	if decodeErr != nil || ref.validate(src.Kind) != nil || validateCredentialType(req.CredentialType) != nil {
		emitAuditEvent(r, auditProvider, pd.ID, action, "credential_source", id, AuditOutcomeFailure)
		writeBadRequest(w, "credential_type and a valid reference are required")
		return
	}
	tester, ok := creds.(externalCredentialTester)
	if !ok {
		writeServiceUnavailable(w, "this credential store cannot test references")
		return
	}
	fields, err := tester.TestExternal(r.Context(), id, src.Tenant, req.CredentialType, ref)
	if err != nil {
		emitAuditEventDetail(r, auditProvider, pd.ID, action, "credential_source", id, AuditOutcomeFailure, fmt.Sprintf(`{"error":%q}`, err.Error()))
		writeJSONData(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	emitAuditEvent(r, auditProvider, pd.ID, action, "credential_source", id, AuditOutcomeSuccess)
	writeJSONData(w, map[string]any{"ok": true, "fields": fields})
}
