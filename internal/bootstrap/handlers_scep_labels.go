// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
	"kryptkeeper/internal/scep"
)

const (
	scepLabelAuditType    = "scep_label"
	scepLabelBodyMaxBytes = 16 * 1024
	scepLabelDescMax      = 500
)

// Entra tenant ids are GUIDs or domains; the pattern also keeps the value safe
// to put in the token endpoint's path.
var scepTenantRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)

// SCEPLabelStore is the scep.LabelStore surface the API needs.
type SCEPLabelStore interface {
	Get(ctx context.Context, label string) (scep.Label, error)
	List(ctx context.Context) ([]scep.Label, error)
	Create(ctx context.Context, l scep.Label) (scep.Label, error)
	Delete(ctx context.Context, label string) error
}

type scepLabelView struct {
	scep.Label
	URL string `json:"url"`
}

// RegisterSCEPLabelHandlers mounts the SCEP label API (W20-23, D-327): named
// endpoints /scep/<label> in Intune challenge mode. pki-admin only and
// instance-wide, like EST labels. The Entra app's secret is never accepted
// here: the label names an api_token credential in the outbound store
// (credential_ref), which must exist, be visible to the caller, and hold
// the app's client_secret or certificate. Every outcome is audited.
func RegisterSCEPLabelHandlers(mux *http.ServeMux, auth *Authenticator, store SCEPLabelStore, templates TemplateProvider, creds SCEPCredentialLookup, auditProvider AuditProvider) {
	if store == nil {
		return
	}
	authorize := func(w http.ResponseWriter, r *http.Request, action, id string) (AuthPrincipal, bool) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", action, scepLabelAuditType, id, AuditOutcomeDenied)
			writeUnauthorized(w)
			return AuthPrincipal{}, false
		}
		if !isAdminRole(pd.Role) {
			emitAuditEvent(r, auditProvider, pd.ID, action, scepLabelAuditType, id, AuditOutcomeDenied)
			writeForbidden(w, "pki-admin role required for SCEP labels")
			return AuthPrincipal{}, false
		}
		if denyNonSuperAdminGlobal(w, r, auditProvider, pd, action, scepLabelAuditType, id) {
			return AuthPrincipal{}, false
		}
		return pd, true
	}
	view := func(l scep.Label) scepLabelView {
		base := strings.TrimRight(os.Getenv("KRYPTKEEPER_BASE_URL"), "/")
		return scepLabelView{Label: l, URL: base + "/scep/" + l.Label}
	}
	writeData := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if err := json.NewEncoder(w).Encode(struct {
			Data any `json:"data"`
		}{Data: v}); err != nil {
			logging.Infof("scep label response: %v", err)
		}
	}
	fail := func(w http.ResponseWriter, r *http.Request, principal, action, id string, err error) {
		logging.Infof("scep label %s: %v", action, err)
		emitAuditEvent(r, auditProvider, principal, action, scepLabelAuditType, id, AuditOutcomeFailure)
		writeServiceUnavailable(w, "scep labels unavailable")
	}
	badRequest := func(w http.ResponseWriter, r *http.Request, principal, action, id, msg string) {
		emitAuditEventDetail(r, auditProvider, principal, action, scepLabelAuditType, id, AuditOutcomeFailure, msg)
		writeBadRequest(w, msg)
	}

	mux.HandleFunc("/api/v1/scep/labels", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if _, ok := authorize(w, r, "scep.label.list", "-"); !ok {
				return
			}
			list, err := store.List(r.Context())
			if err != nil {
				logging.Infof("scep label list: %v", err)
				writeServiceUnavailable(w, "scep labels unavailable")
				return
			}
			views := make([]scepLabelView, 0, len(list))
			for _, l := range list {
				views = append(views, view(l))
			}
			writeData(w, http.StatusOK, views)
		case http.MethodPost:
			const action = "scep.label.create"
			pd, ok := authorize(w, r, action, "-")
			if !ok {
				return
			}
			var req struct {
				Label            string `json:"label"`
				Mode             string `json:"mode"`
				TemplateID       string `json:"template_id"`
				IntuneTenantID   string `json:"intune_tenant_id"`
				IntuneClientID   string `json:"intune_client_id"`
				CredentialRef    string `json:"credential_ref"`
				IssuingAuthority string `json:"issuing_authority"`
				Description      string `json:"description"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, scepLabelBodyMaxBytes)).Decode(&req); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, action, scepLabelAuditType, "-", AuditOutcomeFailure)
				if rejectOversizeBody(w, err) {
					return
				}
				writeBadRequest(w, "invalid request body")
				return
			}
			req.TemplateID = strings.TrimSpace(req.TemplateID)
			req.IntuneTenantID = strings.TrimSpace(req.IntuneTenantID)
			req.IntuneClientID = strings.TrimSpace(req.IntuneClientID)
			req.CredentialRef = strings.TrimSpace(req.CredentialRef)
			switch {
			case !scep.ValidLabel(req.Label):
				badRequest(w, r, pd.ID, action, "-", "label must be 1-32 characters of a-z 0-9 and inner hyphens")
				return
			case req.Mode != scep.ModeIntune:
				badRequest(w, r, pd.ID, action, req.Label, `mode must be "intune"`)
				return
			case !scepTenantRE.MatchString(req.IntuneTenantID):
				badRequest(w, r, pd.ID, action, req.Label, "intune_tenant_id must be the Entra tenant GUID or domain")
				return
			case req.IntuneClientID == "" || len(req.IntuneClientID) > 128:
				badRequest(w, r, pd.ID, action, req.Label, "intune_client_id is required")
				return
			case req.CredentialRef == "":
				badRequest(w, r, pd.ID, action, req.Label, "credential_ref is required")
				return
			case req.TemplateID == "":
				badRequest(w, r, pd.ID, action, req.Label, "template_id is required")
				return
			case len(req.Description) > scepLabelDescMax || len(req.IssuingAuthority) > 256:
				badRequest(w, r, pd.ID, action, req.Label, "description or issuing_authority is too long")
				return
			}
			if templates == nil || creds == nil {
				fail(w, r, pd.ID, action, req.Label, errors.New("template provider or credential store missing"))
				return
			}
			if _, found, err := templates.GetTemplate(r.Context(), req.TemplateID); err != nil {
				fail(w, r, pd.ID, action, req.Label, err)
				return
			} else if !found {
				badRequest(w, r, pd.ID, action, req.Label, "template_id does not name a template")
				return
			}
			meta, err := creds.Get(r.Context(), req.CredentialRef)
			if err != nil || !stampedTenantVisible(pd, meta.Tenant) {
				badRequest(w, r, pd.ID, action, req.Label, "credential_ref does not name a credential you can use")
				return
			}
			if meta.CredentialType != CredentialTypeAPIToken {
				badRequest(w, r, pd.ID, action, req.Label, "credential_ref must be an "+CredentialTypeAPIToken+" credential holding the Entra app's client_secret or certificate_pem and private_key_pem")
				return
			}
			created, err := store.Create(r.Context(), scep.Label{
				Label: req.Label, Mode: req.Mode, TemplateID: req.TemplateID, IntuneTenantID: req.IntuneTenantID,
				IntuneClientID: req.IntuneClientID, CredentialRef: req.CredentialRef, IssuingAuthority: req.IssuingAuthority,
				Description: req.Description, CreatedBy: pd.ID,
			})
			if errors.Is(err, scep.ErrLabelExists) {
				emitAuditEvent(r, auditProvider, pd.ID, action, scepLabelAuditType, req.Label, AuditOutcomeFailure)
				writeConflict(w, "scep label already exists")
				return
			}
			if err != nil {
				fail(w, r, pd.ID, action, req.Label, err)
				return
			}
			emitAuditEventDetail(r, auditProvider, pd.ID, action, scepLabelAuditType, created.Label, AuditOutcomeSuccess,
				"mode=intune template_id="+created.TemplateID+" tenant="+created.IntuneTenantID+" credential_ref="+created.CredentialRef)
			writeData(w, http.StatusCreated, view(created))
		default:
			writeMethodNotAllowed(w, "GET, POST")
		}
	})

	mux.HandleFunc("/api/v1/scep/labels/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/api/v1/scep/labels/")
		if name == "" || strings.Contains(name, "/") {
			writeNotFound(w, "scep label not found")
			return
		}
		if r.Method != http.MethodDelete {
			writeMethodNotAllowed(w, "DELETE")
			return
		}
		const action = "scep.label.delete"
		pd, ok := authorize(w, r, action, name)
		if !ok {
			return
		}
		if err := store.Delete(r.Context(), name); err != nil {
			if errors.Is(err, scep.ErrLabelNotFound) {
				emitAuditEvent(r, auditProvider, pd.ID, action, scepLabelAuditType, name, AuditOutcomeFailure)
				writeNotFound(w, "scep label not found")
				return
			}
			fail(w, r, pd.ID, action, name, err)
			return
		}
		emitAuditEvent(r, auditProvider, pd.ID, action, scepLabelAuditType, name, AuditOutcomeSuccess)
		w.WriteHeader(http.StatusNoContent)
	})
}
