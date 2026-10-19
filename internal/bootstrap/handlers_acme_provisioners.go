// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"errors"
	"kryptkeeper/internal/logging"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/acme"
)

const acmeProvisionerResource = "acme_provisioner"

type acmeProvisionerView struct {
	Name         string   `json:"name"`
	CAID         string   `json:"ca_id"`
	TemplateID   string   `json:"template_id"`
	AllowNames   []string `json:"allow_names"`
	Challenges   []string `json:"challenges"`
	DirectoryURL string   `json:"directory_url"`
}

type acmeProvisionerRequest struct {
	Name       string   `json:"name"`
	CAID       string   `json:"ca_id"`
	TemplateID string   `json:"template_id"`
	AllowNames []string `json:"allow_names"`
	Challenges []string `json:"challenges"`
}

// RegisterACMEProvisionerHandlers mounts the ACME provisioner admin API
// (W26-02): GET/POST /api/v1/acme/provisioners and GET/PUT/DELETE
// /api/v1/acme/provisioners/{name}. pki-admin only, instance-wide. caExists
// checks ca_id; templates (optional) checks template_id; baseURL builds the
// computed directory_url.
func RegisterACMEProvisionerHandlers(mux *http.ServeMux, auth *Authenticator, store acme.ProvisionerStore, caExists func(id string) bool, templates TemplateProvider, baseURL string, auditProvider AuditProvider) {
	if store == nil {
		return
	}
	baseURL = strings.TrimRight(baseURL, "/")
	authorize := func(w http.ResponseWriter, r *http.Request, action, resID string) (string, bool) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", action, acmeProvisionerResource, resID, AuditOutcomeDenied)
			writeUnauthorized(w)
			return "", false
		}
		if !isAdminRole(pd.Role) {
			emitAuditEvent(r, auditProvider, pd.ID, action, acmeProvisionerResource, resID, AuditOutcomeDenied)
			writeForbidden(w, "pki-admin role required for ACME provisioners")
			return "", false
		}
		// Provisioners shape the one instance-wide ACME endpoint.
		if denyNonSuperAdminGlobal(w, r, auditProvider, pd, action, acmeProvisionerResource, resID) {
			return "", false
		}
		return pd.ID, true
	}
	view := func(p acme.Provisioner) acmeProvisionerView {
		v := acmeProvisionerView{Name: p.Name, CAID: p.CAID, TemplateID: p.TemplateID, AllowNames: p.AllowNames,
			Challenges: p.Challenges, DirectoryURL: baseURL + "/acme/" + p.Name + "/directory"}
		if v.AllowNames == nil {
			v.AllowNames = []string{}
		}
		if v.Challenges == nil {
			v.Challenges = []string{}
		}
		return v
	}
	writeData := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if err := json.NewEncoder(w).Encode(struct {
			Data any `json:"data"`
		}{Data: v}); err != nil {
			logging.Infof("acme provisioner response: %v", err)
		}
	}
	fail := func(w http.ResponseWriter, r *http.Request, principal, action, id, msg string) {
		emitAuditEventDetail(r, auditProvider, principal, action, acmeProvisionerResource, id, AuditOutcomeFailure, msg)
		writeBadRequest(w, msg)
	}
	unavailable := func(w http.ResponseWriter, r *http.Request, principal, action, id string, err error) {
		logging.Infof("%s: %v", action, err)
		emitAuditEvent(r, auditProvider, principal, action, acmeProvisionerResource, id, AuditOutcomeFailure)
		writeServiceUnavailable(w, "acme provisioners unavailable")
	}
	// build decodes and validates a create/update body; "" msg means ok.
	build := func(w http.ResponseWriter, r *http.Request, name string) (acme.Provisioner, string) {
		var req acmeProvisionerRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
			if rejectOversizeBody(w, err) {
				return acme.Provisioner{}, "-"
			}
			return acme.Provisioner{}, "invalid request body"
		}
		if name == "" {
			name = strings.TrimSpace(req.Name)
		}
		p := acme.Provisioner{Name: name, CAID: strings.TrimSpace(req.CAID), TemplateID: strings.TrimSpace(req.TemplateID),
			AllowNames: req.AllowNames, Challenges: req.Challenges}
		if err := acme.ValidateProvisioner(p); err != nil {
			return p, err.Error()
		}
		if caExists != nil && !caExists(p.CAID) {
			return p, "unknown ca_id"
		}
		if p.TemplateID != "" && templates != nil {
			if _, found, err := templates.GetTemplate(r.Context(), p.TemplateID); err != nil || !found {
				return p, "unknown template_id"
			}
		}
		return p, ""
	}

	mux.HandleFunc("/api/v1/acme/provisioners", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if _, ok := authorize(w, r, "acme.provisioner.list", "-"); !ok {
				return
			}
			list, err := store.List(r.Context())
			if err != nil {
				logging.Infof("acme provisioner list: %v", err)
				writeServiceUnavailable(w, "acme provisioners unavailable")
				return
			}
			views := make([]acmeProvisionerView, 0, len(list))
			for _, p := range list {
				views = append(views, view(p))
			}
			writeData(w, http.StatusOK, views)
		case http.MethodPost:
			principal, ok := authorize(w, r, "acme.provisioner.create", "-")
			if !ok {
				return
			}
			p, msg := build(w, r, "")
			if msg == "-" {
				emitAuditEvent(r, auditProvider, principal, "acme.provisioner.create", acmeProvisionerResource, "-", AuditOutcomeFailure)
				return
			}
			if msg != "" {
				id := "-"
				if p.Name != "" {
					id = p.Name
				}
				fail(w, r, principal, "acme.provisioner.create", id, msg)
				return
			}
			now := time.Now().UTC().Truncate(time.Second)
			p.CreatedBy, p.CreatedAt, p.UpdatedAt = principal, now, now
			switch err := store.Create(r.Context(), p); {
			case err == nil:
				emitAuditEvent(r, auditProvider, principal, "acme.provisioner.create", acmeProvisionerResource, p.Name, AuditOutcomeSuccess)
				writeData(w, http.StatusCreated, view(p))
			case errors.Is(err, acme.ErrProvisionerExists):
				emitAuditEvent(r, auditProvider, principal, "acme.provisioner.create", acmeProvisionerResource, p.Name, AuditOutcomeFailure)
				writeConflict(w, "acme provisioner already exists")
			default:
				unavailable(w, r, principal, "acme.provisioner.create", p.Name, err)
			}
		default:
			writeMethodNotAllowed(w, "GET, POST")
		}
	})

	mux.HandleFunc("/api/v1/acme/provisioners/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/api/v1/acme/provisioners/")
		action := map[string]string{http.MethodGet: "acme.provisioner.get", http.MethodPut: "acme.provisioner.update",
			http.MethodDelete: "acme.provisioner.delete"}[r.Method]
		if action == "" {
			writeMethodNotAllowed(w, "GET, PUT, DELETE")
			return
		}
		if name == "" || strings.Contains(name, "/") {
			emitAuditEvent(r, auditProvider, "", action, acmeProvisionerResource, "-", AuditOutcomeFailure)
			writeNotFound(w, "acme provisioner not found")
			return
		}
		principal, ok := authorize(w, r, action, name)
		if !ok {
			return
		}
		notFound := func() {
			emitAuditEvent(r, auditProvider, principal, action, acmeProvisionerResource, name, AuditOutcomeFailure)
			writeNotFound(w, "acme provisioner not found")
		}
		switch r.Method {
		case http.MethodGet:
			p, found, err := store.Get(r.Context(), name)
			switch {
			case err != nil:
				unavailable(w, r, principal, action, name, err)
			case !found:
				notFound()
			default:
				writeData(w, http.StatusOK, view(p))
			}
		case http.MethodPut:
			if _, found, err := store.Get(r.Context(), name); err != nil {
				unavailable(w, r, principal, action, name, err)
				return
			} else if !found {
				notFound()
				return
			}
			p, msg := build(w, r, name)
			if msg == "-" {
				emitAuditEvent(r, auditProvider, principal, action, acmeProvisionerResource, name, AuditOutcomeFailure)
				return
			}
			if msg != "" {
				fail(w, r, principal, action, name, msg)
				return
			}
			p.UpdatedAt = time.Now().UTC().Truncate(time.Second)
			switch err := store.Update(r.Context(), p); {
			case err == nil:
				emitAuditEvent(r, auditProvider, principal, action, acmeProvisionerResource, name, AuditOutcomeSuccess)
				cur, _, _ := store.Get(r.Context(), name)
				writeData(w, http.StatusOK, view(cur))
			case errors.Is(err, acme.ErrProvisionerNotFound):
				notFound()
			default:
				unavailable(w, r, principal, action, name, err)
			}
		case http.MethodDelete:
			switch err := store.Delete(r.Context(), name); {
			case err == nil:
				emitAuditEvent(r, auditProvider, principal, action, acmeProvisionerResource, name, AuditOutcomeSuccess)
				w.WriteHeader(http.StatusNoContent)
			case errors.Is(err, acme.ErrProvisionerNotFound):
				notFound()
			default:
				unavailable(w, r, principal, action, name, err)
			}
		}
	})
}
