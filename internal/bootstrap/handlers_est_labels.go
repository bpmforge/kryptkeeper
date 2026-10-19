// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"kryptkeeper/internal/logging"
	"net/http"
	"os"
	"strings"
	"time"

	"kryptkeeper/internal/est"
)

const (
	estLabelAuditType    = "est_label"
	estLabelBodyMaxBytes = 16 * 1024
	estLabelDescMax      = 500
)

// ESTLabelStore is the est.LabelStore surface the API needs.
type ESTLabelStore interface {
	Get(ctx context.Context, label string) (est.Label, error)
	List(ctx context.Context) ([]est.Label, error)
	Create(ctx context.Context, l est.Label) (est.Label, error)
	Update(ctx context.Context, label, templateID, description string) (est.Label, error)
	Delete(ctx context.Context, label string) error
}

type estLabelView struct {
	est.Label
	URL string `json:"url"`
}

// RegisterESTLabelHandlers mounts the EST label API (W26-06): named endpoints
// /.well-known/est/<label>/, each bound to one template. pki-admin only; labels
// are instance-wide. Create and update verify the template exists. Every
// outcome, including refusals, is audited.
func RegisterESTLabelHandlers(mux *http.ServeMux, auth *Authenticator, store ESTLabelStore, templates TemplateProvider, auditProvider AuditProvider) {
	if store == nil {
		return
	}
	authorize := func(w http.ResponseWriter, r *http.Request, action, id string) (string, bool) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", action, estLabelAuditType, id, AuditOutcomeDenied)
			writeUnauthorized(w)
			return "", false
		}
		if !isAdminRole(pd.Role) {
			emitAuditEvent(r, auditProvider, pd.ID, action, estLabelAuditType, id, AuditOutcomeDenied)
			writeForbidden(w, "pki-admin role required for EST labels")
			return "", false
		}
		if denyNonSuperAdminGlobal(w, r, auditProvider, pd, action, estLabelAuditType, id) {
			return "", false
		}
		return pd.ID, true
	}
	view := func(l est.Label) estLabelView {
		base := strings.TrimRight(os.Getenv("KRYPTKEEPER_BASE_URL"), "/")
		return estLabelView{Label: l, URL: base + "/.well-known/est/" + l.Label + "/"}
	}
	writeData := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if err := json.NewEncoder(w).Encode(struct {
			Data any `json:"data"`
		}{Data: v}); err != nil {
			logging.Infof("est label response: %v", err)
		}
	}
	fail := func(w http.ResponseWriter, r *http.Request, principal, action, id string, err error) {
		logging.Infof("est label %s: %v", action, err)
		emitAuditEvent(r, auditProvider, principal, action, estLabelAuditType, id, AuditOutcomeFailure)
		writeServiceUnavailable(w, "est labels unavailable")
	}
	badRequest := func(w http.ResponseWriter, r *http.Request, principal, action, id, msg string) {
		emitAuditEventDetail(r, auditProvider, principal, action, estLabelAuditType, id, AuditOutcomeFailure, msg)
		writeBadRequest(w, msg)
	}
	notFound := func(w http.ResponseWriter, r *http.Request, principal, action, id string) {
		emitAuditEvent(r, auditProvider, principal, action, estLabelAuditType, id, AuditOutcomeFailure)
		writeNotFound(w, "est label not found")
	}
	type body struct {
		Label       string `json:"label"`
		TemplateID  string `json:"template_id"`
		Description string `json:"description"`
	}
	// readBody decodes and validates the template binding; ok is false once
	// the response and audit row have been written.
	readBody := func(w http.ResponseWriter, r *http.Request, principal, action, id string) (body, bool) {
		var req body
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, estLabelBodyMaxBytes)).Decode(&req); err != nil {
			emitAuditEvent(r, auditProvider, principal, action, estLabelAuditType, id, AuditOutcomeFailure)
			if rejectOversizeBody(w, err) {
				return req, false
			}
			writeBadRequest(w, "invalid request body")
			return req, false
		}
		req.TemplateID = strings.TrimSpace(req.TemplateID)
		if req.TemplateID == "" {
			badRequest(w, r, principal, action, id, "template_id is required")
			return req, false
		}
		if len(req.Description) > estLabelDescMax {
			badRequest(w, r, principal, action, id, "description is too long")
			return req, false
		}
		if templates == nil {
			fail(w, r, principal, action, id, errors.New("no template provider"))
			return req, false
		}
		_, found, err := templates.GetTemplate(r.Context(), req.TemplateID)
		if err != nil {
			fail(w, r, principal, action, id, err)
			return req, false
		}
		if !found {
			badRequest(w, r, principal, action, id, "template_id does not name a template")
			return req, false
		}
		return req, true
	}

	mux.HandleFunc("/api/v1/est/labels", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if _, ok := authorize(w, r, "est.label.list", "-"); !ok {
				return
			}
			list, err := store.List(r.Context())
			if err != nil {
				logging.Infof("est label list: %v", err)
				writeServiceUnavailable(w, "est labels unavailable")
				return
			}
			views := make([]estLabelView, 0, len(list))
			for _, l := range list {
				views = append(views, view(l))
			}
			writeData(w, http.StatusOK, views)
		case http.MethodPost:
			const action = "est.label.create"
			principal, ok := authorize(w, r, action, "-")
			if !ok {
				return
			}
			req, ok := readBody(w, r, principal, action, "-")
			if !ok {
				return
			}
			if !est.ValidLabel(req.Label) {
				badRequest(w, r, principal, action, "-", "label must be 1-32 characters of a-z 0-9 and inner hyphens, and not an EST operation name")
				return
			}
			created, err := store.Create(r.Context(), est.Label{Label: req.Label, TemplateID: req.TemplateID, Description: req.Description, CreatedBy: principal})
			if errors.Is(err, est.ErrLabelExists) {
				emitAuditEvent(r, auditProvider, principal, action, estLabelAuditType, req.Label, AuditOutcomeFailure)
				writeConflict(w, "est label already exists")
				return
			}
			if err != nil {
				fail(w, r, principal, action, req.Label, err)
				return
			}
			emitAuditEventDetail(r, auditProvider, principal, action, estLabelAuditType, created.Label, AuditOutcomeSuccess, "template_id="+created.TemplateID)
			writeData(w, http.StatusCreated, view(created))
		default:
			writeMethodNotAllowed(w, "GET, POST")
		}
	})

	mux.HandleFunc("/api/v1/est/labels/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/api/v1/est/labels/")
		if name == "" || strings.Contains(name, "/") {
			writeNotFound(w, "est label not found")
			return
		}
		switch r.Method {
		case http.MethodGet:
			const action = "est.label.get"
			if _, ok := authorize(w, r, action, name); !ok {
				return
			}
			l, err := store.Get(r.Context(), name)
			if errors.Is(err, est.ErrLabelNotFound) {
				writeNotFound(w, "est label not found")
				return
			}
			if err != nil {
				logging.Infof("est label get: %v", err)
				writeServiceUnavailable(w, "est labels unavailable")
				return
			}
			writeData(w, http.StatusOK, view(l))
		case http.MethodPut:
			const action = "est.label.update"
			principal, ok := authorize(w, r, action, name)
			if !ok {
				return
			}
			req, ok := readBody(w, r, principal, action, name)
			if !ok {
				return
			}
			if req.Label != "" && req.Label != name {
				badRequest(w, r, principal, action, name, "label in the body does not match the path")
				return
			}
			l, err := store.Update(r.Context(), name, req.TemplateID, req.Description)
			if errors.Is(err, est.ErrLabelNotFound) {
				notFound(w, r, principal, action, name)
				return
			}
			if err != nil {
				fail(w, r, principal, action, name, err)
				return
			}
			emitAuditEventDetail(r, auditProvider, principal, action, estLabelAuditType, name, AuditOutcomeSuccess, "template_id="+l.TemplateID)
			writeData(w, http.StatusOK, view(l))
		case http.MethodDelete:
			const action = "est.label.delete"
			principal, ok := authorize(w, r, action, name)
			if !ok {
				return
			}
			if err := store.Delete(r.Context(), name); err != nil {
				if errors.Is(err, est.ErrLabelNotFound) {
					notFound(w, r, principal, action, name)
					return
				}
				fail(w, r, principal, action, name, err)
				return
			}
			emitAuditEvent(r, auditProvider, principal, action, estLabelAuditType, name, AuditOutcomeSuccess)
			w.WriteHeader(http.StatusNoContent)
		default:
			writeMethodNotAllowed(w, "GET, PUT, DELETE")
		}
	})
}
