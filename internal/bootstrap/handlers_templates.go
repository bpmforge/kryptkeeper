// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func registerTemplateHandlers(mux *http.ServeMux, auth *Authenticator, provider TemplateProvider, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/templates", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			auditAction := "template.list"
			if r.Method == http.MethodPost {
				auditAction = "template.create"
			}
			emitAuditEvent(r, auditProvider, "", auditAction, "template", "templates", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		if r.Method == http.MethodPost {
			capBody(w, r, maxTemplateBodyBytes)
			createReq, err := parseTemplateUpsertRequest(r.Body)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "template.create", "template", "templates", AuditOutcomeFailure)
				if rejectOversizeBody(w, err) {
					return
				}
				writeBadRequestJSON(w, templateRequestErrorMessage(err))
				return
			}

			if !tenantBypass(pd) && activeTenantStore != nil {
				exists, terr := activeTenantStore.TenantExists(r.Context(), pd.Tenant)
				if terr != nil {
					emitAuditEvent(r, auditProvider, pd.ID, "template.create", "template", "templates", AuditOutcomeFailure)
					writeServiceUnavailable(w, "tenant lookup failed")
					return
				}
				if !exists {
					emitAuditEvent(r, auditProvider, pd.ID, "template.create", "template", "templates", AuditOutcomeDenied)
					writeBadRequest(w, "unknown tenant")
					return
				}
			}

			created, err := provider.CreateTemplate(r.Context(), createReq)
			if err != nil {
				if errors.Is(err, errTemplateConflict) {
					emitAuditEvent(r, auditProvider, pd.ID, "template.create", "template", "templates", AuditOutcomeFailure)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`{"error":"conflict","message":"template name or oid already exists"}`))
					return
				}
				if errors.Is(err, errTemplateInvalidCreate) {
					emitAuditEvent(r, auditProvider, pd.ID, "template.create", "template", "templates", AuditOutcomeFailure)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"bad_request","message":"invalid request body"}`))
					return
				}
				emitAuditEvent(r, auditProvider, pd.ID, "template.create", "template", "templates", AuditOutcomeFailure)
				log.Printf("template create unavailable: %v", err)
				writeServiceUnavailable(w, "template unavailable")
				return
			}

			if !tenantBypass(pd) && pd.Tenant != DefaultTenant && activeTenantStore != nil {
				if merr := activeTenantStore.SetTemplateTenant(r.Context(), created.ID, pd.Tenant); merr != nil {
					log.Printf("auto-map template %s to tenant %s failed: %v", created.ID, pd.Tenant, merr)
				}
			}

			emitAuditEvent(r, auditProvider, pd.ID, "template.create", "template", created.ID, AuditOutcomeSuccess)
			resp := struct {
				Data TemplateItem `json:"data"`
			}{Data: created}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Location", "/api/v1/templates/"+created.ID)
			w.Header().Set("ETag", strconv.Itoa(created.Revision))
			w.WriteHeader(http.StatusCreated)
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				log.Printf("failed to encode /api/v1/templates create response: %v", err)
			}
			return
		}

		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, "GET, POST")
			return
		}

		query := TemplateListQuery{
			Limit:  parseTemplateLimit(r.URL.Query().Get("limit"), 25),
			Offset: parseTemplateOffset(r.URL.Query().Get("cursor")),
			Q:      strings.TrimSpace(r.URL.Query().Get("q")),
			Active: parseTemplateActive(r.URL.Query().Get("active")),
		}

		result, err := provider.ListTemplates(r.Context(), query)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "template.list", "template", "templates", AuditOutcomeFailure)
			log.Printf("template list unavailable: %v", err)
			writeServiceUnavailable(w, "template list unavailable")
			return
		}
		emitAuditEvent(r, auditProvider, pd.ID, "template.list", "template", "templates", AuditOutcomeSuccess)

		result.Items = filterTemplatesByTenant(r.Context(), activeTenantStore, pd, result.Items)

		resp := struct {
			Data []TemplateItem `json:"data"`
			Meta struct {
				Total      int     `json:"total"`
				Limit      int     `json:"limit"`
				NextCursor *string `json:"next_cursor"`
				PrevCursor *string `json:"prev_cursor"`
			} `json:"meta"`
		}{Data: result.Items}
		resp.Meta.Total = result.Total
		resp.Meta.Limit = result.Limit
		nextOffset := query.Offset + len(result.Items)
		if nextOffset < result.Total {
			next := strconv.Itoa(nextOffset)
			resp.Meta.NextCursor = &next
		}
		if query.Offset > 0 {
			prevOffset := query.Offset - query.Limit
			if prevOffset < 0 {
				prevOffset = 0
			}
			prev := strconv.Itoa(prevOffset)
			resp.Meta.PrevCursor = &prev
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("failed to encode /api/v1/templates response: %v", err)
		}
	})

	mux.HandleFunc("/api/v1/templates/", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			auditAction := "template.get"
			if r.Method == http.MethodPatch {
				auditAction = "template.update"
			}
			if r.Method == http.MethodDelete {
				auditAction = "template.delete"
			}
			emitAuditEvent(r, auditProvider, "", auditAction, "template", "template-id", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		tail := strings.TrimPrefix(r.URL.Path, "/api/v1/templates/")
		if strings.HasSuffix(tail, "/clone") {
			if r.Method != http.MethodPost {
				writeMethodNotAllowed(w, "POST")
				return
			}
			id := strings.TrimSuffix(tail, "/clone")
			if id == "" || strings.Contains(id, "/") {
				emitAuditEvent(r, auditProvider, pd.ID, "template.clone", "template", id, AuditOutcomeFailure)
				writeNotFound(w, "template not found")
				return
			}
			if !templateVisibleToTenant(r.Context(), activeTenantStore, pd, id) {
				emitAuditEvent(r, auditProvider, pd.ID, "template.clone", "template", id, AuditOutcomeDenied)
				writeForbidden(w, "forbidden")
				return
			}

			capBody(w, r, maxTemplateBodyBytes)
			cloneReq, err := parseTemplateCloneRequest(r.Body)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "template.clone", "template", id, AuditOutcomeFailure)
				if rejectOversizeBody(w, err) {
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"bad_request","message":"invalid request body"}`))
				return
			}

			cloned, err := provider.CloneTemplate(r.Context(), id, cloneReq)
			if err != nil {
				if errors.Is(err, errTemplateNotFound) {
					emitAuditEvent(r, auditProvider, pd.ID, "template.clone", "template", id, AuditOutcomeFailure)
					writeNotFound(w, "template not found")
					return
				}
				if errors.Is(err, errTemplateConflict) {
					emitAuditEvent(r, auditProvider, pd.ID, "template.clone", "template", id, AuditOutcomeFailure)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`{"error":"conflict","message":"template name or oid already exists"}`))
					return
				}
				if errors.Is(err, errTemplateInvalidCreate) {
					emitAuditEvent(r, auditProvider, pd.ID, "template.clone", "template", id, AuditOutcomeFailure)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"bad_request","message":"invalid request body"}`))
					return
				}
				emitAuditEvent(r, auditProvider, pd.ID, "template.clone", "template", id, AuditOutcomeFailure)
				log.Printf("template clone unavailable: %v", err)
				writeServiceUnavailable(w, "template unavailable")
				return
			}

			if !tenantBypass(pd) && pd.Tenant != DefaultTenant && activeTenantStore != nil {
				if merr := activeTenantStore.SetTemplateTenant(r.Context(), cloned.ID, pd.Tenant); merr != nil {
					log.Printf("auto-map cloned template %s to tenant %s failed: %v", cloned.ID, pd.Tenant, merr)
				}
			}
			emitAuditEvent(r, auditProvider, pd.ID, "template.clone", "template", id, AuditOutcomeSuccess)
			resp := struct {
				Data TemplateItem `json:"data"`
			}{Data: cloned}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Location", "/api/v1/templates/"+cloned.ID)
			w.Header().Set("ETag", strconv.Itoa(cloned.Revision))
			w.WriteHeader(http.StatusCreated)
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				log.Printf("failed to encode /api/v1/templates/{id}/clone response: %v", err)
			}
			return
		}

		id := tail
		if id == "" || strings.Contains(id, "/") {
			auditAction := "template.get"
			if r.Method == http.MethodPatch {
				auditAction = "template.update"
			}
			if r.Method == http.MethodDelete {
				auditAction = "template.delete"
			}
			emitAuditEvent(r, auditProvider, pd.ID, auditAction, "template", id, AuditOutcomeFailure)
			writeNotFound(w, "template not found")
			return
		}
		if !templateVisibleToTenant(r.Context(), activeTenantStore, pd, id) {
			auditAction := "template.get"
			if r.Method == http.MethodPatch {
				auditAction = "template.update"
			}
			if r.Method == http.MethodPut {
				auditAction = "template.replace"
			}
			if r.Method == http.MethodDelete {
				auditAction = "template.delete"
			}
			emitAuditEvent(r, auditProvider, pd.ID, auditAction, "template", id, AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}

		if r.Method == http.MethodDelete {
			err := provider.DeleteTemplate(r.Context(), id)
			if err != nil {
				if errors.Is(err, errTemplateNotFound) {
					emitAuditEvent(r, auditProvider, pd.ID, "template.delete", "template", id, AuditOutcomeFailure)
					writeNotFound(w, "template not found")
					return
				}
				if errors.Is(err, errTemplateConflict) {
					emitAuditEvent(r, auditProvider, pd.ID, "template.delete", "template", id, AuditOutcomeFailure)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`{"error":"conflict","message":"template has issued certificates"}`))
					return
				}

				emitAuditEvent(r, auditProvider, pd.ID, "template.delete", "template", id, AuditOutcomeFailure)
				log.Printf("template delete unavailable: %v", err)
				writeServiceUnavailable(w, "template unavailable")
				return
			}

			emitAuditEvent(r, auditProvider, pd.ID, "template.delete", "template", id, AuditOutcomeSuccess)
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if r.Method == http.MethodPatch {
			capBody(w, r, maxTemplateBodyBytes)
			patchReq, err := parseTemplatePatchRequest(r.Body)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "template.update", "template", id, AuditOutcomeFailure)
				if rejectOversizeBody(w, err) {
					return
				}
				if errors.Is(err, errTemplateImmutableField) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnprocessableEntity)
					_, _ = w.Write([]byte(`{"error":"unprocessable_entity","message":"attempt to modify immutable field"}`))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"bad_request","message":"invalid request body"}`))
				return
			}

			updated, err := provider.PatchTemplate(r.Context(), id, patchReq)
			if err != nil {
				if errors.Is(err, errTemplateNotFound) {
					emitAuditEvent(r, auditProvider, pd.ID, "template.update", "template", id, AuditOutcomeFailure)
					writeNotFound(w, "template not found")
					return
				}
				if errors.Is(err, errTemplateImmutableField) {
					emitAuditEvent(r, auditProvider, pd.ID, "template.update", "template", id, AuditOutcomeFailure)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnprocessableEntity)
					_, _ = w.Write([]byte(`{"error":"unprocessable_entity","message":"attempt to modify immutable field"}`))
					return
				}
				if errors.Is(err, errTemplateInvalidPatch) {
					emitAuditEvent(r, auditProvider, pd.ID, "template.update", "template", id, AuditOutcomeFailure)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"bad_request","message":"invalid request body"}`))
					return
				}

				emitAuditEvent(r, auditProvider, pd.ID, "template.update", "template", id, AuditOutcomeFailure)
				log.Printf("template patch unavailable: %v", err)
				writeServiceUnavailable(w, "template unavailable")
				return
			}

			emitAuditEvent(r, auditProvider, pd.ID, "template.update", "template", id, AuditOutcomeSuccess)
			resp := struct {
				Data TemplateItem `json:"data"`
			}{Data: updated}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				log.Printf("failed to encode /api/v1/templates/{id} patch response: %v", err)
			}
			return
		}

		if r.Method == http.MethodPut {
			expectedRevision, err := parseIfMatchRevision(r.Header.Get("If-Match"))
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "template.replace", "template", id, AuditOutcomeFailure)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusPreconditionFailed)
				_, _ = w.Write([]byte(`{"error":"precondition_failed","message":"if-match header required"}`))
				return
			}

			capBody(w, r, maxTemplateBodyBytes)
			req, err := parseTemplateUpsertRequest(r.Body)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "template.replace", "template", id, AuditOutcomeFailure)
				if rejectOversizeBody(w, err) {
					return
				}
				writeBadRequestJSON(w, templateRequestErrorMessage(err))
				return
			}

			replaced, err := provider.ReplaceTemplate(r.Context(), id, req, expectedRevision)
			if err != nil {
				if errors.Is(err, errTemplateNotFound) {
					emitAuditEvent(r, auditProvider, pd.ID, "template.replace", "template", id, AuditOutcomeFailure)
					writeNotFound(w, "template not found")
					return
				}
				if errors.Is(err, errTemplateConflict) {
					emitAuditEvent(r, auditProvider, pd.ID, "template.replace", "template", id, AuditOutcomeFailure)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`{"error":"conflict","message":"template name or oid already exists"}`))
					return
				}
				if errors.Is(err, errTemplatePrecondition) {
					emitAuditEvent(r, auditProvider, pd.ID, "template.replace", "template", id, AuditOutcomeFailure)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusPreconditionFailed)
					_, _ = w.Write([]byte(`{"error":"precondition_failed","message":"if-match revision mismatch"}`))
					return
				}
				if errors.Is(err, errTemplateInvalidCreate) {
					emitAuditEvent(r, auditProvider, pd.ID, "template.replace", "template", id, AuditOutcomeFailure)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"bad_request","message":"invalid request body"}`))
					return
				}

				emitAuditEvent(r, auditProvider, pd.ID, "template.replace", "template", id, AuditOutcomeFailure)
				log.Printf("template replace unavailable: %v", err)
				writeServiceUnavailable(w, "template unavailable")
				return
			}

			emitAuditEvent(r, auditProvider, pd.ID, "template.replace", "template", id, AuditOutcomeSuccess)
			resp := struct {
				Data TemplateItem `json:"data"`
			}{Data: replaced}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", strconv.Itoa(replaced.Revision))
			w.WriteHeader(http.StatusOK)
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				log.Printf("failed to encode /api/v1/templates/{id} put response: %v", err)
			}
			return
		}

		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, "GET, PUT, PATCH, DELETE")
			return
		}

		item, found, err := provider.GetTemplate(r.Context(), id)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "template.get", "template", id, AuditOutcomeFailure)
			log.Printf("template get unavailable: %v", err)
			writeServiceUnavailable(w, "template unavailable")
			return
		}
		if !found {
			emitAuditEvent(r, auditProvider, pd.ID, "template.get", "template", id, AuditOutcomeFailure)
			writeNotFound(w, "template not found")
			return
		}
		emitAuditEvent(r, auditProvider, pd.ID, "template.get", "template", id, AuditOutcomeSuccess)

		resp := struct {
			Data TemplateItem `json:"data"`
		}{Data: item}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", strconv.Itoa(item.Revision))
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("failed to encode /api/v1/templates/{id} response: %v", err)
		}
	})
}

// maxTemplateBodyBytes bounds a template document; policy blocks and name
// lists are the only large parts and stay far below this.
const maxTemplateBodyBytes = 256 << 10

func parseTemplatePatchRequest(body io.Reader) (TemplatePatchRequest, error) {
	raw, err := io.ReadAll(body)
	if err != nil {
		if isBodyTooLarge(err) {
			return TemplatePatchRequest{}, errBodyTooLarge
		}
		return TemplatePatchRequest{}, errTemplateInvalidPatch
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return TemplatePatchRequest{}, nil
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(raw, &payload); err != nil {
		return TemplatePatchRequest{}, errTemplateInvalidPatch
	}

	for key := range payload {
		switch key {
		case "display_name", "auto_enroll", "active", "allowed_algorithms":
			// mutable — allowed_algorithms is a policy knob, not identity (W18-15)
		case "id", "name", "oid", "key_usage", "extended_key_usage", "min_key_size", "validity_period", "renewal_overlap", "revision", "schema_version", "issued_count", "created_at", "updated_at":
			return TemplatePatchRequest{}, errTemplateImmutableField
		default:
			return TemplatePatchRequest{}, errTemplateInvalidPatch
		}
	}

	var req TemplatePatchRequest
	if rawDisplay, ok := payload["display_name"]; ok {
		var display string
		if err := json.Unmarshal(rawDisplay, &display); err != nil {
			return TemplatePatchRequest{}, errTemplateInvalidPatch
		}
		req.DisplayName = &display
	}
	if rawAutoEnroll, ok := payload["auto_enroll"]; ok {
		var autoEnroll bool
		if err := json.Unmarshal(rawAutoEnroll, &autoEnroll); err != nil {
			return TemplatePatchRequest{}, errTemplateInvalidPatch
		}
		req.AutoEnroll = &autoEnroll
	}
	if rawActive, ok := payload["active"]; ok {
		var active bool
		if err := json.Unmarshal(rawActive, &active); err != nil {
			return TemplatePatchRequest{}, errTemplateInvalidPatch
		}
		req.Active = &active
	}
	if rawAlgos, ok := payload["allowed_algorithms"]; ok {
		var algos []string
		if err := json.Unmarshal(rawAlgos, &algos); err != nil || len(algos) == 0 {
			return TemplatePatchRequest{}, errTemplateInvalidPatch
		}
		req.AllowedAlgorithms = &algos
	}

	return req, nil
}

func parseTemplateUpsertRequest(body io.Reader) (TemplateUpsertRequest, error) {
	raw, err := io.ReadAll(body)
	if err != nil {
		if isBodyTooLarge(err) {
			return TemplateUpsertRequest{}, errBodyTooLarge
		}
		return TemplateUpsertRequest{}, errTemplateInvalidCreate
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return TemplateUpsertRequest{}, errTemplateInvalidCreate
	}

	var req TemplateUpsertRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return TemplateUpsertRequest{}, errTemplateInvalidCreate
	}
	if err := validateTemplateUpsertRequest(req); err != nil {
		return TemplateUpsertRequest{}, err
	}
	return req, nil
}

// templateRequestErrorMessage keeps the generic message for malformed bodies
// but tells the admin why an SSH or name policy was refused: nothing else in the
// request is attacker-influenced text, and a policy rejection is otherwise
// undiagnosable.
func templateRequestErrorMessage(err error) string {
	if msg := err.Error(); strings.Contains(msg, "invalid ssh policy") {
		return msg[strings.Index(msg, "invalid ssh policy"):]
	} else if i := strings.Index(msg, "name_policy:"); i >= 0 {
		return msg[i:]
	}
	return "invalid request body"
}

func parseIfMatchRevision(headerValue string) (int, error) {
	trimmed := strings.TrimSpace(headerValue)
	if trimmed == "" {
		return 0, errTemplatePrecondition
	}
	trimmed = strings.Trim(trimmed, "\"")
	rev, err := strconv.Atoi(trimmed)
	if err != nil || rev <= 0 {
		return 0, errTemplatePrecondition
	}
	return rev, nil
}

func parseTemplateCloneRequest(body io.Reader) (TemplateCloneRequest, error) {
	raw, err := io.ReadAll(body)
	if err != nil {
		if isBodyTooLarge(err) {
			return TemplateCloneRequest{}, errBodyTooLarge
		}
		return TemplateCloneRequest{}, errTemplateInvalidCreate
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return TemplateCloneRequest{}, errTemplateInvalidCreate
	}

	var req TemplateCloneRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return TemplateCloneRequest{}, errTemplateInvalidCreate
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.DisplayName) == "" {
		return TemplateCloneRequest{}, errTemplateInvalidCreate
	}
	return req, nil
}
