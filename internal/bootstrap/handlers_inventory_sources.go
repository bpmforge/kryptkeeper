// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// W11-05: the inventory-sources API — CRUD plus a manual sync trigger that
// returns the run report.
func RegisterInventorySourceHandlers(mux *http.ServeMux, auth *Authenticator, store InventorySourceStore, provider CertificateProvider, creds OutboundCredentialStore, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/inventory-sources", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return
		}
		if store == nil {
			writeServiceUnavailable(w, "inventory source store not configured")
			return
		}
		switch r.Method {
		case http.MethodGet:
			recs, err := store.List(r.Context())
			if err != nil {
				writeServiceUnavailable(w, "list failed")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "inventory_source.list", "inventory_source", "inventory-sources", AuditOutcomeSuccess)
			writeJSONStatus(w, http.StatusOK, struct {
				Data []InventorySourceRecord `json:"data"`
			}{Data: recs})
		case http.MethodPost:
			body := http.MaxBytesReader(w, r.Body, 64*1024)
			defer body.Close()
			raw, err := io.ReadAll(body)
			if err != nil {
				writeBadRequestJSON(w, "invalid request body")
				return
			}
			var req InventorySourceRecord
			if err := json.Unmarshal(raw, &req); err != nil {
				writeBadRequestJSON(w, "invalid request body")
				return
			}
			id, err := newInventorySourceID()
			if err != nil {
				writeServiceUnavailable(w, "id generation failed")
				return
			}
			req.ID = id
			if !tenantBypass(pd) {
				req.Tenant = pd.Tenant
			}
			created, err := store.Create(r.Context(), req)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "inventory_source.create", "inventory_source", id, AuditOutcomeFailure)
				if errors.Is(err, errInventorySourceInvalid) {
					writeBadRequestJSON(w, err.Error())
					return
				}
				writeServiceUnavailable(w, "create failed")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "inventory_source.create", "inventory_source", id, AuditOutcomeSuccess)
			writeJSONStatus(w, http.StatusCreated, struct {
				Data InventorySourceRecord `json:"data"`
			}{Data: created})
		default:
			writeMethodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
		}
	})

	mux.HandleFunc("/api/v1/inventory-sources/", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return
		}
		if store == nil {
			writeServiceUnavailable(w, "inventory source store not configured")
			return
		}
		tail := strings.TrimPrefix(r.URL.Path, "/api/v1/inventory-sources/")

		if id, ok := strings.CutSuffix(tail, "/sync"); ok && id != "" && !strings.Contains(id, "/") {
			if r.Method != http.MethodPost {
				writeMethodNotAllowed(w, http.MethodPost)
				return
			}
			rec, err := store.Get(r.Context(), id)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "inventory_source.sync", "inventory_source", id, AuditOutcomeFailure)
				writeNotFound(w, "inventory source not found")
				return
			}
			source, err := buildInventorySource(r.Context(), rec, creds)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "inventory_source.sync", "inventory_source", id, AuditOutcomeFailure)
				writeBadRequestJSON(w, err.Error())
				return
			}
			result, err := syncInventorySource(r.Context(), source, rec.ID, provider)
			now := time.Now().UTC().Format(time.RFC3339)
			summary, _ := json.Marshal(result)
			if err != nil {
				_ = store.RecordSync(r.Context(), rec.ID, now, `{"error":`+strconvQuote(err.Error())+`}`) // best-effort failure-status write; sync failure already reported to caller
				emitAuditEvent(r, auditProvider, pd.ID, "inventory_source.sync", "inventory_source", id, AuditOutcomeFailure)
				writeServiceUnavailable(w, "sync failed: "+err.Error())
				return
			}
			if err := store.RecordSync(r.Context(), rec.ID, now, string(summary)); err != nil {
				writeServiceUnavailable(w, "sync succeeded but recording it failed: "+err.Error())
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "inventory_source.sync", "inventory_source", id, AuditOutcomeSuccess)
			writeJSONStatus(w, http.StatusOK, struct {
				Data InventorySyncResult `json:"data"`
			}{Data: result})
			return
		}

		id := tail
		if id == "" || strings.Contains(id, "/") {
			writeNotFound(w, "inventory source not found")
			return
		}
		if r.Method != http.MethodDelete {
			writeMethodNotAllowed(w, http.MethodDelete)
			return
		}
		if err := store.Delete(r.Context(), id); err != nil {
			if errors.Is(err, errInventorySourceNotFound) {
				writeNotFound(w, "inventory source not found")
				return
			}
			writeServiceUnavailable(w, "delete failed")
			return
		}
		emitAuditEvent(r, auditProvider, pd.ID, "inventory_source.delete", "inventory_source", id, AuditOutcomeSuccess)
		w.WriteHeader(http.StatusNoContent)
	})
}

func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
