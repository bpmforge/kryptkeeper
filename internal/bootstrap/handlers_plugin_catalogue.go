// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
	"kryptkeeper/internal/plugins/delivery"
)

// registerPluginCatalogueHandlers mounts the signed-catalogue API (W38-11,
// D-328). Every route is pki-admin: listing makes the hub fetch from the
// network, so it is an administrator's act, not a background read, and every
// outcome writes an audit row. Install returns what a manual upload returns
// (a disabled version); enabling still goes through the delivery-plugins
// enable route and its second-person approval.
func registerPluginCatalogueHandlers(mux *http.ServeMux, auth *Authenticator, mgr *DeliveryPluginManager, auditProvider AuditProvider) {
	authenticate := func(w http.ResponseWriter, r *http.Request, action, target string) (AuthPrincipal, bool) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", action, "delivery_plugin", target, AuditOutcomeDenied)
			writeUnauthorized(w)
			return pd, false
		}
		if !isAdminRole(pd.Role) {
			emitAuditEvent(r, auditProvider, pd.ID, action, "delivery_plugin", target, AuditOutcomeDenied)
			writeForbidden(w, "pki-admin role required for the plugin catalogue")
			return pd, false
		}
		if denyNonSuperAdminGlobal(w, r, auditProvider, pd, action, "delivery_plugin", target) {
			return pd, false
		}
		return pd, true
	}
	fail := func(w http.ResponseWriter, r *http.Request, pd AuthPrincipal, action, target string, err error) {
		emitAuditEventDetail(r, auditProvider, pd.ID, action, "delivery_plugin", target, AuditOutcomeFailure, truncateForAudit(err.Error()))
		switch {
		case errors.Is(err, errCatalogueNotFound), errors.Is(err, errPluginNotFound):
			writeNotFound(w, err.Error())
		case errors.Is(err, errCatalogueIncompat), errors.Is(err, errPluginVersionExists), errors.Is(err, errPluginInUse):
			writeConflict(w, err.Error())
		case errors.Is(err, errCatalogueOff), errors.Is(err, errPluginsOff):
			writeServiceUnavailable(w, err.Error())
		case errors.Is(err, errCatalogueFetch), errors.Is(err, errCatalogueVerify):
			// The upstream is the failing party: say so, and do not echo
			// anything beyond the wrapped fetch error.
			writeErrorEnvelope(w, http.StatusBadGateway, "bad_gateway", err.Error())
		case errors.Is(err, delivery.ErrHashMismatch), errors.Is(err, errCatalogueMismatch), errors.Is(err, errPluginSignature),
			errors.Is(err, delivery.ErrGrantExceedsManifest), errors.Is(err, delivery.ErrKindNotRunnable),
			strings.HasPrefix(err.Error(), "manifest:"), strings.HasPrefix(err.Error(), "plugin signature:"),
			strings.HasPrefix(err.Error(), "catalogue:"), strings.HasPrefix(err.Error(), "compile plugin"), strings.Contains(err.Error(), "does not export"):
			writeBadRequest(w, err.Error())
		default:
			logging.Infof("plugin catalogue: %v", err)
			writeServiceUnavailable(w, "plugin catalogue unavailable")
		}
	}
	ready := func() error {
		switch {
		case mgr == nil:
			return errPluginsOff
		case mgr.catalogue == nil:
			return errCatalogueOff
		}
		return nil
	}

	mux.HandleFunc("/api/v1/plugin-catalogue", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, "GET")
			return
		}
		const action = "plugin_catalogue.list"
		pd, ok := authenticate(w, r, action, "-")
		if !ok {
			return
		}
		if err := ready(); err != nil {
			fail(w, r, pd, action, "-", err)
			return
		}
		cat, err := mgr.catalogue.Load(r.Context())
		if err != nil {
			fail(w, r, pd, action, "-", err)
			return
		}
		rows, err := mgr.catalogue.Rows(r.Context(), cat)
		if err != nil {
			fail(w, r, pd, action, "-", err)
			return
		}
		emitAuditEvent(r, auditProvider, pd.ID, action, "delivery_plugin", "-", AuditOutcomeSuccess)
		writeJSONData(w, map[string]any{"generated_at": cat.GeneratedAt, "entries": rows})
	})

	mux.HandleFunc("/api/v1/plugin-catalogue/import", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, "POST")
			return
		}
		const action = "plugin_catalogue.import"
		pd, ok := authenticate(w, r, action, "-")
		if !ok {
			return
		}
		if mgr == nil {
			fail(w, r, pd, action, "-", errPluginsOff)
			return
		}
		var req struct {
			CatalogueBase64 string `json:"catalogue_base64"`
			CatalogueBundle string `json:"catalogue_bundle"`
			ID              string `json:"id"`
			Version         string `json:"version"`
			ManifestBase64  string `json:"manifest_base64"`
			Bundle          string `json:"bundle"`
			WasmBase64      string `json:"wasm_base64"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPluginUpload)).Decode(&req); err != nil {
			if rejectOversizeBody(w, err) {
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, action, "delivery_plugin", "-", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}
		dec := func(s string) []byte { b, _ := base64.StdEncoding.DecodeString(s); return b }
		cat, manifest, wasm := dec(req.CatalogueBase64), dec(req.ManifestBase64), dec(req.WasmBase64)
		if req.ID == "" || len(cat) == 0 || len(manifest) == 0 || len(wasm) == 0 {
			emitAuditEvent(r, auditProvider, pd.ID, action, "delivery_plugin", "-", AuditOutcomeFailure)
			writeBadRequest(w, "id, catalogue_base64, manifest_base64 and wasm_base64 are required (base64)")
			return
		}
		v, err := mgr.ImportCatalogue(r.Context(), cat, req.CatalogueBundle, req.ID, req.Version, manifest, []byte(req.Bundle), wasm, pd.ID)
		if err != nil {
			fail(w, r, pd, action, req.ID, err)
			return
		}
		writeInstalled(w, r, auditProvider, pd, action, v)
	})

	mux.HandleFunc("/api/v1/plugin-catalogue/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/plugin-catalogue/"), "/"), "/")
		if len(parts) != 2 || parts[1] != "install" || r.Method != http.MethodPost {
			writeNotFound(w, "no such plugin catalogue route")
			return
		}
		const action = "plugin_catalogue.install"
		id := parts[0]
		pd, ok := authenticate(w, r, action, id)
		if !ok {
			return
		}
		if err := ready(); err != nil {
			fail(w, r, pd, action, id, err)
			return
		}
		var req struct {
			Version string `json:"version"`
		}
		if r.ContentLength != 0 {
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, action, "delivery_plugin", id, AuditOutcomeFailure)
				writeBadRequest(w, "invalid request body (optional version)")
				return
			}
		}
		v, err := mgr.catalogue.Install(r.Context(), id, req.Version, pd.ID)
		if err != nil {
			fail(w, r, pd, action, id, err)
			return
		}
		writeInstalled(w, r, auditProvider, pd, action, v)
	})
}

// writeInstalled audits and answers 201 with the installed (disabled) version,
// the same body the upload route returns.
func writeInstalled(w http.ResponseWriter, r *http.Request, auditProvider AuditProvider, pd AuthPrincipal, action string, v DeliveryPluginVersion) {
	emitAuditEventDetail(r, auditProvider, pd.ID, action, "delivery_plugin", v.PluginID, AuditOutcomeSuccess, pluginAuditDetail(v))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(struct {
		Data DeliveryPluginVersion `json:"data"`
	}{Data: v})
}
