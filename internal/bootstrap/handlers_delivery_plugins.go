// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"kryptkeeper/internal/logging"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/plugins/delivery"
)

// maxPluginUpload bounds an install request: a base64 module plus manifest.
const maxPluginUpload = 48 << 20

// registerDeliveryPluginHandlers mounts the delivery plugin API (W20-20).
// Reading is open to any authenticated principal, so operators can see what
// a target's plugin may do; every change needs pki-admin, and enabling a
// plugin with High or Critical capabilities goes through the approval queue.
// With plugins off (nil manager) every route answers 503 and says why.
func registerDeliveryPluginHandlers(mux *http.ServeMux, auth *Authenticator, mgr *DeliveryPluginManager, auditProvider AuditProvider) {
	authenticate := func(w http.ResponseWriter, r *http.Request, action string, admin bool) (AuthPrincipal, bool) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", action, "delivery_plugin", "-", AuditOutcomeDenied)
			writeUnauthorized(w)
			return pd, false
		}
		if admin && !isAdminRole(pd.Role) {
			emitAuditEvent(r, auditProvider, pd.ID, action, "delivery_plugin", "-", AuditOutcomeDenied)
			writeForbidden(w, "pki-admin role required to change delivery plugins")
			return pd, false
		}
		if admin && denyNonSuperAdminGlobal(w, r, auditProvider, pd, action, "delivery_plugin", "-") {
			return pd, false
		}
		if mgr == nil {
			writeServiceUnavailable(w, errPluginsOff.Error())
			return pd, false
		}
		return pd, true
	}
	fail := func(w http.ResponseWriter, err error) {
		switch {
		case errors.Is(err, errPluginNotFound):
			writeNotFound(w, err.Error())
		case errors.Is(err, errPluginVersionExists), errors.Is(err, errPluginInUse):
			writeConflict(w, err.Error())
		case errors.Is(err, delivery.ErrHashMismatch), errors.Is(err, delivery.ErrGrantExceedsManifest), strings.HasPrefix(err.Error(), "manifest:"),
			errors.Is(err, errPluginSignature), strings.HasPrefix(err.Error(), "plugin signature:"),
			strings.HasPrefix(err.Error(), "compile plugin"), strings.Contains(err.Error(), "does not export"):
			writeBadRequest(w, err.Error())
		default:
			logging.Infof("delivery plugins: %v", err)
			writeServiceUnavailable(w, "delivery plugins unavailable")
		}
	}

	mux.HandleFunc("/api/v1/delivery-plugins", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if _, ok := authenticate(w, r, "delivery_plugin.list", false); !ok {
				return
			}
			list, err := mgr.List(r.Context())
			if err != nil {
				fail(w, err)
				return
			}
			writeJSONData(w, list)
		case http.MethodPost:
			pd, ok := authenticate(w, r, "delivery_plugin.install", true)
			if !ok {
				return
			}
			// A signature covers manifest.json's exact bytes, which re-encoding
			// as a JSON object would change, so a signed install sends them
			// as manifest_base64.
			var req struct {
				Manifest       json.RawMessage `json:"manifest"`
				ManifestBase64 string          `json:"manifest_base64"`
				Signature      string          `json:"signature"`
				WasmBase64     string          `json:"wasm_base64"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPluginUpload)).Decode(&req); err != nil {
				if rejectOversizeBody(w, err) {
					return
				}
				emitAuditEvent(r, auditProvider, pd.ID, "delivery_plugin.install", "delivery_plugin", "-", AuditOutcomeFailure)
				writeBadRequest(w, "invalid request body (manifest object and wasm_base64)")
				return
			}
			manifest := []byte(req.Manifest)
			switch {
			case req.ManifestBase64 != "" && len(req.Manifest) > 0:
				emitAuditEvent(r, auditProvider, pd.ID, "delivery_plugin.install", "delivery_plugin", "-", AuditOutcomeFailure)
				writeBadRequest(w, "send manifest or manifest_base64, not both")
				return
			case req.ManifestBase64 != "":
				raw, err := base64.StdEncoding.DecodeString(req.ManifestBase64)
				if err != nil || len(raw) == 0 {
					emitAuditEvent(r, auditProvider, pd.ID, "delivery_plugin.install", "delivery_plugin", "-", AuditOutcomeFailure)
					writeBadRequest(w, "manifest_base64 is not base64")
					return
				}
				manifest = raw
			case strings.TrimSpace(req.Signature) != "":
				emitAuditEvent(r, auditProvider, pd.ID, "delivery_plugin.install", "delivery_plugin", "-", AuditOutcomeFailure)
				writeBadRequest(w, "a signed install must send manifest.json's exact bytes as manifest_base64")
				return
			}
			wasm, err := base64.StdEncoding.DecodeString(req.WasmBase64)
			if err != nil || len(wasm) == 0 {
				emitAuditEvent(r, auditProvider, pd.ID, "delivery_plugin.install", "delivery_plugin", "-", AuditOutcomeFailure)
				writeBadRequest(w, "wasm_base64 is not base64")
				return
			}
			v, err := mgr.Install(r.Context(), manifest, wasm, req.Signature, pd.ID)
			if err != nil {
				emitAuditEventDetail(r, auditProvider, pd.ID, "delivery_plugin.install", "delivery_plugin", "-", AuditOutcomeFailure, truncateForAudit(err.Error()))
				fail(w, err)
				return
			}
			emitAuditEventDetail(r, auditProvider, pd.ID, "delivery_plugin.install", "delivery_plugin", v.PluginID, AuditOutcomeSuccess, pluginAuditDetail(v))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(struct {
				Data DeliveryPluginVersion `json:"data"`
			}{Data: v})
		default:
			writeMethodNotAllowed(w, "GET, POST")
		}
	})

	mux.HandleFunc("/api/v1/delivery-plugins/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/delivery-plugins/"), "/"), "/")
		id := parts[0]
		switch {
		case len(parts) == 1 && r.Method == http.MethodGet:
			if _, ok := authenticate(w, r, "delivery_plugin.get", false); !ok {
				return
			}
			p, err := mgr.Get(r.Context(), id)
			if err != nil {
				fail(w, err)
				return
			}
			writeJSONData(w, p)
		case len(parts) == 1 && r.Method == http.MethodDelete:
			pd, ok := authenticate(w, r, "delivery_plugin.remove", true)
			if !ok {
				return
			}
			if err := mgr.Remove(r.Context(), id); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "delivery_plugin.remove", "delivery_plugin", id, AuditOutcomeFailure)
				fail(w, err)
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "delivery_plugin.remove", "delivery_plugin", id, AuditOutcomeSuccess)
			w.WriteHeader(http.StatusNoContent)
		case len(parts) == 2 && parts[1] == "disable" && r.Method == http.MethodPost:
			pd, ok := authenticate(w, r, "delivery_plugin.disable", true)
			if !ok {
				return
			}
			if err := mgr.Disable(r.Context(), id); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "delivery_plugin.disable", "delivery_plugin", id, AuditOutcomeFailure)
				fail(w, err)
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "delivery_plugin.disable", "delivery_plugin", id, AuditOutcomeSuccess)
			writeJSONData(w, map[string]string{"status": "disabled"})
		case len(parts) == 4 && parts[1] == "versions" && parts[3] == "enable" && r.Method == http.MethodPost:
			pd, ok := authenticate(w, r, "delivery_plugin.enable", true)
			if !ok {
				return
			}
			v, actionID, err := mgr.RequestEnable(r.Context(), id, parts[2], pd.ID, pd.Tenant)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "delivery_plugin.enable", "delivery_plugin", id, AuditOutcomeFailure)
				fail(w, err)
				return
			}
			if actionID != "" {
				emitAuditEventDetail(r, auditProvider, pd.ID, "delivery_plugin.enable_requested", "delivery_plugin", id, AuditOutcomeSuccess,
					pluginAuditDetail(v)+" pending_action="+actionID)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusAccepted)
				_ = json.NewEncoder(w).Encode(struct {
					Data any `json:"data"`
				}{Data: map[string]string{"status": "pending_approval", "pending_action_id": actionID,
					"message": "this version's capabilities need a second person: approve it in Approvals"}})
				return
			}
			emitAuditEventDetail(r, auditProvider, pd.ID, "delivery_plugin.enable", "delivery_plugin", id, AuditOutcomeSuccess, pluginAuditDetail(v))
			writeJSONData(w, map[string]string{"status": "enabled", "version": v.Version})
		default:
			writeNotFound(w, "no such delivery plugin route")
		}
	})
}

func pluginAuditDetail(v DeliveryPluginVersion) string {
	d := fmt.Sprintf("version=%s sha256=%s capabilities=%s trust=%s", v.Version, v.SHA256, v.CapabilityTier, v.Tier)
	if v.SignerKeyID != "" {
		d += " signer=" + v.SignerKeyID
	}
	return d
}

func truncateForAudit(s string) string {
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}
