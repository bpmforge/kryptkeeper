// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"kryptkeeper/internal/acme"
	"kryptkeeper/internal/logging"
)

const acmeDeviceResource = "acme_device"

type acmeDeviceView struct {
	Identifier string    `json:"identifier"`
	Label      string    `json:"label"`
	TenantID   string    `json:"tenant_id"`
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
}

func deviceTenant(stamped string) string {
	if stamped == "" {
		return DefaultTenant
	}
	return stamped
}

// RegisterACMEDeviceHandlers mounts the device inventory API behind ACME
// device-attest-01 (W40-02, D-317): POST /api/v1/acme/devices adds a permanent
// identifier, GET lists the caller's tenant's entries, DELETE
// /api/v1/acme/devices/{identifier} removes one (the identifier is
// percent-encoded, as it may contain "/"). pki-admin only. An identifier is
// unique across the hub, so a tenant cannot claim a device another tenant
// already owns, and with MULTI_TENANCY on a tenant sees and removes only its
// own entries.
func RegisterACMEDeviceHandlers(mux *http.ServeMux, auth *Authenticator, store acme.DeviceAllowlist, auditProvider AuditProvider) {
	if store == nil {
		return
	}
	authorize := func(w http.ResponseWriter, r *http.Request, action, resID string) (AuthPrincipal, bool) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", action, acmeDeviceResource, resID, AuditOutcomeDenied)
			writeUnauthorized(w)
			return AuthPrincipal{}, false
		}
		if !isAdminRole(pd.Role) {
			emitAuditEvent(r, auditProvider, pd.ID, action, acmeDeviceResource, resID, AuditOutcomeDenied)
			writeForbidden(w, "pki-admin role required for the ACME device inventory")
			return AuthPrincipal{}, false
		}
		return pd, true
	}
	writeData := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		if err := json.NewEncoder(w).Encode(struct {
			Data any `json:"data"`
		}{Data: v}); err != nil {
			logging.Infof("acme device response: %v", err)
		}
	}
	view := func(e acme.DeviceEntry) acmeDeviceView {
		return acmeDeviceView{e.Identifier, e.Label, deviceTenant(e.TenantID), e.CreatedBy, e.CreatedAt}
	}

	mux.HandleFunc("/api/v1/acme/devices", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			pd, ok := authorize(w, r, "acme.device.list", "-")
			if !ok {
				return
			}
			list, err := store.List(r.Context())
			if err != nil {
				logging.Infof("acme device list: %v", err)
				emitAuditEvent(r, auditProvider, pd.ID, "acme.device.list", acmeDeviceResource, "-", AuditOutcomeFailure)
				writeServiceUnavailable(w, "acme device inventory unavailable")
				return
			}
			views := make([]acmeDeviceView, 0, len(list))
			for _, e := range list {
				if stampedTenantVisible(pd, e.TenantID) {
					views = append(views, view(e))
				}
			}
			emitAuditEvent(r, auditProvider, pd.ID, "acme.device.list", acmeDeviceResource, "-", AuditOutcomeSuccess)
			writeData(w, http.StatusOK, views)
		case http.MethodPost:
			pd, ok := authorize(w, r, "acme.device.add", "-")
			if !ok {
				return
			}
			var req struct {
				Identifier string `json:"identifier"`
				Label      string `json:"label"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&req); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "acme.device.add", acmeDeviceResource, "-", AuditOutcomeFailure)
				if rejectOversizeBody(w, err) {
					return
				}
				writeBadRequest(w, "invalid request body")
				return
			}
			req.Label = strings.TrimSpace(req.Label)
			if err := acme.ValidateDeviceIdentifier(req.Identifier); err != nil {
				emitAuditEventDetail(r, auditProvider, pd.ID, "acme.device.add", acmeDeviceResource, "-", AuditOutcomeFailure, "invalid identifier")
				writeBadRequest(w, "identifier: "+err.Error())
				return
			}
			if len(req.Label) > 200 {
				emitAuditEventDetail(r, auditProvider, pd.ID, "acme.device.add", acmeDeviceResource, req.Identifier, AuditOutcomeFailure, "label too long")
				writeBadRequest(w, "label must be at most 200 characters")
				return
			}
			tenant := ""
			if multiTenancyEnabled() && pd.Tenant != DefaultTenant {
				tenant = pd.Tenant
			}
			entry := acme.DeviceEntry{Identifier: req.Identifier, TenantID: tenant, Label: req.Label, CreatedBy: pd.ID, CreatedAt: time.Now().UTC().Truncate(time.Second)}
			err := store.Add(r.Context(), entry)
			switch {
			case err == nil:
				emitAuditEventDetail(r, auditProvider, pd.ID, "acme.device.add", acmeDeviceResource, req.Identifier, AuditOutcomeSuccess, req.Label)
				writeData(w, http.StatusCreated, view(entry))
			case errors.Is(err, acme.ErrDeviceExists):
				// The same answer whoever owns the entry, so a tenant cannot
				// probe another tenant's inventory beyond "taken".
				emitAuditEvent(r, auditProvider, pd.ID, "acme.device.add", acmeDeviceResource, req.Identifier, AuditOutcomeFailure)
				writeConflict(w, "device already in the inventory")
			default:
				logging.Infof("acme device add: %v", err)
				emitAuditEvent(r, auditProvider, pd.ID, "acme.device.add", acmeDeviceResource, req.Identifier, AuditOutcomeFailure)
				writeServiceUnavailable(w, "acme device inventory unavailable")
			}
		default:
			writeMethodNotAllowed(w, "GET, POST")
		}
	})

	mux.HandleFunc("/api/v1/acme/devices/", func(w http.ResponseWriter, r *http.Request) {
		escaped := strings.TrimPrefix(r.URL.EscapedPath(), "/api/v1/acme/devices/")
		id, err := url.PathUnescape(escaped)
		if err != nil || id == "" {
			emitAuditEvent(r, auditProvider, "", "acme.device.remove", acmeDeviceResource, "-", AuditOutcomeFailure)
			writeNotFound(w, "device not found")
			return
		}
		if r.Method != http.MethodDelete {
			writeMethodNotAllowed(w, http.MethodDelete)
			return
		}
		pd, ok := authorize(w, r, "acme.device.remove", id)
		if !ok {
			return
		}
		// A tenant's request for another tenant's entry is a plain not-found.
		entry, found, err := store.Lookup(r.Context(), id)
		if err == nil && (!found || !stampedTenantVisible(pd, entry.TenantID)) {
			emitAuditEvent(r, auditProvider, pd.ID, "acme.device.remove", acmeDeviceResource, id, AuditOutcomeFailure)
			writeNotFound(w, "device not found")
			return
		}
		if err == nil {
			err = store.Delete(r.Context(), id)
		}
		switch {
		case err == nil:
			emitAuditEvent(r, auditProvider, pd.ID, "acme.device.remove", acmeDeviceResource, id, AuditOutcomeSuccess)
			w.WriteHeader(http.StatusNoContent)
		case errors.Is(err, acme.ErrDeviceNotFound):
			emitAuditEvent(r, auditProvider, pd.ID, "acme.device.remove", acmeDeviceResource, id, AuditOutcomeFailure)
			writeNotFound(w, "device not found")
		default:
			logging.Infof("acme device remove: %v", err)
			emitAuditEvent(r, auditProvider, pd.ID, "acme.device.remove", acmeDeviceResource, id, AuditOutcomeFailure)
			writeServiceUnavailable(w, "acme device inventory unavailable")
		}
	})
}

// NewACMEDeviceCheck returns the inventory test the ACME server runs before
// attesting and at finalize. With MULTI_TENANCY on, the entry's tenant must be
// the tenant of the CA issuing the certificate (tenants may be nil only when
// tenancy is off); otherwise any entry in the inventory allows the device.
// A lookup failure is an error, which the server treats as a refusal.
func NewACMEDeviceCheck(list acme.DeviceAllowlist, tenants TenantStore) func(ctx context.Context, caID, identifier string) (bool, error) {
	return func(ctx context.Context, caID, identifier string) (bool, error) {
		entry, found, err := list.Lookup(ctx, identifier)
		if err != nil || !found {
			return false, err
		}
		if !multiTenancyEnabled() {
			return true, nil
		}
		if tenants == nil {
			return false, errors.New("multi-tenancy is on but no tenant store is available")
		}
		caTenant, err := tenants.CATenant(ctx, caID)
		if err != nil {
			return false, err
		}
		return deviceTenant(entry.TenantID) == deviceTenant(caTenant), nil
	}
}

// NewACMETemplateDeviceCheck returns the template test for device attestation:
// the template must exist, be active and carry the explicit flag. Anything else,
// including a lookup failure, is a refusal.
func NewACMETemplateDeviceCheck(templates TemplateProvider) func(ctx context.Context, templateID string) (bool, error) {
	return func(ctx context.Context, templateID string) (bool, error) {
		if templates == nil || templateID == "" {
			return false, nil
		}
		tpl, found, err := templates.GetTemplate(ctx, templateID)
		if err != nil {
			return false, err
		}
		return found && tpl.Active && tpl.DeviceAttestation, nil
	}
}
