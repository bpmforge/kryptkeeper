// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/logging"
)

// registerExternalCAHandlers mounts POST /api/v1/cas/external (W36-02): bind a
// CA row to an issuer connector so the hub's front doors sign through it. It
// is a separate registration, called next to RegisterConnectorHandlers, because
// it needs the connector and credential stores registerCAHandlers never sees.
// The exact pattern wins over the /api/v1/cas/ subtree.
func registerExternalCAHandlers(mux *http.ServeMux, auth *Authenticator, caProvider CAProvider, connectorStore ConnectorStore, creds OutboundCredentialStore, tenantStore TenantStore, auditProvider AuditProvider) {
	dualControl := NewKeyDualControlFromEnv(NewPendingActionStoreFromEnv())
	mux.HandleFunc("/api/v1/cas/external", func(w http.ResponseWriter, r *http.Request) {
		handleCAExternalCreate(w, r, auth, caProvider, connectorStore, creds, tenantStore, auditProvider, dualControl)
	})
}

// externalBindingTenantError applies D-308 for a principal: under multi-tenancy
// a tenant-scoped caller may bind only a connector stamped with their own
// tenant and a credential in their tenant. A default-tenant credential is a
// global-admin asset and binds only for a bypass principal.
func externalBindingTenantError(r *http.Request, pd AuthPrincipal, rec ConnectorRecord, creds OutboundCredentialStore) error {
	if !multiTenancyEnabled() {
		return nil
	}
	connTenant := rec.Tenant
	if connTenant == "" {
		connTenant = DefaultTenant
	}
	if !tenantBypass(pd) && connTenant != pd.Tenant {
		return errExternalCATenantMismatch
	}
	if rec.CredentialRef == "" || creds == nil {
		return nil
	}
	meta, err := creds.Get(r.Context(), rec.CredentialRef)
	if err != nil {
		return fmt.Errorf("connector credential cannot be checked: %w", err)
	}
	credTenant := meta.Tenant
	if credTenant == "" {
		credTenant = DefaultTenant
	}
	switch {
	case credTenant == connTenant:
		return nil
	case credTenant == DefaultTenant && tenantBypass(pd):
		return nil
	}
	return errExternalCATenantMismatch
}

func handleCAExternalCreate(w http.ResponseWriter, r *http.Request, auth *Authenticator, caProvider CAProvider, connectorStore ConnectorStore, creds OutboundCredentialStore, tenantStore TenantStore, auditProvider AuditProvider, dc *KeyDualControl) {
	pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
	if err != nil {
		emitAuditEvent(r, auditProvider, "", "ca.external.create", "ca", "external", AuditOutcomeDenied)
		writeUnauthorized(w)
		return
	}
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	if !isAdminRole(pd.Role) {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.external.create", "ca", "external", AuditOutcomeDenied)
		writeForbidden(w, "admin role required to create an external CA")
		return
	}
	creator, ok := caProvider.(ExternalCACreator)
	if !ok || connectorStore == nil {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.external.create", "ca", "external", AuditOutcomeFailure)
		writeServiceUnavailable(w, "external CAs are not supported by this provider")
		return
	}
	var req struct {
		Name             string `json:"name"`
		ConnectorID      string `json:"connector_id"`
		TrustPEM         string `json:"trust_pem"`
		ApprovedActionID string `json:"approved_action_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.external.create", "ca", "external", AuditOutcomeFailure)
		writeBadRequest(w, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.ConnectorID = strings.TrimSpace(req.ConnectorID)
	if req.Name == "" || req.ConnectorID == "" || strings.TrimSpace(req.TrustPEM) == "" {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.external.create", "ca", "external", AuditOutcomeFailure)
		writeBadRequest(w, "name, connector_id and trust_pem are required")
		return
	}
	rec, gerr := connectorStore.Get(r.Context(), req.ConnectorID)
	if gerr != nil {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.external.create", "ca", "external", AuditOutcomeFailure)
		writeBadRequest(w, "unknown connector")
		return
	}
	// A foreign tenant's connector answers like a missing one: no existence oracle.
	if !stampedTenantVisible(pd, rec.Tenant) {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.external.create", "ca", "external", AuditOutcomeDenied)
		writeBadRequest(w, "unknown connector")
		return
	}
	if terr := externalConnectorTypeError(rec.Type); terr != nil {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.external.create", "ca", "external", AuditOutcomeFailure)
		writeBadRequest(w, terr.Error())
		return
	}
	if terr := externalBindingTenantError(r, pd, rec, creds); terr != nil {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.external.create", "ca", "external", AuditOutcomeDenied)
		writeBadRequest(w, terr.Error())
		return
	}
	if !dc.gate(w, r, auth, auditProvider, pd, egressGate{
		actionType:  keyActionCAImport,
		keyID:       "external:" + req.ConnectorID,
		approvedID:  req.ApprovedActionID,
		auditAction: "ca.external.create",
		message:     "dual control is on - a second approver must approve this external CA; after approval retry with approved_action_id",
	}) {
		return
	}
	created, err := creator.CreateExternalCA(r.Context(), req.Name, req.ConnectorID, []byte(req.TrustPEM))
	if err != nil {
		emitAuditEvent(r, auditProvider, pd.ID, "ca.external.create", "ca", "external", AuditOutcomeFailure)
		if errors.Is(err, ca.ErrExternalCAInvalid) {
			writeBadRequest(w, err.Error())
			return
		}
		logging.Warnf("external ca create failed: %v", err)
		writeServiceUnavailable(w, "external ca create failed")
		return
	}
	created = withCAEffectiveStatus(created, time.Now().UTC())
	created.CertificatePEM = ""
	caTenant := pd.Tenant
	if tenantBypass(pd) {
		caTenant = rec.Tenant
	}
	if caTenant != "" && caTenant != DefaultTenant && tenantStore != nil {
		if merr := tenantStore.SetCATenant(r.Context(), created.ID, caTenant); merr != nil {
			logging.Warnf("auto-map ca %s to tenant %s failed: %v", created.ID, caTenant, merr)
		}
	}
	detail, _ := json.Marshal(map[string]any{
		"connector_id":       req.ConnectorID,
		"trust_fingerprints": trustFingerprints([]byte(req.TrustPEM)),
	})
	emitAuditEventDetail(r, auditProvider, pd.ID, "ca.external.create", "ca", created.ID, AuditOutcomeSuccess, string(detail))
	writeJSONStatus(w, http.StatusCreated, struct {
		Data CAListItem `json:"data"`
	}{Data: created})
}

// trustFingerprints lists the SHA-256 of each certificate in a bundle so the
// audit row records which upstream the operator vouched for.
func trustFingerprints(bundle []byte) []string {
	out := []string{}
	rest := bundle
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			continue
		}
		sum := sha256.Sum256(block.Bytes)
		out = append(out, hex.EncodeToString(sum[:]))
	}
}
