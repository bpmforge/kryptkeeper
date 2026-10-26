// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"net/http"
	"time"

	"kryptkeeper/internal/connectors"
)

const connectorProbeTimeout = 10 * time.Second

// handleConnectorTest serves POST /api/v1/connectors/{id}/test: one live
// Health probe of the stored connector. A tenant's foreign row and a missing
// row both answer 404 so the id space is not an oracle.
func handleConnectorTest(w http.ResponseWriter, r *http.Request, pd AuthPrincipal, id string, store ConnectorStore, provider CertificateProvider, creds OutboundCredentialStore, audit AuditProvider) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	if !isAdminRole(pd.Role) {
		emitAuditEvent(r, audit, pd.ID, "connector.test", "connector", id, AuditOutcomeDenied)
		writeForbidden(w, "testing a connector needs the pki-admin role")
		return
	}
	rec, err := store.Get(r.Context(), id)
	if err != nil || !stampedTenantVisible(pd, rec.Tenant) {
		outcome := AuditOutcomeDenied
		if err != nil {
			outcome = AuditOutcomeFailure
		}
		emitAuditEvent(r, audit, pd.ID, "connector.test", "connector", id, outcome)
		writeNotFound(w, "connector not found")
		return
	}
	health := connectors.Health{Status: "unknown", Detail: "connector type " + rec.Type + " has no runtime implementation"}
	if c := buildRuntimeConnector(rec, provider, creds); c != nil {
		ctx, cancel := context.WithTimeout(r.Context(), connectorProbeTimeout)
		health = c.Health(ctx)
		cancel()
	}
	health.Detail = scrubUpstreamError(health.Detail)
	emitAuditEvent(r, audit, pd.ID, "connector.test", "connector", id, AuditOutcomeSuccess)
	writeJSONStatus(w, http.StatusOK, struct {
		Status string `json:"status"`
		Detail string `json:"detail"`
	}{Status: health.Status, Detail: health.Detail})
}
