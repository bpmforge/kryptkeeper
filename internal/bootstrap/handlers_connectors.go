// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/connectors"
)

// W11-03: the connectors API. Listing carries a LIVE health probe per row —
// a failing connector is a visible state on the listing, never a dropped
// row. Rows whose type has no runtime implementation yet (acme before
// W11-04) report health "unknown" with a reason, which is the honest state.

// buildRuntimeConnector materializes a stored row into a runtime connector.
// Returns nil when the type has no implementation yet.
func buildRuntimeConnector(rec ConnectorRecord, provider CertificateProvider, creds OutboundCredentialStore) connectors.IssuerConnector {
	switch rec.Type {
	case "internal":
		var cfg struct {
			CAID string `json:"ca_id"`
		}
		_ = json.Unmarshal([]byte(rec.ConfigJSON), &cfg) // malformed config zeroes out; connector then fails clearly on use
		return NewInternalIssuerConnector(rec.ID, provider, cfg.CAID)
	case "acme":
		// W11-04: the upstream RFC 8555 client.
		return wrapWithDCVTracking(NewACMEIssuerConnector(rec, provider, creds), rec.Tenant, sharedDCVTracker())
	case "digicert", "scep", "est", "wstep":
		// W27-35: credentials resolve lazily per call from credential_ref.
		return NewUpstreamIssuerConnector(rec, creds)
	default:
		return nil
	}
}

// BuildConnectorRegistry loads every stored connector row into a registry.
// Callers that need issuance routing (takeover, W11-04 renewals) share this
// one construction path.
func BuildConnectorRegistry(ctx context.Context, store ConnectorStore, provider CertificateProvider, creds OutboundCredentialStore) (*connectors.Registry, error) {
	registry := connectors.NewRegistry()
	if store == nil {
		return registry, nil
	}
	recs, err := store.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, rec := range recs {
		if c := buildRuntimeConnector(rec, provider, creds); c != nil {
			registry.Register(c)
		}
	}
	return registry, nil
}

type connectorListEntry struct {
	ConnectorRecord
	Health connectors.Health `json:"health"`
}

// RegisterConnectorHandlers mounts /api/v1/connectors (GET list+health,
// POST create) and /api/v1/connectors/{id} (DELETE).
func RegisterConnectorHandlers(mux *http.ServeMux, auth *Authenticator, store ConnectorStore, provider CertificateProvider, creds OutboundCredentialStore, auditProvider AuditProvider) {
	registerDCVHandlers(mux, auth, sharedDCVTracker, auditProvider)
	if store != nil {
		startDCVWarnLoop(dcvWarnInterval(), sharedDCVTracker, auditProvider)
	}
	mux.HandleFunc("/api/v1/connectors", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return
		}
		if store == nil {
			writeServiceUnavailable(w, "connector store not configured")
			return
		}
		switch r.Method {
		case http.MethodGet:
			recs, err := store.List(r.Context())
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "connector.list", "connector", "connectors", AuditOutcomeFailure)
				writeServiceUnavailable(w, "connector list failed")
				return
			}
			entries := make([]connectorListEntry, 0, len(recs))
			for _, rec := range recs {
				if !stampedTenantVisible(pd, rec.Tenant) {
					continue
				}
				entry := connectorListEntry{ConnectorRecord: rec}
				if c := buildRuntimeConnector(rec, provider, creds); c != nil {
					probeCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
					entry.Health = c.Health(probeCtx)
					cancel()
				} else {
					entry.Health = connectors.Health{Status: "unknown", Detail: "connector type " + rec.Type + " has no runtime implementation"}
				}
				entries = append(entries, entry)
			}
			emitAuditEvent(r, auditProvider, pd.ID, "connector.list", "connector", "connectors", AuditOutcomeSuccess)
			writeJSONStatus(w, http.StatusOK, struct {
				Data []connectorListEntry `json:"data"`
			}{Data: entries})
		case http.MethodPost:
			body := http.MaxBytesReader(w, r.Body, 64*1024)
			defer body.Close()
			raw, err := io.ReadAll(body)
			if err != nil {
				writeBadRequestJSON(w, "invalid request body")
				return
			}
			var req ConnectorRecord
			if err := json.Unmarshal(raw, &req); err != nil {
				writeBadRequestJSON(w, "invalid request body")
				return
			}
			if err := validateConnectorRecord(req); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "connector.create", "connector", "connectors", AuditOutcomeFailure)
				writeBadRequestJSON(w, err.Error())
				return
			}
			id, err := newConnectorID()
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
				emitAuditEvent(r, auditProvider, pd.ID, "connector.create", "connector", id, AuditOutcomeFailure)
				writeServiceUnavailable(w, "create failed")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "connector.create", "connector", id, AuditOutcomeSuccess)
			writeJSONStatus(w, http.StatusCreated, struct {
				Data ConnectorRecord `json:"data"`
			}{Data: created})
		default:
			writeMethodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
		}
	})

	mux.HandleFunc("/api/v1/connectors/", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return
		}
		if store == nil {
			writeServiceUnavailable(w, "connector store not configured")
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/connectors/")
		if id == "" || strings.Contains(id, "/") {
			writeNotFound(w, "connector not found")
			return
		}
		if r.Method != http.MethodDelete {
			writeMethodNotAllowed(w, http.MethodDelete)
			return
		}
		// Look up first so another tenant's connector is indistinguishable from
		// a missing one. A lookup failure is treated as not found (deny).
		existing, gerr := store.Get(r.Context(), id)
		if gerr != nil || !stampedTenantVisible(pd, existing.Tenant) {
			// A lookup failure and a foreign tenant's row both answer 404 (no
			// existence oracle) but must still leave a row (W22-06).
			outcome := AuditOutcomeDenied
			if gerr != nil {
				outcome = AuditOutcomeFailure
			}
			emitAuditEvent(r, auditProvider, pd.ID, "connector.delete", "connector", id, outcome)
			writeNotFound(w, "connector not found")
			return
		}
		if err := store.Delete(r.Context(), id); err != nil {
			if errors.Is(err, errConnectorNotFound) {
				emitAuditEvent(r, auditProvider, pd.ID, "connector.delete", "connector", id, AuditOutcomeFailure)
				writeNotFound(w, "connector not found")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "connector.delete", "connector", id, AuditOutcomeFailure)
			writeServiceUnavailable(w, "delete failed")
			return
		}
		emitAuditEvent(r, auditProvider, pd.ID, "connector.delete", "connector", id, AuditOutcomeSuccess)
		w.WriteHeader(http.StatusNoContent)
	})
}
