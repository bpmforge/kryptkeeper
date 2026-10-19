// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
)

// W34-06 (D-205): /api/v1/discovery/authorized-issuers.
//
// An authorized issuer is a CA group the operator accepts certificates from.
// Rows are tenant-scoped: another tenant's row is indistinguishable from a
// missing one. Every outcome is audited, validation failures included, so the
// route matrix (W22-06) sees a row for any probe.

const (
	auditAuthorizedIssuerCreate = "discovery.authorized_issuer.create"
	auditAuthorizedIssuerDelete = "discovery.authorized_issuer.delete"
	auditAuthorizedIssuerList   = "discovery.authorized_issuer.list"
	authorizedIssuerBodyMax     = 128 << 10
	authorizedIssuerPrefix      = "/api/v1/discovery/authorized-issuers"
)

// issuerReclassifier is implemented by discovery providers that can re-derive
// the stored issuer class of a tenant's certificates after its declared set
// changed, so the page reflects a new rule before the next scan.
type issuerReclassifier interface {
	ReclassifyIssuers(ctx context.Context, tenant string) error
}

// reclassifyIssuers is best-effort: the rule is already saved, and the next
// scan classifies from the full served chain either way.
func reclassifyIssuers(r *http.Request, provider DiscoveryProvider, tenant string) {
	rc, ok := provider.(issuerReclassifier)
	if !ok {
		return
	}
	if err := rc.ReclassifyIssuers(r.Context(), tenant); err != nil {
		logging.Warnf("authorized issuers: reclassifying stored certificates failed (next scan will correct): %v", err)
	}
}

// Routes are registered with string literals (not authorizedIssuerPrefix)
// because scripts/validate-openapi.sh greps for HandleFunc("...") literals.
func registerAuthorizedIssuerHandlers(mux *http.ServeMux, auth *Authenticator, store authorizedIssuerStore, provider DiscoveryProvider, audit AuditProvider) {
	mux.HandleFunc("/api/v1/discovery/authorized-issuers", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			listAuthorizedIssuers(w, r, auth, store, audit)
		case http.MethodPost:
			createAuthorizedIssuer(w, r, auth, store, provider, audit)
		default:
			writeMethodNotAllowed(w, "GET, POST")
		}
	})
	mux.HandleFunc("/api/v1/discovery/authorized-issuers/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			writeMethodNotAllowed(w, http.MethodDelete)
			return
		}
		deleteAuthorizedIssuer(w, r, auth, store, provider, audit)
	})
}

func listAuthorizedIssuers(w http.ResponseWriter, r *http.Request, auth *Authenticator, store authorizedIssuerStore, audit AuditProvider) {
	pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
	if err != nil {
		emitAuditEvent(r, audit, "", auditAuthorizedIssuerList, "authorized_issuer", "list", AuditOutcomeDenied)
		writeUnauthorized(w)
		return
	}
	if !canReadOperationalSummaries(pd) {
		emitAuditEvent(r, audit, pd.ID, auditAuthorizedIssuerList, "authorized_issuer", "list", AuditOutcomeDenied)
		writeForbidden(w, "forbidden")
		return
	}
	if store == nil {
		emitAuditEvent(r, audit, pd.ID, auditAuthorizedIssuerList, "authorized_issuer", "list", AuditOutcomeFailure)
		writeServiceUnavailable(w, "authorized issuers unavailable")
		return
	}
	var tenant *string
	if !tenantBypass(pd) {
		t := discoveryTenantValue(pd.Tenant)
		tenant = &t
	}
	items, err := store.List(r.Context(), tenant)
	if err != nil {
		emitAuditEvent(r, audit, pd.ID, auditAuthorizedIssuerList, "authorized_issuer", "list", AuditOutcomeFailure)
		logging.Warnf("authorized issuers list failed: %v", err)
		writeServiceUnavailable(w, "authorized issuers unavailable")
		return
	}
	emitAuditEvent(r, audit, pd.ID, auditAuthorizedIssuerList, "authorized_issuer", "list", AuditOutcomeSuccess)
	writeJSONData(w, items)
}

func createAuthorizedIssuer(w http.ResponseWriter, r *http.Request, auth *Authenticator, store authorizedIssuerStore, provider DiscoveryProvider, audit AuditProvider) {
	pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
	if err != nil {
		emitAuditEvent(r, audit, "", auditAuthorizedIssuerCreate, "authorized_issuer", "new", AuditOutcomeDenied)
		writeUnauthorized(w)
		return
	}
	if !canManageDiscovery(pd) {
		emitAuditEvent(r, audit, pd.ID, auditAuthorizedIssuerCreate, "authorized_issuer", "new", AuditOutcomeDenied)
		writeForbidden(w, "forbidden")
		return
	}
	var body AuthorizedIssuer
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, authorizedIssuerBodyMax)).Decode(&body); err != nil {
		emitAuditEvent(r, audit, pd.ID, auditAuthorizedIssuerCreate, "authorized_issuer", "new", AuditOutcomeFailure)
		writeBadRequest(w, "body must be {\"name\": string, \"kind\": \"ca_cert|issuer_dn|spki_sha256\", \"value\": string, \"notes\"?: string}")
		return
	}
	item, err := validateAuthorizedIssuer(body)
	if err != nil {
		emitAuditEvent(r, audit, pd.ID, auditAuthorizedIssuerCreate, "authorized_issuer", "new", AuditOutcomeFailure)
		writeBadRequest(w, err.Error())
		return
	}
	if store == nil {
		emitAuditEvent(r, audit, pd.ID, auditAuthorizedIssuerCreate, "authorized_issuer", "new", AuditOutcomeFailure)
		writeServiceUnavailable(w, "authorized issuers unavailable")
		return
	}
	item.ID = newAuthorizedIssuerID()
	item.Tenant = discoveryTenantValue(pd.Tenant)
	item.CreatedBy = pd.ID
	item.CreatedAt = authorizedIssuerNow().Format(time.RFC3339)
	if err := store.Create(r.Context(), item); err != nil {
		emitAuditEvent(r, audit, pd.ID, auditAuthorizedIssuerCreate, "authorized_issuer", item.ID, AuditOutcomeFailure)
		if errors.Is(err, errAuthorizedIssuerExists) {
			writeConflict(w, "that issuer is already authorized")
			return
		}
		logging.Warnf("authorized issuer create failed: %v", err)
		writeServiceUnavailable(w, "authorized issuers unavailable")
		return
	}
	reclassifyIssuers(r, provider, item.Tenant)
	emitAuditEventDetail(r, audit, pd.ID, auditAuthorizedIssuerCreate, "authorized_issuer", item.ID, AuditOutcomeSuccess, authorizedIssuerSummary(item))
	writeJSONStatus(w, http.StatusCreated, map[string]any{"data": item})
}

func deleteAuthorizedIssuer(w http.ResponseWriter, r *http.Request, auth *Authenticator, store authorizedIssuerStore, provider DiscoveryProvider, audit AuditProvider) {
	id := strings.TrimPrefix(r.URL.Path, authorizedIssuerPrefix+"/")
	pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
	if err != nil {
		emitAuditEvent(r, audit, "", auditAuthorizedIssuerDelete, "authorized_issuer", id, AuditOutcomeDenied)
		writeUnauthorized(w)
		return
	}
	if !canManageDiscovery(pd) {
		emitAuditEvent(r, audit, pd.ID, auditAuthorizedIssuerDelete, "authorized_issuer", id, AuditOutcomeDenied)
		writeForbidden(w, "forbidden")
		return
	}
	if id == "" || strings.Contains(id, "/") {
		emitAuditEvent(r, audit, pd.ID, auditAuthorizedIssuerDelete, "authorized_issuer", id, AuditOutcomeFailure)
		writeNotFound(w, "authorized issuer not found")
		return
	}
	if store == nil {
		emitAuditEvent(r, audit, pd.ID, auditAuthorizedIssuerDelete, "authorized_issuer", id, AuditOutcomeFailure)
		writeServiceUnavailable(w, "authorized issuers unavailable")
		return
	}
	item, err := store.Get(r.Context(), id)
	if errors.Is(err, errAuthorizedIssuerNotFound) {
		emitAuditEvent(r, audit, pd.ID, auditAuthorizedIssuerDelete, "authorized_issuer", id, AuditOutcomeFailure)
		writeNotFound(w, "authorized issuer not found")
		return
	}
	if err != nil {
		emitAuditEvent(r, audit, pd.ID, auditAuthorizedIssuerDelete, "authorized_issuer", id, AuditOutcomeFailure)
		writeServiceUnavailable(w, "authorized issuers unavailable")
		return
	}
	// Another tenant's row is indistinguishable from a missing one.
	if !stampedTenantVisible(pd, item.Tenant) {
		emitAuditEvent(r, audit, pd.ID, auditAuthorizedIssuerDelete, "authorized_issuer", id, AuditOutcomeDenied)
		writeNotFound(w, "authorized issuer not found")
		return
	}
	if err := store.Delete(r.Context(), id); err != nil {
		emitAuditEvent(r, audit, pd.ID, auditAuthorizedIssuerDelete, "authorized_issuer", id, AuditOutcomeFailure)
		if errors.Is(err, errAuthorizedIssuerNotFound) {
			writeNotFound(w, "authorized issuer not found")
			return
		}
		writeServiceUnavailable(w, "authorized issuers unavailable")
		return
	}
	reclassifyIssuers(r, provider, item.Tenant)
	emitAuditEventDetail(r, audit, pd.ID, auditAuthorizedIssuerDelete, "authorized_issuer", id, AuditOutcomeSuccess, authorizedIssuerSummary(item))
	writeJSONData(w, map[string]string{"status": "deleted"})
}

// authorizedIssuerSummary is the audit change summary: what was declared, never
// the certificate body.
func authorizedIssuerSummary(a AuthorizedIssuer) string {
	b, err := json.Marshal(map[string]string{"name": a.Name, "kind": a.Kind})
	if err != nil {
		return ""
	}
	return string(b)
}
