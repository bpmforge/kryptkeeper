// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"time"

	"kryptkeeper/internal/logging"
)

// ownerlessQueueTeam is the owner_team value of the ownerless queue (W32-30):
// the routes a routed rule uses for a certificate that has no owner team. It
// is created through the ordinary team-routes API; a certificate whose owner
// team is literally this string would be routed the same way, which is
// harmless (it reaches the queue its operators chose).
const ownerlessQueueTeam = "!ownerless"

const (
	ownerlessDefaultWithinDays = 30
	ownerlessMaxWithinDays     = 3650
	ownerlessDefaultLimit      = 100
	ownerlessMaxLimit          = 500
)

// ownerlessCertificate is one row of the ownerless-expiring listing.
type ownerlessCertificate struct {
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	CommonName        string `json:"common_name"`
	ValidUntil        string `json:"valid_until"`
	// DaysLeft is negative for a certificate that has already expired.
	DaysLeft   int    `json:"days_left"`
	OwnerEmail string `json:"owner_email,omitempty"`
	CAID       string `json:"ca_id,omitempty"`
}

// ownerlessExpiring returns the active certificates with no owner team whose
// expiry falls within within of now (already-expired ones included: nobody
// owns them either), soonest first, using the same "unowned" definition as the
// dashboard count and ?owner=unassigned (certificate_active.go).
func ownerlessExpiring(ctx context.Context, certs CertificateProvider, pd AuthPrincipal, now time.Time, within time.Duration) ([]ownerlessCertificate, error) {
	query := CertificateListQuery{Owner: ownerFilterUnassigned}
	var items []CertificateItem
	if tenantBypass(pd) {
		if err := ForEachCertificate(ctx, certs, query, func(item CertificateItem) error {
			items = append(items, item)
			return nil
		}); err != nil {
			return nil, err
		}
	} else {
		visible, err := listCertificatesTenantFiltered(ctx, certs, activeTenantStore, pd, query)
		if err != nil {
			return nil, err
		}
		items = visible
	}
	out := make([]ownerlessCertificate, 0)
	for _, it := range items {
		until, err := time.Parse(time.RFC3339, it.ValidUntil)
		// The provider filters too; re-checking keeps a provider that ignores
		// the Owner filter from listing owned certificates as ownerless.
		if err != nil || until.Sub(now) > within || !isUnownedCertificate(&it) {
			continue
		}
		out = append(out, ownerlessCertificate{
			FingerprintSHA256: it.FingerprintSHA256, CommonName: it.CommonName, ValidUntil: it.ValidUntil,
			DaysLeft: int(until.Sub(now).Hours() / 24), OwnerEmail: it.OwnerEmail, CAID: it.CAID,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ValidUntil != out[j].ValidUntil {
			return out[i].ValidUntil < out[j].ValidUntil
		}
		return out[i].FingerprintSHA256 < out[j].FingerprintSHA256
	})
	return out, nil
}

// registerOwnerlessHandler mounts GET /api/v1/notifications/ownerless: the
// dashboard/API listing of expiring certificates nobody owns (W32-30, US-044).
func registerOwnerlessHandler(mux *http.ServeMux, auth *Authenticator, certs CertificateProvider, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/notifications/ownerless", func(w http.ResponseWriter, r *http.Request) {
		const action = "notification.ownerless.list"
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", action, "notification", "ownerless", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		if !canReadOperationalSummaries(principal) {
			emitAuditEvent(r, auditProvider, principal.ID, action, "notification", "ownerless", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}
		within, ok := boundedIntParam(r, "within_days", ownerlessDefaultWithinDays, 1, ownerlessMaxWithinDays)
		limit, ok2 := boundedIntParam(r, "limit", ownerlessDefaultLimit, 1, ownerlessMaxLimit)
		if !ok || !ok2 {
			emitAuditEvent(r, auditProvider, principal.ID, action, "notification", "ownerless", AuditOutcomeFailure)
			writeBadRequest(w, "within_days must be 1-3650 and limit 1-500")
			return
		}
		if certs == nil {
			emitAuditEvent(r, auditProvider, principal.ID, action, "notification", "ownerless", AuditOutcomeFailure)
			writeServiceUnavailable(w, "certificate inventory unavailable")
			return
		}
		items, err := ownerlessExpiring(r.Context(), certs, principal, time.Now().UTC(), time.Duration(within)*24*time.Hour)
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, action, "notification", "ownerless", AuditOutcomeFailure)
			logging.Warnf("ownerless certificates unavailable: %v", err)
			writeServiceUnavailable(w, "ownerless certificates unavailable")
			return
		}
		emitAuditEvent(r, auditProvider, principal.ID, action, "notification", "ownerless", AuditOutcomeSuccess)
		total := len(items)
		if total > limit {
			items = items[:limit]
		}
		resp := struct {
			Data struct {
				Items []ownerlessCertificate `json:"items"`
			} `json:"data"`
			Meta struct {
				Total      int `json:"total"`
				WithinDays int `json:"within_days"`
			} `json:"meta"`
		}{}
		resp.Data.Items = items
		resp.Meta.Total = total
		resp.Meta.WithinDays = within
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logging.Warnf("failed to encode /api/v1/notifications/ownerless response: %v", err)
		}
	})
}

// boundedIntParam reads an optional integer query parameter; ok is false for a
// value that is not an integer within [lo, hi].
func boundedIntParam(r *http.Request, name string, def, lo, hi int) (int, bool) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < lo || n > hi {
		return 0, false
	}
	return n, true
}
