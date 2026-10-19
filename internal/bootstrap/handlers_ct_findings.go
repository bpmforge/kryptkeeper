// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/ctmonitor"
)

// W24-19 (FR-P15, NFR-P2, UC-C07): tenant-scoped, audited triage API over the
// findings the CT monitor persists. Nothing here revokes: a finding for a
// certificate this hub's CA issued but never recorded only carries a link to
// the normal revoke flow, so UC-A10 dual control still applies.

const (
	ctStatusOpen         = "open"
	ctStatusAcknowledged = "acknowledged"
	ctStatusKnownIssuer  = "known_issuer"

	ctFindingsDefaultLimit = 100
	ctFindingsMaxLimit     = 500
)

// ctFindingView is the wire shape; Resolution is folded into Status so the
// stored open|acknowledged pair surfaces as open|acknowledged|known_issuer.
type ctFindingView struct {
	ID         string     `json:"id"`
	LogID      string     `json:"log_id"`
	Domain     string     `json:"domain"`
	CommonName string     `json:"common_name"`
	DNSNames   []string   `json:"dns_names"`
	CA         string     `json:"ca"`
	Serial     string     `json:"serial"`
	NotBefore  time.Time  `json:"not_before"`
	NotAfter   time.Time  `json:"not_after"`
	Source     string     `json:"source"`
	Status     string     `json:"status"`
	ResolvedBy string     `json:"resolved_by"`
	ResolvedAt *time.Time `json:"resolved_at"`
	CreatedAt  time.Time  `json:"created_at"`
	Ours       bool       `json:"ours"`
	RevokeURL  string     `json:"revoke_url,omitempty"`
}

func ctFindingStatus(f ctmonitor.Finding) string {
	if f.Status != ctStatusAcknowledged {
		return ctStatusOpen
	}
	if f.Resolution == ctmonitor.ResolutionKnownIssuer {
		return ctStatusKnownIssuer
	}
	return ctStatusAcknowledged
}

// canManageCTFindings gates the triage mutations.
func canManageCTFindings(principal AuthPrincipal) bool {
	switch strings.TrimSpace(principal.Role) {
	case "pki-admin", "pki-operator":
		return true
	}
	return hasScope(principal.Scopes, "*") || hasScope(principal.Scopes, "ops:write")
}

// ctIssuerCN extracts the CN= value of an RFC 4514-ish or crt.sh issuer string.
func ctIssuerCN(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if len(part) > 3 && strings.EqualFold(part[:3], "cn=") {
			return strings.TrimSpace(part[3:])
		}
	}
	return ""
}

// ctOursMatcher reports whether a finding's issuer is one of this hub's CAs:
// the full issuer DN equals a CA's subject DN, or the issuer CN equals the
// CA's subject CN / name. Equality (not substring) so a look-alike issuer
// never gets the "ours" revoke hint; any lookup failure yields "not ours".
func ctOursMatcher(ctx context.Context, caProvider CAProvider) func(issuer string) bool {
	if caProvider == nil {
		return func(string) bool { return false }
	}
	res, err := caProvider.ListCAs(ctx, CAListQuery{Limit: ctFindingsMaxLimit})
	if err != nil {
		return func(string) bool { return false }
	}
	items := res.Items
	return func(issuer string) bool {
		issuer = strings.TrimSpace(issuer)
		cn := ctIssuerCN(issuer)
		for _, ca := range items {
			if ca.Certificate != nil {
				subj := strings.TrimSpace(ca.Certificate.SubjectDN)
				if subj != "" && strings.EqualFold(subj, issuer) {
					return true
				}
				if cn != "" && strings.EqualFold(ctIssuerCN(subj), cn) {
					return true
				}
			}
			if cn != "" && (strings.EqualFold(strings.TrimSpace(ca.DisplayName), cn) || strings.EqualFold(strings.TrimSpace(ca.Name), cn)) {
				return true
			}
		}
		return false
	}
}

func toCTFindingView(f ctmonitor.Finding, ours func(string) bool) ctFindingView {
	v := ctFindingView{
		ID: f.ID, LogID: f.ID, Domain: f.Domain, CommonName: f.CommonName,
		DNSNames: f.DNSNames, CA: f.Issuer, Serial: f.Serial,
		NotBefore: f.NotBefore, NotAfter: f.NotAfter, Source: f.Source,
		Status: ctFindingStatus(f), ResolvedBy: f.ResolvedBy, CreatedAt: f.CreatedAt,
	}
	if v.DNSNames == nil {
		v.DNSNames = []string{}
	}
	if !f.ResolvedAt.IsZero() {
		t := f.ResolvedAt
		v.ResolvedAt = &t
	}
	if f.Serial != "" && ours(f.Issuer) {
		v.Ours = true
		v.RevokeURL = "/certificates?q=" + url.QueryEscape(f.Serial)
	}
	return v
}

func ctFindingVisible(pd AuthPrincipal, f ctmonitor.Finding) bool {
	return tenantBypass(pd) || f.Tenant == pd.Tenant
}

// RegisterCTFindingsHandlers mounts GET /api/v1/ct/findings and
// POST /api/v1/ct/findings/{id}/{acknowledge|known-issuer}. store may be nil
// (DB unavailable): every route then reports 503.
func RegisterCTFindingsHandlers(mux *http.ServeMux, auth *Authenticator, store *ctmonitor.Store, caProvider CAProvider, auditProvider AuditProvider) {
	authenticate := func(w http.ResponseWriter, r *http.Request) (AuthPrincipal, bool) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return AuthPrincipal{}, false
		}
		return pd, true
	}

	mux.HandleFunc("/api/v1/ct/findings", func(w http.ResponseWriter, r *http.Request) {
		pd, ok := authenticate(w, r)
		if !ok {
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		const action = "ct.finding.list"
		if store == nil {
			emitAuditEvent(r, auditProvider, pd.ID, action, "ct_finding", "findings", AuditOutcomeFailure)
			writeServiceUnavailable(w, "ct findings unavailable")
			return
		}
		if !canReadOperationalSummaries(pd) {
			emitAuditEvent(r, auditProvider, pd.ID, action, "ct_finding", "findings", AuditOutcomeDenied)
			writeForbidden(w, "insufficient permissions")
			return
		}
		status := strings.TrimSpace(r.URL.Query().Get("status"))
		switch status {
		case "", ctStatusOpen, ctStatusAcknowledged, ctStatusKnownIssuer:
		default:
			emitAuditEvent(r, auditProvider, pd.ID, action, "ct_finding", "findings", AuditOutcomeFailure)
			writeBadRequest(w, "invalid status")
			return
		}
		limit := ctFindingsDefaultLimit
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 1 {
				emitAuditEvent(r, auditProvider, pd.ID, action, "ct_finding", "findings", AuditOutcomeFailure)
				writeBadRequest(w, "invalid limit")
				return
			}
			limit = min(n, ctFindingsMaxLimit)
		}
		// known_issuer is a resolution of stored status 'acknowledged'.
		storedStatus := status
		if status == ctStatusKnownIssuer {
			storedStatus = ctStatusAcknowledged
		}
		all, err := store.List(r.Context(), storedStatus)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, action, "ct_finding", "findings", AuditOutcomeFailure)
			writeServiceUnavailable(w, "list failed")
			return
		}
		ours := ctOursMatcher(r.Context(), caProvider)
		views := make([]ctFindingView, 0, len(all))
		for _, f := range all {
			if !ctFindingVisible(pd, f) {
				continue
			}
			v := toCTFindingView(f, ours)
			if status != "" && v.Status != status {
				continue // acknowledged vs known_issuer split
			}
			views = append(views, v)
		}
		sort.SliceStable(views, func(i, j int) bool {
			if !views[i].CreatedAt.Equal(views[j].CreatedAt) {
				return views[i].CreatedAt.After(views[j].CreatedAt)
			}
			return views[i].ID < views[j].ID
		})
		total := len(views)
		if len(views) > limit {
			views = views[:limit]
		}
		emitAuditEvent(r, auditProvider, pd.ID, action, "ct_finding", "findings", AuditOutcomeSuccess)
		writeJSONData(w, map[string]any{"findings": views, "total": total})
	})

	mux.HandleFunc("/api/v1/ct/findings/", func(w http.ResponseWriter, r *http.Request) {
		pd, ok := authenticate(w, r)
		if !ok {
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/api/v1/ct/findings/")
		slash := strings.LastIndex(rest, "/")
		if slash <= 0 {
			writeNotFound(w, "not found")
			return
		}
		id, verb := rest[:slash], rest[slash+1:]
		var action, resolution string
		switch verb {
		case "acknowledge":
			action, resolution = "ct.finding.acknowledge", ctmonitor.ResolutionAcknowledged
		case "known-issuer":
			action, resolution = "ct.finding.known_issuer", ctmonitor.ResolutionKnownIssuer
		default:
			writeNotFound(w, "not found")
			return
		}
		if store == nil {
			emitAuditEvent(r, auditProvider, pd.ID, action, "ct_finding", id, AuditOutcomeFailure)
			writeServiceUnavailable(w, "ct findings unavailable")
			return
		}
		if !canManageCTFindings(pd) {
			emitAuditEvent(r, auditProvider, pd.ID, action, "ct_finding", id, AuditOutcomeDenied)
			writeForbidden(w, "insufficient permissions")
			return
		}
		f, err := store.Get(r.Context(), id)
		if err == nil && !ctFindingVisible(pd, f) {
			err = ctmonitor.ErrFindingNotFound // 404, never 403: do not leak existence
		}
		if err == nil {
			err = store.Resolve(r.Context(), id, resolution, pd.ID, time.Now())
		}
		if errors.Is(err, ctmonitor.ErrFindingNotFound) {
			emitAuditEvent(r, auditProvider, pd.ID, action, "ct_finding", id, AuditOutcomeFailure)
			writeNotFound(w, "ct finding not found")
			return
		}
		if err == nil {
			f, err = store.Get(r.Context(), id)
		}
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, action, "ct_finding", id, AuditOutcomeFailure)
			writeServiceUnavailable(w, "update failed")
			return
		}
		emitAuditEvent(r, auditProvider, pd.ID, action, "ct_finding", id, AuditOutcomeSuccess)
		writeJSONData(w, toCTFindingView(f, ctOursMatcher(r.Context(), caProvider)))
	})
}

// newCTStoreFromEnv opens the CT findings store on the hub's shared database
// (same DSN resolution as the managed-target store). Returns nil on any
// failure; handlers then answer 503.
func newCTStoreFromEnv() *ctmonitor.Store {
	state := newDBProviderState[*ctmonitor.Store](
		"ct-findings",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_TARGETS_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_TARGETS_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_TARGETS_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) *ctmonitor.Store { return openCTStore(db, false) },
		func(db *sql.DB) *ctmonitor.Store { return openCTStore(db, true) },
	)
	if state.openErr != nil || state.store == nil {
		_ = dbProviderUnavailable("ct-findings", state.openErr) // logs the outage itself
		return nil
	}
	return state.store
}

func openCTStore(db *sql.DB, postgres bool) *ctmonitor.Store {
	s, err := ctmonitor.NewStore(db, postgres)
	if err != nil {
		_ = dbProviderUnavailable("ct-findings", err) // logs the outage itself
		return nil
	}
	return s
}
