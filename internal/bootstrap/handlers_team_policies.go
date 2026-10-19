// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
)

// W33-20: /api/v1/team-policies. Reads need any signed-in principal, writes
// need pki-admin (and the write gate maps the prefix to admin too). A team
// belongs to one tenant; another tenant's team answers 404, never 403, so
// existence does not leak. ?tenant= is honored only for a principal that
// bypasses tenant filtering.

// WithTeamPolicyAdmin mounts the team-policy API and registers the executor
// for parked loosenings. A nil db returns nil, which Run skips.
func WithTeamPolicyAdmin(auth *Authenticator, db *sql.DB, postgres bool, auditProvider AuditProvider) ServerOption {
	if db == nil {
		return nil
	}
	var store TeamPolicyStore = newDBTeamPolicyStore(db, postgres)
	if err := store.EnsureSchema(context.Background()); err != nil {
		logging.Warnf("team policies: schema unavailable, the API will answer 503: %v", err)
		store = nil
	}
	// W33-21: with a core DB, enforcement is always on. A store or counter
	// that failed to initialise leaves the enforcer unable to evaluate, so
	// issuance is refused (503) rather than allowed.
	enf := &teamPolicyEnforcer{counters: newTeamCounterStore(db, postgres)}
	if store != nil {
		enf.policies = store
	}
	if err := enf.counters.EnsureSchema(context.Background()); err != nil {
		logging.Warnf("team quota counters: schema unavailable, issuance for teams will be refused: %v", err)
		enf.counters = nil
	}
	activeTeamEnforcer = enf
	return func(c *ServerConfig) {
		pending := NewPendingActionStoreFromEnv()
		if store != nil {
			WithActionExecutor(ActionTeamPolicyLoosen, newTeamPolicyLoosenExecutor(store, auditProvider))(c)
		}
		WithExtraHandlers(func(mux *http.ServeMux) {
			registerTeamPolicyHandlers(mux, auth, store, auditProvider, pending)
		})(c)
	}
}

type teamPolicyBody struct {
	Team               *string   `json:"team"`
	AllowedCAs         *[]string `json:"allowed_cas"`
	AllowedTemplates   *[]string `json:"allowed_templates"`
	AllowedDNSSuffixes *[]string `json:"allowed_dns_suffixes"`
	AllowedDNSNames    *[]string `json:"allowed_dns_names"`
	MaxValidityDays    *int      `json:"max_validity_days"`
	MonthlyQuota       *int      `json:"monthly_quota"`
}

// apply overlays the supplied fields onto p; list fields replace the list.
func (b teamPolicyBody) apply(p *TeamPolicy) {
	if b.Team != nil {
		p.Team = strings.TrimSpace(*b.Team)
	}
	if b.AllowedCAs != nil {
		p.AllowedCAs = append([]string(nil), *b.AllowedCAs...)
	}
	if b.AllowedTemplates != nil {
		p.AllowedTemplates = append([]string(nil), *b.AllowedTemplates...)
	}
	if b.AllowedDNSSuffixes != nil {
		p.AllowedDNSSuffixes = append([]string(nil), *b.AllowedDNSSuffixes...)
	}
	if b.AllowedDNSNames != nil {
		p.AllowedDNSNames = append([]string(nil), *b.AllowedDNSNames...)
	}
	if b.MaxValidityDays != nil {
		p.MaxValidityDays = *b.MaxValidityDays
	}
	if b.MonthlyQuota != nil {
		p.MonthlyQuota = *b.MonthlyQuota
	}
	p.normalizeLists()
}

func registerTeamPolicyHandlers(mux *http.ServeMux, auth *Authenticator, store TeamPolicyStore, audit AuditProvider, pending PendingActionStore) {
	// tenantFor resolves the tenant a request acts in.
	tenantFor := func(r *http.Request, pd AuthPrincipal) string {
		if t := strings.TrimSpace(r.URL.Query().Get("tenant")); t != "" && tenantBypass(pd) {
			return t
		}
		if pd.Tenant == "" {
			return DefaultTenant
		}
		return pd.Tenant
	}
	// begin authenticates and, for writes, requires an admin. It writes the
	// refusal (audited as denied) itself.
	begin := func(w http.ResponseWriter, r *http.Request, action, team string, write bool) (AuthPrincipal, string, bool) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return AuthPrincipal{}, "", false
		}
		tenant := tenantFor(r, pd)
		// Reads: pki-admin and auditor see every team's policy in the tenant;
		// anyone else may read only their own team's policy (team = principal
		// id), never the list, so one team cannot enumerate another's allowed
		// CAs and domains.
		if !write && !isAdminRole(pd.Role) && strings.TrimSpace(pd.Role) != "auditor" && (team == "" || team != pd.ID) {
			emitAuditEvent(r, audit, pd.ID, action, teamPolicyResource, teamPolicyResourceID(tenant, team), AuditOutcomeDenied)
			writeForbidden(w, "team policies are readable only by their own team, auditors and pki-admins")
			return AuthPrincipal{}, "", false
		}
		if write && !isAdminRole(pd.Role) {
			emitAuditEvent(r, audit, pd.ID, action, teamPolicyResource, teamPolicyResourceID(tenant, team), AuditOutcomeDenied)
			writeForbidden(w, "team policies require the pki-admin role to change")
			return AuthPrincipal{}, "", false
		}
		if store == nil {
			emitAuditEvent(r, audit, pd.ID, action, teamPolicyResource, teamPolicyResourceID(tenant, team), AuditOutcomeFailure)
			writeServiceUnavailable(w, "team policy store unavailable")
			return AuthPrincipal{}, "", false
		}
		return pd, tenant, true
	}
	fail := func(w http.ResponseWriter, r *http.Request, pd AuthPrincipal, action, tenant, team string, write func()) {
		emitAuditEvent(r, audit, pd.ID, action, teamPolicyResource, teamPolicyResourceID(tenant, team), AuditOutcomeFailure)
		write()
	}

	mux.HandleFunc("/api/v1/team-policies", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			pd, tenant, ok := begin(w, r, "team_policy.list", "", false)
			if !ok {
				return
			}
			all := tenantBypass(pd) && strings.TrimSpace(r.URL.Query().Get("tenant")) == ""
			items, err := store.List(r.Context(), tenant, all)
			if err != nil {
				fail(w, r, pd, "team_policy.list", tenant, "", func() { writeServiceUnavailable(w, "team policy list failed") })
				return
			}
			emitAuditEvent(r, audit, pd.ID, "team_policy.list", teamPolicyResource, teamPolicyResourceID(tenant, "*"), AuditOutcomeSuccess)
			writeJSONData(w, items)
		case http.MethodPost:
			pd, tenant, ok := begin(w, r, "team_policy.create", "", true)
			if !ok {
				return
			}
			var body teamPolicyBody
			if !decodePolicyBody(w, r, &body, teamPolicyBodyMax) {
				emitAuditEvent(r, audit, pd.ID, "team_policy.create", teamPolicyResource, teamPolicyResourceID(tenant, ""), AuditOutcomeFailure)
				return
			}
			next := TeamPolicy{Tenant: tenant}
			body.apply(&next)
			if msg := validateTeamPolicy(next); msg != "" {
				fail(w, r, pd, "team_policy.create", tenant, next.Team, func() { writeBadRequest(w, msg) })
				return
			}
			if msg := validateTeamPolicyTenants(r.Context(), next); msg != "" {
				fail(w, r, pd, "team_policy.create", tenant, next.Team, func() { writeBadRequest(w, msg) })
				return
			}
			if _, found, err := store.Get(r.Context(), tenant, next.Team); err != nil {
				fail(w, r, pd, "team_policy.create", tenant, next.Team, func() { writeServiceUnavailable(w, "team policy lookup failed") })
				return
			} else if found {
				fail(w, r, pd, "team_policy.create", tenant, next.Team, func() { writeConflict(w, "team policy already exists") })
				return
			}
			// Creating a policy restricts a team that was unrestricted, so it
			// is always a tightening and applies at once.
			saved, err := store.Put(r.Context(), next, 0, pd.ID)
			if errors.Is(err, errTeamPolicyExists) {
				fail(w, r, pd, "team_policy.create", tenant, next.Team, func() { writeConflict(w, "team policy already exists") })
				return
			}
			if err != nil {
				fail(w, r, pd, "team_policy.create", tenant, next.Team, func() { writeServiceUnavailable(w, "team policy create failed") })
				return
			}
			emitAuditEventDetail(r, audit, pd.ID, "team_policy.create", teamPolicyResource, teamPolicyResourceID(tenant, saved.Team), AuditOutcomeSuccess, teamPolicySummary(saved))
			writeJSONStatus(w, http.StatusCreated, map[string]any{"data": saved})
		default:
			writeMethodNotAllowed(w, "GET, POST")
		}
	})

	mux.HandleFunc("/api/v1/team-policies/", func(w http.ResponseWriter, r *http.Request) {
		// r.URL.Path is already percent-decoded; decoding again would let
		// "%2541" name team "A".
		team := strings.TrimPrefix(r.URL.Path, "/api/v1/team-policies/")
		if team == "" || strings.Contains(team, "/") {
			writeNotFound(w, "team policy not found")
			return
		}
		var action string
		var write bool
		switch r.Method {
		case http.MethodGet:
			action = "team_policy.get"
		case http.MethodPatch:
			action, write = "team_policy.update", true
		case http.MethodDelete:
			action, write = "team_policy.delete", true
		default:
			writeMethodNotAllowed(w, "GET, PATCH, DELETE")
			return
		}
		pd, tenant, ok := begin(w, r, action, team, write)
		if !ok {
			return
		}
		cur, found, err := store.Get(r.Context(), tenant, team)
		if err != nil {
			fail(w, r, pd, action, tenant, team, func() { writeServiceUnavailable(w, "team policy lookup failed") })
			return
		}
		if !found {
			fail(w, r, pd, action, tenant, team, func() { writeNotFound(w, "team policy not found") })
			return
		}
		switch r.Method {
		case http.MethodGet:
			emitAuditEvent(r, audit, pd.ID, action, teamPolicyResource, teamPolicyResourceID(tenant, team), AuditOutcomeSuccess)
			writeJSONData(w, cur)
		case http.MethodPatch:
			var body teamPolicyBody
			if !decodePolicyBody(w, r, &body, teamPolicyBodyMax) {
				emitAuditEvent(r, audit, pd.ID, action, teamPolicyResource, teamPolicyResourceID(tenant, team), AuditOutcomeFailure)
				return
			}
			if body.Team != nil && strings.TrimSpace(*body.Team) != team {
				fail(w, r, pd, action, tenant, team, func() { writeBadRequest(w, "team cannot be renamed") })
				return
			}
			next := cur
			body.apply(&next)
			if msg := validateTeamPolicy(next); msg != "" {
				fail(w, r, pd, action, tenant, team, func() { writeBadRequest(w, msg) })
				return
			}
			if msg := validateTeamPolicyTenants(r.Context(), next); msg != "" {
				fail(w, r, pd, action, tenant, team, func() { writeBadRequest(w, msg) })
				return
			}
			if reasons := teamPolicyLoosening(cur, next); len(reasons) > 0 {
				proposeTeamPolicyLoosening(w, r, pd, pending, audit, teamPolicyLoosenParams{
					Tenant: tenant, Team: team, Proposed: next, Reasons: reasons, BaseVersion: cur.Version,
				}, action)
				return
			}
			saved, err := store.Put(r.Context(), next, cur.Version, pd.ID)
			if errors.Is(err, errTeamPolicyStale) {
				fail(w, r, pd, action, tenant, team, func() { writeConflict(w, errTeamPolicyStale.Error()) })
				return
			}
			if err != nil {
				fail(w, r, pd, action, tenant, team, func() { writeServiceUnavailable(w, "team policy update failed") })
				return
			}
			emitAuditEventDetail(r, audit, pd.ID, action, teamPolicyResource, teamPolicyResourceID(tenant, team), AuditOutcomeSuccess, teamPolicySummary(saved))
			writeJSONData(w, saved)
		case http.MethodDelete:
			// Absent means unrestricted, so deleting always loosens: it is
			// parked for a second approver and the policy keeps applying.
			proposeTeamPolicyLoosening(w, r, pd, pending, audit, teamPolicyLoosenParams{
				Tenant: tenant, Team: team, Reasons: []string{"policy deleted (team becomes unrestricted)"},
				BaseVersion: cur.Version, Delete: true,
			}, action)
		}
	})
}

// proposeTeamPolicyLoosening parks a loosening in the approval queue and
// answers 202. Nothing is written to the policy row; with no queue available
// the change is refused rather than applied.
func proposeTeamPolicyLoosening(w http.ResponseWriter, r *http.Request, pd AuthPrincipal, pending PendingActionStore, audit AuditProvider, p teamPolicyLoosenParams, auditAction string) {
	resID := teamPolicyResourceID(p.Tenant, p.Team)
	if pending == nil {
		emitAuditEvent(r, audit, pd.ID, auditAction, teamPolicyResource, resID, AuditOutcomeFailure)
		writeServiceUnavailable(w, "approval queue unavailable; loosening a team policy needs a second approver")
		return
	}
	params, err := json.Marshal(p)
	if err != nil {
		emitAuditEvent(r, audit, pd.ID, auditAction, teamPolicyResource, resID, AuditOutcomeFailure)
		writeServiceUnavailable(w, "team policy change could not be queued")
		return
	}
	created, err := pending.Create(r.Context(), PendingAction{
		ActionType: ActionTeamPolicyLoosen, Params: params, ProposedBy: pd.ID, Tenant: pd.Tenant,
		Rationale: strings.Join(p.Reasons, "; "),
	})
	if err != nil {
		emitAuditEvent(r, audit, pd.ID, auditAction, teamPolicyResource, resID, AuditOutcomeFailure)
		writeServiceUnavailable(w, "team policy change could not be queued")
		return
	}
	emitAuditEventDetail(r, audit, pd.ID, auditAction, teamPolicyResource, resID, AuditOutcomePendingApproval, "proposed (pending approval): "+strings.Join(p.Reasons, "; "))
	writeJSONStatus(w, http.StatusAccepted, map[string]any{"data": map[string]any{
		"status": "pending_approval", "pending_action_id": created.ID, "reasons": p.Reasons,
	}})
}
