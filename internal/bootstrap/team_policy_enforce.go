// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/logging"
)

// W33-21 (FR-P8, FR-P45, UC-M04): issuance is checked against the requester's
// team policy (W33-20) and monthly quota, refusing with a specific 403
// error_code. Enforcement fails closed: a lookup or counter error refuses
// issuance (503), it never lets the request through.
//
// Semantics (D-195, the back-compat contract): a team with no policy row is
// unrestricted; an empty allow-list places no restriction on that axis;
// max_validity_days 0 is no cap; monthly_quota 0 is unlimited (no counter is
// touched). Every non-admin request carries team = its principal id, so
// deny-by-default would have refused all existing installs on upgrade. The
// two-person rule survives because deleting a policy or widening any
// restriction is approval-gated in the team-policy API (team_policy_store.go).
// An unparseable CSR is still refused when a name restriction applies.

const (
	CodeTeamCANotAllowed       = "team_policy_ca_not_allowed"
	CodeTeamTemplateNotAllowed = "team_policy_template_not_allowed"
	CodeTeamNameNotAllowed     = "team_policy_name_not_allowed"
	CodeTeamValidityExceeded   = "team_policy_validity_exceeded"
	CodeTeamQuotaExceeded      = "team_quota_exceeded"
)

// PolicyDenial is one specific refusal.
type PolicyDenial struct{ Code, Message string }

const teamCounterSchema = `
CREATE TABLE IF NOT EXISTS team_request_counters (
  team_id TEXT NOT NULL, period TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (team_id, period));`

// teamCounterStore is the monthly issuance counter, one row per team-month.
type teamCounterStore struct {
	db *sql.DB
	ph func(int) string
}

func newTeamCounterStore(db *sql.DB, postgres bool) *teamCounterStore {
	ph := sqlitePlaceholder
	if postgres {
		ph = postgresPlaceholder
	}
	return &teamCounterStore{db: db, ph: ph}
}

func (s *teamCounterStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, teamCounterSchema)
	return err
}

// reserve is one atomic upsert: the row only advances while it is below limit,
// so concurrent callers can never overshoot. false means the quota is spent.
func (s *teamCounterStore) reserve(ctx context.Context, key, period string, limit int) (bool, error) {
	if limit <= 0 {
		return false, nil // the insert arm would otherwise create count=1
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO team_request_counters (team_id, period, count) VALUES (`+s.ph(1)+`, `+s.ph(2)+`, 1)
		ON CONFLICT (team_id, period) DO UPDATE SET count = team_request_counters.count + 1
		WHERE team_request_counters.count < `+s.ph(3), key, period, limit)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (s *teamCounterStore) release(ctx context.Context, key, period string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE team_request_counters SET count = count - 1 WHERE team_id = `+s.ph(1)+` AND period = `+s.ph(2)+` AND count > 0`, key, period)
	return err
}

func (s *teamCounterStore) used(ctx context.Context, key, period string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count FROM team_request_counters WHERE team_id = `+s.ph(1)+` AND period = `+s.ph(2), key, period).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return n, err
}

type teamPolicyEnforcer struct {
	policies  TeamPolicyStore
	templates TemplateProvider
	counters  *teamCounterStore
	now       func() time.Time // injectable; default time.Now().UTC()
}

// activeTeamEnforcer is nil when enforcement is off (no core DB), like
// activeTenantStore.
var activeTeamEnforcer *teamPolicyEnforcer

func (e *teamPolicyEnforcer) clock() time.Time {
	if e.now != nil {
		return e.now().UTC()
	}
	return time.Now().UTC()
}

func quotaPeriod(t time.Time) string { return t.UTC().Format("2006-01") }

// nextPeriodStart is the first instant of the following UTC month.
func nextPeriodStart(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, time.UTC)
}

// teamRequestFromApproval rebuilds the issuance request an approval parked.
func teamRequestFromApproval(apr ApprovalRequest) CertificateIssueRequest {
	return CertificateIssueRequest{CAID: apr.CAID, TemplateID: apr.TemplateID, CSRPEM: apr.CSRPEM, TeamID: apr.TeamID}
}

// Check evaluates CA, template, names and validity against the team's policy.
// It does not touch the quota. A non-nil error means the policy could not be
// evaluated and the caller must refuse (fail closed).
func (e *teamPolicyEnforcer) Check(ctx context.Context, tenant, team string, req CertificateIssueRequest) (*PolicyDenial, error) {
	if e.policies == nil {
		return nil, errors.New("team policy store unavailable")
	}
	pol, found, err := e.policies.Get(ctx, tenant, team)
	if err != nil {
		return nil, fmt.Errorf("team policy lookup: %w", err)
	}
	if !found {
		return nil, nil // no policy: unrestricted
	}
	if len(pol.AllowedCAs) > 0 && !slices.Contains(pol.AllowedCAs, req.CAID) {
		return &PolicyDenial{CodeTeamCANotAllowed, "team policy does not allow requests from this CA"}, nil
	}
	if len(pol.AllowedTemplates) > 0 && !slices.Contains(pol.AllowedTemplates, req.TemplateID) {
		return &PolicyDenial{CodeTeamTemplateNotAllowed, "team policy does not allow this template"}, nil
	}
	if len(pol.AllowedDNSSuffixes) > 0 || len(pol.AllowedDNSNames) > 0 {
		if d := checkTeamNames(pol, req.CSRPEM); d != nil {
			return d, nil
		}
	}
	if pol.MaxValidityDays == 0 {
		return nil, nil
	}
	if e.templates == nil {
		return nil, errors.New("template provider unavailable for team policy")
	}
	tpl, ok, err := e.templates.GetTemplate(ctx, req.TemplateID)
	if err != nil {
		return nil, fmt.Errorf("team policy template lookup: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("team policy: template %q not found", req.TemplateID)
	}
	v, err := templateValidity(tpl)
	if err != nil {
		return nil, err
	}
	if v > time.Duration(pol.MaxValidityDays)*24*time.Hour {
		return &PolicyDenial{CodeTeamValidityExceeded, fmt.Sprintf("template validity exceeds your team's maximum of %d days", pol.MaxValidityDays)}, nil
	}
	return nil, nil
}

// checkTeamNames requires every DNS SAN, and a hostname-shaped CN, to be an
// allowed name or fall under an allowed suffix. A CSR that cannot be parsed
// is refused: the names cannot be judged, so the request does not pass.
func checkTeamNames(pol TeamPolicy, csrPEM string) *PolicyDenial {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return &PolicyDenial{CodeTeamNameNotAllowed, "requested names could not be read from the CSR"}
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return &PolicyDenial{CodeTeamNameNotAllowed, "requested names could not be read from the CSR"}
	}
	names := slices.Clone(csr.DNSNames)
	if cn := strings.TrimSpace(csr.Subject.CommonName); cn != "" && !strings.ContainsAny(cn, " ,=@/:") {
		names = append(names, cn)
	}
	for _, n := range names {
		norm := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
		ok := ca.DNSNameMatchesSuffixes(n, pol.AllowedDNSSuffixes)
		for _, a := range pol.AllowedDNSNames {
			if strings.TrimSuffix(strings.ToLower(strings.TrimSpace(a)), ".") == norm {
				ok = true
			}
		}
		if !ok {
			return &PolicyDenial{CodeTeamNameNotAllowed, fmt.Sprintf("requested name %q is outside your team's allowed domains", n)}
		}
	}
	return nil
}

// quotaReservation names the counter row a Reserve bumped so Release undoes
// that exact month even if the clock has rolled over since.
type quotaReservation struct{ key, period string }

// Reserve atomically takes one slot of the team's monthly quota. A nil
// denial with a nil error means the slot is held; a non-nil error means the
// counter could not be used and issuance must be refused.
func (e *teamPolicyEnforcer) Reserve(ctx context.Context, tenant, team string) (*quotaReservation, *PolicyDenial, error) {
	if e.policies == nil || e.counters == nil {
		return nil, nil, errors.New("team quota store unavailable")
	}
	pol, found, err := e.policies.Get(ctx, tenant, team)
	if err != nil {
		return nil, nil, fmt.Errorf("team policy lookup: %w", err)
	}
	now := e.clock()
	if !found || pol.MonthlyQuota == 0 {
		return nil, nil, nil // no policy or unlimited quota: nothing to reserve
	}
	res := &quotaReservation{key: teamPolicyResourceID(tenant, team), period: quotaPeriod(now)}
	ok, err := e.counters.reserve(ctx, res.key, res.period, pol.MonthlyQuota)
	if err != nil {
		return nil, nil, fmt.Errorf("team quota reserve: %w", err)
	}
	if !ok {
		return nil, &PolicyDenial{CodeTeamQuotaExceeded, fmt.Sprintf("monthly certificate quota of %d reached; resets %s", pol.MonthlyQuota, nextPeriodStart(now).Format("2006-01-02"))}, nil
	}
	return res, nil, nil
}

// Release returns a reserved slot (floor 0). A failure is logged: the slot
// stays spent, which errs toward the quota, never past it.
func (e *teamPolicyEnforcer) Release(ctx context.Context, res *quotaReservation) {
	if res == nil || e.counters == nil {
		return
	}
	if err := e.counters.release(context.WithoutCancel(ctx), res.key, res.period); err != nil {
		logging.Warnf("team quota release for %s failed: %v", res.key, err)
	}
}

// Usage reports the current month's consumption. limit is the policy quota
// (0 when there is no policy or the quota is unlimited).
func (e *teamPolicyEnforcer) Usage(ctx context.Context, tenant, team string) (used, limit int, resetsAt time.Time, err error) {
	if e.policies == nil || e.counters == nil {
		return 0, 0, time.Time{}, errors.New("team quota store unavailable")
	}
	now := e.clock()
	pol, found, err := e.policies.Get(ctx, tenant, team)
	if err != nil {
		return 0, 0, time.Time{}, err
	}
	if found {
		limit = pol.MonthlyQuota
	}
	used, err = e.counters.used(ctx, teamPolicyResourceID(tenant, team), quotaPeriod(now))
	return used, limit, nextPeriodStart(now), err
}

// writeForbiddenCode answers 403 with a machine-readable error_code beside
// the human message.
func writeForbiddenCode(w http.ResponseWriter, code, message string) {
	if shouldUseProblemJSON() {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusForbidden)
		payload, _ := json.Marshal(map[string]any{
			"type": "about:blank", "title": titleForStatus(http.StatusForbidden),
			"status": http.StatusForbidden, "detail": message, "error_code": code,
		})
		_, _ = w.Write(payload)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	payload, _ := json.Marshal(map[string]string{"error": "forbidden", "error_code": code, "message": message})
	_, _ = w.Write(payload)
}

// teamTenantForRequest is the tenant whose team policy applies. A scoped
// principal is its own tenant; a bypass principal acts in the CA's tenant.
func teamTenantForRequest(ctx context.Context, pd AuthPrincipal, caID string) (string, error) {
	if !tenantBypass(pd) {
		if pd.Tenant == "" {
			return DefaultTenant, nil
		}
		return pd.Tenant, nil
	}
	if activeTenantStore == nil {
		return DefaultTenant, nil
	}
	return activeTenantStore.CATenant(ctx, caID)
}

// enforceTeamPolicyAtIssue runs the policy check and quota reservation for a
// certificate POST. It writes the refusal and audits it, returning ok=false;
// on ok=true res (possibly nil when enforcement is off) must be released if
// issuance then fails.
func enforceTeamPolicyAtIssue(w http.ResponseWriter, r *http.Request, auditProvider AuditProvider, pd AuthPrincipal, req CertificateIssueRequest) (res *quotaReservation, release func(context.Context), ok bool) {
	e := activeTeamEnforcer
	if e == nil || req.TeamID == "" {
		return nil, func(context.Context) {}, true
	}
	fail := func(msg string, err error) {
		logging.Warnf("team policy enforcement unavailable: principal=%q team=%q: %v", pd.ID, truncateForLog(req.TeamID), err)
		emitAuditEventDetail(r, auditProvider, pd.ID, "certificate.issue", "certificate", "certificates", AuditOutcomeFailure, "field=team_policy reason=enforcement_unavailable")
		writeServiceUnavailable(w, msg)
	}
	tenant, err := teamTenantForRequest(r.Context(), pd, req.CAID)
	if err != nil {
		fail("team policy unavailable", err)
		return nil, nil, false
	}
	denial, err := e.Check(r.Context(), tenant, req.TeamID, req)
	if err != nil {
		fail("team policy unavailable", err)
		return nil, nil, false
	}
	if denial != nil {
		emitAuditEventDetail(r, auditProvider, pd.ID, "certificate.issue", "certificate", "certificates", AuditOutcomeDenied, "field=team_policy reason="+denial.Code)
		writeForbiddenCode(w, denial.Code, denial.Message)
		return nil, nil, false
	}
	res, denial, err = e.Reserve(r.Context(), tenant, req.TeamID)
	if err != nil {
		fail("team quota unavailable", err)
		return nil, nil, false
	}
	if denial != nil {
		detail := "field=team_policy reason=" + denial.Code
		action, rtype, rid := "certificate.issue", "certificate", "certificates"
		if denial.Code == CodeTeamQuotaExceeded {
			action, rtype, rid = "request.quota_exceeded", "team", req.TeamID
			detail = fmt.Sprintf(`{"error_code":%q,"limit":%d,"period":%q}`, denial.Code, quotaLimitOf(r.Context(), e, tenant, req.TeamID), quotaPeriod(e.clock()))
		}
		emitAuditEventDetail(r, auditProvider, pd.ID, action, rtype, rid, AuditOutcomeDenied, detail)
		writeForbiddenCode(w, denial.Code, denial.Message)
		return nil, nil, false
	}
	return res, func(ctx context.Context) { e.Release(ctx, res) }, true
}

func quotaLimitOf(ctx context.Context, e *teamPolicyEnforcer, tenant, team string) int {
	if _, limit, _, err := e.Usage(ctx, tenant, team); err == nil {
		return limit
	}
	return 0
}

// reevaluateTeamPolicyAtApproval re-runs the policy (not the quota, already
// reserved at filing) against the current policy and template so a change
// between request and approval is honored. nil, nil means the request may
// proceed or enforcement does not apply.
func reevaluateTeamPolicyAtApproval(ctx context.Context, apr ApprovalRequest) (*PolicyDenial, error) {
	e := activeTeamEnforcer
	if e == nil || apr.Kind == approvalKindSSH || apr.TeamID == "" {
		return nil, nil
	}
	return e.Check(ctx, approvalTenant(ctx, activeTenantStore, apr), apr.TeamID, teamRequestFromApproval(apr))
}

// registerQuotaHandler mounts GET /api/v1/certificates/quota. Any
// authenticated principal reads its own team's usage; a tenant-bypass admin
// names the team with ?team_id=.
func registerQuotaHandler(mux *http.ServeMux, auth *Authenticator, auditProvider AuditProvider) {
	mux.HandleFunc("GET /api/v1/certificates/quota", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return
		}
		team := pd.ID
		if isCertificateAdmin(pd) {
			team = strings.TrimSpace(r.URL.Query().Get("team_id"))
			if team == "" {
				writeBadRequest(w, "team_id is required")
				return
			}
		}
		e := activeTeamEnforcer
		if e == nil {
			writeServiceUnavailable(w, "team quota not configured")
			return
		}
		tenant := pd.Tenant
		if tenantBypass(pd) {
			tenant = strings.TrimSpace(r.URL.Query().Get("tenant"))
		}
		if tenant == "" {
			tenant = DefaultTenant
		}
		used, limit, resets, err := e.Usage(r.Context(), tenant, team)
		if err != nil {
			logging.Warnf("team quota usage failed: %v", err)
			writeServiceUnavailable(w, "team quota unavailable")
			return
		}
		var remaining any // null when unlimited
		if limit > 0 {
			remaining = max(limit-used, 0)
		}
		data := map[string]any{
			"team_id": team, "period": quotaPeriod(e.clock()), "limit": limit, "used": used,
			"remaining": remaining, "warn": limit > 0 && used*100 >= limit*80, "resets_at": resets.Format(time.RFC3339),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	})
}
