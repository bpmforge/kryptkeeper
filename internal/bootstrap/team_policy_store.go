// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/logging"
)

// W33-20 (FR-P8, UC-M04 step 1): per-team issuance allowance and the
// approval-gated admin API over it. Enforcement at request time is a later
// ticket; this one only stores the allowance and guards who may widen it.
//
// Semantics (D-195): an absent policy means the team is unrestricted
// (back-compat), an empty list means no restriction on that axis, and a
// max_validity_days or monthly_quota of 0 means no cap. Creating a policy is
// therefore always a tightening and applies at once. Anything that removes or
// widens a restriction (deleting the policy, emptying a list, adding to a
// non-empty list, raising a cap or quota or setting it to 0) is parked for a
// second approver, as W22-15 does for issuance policies.
//
// Teams are only the free-string owner_team on certificates today, so the
// team key is that string, scoped by tenant.

// ActionTeamPolicyLoosen is the pending-action type of a parked team-policy
// loosening. Like ActionPolicyLoosen it runs through the executor map, so
// validActionType stays untouched.
const ActionTeamPolicyLoosen = "team_policy.loosen"

const (
	teamNameMax        = 120
	teamListMax        = 100
	teamEntryMax       = 253
	teamQuotaMax       = 1000000
	teamPolicyBodyMax  = 64 * 1024
	teamPolicyResource = "team-policy"
)

var (
	errTeamPolicyStale  = errors.New("team policy changed since proposal")
	errTeamPolicyExists = errors.New("team policy already exists")
)

const teamPolicySchema = `
CREATE TABLE IF NOT EXISTS team_policies (
  tenant TEXT NOT NULL DEFAULT 'default', team TEXT NOT NULL,
  allowed_cas TEXT NOT NULL DEFAULT '[]', allowed_templates TEXT NOT NULL DEFAULT '[]',
  allowed_dns_suffixes TEXT NOT NULL DEFAULT '[]', allowed_dns_names TEXT NOT NULL DEFAULT '[]',
  max_validity_days INTEGER NOT NULL DEFAULT 0, monthly_quota INTEGER NOT NULL DEFAULT 0,
  version INTEGER NOT NULL DEFAULT 1, updated_by TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY (tenant, team));
CREATE INDEX IF NOT EXISTS idx_team_policies_tenant ON team_policies(tenant);`

// TeamPolicy is one team's issuance allowance. List fields never serialize
// as null.
type TeamPolicy struct {
	Tenant             string   `json:"tenant"`
	Team               string   `json:"team"`
	AllowedCAs         []string `json:"allowed_cas"`
	AllowedTemplates   []string `json:"allowed_templates"`
	AllowedDNSSuffixes []string `json:"allowed_dns_suffixes"`
	AllowedDNSNames    []string `json:"allowed_dns_names"`
	MaxValidityDays    int      `json:"max_validity_days"`
	MonthlyQuota       int      `json:"monthly_quota"`
	Version            int      `json:"version"`
	UpdatedBy          string   `json:"updated_by"`
	CreatedAt          string   `json:"created_at"`
	UpdatedAt          string   `json:"updated_at"`
}

// TeamPolicyStore persists team policies.
type TeamPolicyStore interface {
	EnsureSchema(ctx context.Context) error
	// List returns one tenant's policies, or every tenant's when all is true.
	List(ctx context.Context, tenant string, all bool) ([]TeamPolicy, error)
	Get(ctx context.Context, tenant, team string) (TeamPolicy, bool, error)
	// Put writes p. baseVersion 0 creates (errTeamPolicyExists on a
	// duplicate); otherwise the stored version must equal baseVersion
	// (errTeamPolicyStale if it moved or the row is gone). The stored
	// version advances by one.
	Put(ctx context.Context, p TeamPolicy, baseVersion int, by string) (TeamPolicy, error)
	Delete(ctx context.Context, tenant, team string) (bool, error)
}

type dbTeamPolicyStore struct {
	db *sql.DB
	ph func(int) string
}

func newDBTeamPolicyStore(db *sql.DB, postgres bool) *dbTeamPolicyStore {
	ph := sqlitePlaceholder
	if postgres {
		ph = postgresPlaceholder
	}
	return &dbTeamPolicyStore{db: db, ph: ph}
}

func (s *dbTeamPolicyStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, teamPolicySchema)
	return err
}

const teamPolicyCols = `tenant, team, allowed_cas, allowed_templates, allowed_dns_suffixes, allowed_dns_names,
	max_validity_days, monthly_quota, version, updated_by, created_at, updated_at`

func scanTeamPolicy(sc interface{ Scan(...any) error }) (TeamPolicy, error) {
	var p TeamPolicy
	var cas, tpls, sfx, names string
	if err := sc.Scan(&p.Tenant, &p.Team, &cas, &tpls, &sfx, &names, &p.MaxValidityDays, &p.MonthlyQuota,
		&p.Version, &p.UpdatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return TeamPolicy{}, err
	}
	for _, f := range []struct {
		raw string
		dst *[]string
	}{{cas, &p.AllowedCAs}, {tpls, &p.AllowedTemplates}, {sfx, &p.AllowedDNSSuffixes}, {names, &p.AllowedDNSNames}} {
		if err := json.Unmarshal([]byte(f.raw), f.dst); err != nil {
			return TeamPolicy{}, fmt.Errorf("team policy %s/%s list: %w", p.Tenant, p.Team, err)
		}
	}
	p.normalizeLists()
	return p, nil
}

func (s *dbTeamPolicyStore) List(ctx context.Context, tenant string, all bool) ([]TeamPolicy, error) {
	q, args := `SELECT `+teamPolicyCols+` FROM team_policies`, []any{}
	if !all {
		q += ` WHERE tenant = ` + s.ph(1)
		args = append(args, tenant)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY tenant, team`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TeamPolicy{}
	for rows.Next() {
		p, err := scanTeamPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *dbTeamPolicyStore) Get(ctx context.Context, tenant, team string) (TeamPolicy, bool, error) {
	p, err := scanTeamPolicy(s.db.QueryRowContext(ctx, `SELECT `+teamPolicyCols+` FROM team_policies WHERE tenant = `+s.ph(1)+` AND team = `+s.ph(2), tenant, team))
	if errors.Is(err, sql.ErrNoRows) {
		return TeamPolicy{}, false, nil
	}
	return p, err == nil, err
}

func (s *dbTeamPolicyStore) Put(ctx context.Context, p TeamPolicy, baseVersion int, by string) (TeamPolicy, error) {
	p.normalizeLists()
	lists := make([]string, 4)
	for i, l := range [][]string{p.AllowedCAs, p.AllowedTemplates, p.AllowedDNSSuffixes, p.AllowedDNSNames} {
		b, err := json.Marshal(l)
		if err != nil {
			return TeamPolicy{}, err
		}
		lists[i] = string(b)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return TeamPolicy{}, err
	}
	defer func() { _ = tx.Rollback() }() // no-op once committed

	var cur int
	var created string
	err = tx.QueryRowContext(ctx, `SELECT version, created_at FROM team_policies WHERE tenant = `+s.ph(1)+` AND team = `+s.ph(2), p.Tenant, p.Team).Scan(&cur, &created)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return TeamPolicy{}, err
	}
	switch {
	case baseVersion == 0 && exists:
		return TeamPolicy{}, errTeamPolicyExists
	case baseVersion != 0 && (!exists || cur != baseVersion):
		return TeamPolicy{}, errTeamPolicyStale
	}
	if exists {
		p.Version, p.CreatedAt = cur+1, created
		_, err = tx.ExecContext(ctx, fmt.Sprintf(`UPDATE team_policies SET allowed_cas=%s, allowed_templates=%s, allowed_dns_suffixes=%s,
			allowed_dns_names=%s, max_validity_days=%s, monthly_quota=%s, version=%s, updated_by=%s, updated_at=%s
			WHERE tenant=%s AND team=%s`, s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7), s.ph(8), s.ph(9), s.ph(10), s.ph(11)),
			lists[0], lists[1], lists[2], lists[3], p.MaxValidityDays, p.MonthlyQuota, p.Version, by, now, p.Tenant, p.Team)
	} else {
		p.Version, p.CreatedAt = 1, now
		_, err = tx.ExecContext(ctx, fmt.Sprintf(`INSERT INTO team_policies (`+teamPolicyCols+`)
			VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)`, s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6), s.ph(7), s.ph(8), s.ph(9), s.ph(10), s.ph(11), s.ph(12)),
			p.Tenant, p.Team, lists[0], lists[1], lists[2], lists[3], p.MaxValidityDays, p.MonthlyQuota, p.Version, by, now, now)
	}
	if err != nil {
		// A concurrent create loses on the primary key.
		if !exists {
			if _, found, gerr := s.Get(ctx, p.Tenant, p.Team); gerr == nil && found {
				return TeamPolicy{}, errTeamPolicyExists
			}
		}
		return TeamPolicy{}, err
	}
	if err := tx.Commit(); err != nil {
		return TeamPolicy{}, err
	}
	p.UpdatedBy, p.UpdatedAt = by, now
	return p, nil
}

func (s *dbTeamPolicyStore) Delete(ctx context.Context, tenant, team string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM team_policies WHERE tenant = `+s.ph(1)+` AND team = `+s.ph(2), tenant, team)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// normalizeLists trims, de-duplicates and sorts every list, and turns nil
// into [] so JSON never carries null. Empty entries survive (as one "") so
// validateTeamPolicy can reject them.
func (p *TeamPolicy) normalizeLists() {
	for _, l := range []*[]string{&p.AllowedCAs, &p.AllowedTemplates, &p.AllowedDNSSuffixes, &p.AllowedDNSNames} {
		out := make([]string, 0, len(*l))
		for _, v := range *l {
			out = append(out, strings.TrimSpace(v))
		}
		slices.Sort(out)
		*l = slices.Compact(out)
	}
}

// validateTeamPolicy returns "" when p is well formed, else the 400 message.
// It expects normalizeLists to have run.
func validateTeamPolicy(p TeamPolicy) string {
	team := strings.TrimSpace(p.Team)
	if n := len(team); n < 1 || n > teamNameMax {
		return "team must be 1-120 characters"
	}
	if strings.Contains(team, "/") || strings.IndexFunc(team, unicode.IsControl) >= 0 {
		return "team must not contain '/' or control characters"
	}
	for _, l := range []struct {
		name string
		v    []string
	}{{"allowed_cas", p.AllowedCAs}, {"allowed_templates", p.AllowedTemplates}, {"allowed_dns_suffixes", p.AllowedDNSSuffixes}, {"allowed_dns_names", p.AllowedDNSNames}} {
		if len(l.v) > teamListMax {
			return l.name + " may hold at most 100 entries"
		}
		for _, e := range l.v {
			if e == "" || len(e) > teamEntryMax {
				return l.name + " entries must be 1-253 characters"
			}
		}
	}
	if err := (&ca.NamePolicy{AllowedDNSSuffixes: p.AllowedDNSSuffixes, AllowedDNSNames: p.AllowedDNSNames}).Validate(); err != nil {
		return err.Error()
	}
	if p.MaxValidityDays < 0 || p.MaxValidityDays > policyMaxValidityCap {
		return "max_validity_days must be between 0 and 3650 (0 = no cap)"
	}
	if p.MonthlyQuota < 0 || p.MonthlyQuota > teamQuotaMax {
		return "monthly_quota must be between 0 and 1000000 (0 = unlimited)"
	}
	return ""
}

// validateTeamPolicyTenants requires every CA and template to belong to the
// policy's tenant. It only runs with multi-tenancy on and a tenant store, as
// elsewhere; otherwise every CA maps to the default tenant anyway.
func validateTeamPolicyTenants(ctx context.Context, p TeamPolicy) string {
	if !multiTenancyEnabled() || activeTenantStore == nil {
		return ""
	}
	if ok, err := activeTenantStore.TenantExists(ctx, p.Tenant); err != nil || !ok {
		return "unknown tenant"
	}
	for _, id := range p.AllowedCAs {
		if t, err := activeTenantStore.CATenant(ctx, id); err != nil || t != p.Tenant {
			return "ca not in tenant"
		}
	}
	for _, id := range p.AllowedTemplates {
		if t, err := activeTenantStore.TemplateTenant(ctx, id); err != nil || t != p.Tenant {
			return "template not in tenant"
		}
	}
	return ""
}

// teamPolicyLoosening lists why next removes or widens a restriction in old;
// empty means a tightening or no-op. It applies to an existing policy only:
// creating one (from unrestricted) is always a tightening, and deleting one is
// always a loosening, so both are decided by the caller. Per list, emptying a
// non-empty list or adding any entry to it loosens; filling an empty list or
// removing entries while keeping at least one tightens. For the cap and the
// quota, 0 means none, so raising a non-zero value or setting it to 0 loosens.
func teamPolicyLoosening(old, next TeamPolicy) []string {
	var r []string
	list := func(kind string, o, n []string) {
		if len(o) == 0 {
			return
		}
		if len(n) == 0 {
			r = append(r, kind+" list cleared (no restriction)")
			return
		}
		for _, v := range n {
			if !slices.Contains(o, v) {
				r = append(r, kind+" added: "+v)
			}
		}
	}
	list("CA", old.AllowedCAs, next.AllowedCAs)
	list("template", old.AllowedTemplates, next.AllowedTemplates)
	list("DNS suffix", old.AllowedDNSSuffixes, next.AllowedDNSSuffixes)
	list("DNS name", old.AllowedDNSNames, next.AllowedDNSNames)
	if old.MaxValidityDays > 0 && (next.MaxValidityDays == 0 || next.MaxValidityDays > old.MaxValidityDays) {
		r = append(r, "max validity raised or removed")
	}
	if old.MonthlyQuota > 0 && (next.MonthlyQuota == 0 || next.MonthlyQuota > old.MonthlyQuota) {
		r = append(r, "monthly quota raised or removed")
	}
	return r
}

func teamPolicyResourceID(tenant, team string) string { return tenant + "/" + team }

func teamPolicySummary(p TeamPolicy) string {
	b, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	return string(b)
}

// teamPolicyLoosenParams is the payload of a parked loosening.
type teamPolicyLoosenParams struct {
	Tenant      string     `json:"tenant"`
	Team        string     `json:"team"`
	Proposed    TeamPolicy `json:"proposed"`
	Reasons     []string   `json:"reasons"`
	BaseVersion int        `json:"base_version"`
	// Delete removes the policy (the team becomes unrestricted) instead of
	// writing Proposed.
	Delete bool `json:"delete,omitempty"`
}

// newTeamPolicyLoosenExecutor applies an approved loosening. The queue has
// already enforced approver role, no-self-approval and quorum; this adds the
// tenant check and the staleness check only it can make.
func newTeamPolicyLoosenExecutor(store TeamPolicyStore, audit AuditProvider) ActionExecutor {
	return func(ctx context.Context, action PendingAction, approver AuthPrincipal) (json.RawMessage, error) {
		var p teamPolicyLoosenParams
		if err := json.Unmarshal(action.Params, &p); err != nil {
			return nil, fmt.Errorf("invalid team policy params: %w", err)
		}
		if p.Tenant == "" || p.Team == "" || (!p.Delete && (p.Proposed.Tenant != p.Tenant || p.Proposed.Team != p.Team)) {
			return nil, errors.New("invalid team policy params: tenant/team mismatch")
		}
		if !tenantBypass(approver) && approver.Tenant != p.Tenant {
			return nil, errors.New("team policy belongs to another tenant")
		}
		if p.Delete {
			return executeTeamPolicyDelete(ctx, store, audit, action, approver, p)
		}
		p.Proposed.normalizeLists()
		if msg := validateTeamPolicy(p.Proposed); msg != "" {
			return nil, errors.New(msg)
		}
		if msg := validateTeamPolicyTenants(ctx, p.Proposed); msg != "" {
			return nil, errors.New(msg)
		}
		saved, err := store.Put(ctx, p.Proposed, p.BaseVersion, approver.ID)
		if errors.Is(err, errTeamPolicyStale) || errors.Is(err, errTeamPolicyExists) {
			return nil, errTeamPolicyStale
		}
		if err != nil {
			return nil, err
		}
		if audit != nil {
			if aerr := audit.AppendEntry(ctx, AuditEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339), Action: "team_policy.update", ActorType: "user", ActorID: approver.ID,
				ResourceType: teamPolicyResource, ResourceID: teamPolicyResourceID(saved.Tenant, saved.Team), Outcome: AuditOutcomeSuccess, Tenant: saved.Tenant,
				ChangeSummary: "applied after approval of " + action.ID + " (proposed by " + action.ProposedBy + "; " + strings.Join(p.Reasons, "; ") + "): " + teamPolicySummary(saved),
			}); aerr != nil {
				logging.Errorf("team policy %s/%s changed after approval but the audit append failed: %v", saved.Tenant, saved.Team, aerr)
			}
		}
		return json.Marshal(map[string]any{"tenant": saved.Tenant, "team": saved.Team, "version": saved.Version})
	}
}

// executeTeamPolicyDelete removes the policy once approved, refusing if it
// changed since the proposal.
func executeTeamPolicyDelete(ctx context.Context, store TeamPolicyStore, audit AuditProvider, action PendingAction, approver AuthPrincipal, p teamPolicyLoosenParams) (json.RawMessage, error) {
	cur, found, err := store.Get(ctx, p.Tenant, p.Team)
	if err != nil {
		return nil, err
	}
	if !found || cur.Version != p.BaseVersion {
		return nil, errTeamPolicyStale
	}
	if _, err := store.Delete(ctx, p.Tenant, p.Team); err != nil {
		return nil, err
	}
	if audit != nil {
		if aerr := audit.AppendEntry(ctx, AuditEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339), Action: "team_policy.delete", ActorType: "user", ActorID: approver.ID,
			ResourceType: teamPolicyResource, ResourceID: teamPolicyResourceID(p.Tenant, p.Team), Outcome: AuditOutcomeSuccess, Tenant: p.Tenant,
			ChangeSummary: "deleted after approval of " + action.ID + " (proposed by " + action.ProposedBy + "; " + strings.Join(p.Reasons, "; ") + "): " + teamPolicySummary(cur),
		}); aerr != nil {
			logging.Errorf("team policy %s/%s deleted after approval but the audit append failed: %v", p.Tenant, p.Team, aerr)
		}
	}
	return json.Marshal(map[string]any{"tenant": p.Tenant, "team": p.Team, "deleted": true})
}
