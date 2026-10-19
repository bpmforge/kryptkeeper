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
	"net/http"
	"strings"
	"time"
)

const maxDelegationDays = 30

// ApprovalDelegation lets one approver name a delegate who may decide on
// their behalf for a bounded window. Tenant is the delegator's tenant: the
// row is keyed (delegator, tenant) so equal free-text principal ids in two
// tenants can never overwrite or consume each other's delegation.
type ApprovalDelegation struct {
	Delegator string `json:"delegator"`
	Delegate  string `json:"delegate"`
	StartsAt  string `json:"starts_at"`
	EndsAt    string `json:"ends_at"`
	CreatedAt string `json:"created_at"`
	Tenant    string `json:"tenant,omitempty"`
}

type approvalDelegationStore struct {
	db *sql.DB
	ph func(int) string
}

// delegationStoreForActions derives the store from the pending-action store's
// DB handle (same database); other store types yield nil.
func delegationStoreForActions(s PendingActionStore) *approvalDelegationStore {
	if p, ok := s.(*dbPendingActionStore); ok && p != nil {
		return &approvalDelegationStore{db: p.db, ph: p.ph}
	}
	return nil
}

func delegationStoreForApprovals(s ApprovalStore) *approvalDelegationStore {
	if u, ok := s.(interface{ Unwrap() ApprovalStore }); ok {
		s = u.Unwrap() // W32-26 notifying wrapper
	}
	switch v := s.(type) {
	case *sqliteApprovalStore:
		if v != nil {
			return &approvalDelegationStore{db: v.db, ph: sqlitePlaceholder}
		}
	case *postgresApprovalStore:
		if v != nil {
			return &approvalDelegationStore{db: v.db, ph: postgresPlaceholder}
		}
	}
	return nil
}

func (s *approvalDelegationStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, approvalDelegationSchema)
	return err
}

func (s *approvalDelegationStore) Set(ctx context.Context, d ApprovalDelegation) error {
	q := fmt.Sprintf(`INSERT INTO approval_delegations (delegator, tenant, delegate, starts_at, ends_at, created_at)
		VALUES (%s, %s, %s, %s, %s, %s)
		ON CONFLICT (delegator, tenant) DO UPDATE SET delegate = excluded.delegate,
		starts_at = excluded.starts_at, ends_at = excluded.ends_at, created_at = excluded.created_at`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4), s.ph(5), s.ph(6))
	_, err := s.db.ExecContext(ctx, q, d.Delegator, d.Tenant, d.Delegate, d.StartsAt, d.EndsAt, d.CreatedAt)
	return err
}

func (s *approvalDelegationStore) Clear(ctx context.Context, delegator, tenant string) error {
	_, err := s.db.ExecContext(ctx, fmt.Sprintf(
		`DELETE FROM approval_delegations WHERE delegator = %s AND tenant = %s`, s.ph(1), s.ph(2)), delegator, tenant)
	return err
}

// Get returns the delegator's delegation regardless of its window.
func (s *approvalDelegationStore) Get(ctx context.Context, delegator, tenant string) (ApprovalDelegation, bool, error) {
	var d ApprovalDelegation
	err := s.db.QueryRowContext(ctx, fmt.Sprintf(
		`SELECT delegator, tenant, delegate, starts_at, ends_at, created_at FROM approval_delegations
		 WHERE delegator = %s AND tenant = %s`, s.ph(1), s.ph(2)), delegator, tenant).
		Scan(&d.Delegator, &d.Tenant, &d.Delegate, &d.StartsAt, &d.EndsAt, &d.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ApprovalDelegation{}, false, nil
	}
	if err != nil {
		return ApprovalDelegation{}, false, err
	}
	return d, true, nil
}

// Active returns the delegation only while starts_at <= now <= ends_at.
func (s *approvalDelegationStore) Active(ctx context.Context, delegator, tenant string, now time.Time) (ApprovalDelegation, bool, error) {
	d, ok, err := s.Get(ctx, delegator, tenant)
	if err != nil || !ok {
		return ApprovalDelegation{}, false, err
	}
	start, e1 := time.Parse(time.RFC3339, d.StartsAt)
	end, e2 := time.Parse(time.RFC3339, d.EndsAt)
	if e1 != nil || e2 != nil || now.Before(start) || now.After(end) {
		return ApprovalDelegation{}, false, nil
	}
	return d, true, nil
}

var errDelegationRange = errors.New("delegation range may not exceed 30 days")

// validateDelegation checks the window; the 30-day cap bounds how long a
// forgotten delegation can keep a second person able to decide in someone's
// name.
func validateDelegation(d ApprovalDelegation, now time.Time) error {
	start, err := time.Parse(time.RFC3339, d.StartsAt)
	if err != nil {
		return errors.New("starts_at must be RFC3339")
	}
	end, err := time.Parse(time.RFC3339, d.EndsAt)
	if err != nil {
		return errors.New("ends_at must be RFC3339")
	}
	if !end.After(start) {
		return errors.New("ends_at must be after starts_at")
	}
	if !end.After(now) {
		return errors.New("ends_at must be in the future")
	}
	if end.Sub(start) > maxDelegationDays*24*time.Hour {
		return errDelegationRange
	}
	return nil
}

// delegationTenant is the tenant a principal's delegation lives under.
func delegationTenant(pd AuthPrincipal) string {
	if !multiTenancyEnabled() || pd.Tenant == "" {
		return DefaultTenant
	}
	return pd.Tenant
}

// delegationScopeTenant normalises an action's or CA's tenant the same way.
func delegationScopeTenant(t string) string {
	if !multiTenancyEnabled() || t == "" {
		return DefaultTenant
	}
	return t
}

// delegateMayApprove reports whether principalID currently holds an approver
// capability in the given tenant: an active API key, or an active user in the
// directory. It is a set-time sanity check only; the use-time mayDecide gate
// is authoritative (a key minted by the bootstrap token passes here on role).
func delegateMayApprove(ctx context.Context, auth *Authenticator, principalID, tenant string) bool {
	principalID = strings.TrimSpace(principalID)
	if auth == nil || principalID == "" {
		return false
	}
	for _, rec := range auth.apiKeysSnapshot() {
		if rec.Active && rec.PrincipalID == principalID && canApproveActions(rec.Role) &&
			delegationScopeTenant(rec.Tenant) == tenant {
			return true
		}
	}
	if auth.userProvider != nil {
		users, err := auth.userProvider.ListUsers(ctx)
		if err != nil {
			return false
		}
		for _, u := range users {
			if (u.ID == principalID || strings.EqualFold(u.Email, principalID)) &&
				!isDeprovisionedStatus(u.Status) && canApproveActions(strings.TrimSpace(u.Role)) &&
				delegationScopeTenant(userTenant(u)) == tenant {
				return true
			}
		}
	}
	return false
}

// delegatorHuman is the canonical human behind a delegator's principal id, so
// a quorum counts "A directly" and "A via delegate" as one person.
func delegatorHuman(a *Authenticator, delegatorID string) string {
	if a == nil {
		return delegatorID
	}
	records := a.apiKeysSnapshot()
	for _, r := range records {
		if r.PrincipalID == delegatorID && r.CreatedBy != "" {
			return followCreatedBy(records, r.CreatedBy)
		}
	}
	return delegatorID
}

// authorizeOnBehalf validates an on_behalf_of approval. It returns "" when the
// delegation is valid, else the 403 message. tenant is the decided item's
// tenant: the delegation must live in it, so a delegate can never act across
// a tenant boundary. The delegator must not be the proposer's human (a
// self-approval laundered through a delegate).
func authorizeOnBehalf(ctx context.Context, auth *Authenticator, ds *approvalDelegationStore, pd AuthPrincipal, onBehalfOf, proposedBy, tenant string, now time.Time) string {
	noDelegation := "no active delegation from " + onBehalfOf + " to you"
	if ds == nil {
		return noDelegation
	}
	d, ok, err := ds.Active(ctx, onBehalfOf, delegationScopeTenant(tenant), now)
	if err != nil || !ok || (d.Delegate != pd.ID && d.Delegate != auth.canonicalHuman(pd)) {
		return noDelegation
	}
	proposers := auth.humansBehind(proposedBy)
	if proposers[onBehalfOf] || proposers[delegatorHuman(auth, onBehalfOf)] {
		return msgSelfApproval
	}
	for h := range auth.humansBehind(onBehalfOf) {
		if proposers[h] {
			return msgSelfApproval
		}
	}
	return ""
}

// onBehalfRequest reads the optional approve body. An empty or malformed body
// means "approve as myself": the safe reading, since it never widens authority.
func onBehalfRequest(w http.ResponseWriter, r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	var body struct {
		OnBehalfOf string `json:"on_behalf_of"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body) // absent/invalid body = no delegation
	return strings.TrimSpace(body.OnBehalfOf)
}

func delegationAuditDetail(onBehalfOf, delegate string) string {
	if onBehalfOf == "" {
		return ""
	}
	return fmt.Sprintf("on_behalf_of=%s delegate=%s", onBehalfOf, delegate)
}

// registerApprovalDelegationHandlers mounts GET/PUT/DELETE
// /api/v1/approvals/delegation. Everything is scoped to the caller's own
// (principal, tenant), so there is no cross-tenant read or write path.
func registerApprovalDelegationHandlers(mux *http.ServeMux, auth *Authenticator, ds *approvalDelegationStore, audit AuditProvider) {
	if ds != nil {
		_ = ds.EnsureSchema(context.Background()) // self-heal like the other stores; a failure surfaces as 503 below
	}
	mux.HandleFunc("/api/v1/approvals/delegation", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, audit, "", "approval.delegate", "approval", "-", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if !auth.mayDecide(pd) {
			emitAuditEvent(r, audit, pd.ID, "approval.delegate", "approval", pd.ID, AuditOutcomeDenied)
			writeForbidden(w, approveDeniedMessage(auth, pd, "delegate approvals for"))
			return
		}
		if ds == nil {
			writeServiceUnavailable(w, "delegation store unavailable")
			return
		}
		tenant := delegationTenant(pd)
		switch r.Method {
		case http.MethodGet:
			d, ok, gerr := ds.Get(r.Context(), pd.ID, tenant)
			if gerr != nil {
				writeServiceUnavailable(w, "delegation lookup failed")
				return
			}
			if !ok {
				writeJSONData(w, nil)
				return
			}
			writeJSONData(w, d)
		case http.MethodPut:
			var body struct {
				Delegate string `json:"delegate"`
				StartsAt string `json:"starts_at"`
				EndsAt   string `json:"ends_at"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
				emitAuditEvent(r, audit, pd.ID, "approval.delegate", "approval", pd.ID, AuditOutcomeFailure)
				writeBadRequest(w, "invalid JSON")
				return
			}
			t := time.Now().UTC()
			d := ApprovalDelegation{Delegator: pd.ID, Delegate: strings.TrimSpace(body.Delegate),
				StartsAt: body.StartsAt, EndsAt: body.EndsAt, CreatedAt: t.Format(time.RFC3339), Tenant: tenant}
			if d.Delegate == "" || d.Delegate == pd.ID || d.Delegate == auth.canonicalHuman(pd) {
				emitAuditEvent(r, audit, pd.ID, "approval.delegate", "approval", pd.ID, AuditOutcomeFailure)
				writeBadRequest(w, "delegate must be another principal")
				return
			}
			if verr := validateDelegation(d, t); verr != nil {
				emitAuditEvent(r, audit, pd.ID, "approval.delegate", "approval", pd.ID, AuditOutcomeFailure)
				writeBadRequest(w, verr.Error())
				return
			}
			// Normalise to UTC so stored bounds compare consistently.
			s, _ := time.Parse(time.RFC3339, d.StartsAt)
			e, _ := time.Parse(time.RFC3339, d.EndsAt)
			d.StartsAt, d.EndsAt = s.UTC().Format(time.RFC3339), e.UTC().Format(time.RFC3339)
			if !delegateMayApprove(r.Context(), auth, d.Delegate, tenant) {
				emitAuditEventDetail(r, audit, pd.ID, "approval.delegate", "approval", pd.ID, AuditOutcomeDenied,
					"delegate "+d.Delegate+" lacks approve capability in this tenant")
				writeForbidden(w, "the delegate does not hold an approver role")
				return
			}
			if serr := ds.Set(r.Context(), d); serr != nil {
				emitAuditEvent(r, audit, pd.ID, "approval.delegate", "approval", pd.ID, AuditOutcomeFailure)
				writeServiceUnavailable(w, "delegation could not be saved")
				return
			}
			emitAuditEventDetail(r, audit, pd.ID, "approval.delegate", "approval", pd.ID, AuditOutcomeSuccess,
				fmt.Sprintf("set delegate=%s from=%s to=%s", d.Delegate, d.StartsAt, d.EndsAt))
			writeJSONData(w, d)
		case http.MethodDelete:
			if cerr := ds.Clear(r.Context(), pd.ID, tenant); cerr != nil {
				emitAuditEvent(r, audit, pd.ID, "approval.delegate", "approval", pd.ID, AuditOutcomeFailure)
				writeServiceUnavailable(w, "delegation could not be cleared")
				return
			}
			emitAuditEventDetail(r, audit, pd.ID, "approval.delegate", "approval", pd.ID, AuditOutcomeSuccess, "cleared")
			w.WriteHeader(http.StatusNoContent)
		default:
			writeMethodNotAllowed(w, "GET, PUT, DELETE")
		}
	})
}
