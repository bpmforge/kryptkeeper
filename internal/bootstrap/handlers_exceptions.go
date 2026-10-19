// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
)

// W22-28 (FR-R10): accepted-risk exceptions API.
//
// An exception suppresses a finding on one certificate or CA for a bounded
// time, so creating one is a risk decision that needs a second human. POST
// therefore never writes finding_exceptions: it parks a proposal in the
// pending-action queue (so quorum, expiry and delegation apply), and only the
// executor registered below, run after approval, creates the row.
//
// Tenancy: the proposer's tenant is stamped on the pending action and on the
// resulting exception (finding_exception_tenants). For a platform super-admin
// the stamp is the tenant that owns the target, so the exception lands in the
// tenant whose findings it suppresses. List and delete are scoped by that stamp.

// ExceptionCreateActionType is the pending-action type of an exception proposal.
// validActionType deliberately does not list it: the generic POST
// /pending-actions must not be a second way to create an exception.
const ExceptionCreateActionType = "exception_create"

const (
	exceptionMaxDaysCap   = 365
	exceptionMaxDaysEnv   = "EXCEPTION_MAX_DAYS"
	exceptionNoteMaxChars = 1000
	exceptionFieldMax     = 256
	exceptionBodyMax      = 64 << 10
)

type exceptionRequest struct {
	TargetType        string `json:"target_type"`
	TargetID          string `json:"target_id"`
	FindingCode       string `json:"finding_code"`
	JustificationCode string `json:"justification_code"`
	JustificationNote string `json:"justification_note,omitempty"`
	ExpiresAt         string `json:"expires_at"` // RFC3339
}

// exceptionMaxDays is the longest an exception may run. EXCEPTION_MAX_DAYS can
// only shorten the 365-day cap: an unset, unparseable or non-positive value
// yields the cap, so a typo never widens (or disables) the limit.
func exceptionMaxDays() int {
	raw := strings.TrimSpace(os.Getenv(exceptionMaxDaysEnv))
	if raw == "" {
		return exceptionMaxDaysCap
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return exceptionMaxDaysCap
	}
	return min(n, exceptionMaxDaysCap)
}

var (
	errExceptionWildcard = errors.New("wildcard targets are not allowed")
	errExceptionTarget   = errors.New("target_type must be certificate, ca or target_file")
	errExceptionFields   = errors.New("target_id and finding_code are required")
	errExceptionJustif   = errors.New("justification_code must be one of risk_accepted, compensating_control, false_positive, planned_remediation, not_applicable")
	errExceptionExpiry   = errors.New("expires_at must be an RFC3339 time in the future")
	errExceptionNote     = errors.New("justification_note must be at most 1000 characters")
)

var errDiscoveredFileNotFound = errors.New("discovered file not found")

func errExceptionTooLong() error {
	return fmt.Errorf("expires_at exceeds EXCEPTION_MAX_DAYS (%d)", exceptionMaxDays())
}

// isWildcardToken reports a value that could stand for more than one target.
// Matching is exact everywhere else (findingExceptionKey), so these can never
// match anything today; refusing them keeps a future fuzzy matcher from
// silently turning stored rows into blanket suppressions.
func isWildcardToken(v string) bool {
	if strings.ContainsAny(v, "*?%") {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "all", "any":
		return true
	}
	return false
}

func validateExceptionRequest(r exceptionRequest, now time.Time) error {
	return validateExceptionFields(r, now, true)
}

// validateExceptionFields is validateExceptionRequest with the max-days clause
// switchable: the executor re-validates at approval time but must not apply a
// maximum measured from a later "now" (the limit is judged when proposed).
func validateExceptionFields(r exceptionRequest, now time.Time, checkMax bool) error {
	if r.TargetType != FindingExceptionTargetCertificate && r.TargetType != FindingExceptionTargetCA && r.TargetType != FindingExceptionTargetFile {
		return errExceptionTarget
	}
	id, code := strings.TrimSpace(r.TargetID), strings.TrimSpace(r.FindingCode)
	if id == "" || code == "" || len(id) > exceptionFieldMax || len(code) > exceptionFieldMax {
		return errExceptionFields
	}
	if isWildcardToken(id) || isWildcardToken(code) {
		return errExceptionWildcard
	}
	switch r.JustificationCode {
	case JustificationRiskAccepted, JustificationCompensatingControl, JustificationFalsePositive,
		JustificationPlannedRemediation, JustificationNotApplicable:
	default:
		return errExceptionJustif
	}
	if len([]rune(r.JustificationNote)) > exceptionNoteMaxChars {
		return errExceptionNote
	}
	expires, err := time.Parse(time.RFC3339, r.ExpiresAt)
	if err != nil || !expires.After(now) {
		return errExceptionExpiry
	}
	if checkMax && expires.After(now.Add(time.Duration(exceptionMaxDays())*24*time.Hour)) {
		return errExceptionTooLong()
	}
	return nil
}

type exceptionView struct {
	ID                string `json:"id"`
	TargetType        string `json:"target_type"`
	TargetID          string `json:"target_id"`
	FindingCode       string `json:"finding_code"`
	JustificationCode string `json:"justification_code"`
	JustificationNote string `json:"justification_note,omitempty"`
	CreatedBy         string `json:"created_by"`
	CreatedAt         string `json:"created_at"`
	ExpiresAt         string `json:"expires_at"`
	Status            string `json:"status"` // active | pending
	PendingActionID   string `json:"pending_action_id,omitempty"`
	// TargetLabel names a target_file target as host:path.
	TargetLabel string `json:"target_label,omitempty"`
}

// exceptionTargetTenant resolves the tenant that owns the target: a CA's own
// mapping, or the mapping of the CA that issued the certificate. Without a
// tenant store everything is the default tenant.
func exceptionTargetTenant(ctx context.Context, certs CertificateProvider, cas CAProvider, ts TenantStore, files discoveredFileLookup, targetType, targetID string) (string, error) {
	if targetType == FindingExceptionTargetFile {
		if files == nil {
			return "", errors.New("discovered file lookup unavailable")
		}
		ref, found, err := files.LookupDiscoveredFile(ctx, targetID)
		if err != nil {
			return "", err
		}
		if !found {
			return "", errDiscoveredFileNotFound
		}
		if ref.Tenant == "" {
			return DefaultTenant, nil
		}
		return ref.Tenant, nil
	}
	caID := targetID
	if targetType == FindingExceptionTargetCertificate {
		if certs == nil {
			return "", errors.New("certificate provider unavailable")
		}
		item, found, err := certs.GetCertificate(ctx, targetID)
		if err != nil {
			return "", err
		}
		if !found {
			return "", errCertificateNotFound
		}
		caID = item.CAID
	} else {
		if cas == nil {
			return "", errors.New("ca provider unavailable")
		}
		_, found, err := cas.GetCA(ctx, targetID)
		if err != nil {
			return "", err
		}
		if !found {
			return "", errCANotFound
		}
	}
	if ts == nil {
		return DefaultTenant, nil
	}
	t, err := ts.CATenant(ctx, caID)
	if err != nil {
		return "", err
	}
	if t == "" {
		t = DefaultTenant
	}
	return t, nil
}

// registerExceptionHandlers mounts /api/v1/exceptions. store or pending may be
// nil (their databases failed to open); every route then answers 503.
func registerExceptionHandlers(mux *http.ServeMux, auth *Authenticator, certs CertificateProvider, cas CAProvider, store FindingExceptionStore, pending PendingActionStore, audit AuditProvider) {
	ts, _ := store.(findingExceptionTenantStore)
	ready := func(w http.ResponseWriter) bool {
		if store == nil || pending == nil || ts == nil {
			writeServiceUnavailable(w, "exception store unavailable")
			return false
		}
		return true
	}
	// stamps self-heals the side table on first use of each request path; the
	// DDL is idempotent and the table tiny.
	stamps := func(ctx context.Context) (map[string]string, error) {
		if err := ts.EnsureTenantSchema(ctx); err != nil {
			return nil, err
		}
		return ts.TenantsByID(ctx)
	}

	mux.HandleFunc("/api/v1/exceptions", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return
		}
		if !ready(w) {
			return
		}
		switch r.Method {
		case http.MethodGet:
			listExceptions(w, r, pd, store, ts, pending, stamps)
		case http.MethodPost:
			proposeException(w, r, pd, certs, cas, store, pending, audit)
		default:
			writeMethodNotAllowed(w, "GET, POST")
		}
	})

	mux.HandleFunc("/api/v1/exceptions/", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/exceptions/")
		if id == "" || strings.Contains(id, "/") {
			writeNotFound(w, "exception not found")
			return
		}
		if r.Method != http.MethodDelete {
			writeMethodNotAllowed(w, http.MethodDelete)
			return
		}
		if !ready(w) {
			return
		}
		if pd.Role == RoleMCPAgent {
			emitAuditEvent(r, audit, pd.ID, "exception.delete", "exception", id, AuditOutcomeDenied)
			writeForbidden(w, "the mcp-agent role may not remove exceptions")
			return
		}
		exc, err := store.Get(r.Context(), id)
		if errors.Is(err, errFindingExceptionNotFound) {
			emitAuditEvent(r, audit, pd.ID, "exception.delete", "exception", id, AuditOutcomeFailure)
			writeNotFound(w, "exception not found")
			return
		}
		if err != nil {
			emitAuditEvent(r, audit, pd.ID, "exception.delete", "exception", id, AuditOutcomeFailure)
			writeServiceUnavailable(w, "exception lookup failed")
			return
		}
		tenants, err := stamps(r.Context())
		if err != nil {
			emitAuditEvent(r, audit, pd.ID, "exception.delete", "exception", id, AuditOutcomeFailure)
			writeServiceUnavailable(w, "exception lookup failed")
			return
		}
		// Another tenant's exception is indistinguishable from a missing one.
		if !stampedTenantVisible(pd, tenants[id]) {
			emitAuditEvent(r, audit, pd.ID, "exception.delete", "exception", id, AuditOutcomeDenied)
			writeNotFound(w, "exception not found")
			return
		}
		if err := store.Delete(r.Context(), id); err != nil {
			if errors.Is(err, errFindingExceptionNotFound) {
				writeNotFound(w, "exception not found")
				return
			}
			emitAuditEvent(r, audit, pd.ID, "exception.delete", "exception", id, AuditOutcomeFailure)
			writeServiceUnavailable(w, "exception delete failed")
			return
		}
		if err := ts.ForgetTenant(r.Context(), id); err != nil {
			logging.Infof("exception %s: tenant stamp not removed (harmless orphan): %v", id, err)
		}
		emitAuditEventDetail(r, audit, pd.ID, "exception.delete", "exception", id, AuditOutcomeSuccess, exceptionSummary(exc.TargetType, exc.TargetID, exc.FindingCode))
		writeJSONData(w, map[string]string{"status": "deleted"})
	})
}

// exceptionFiles is the store's discovered-file lookup, nil when it has none.
func exceptionFiles(store FindingExceptionStore) discoveredFileLookup {
	f, _ := store.(discoveredFileLookup)
	return f
}

// exceptionFileLabel names a target_file target host:path for lists.
func exceptionFileLabel(ctx context.Context, files discoveredFileLookup, id string) string {
	if files == nil {
		return ""
	}
	ref, found, err := files.LookupDiscoveredFile(ctx, id)
	if err != nil || !found {
		return ""
	}
	return ref.Host + ":" + ref.Path
}

func exceptionSummary(targetType, targetID, code string) string {
	b, err := json.Marshal(map[string]string{"target_type": targetType, "target_id": targetID, "finding_code": code})
	if err != nil {
		return ""
	}
	return string(b)
}

func listExceptions(w http.ResponseWriter, r *http.Request, pd AuthPrincipal, store FindingExceptionStore, ts findingExceptionTenantStore, pending PendingActionStore, stamps func(context.Context) (map[string]string, error)) {
	now := time.Now()
	active, err := store.ListActive(r.Context(), now)
	if err != nil {
		writeServiceUnavailable(w, "exception list failed")
		return
	}
	tenants, err := stamps(r.Context())
	if err != nil {
		writeServiceUnavailable(w, "exception list failed")
		return
	}
	out := make([]exceptionView, 0, len(active))
	for _, e := range active {
		if !stampedTenantVisible(pd, tenants[e.ID]) {
			continue
		}
		v := exceptionView{
			ID: e.ID, TargetType: e.TargetType, TargetID: e.TargetID, FindingCode: e.FindingCode,
			JustificationCode: e.JustificationCode, JustificationNote: e.JustificationNote,
			CreatedBy: e.CreatedBy, CreatedAt: e.CreatedAt, ExpiresAt: e.ExpiresAt, Status: "active",
		}
		if e.TargetType == FindingExceptionTargetFile {
			v.TargetLabel = exceptionFileLabel(r.Context(), exceptionFiles(store), e.TargetID)
		}
		out = append(out, v)
	}
	actions, err := pending.List(r.Context(), "pending")
	if err != nil {
		writeServiceUnavailable(w, "exception list failed")
		return
	}
	for _, a := range filterPendingActionsByTenant(pd, actions) {
		if a.ActionType != ExceptionCreateActionType {
			continue
		}
		var req exceptionRequest
		if json.Unmarshal(a.Params, &req) != nil {
			continue
		}
		v := exceptionView{
			ID: a.ID, TargetType: req.TargetType, TargetID: req.TargetID, FindingCode: req.FindingCode,
			JustificationCode: req.JustificationCode, JustificationNote: req.JustificationNote,
			CreatedBy: a.ProposedBy, CreatedAt: a.CreatedAt, ExpiresAt: req.ExpiresAt, Status: "pending", PendingActionID: a.ID,
		}
		if req.TargetType == FindingExceptionTargetFile {
			v.TargetLabel = exceptionFileLabel(r.Context(), exceptionFiles(store), req.TargetID)
		}
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	writeJSONData(w, out)
}

func proposeException(w http.ResponseWriter, r *http.Request, pd AuthPrincipal, certs CertificateProvider, cas CAProvider, store FindingExceptionStore, pending PendingActionStore, audit AuditProvider) {
	deny := func(outcome AuditOutcome) {
		emitAuditEvent(r, audit, pd.ID, "exception.create", "exception", "", outcome)
	}
	// An agent may only propose through POST /pending-actions; this proposal
	// is itself the risk decision, so it needs a human principal.
	if pd.Role == RoleMCPAgent {
		deny(AuditOutcomeDenied)
		writeForbidden(w, "the mcp-agent role may not propose exceptions")
		return
	}
	var req exceptionRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, exceptionBodyMax))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		if rejectOversizeBody(w, err) {
			return
		}
		deny(AuditOutcomeFailure)
		writeBadRequest(w, "invalid request body")
		return
	}
	req.TargetID, req.FindingCode = strings.TrimSpace(req.TargetID), strings.TrimSpace(req.FindingCode)
	now := time.Now()
	if err := validateExceptionRequest(req, now); err != nil {
		deny(AuditOutcomeFailure)
		writeBadRequest(w, err.Error())
		return
	}
	// Normalise so the stored params, the list view and the row agree.
	expires, _ := time.Parse(time.RFC3339, req.ExpiresAt) // validated above
	req.ExpiresAt = expires.UTC().Format(time.RFC3339)

	if !exceptionTargetAccessible(w, r, pd, certs, cas, store, req, audit) {
		return
	}

	stamp := pd.Tenant
	if tenantBypass(pd) && multiTenancyEnabled() {
		// A platform super-admin's own tenant says nothing about the target.
		t, err := exceptionTargetTenant(r.Context(), certs, cas, activeTenantStore, exceptionFiles(store), req.TargetType, req.TargetID)
		if err != nil {
			deny(AuditOutcomeFailure)
			writeServiceUnavailable(w, "target tenant unavailable")
			return
		}
		stamp = t
	}

	dup, err := exceptionDuplicate(r.Context(), store, pending, req, now)
	if err != nil {
		deny(AuditOutcomeFailure)
		writeServiceUnavailable(w, "exception lookup failed")
		return
	}
	if dup {
		writeConflict(w, "an active or pending exception already exists for this finding on this target")
		return
	}

	params, err := json.Marshal(req)
	if err != nil {
		deny(AuditOutcomeFailure)
		writeServiceUnavailable(w, "exception could not be queued")
		return
	}
	created, err := pending.Create(r.Context(), PendingAction{
		ActionType: ExceptionCreateActionType,
		Params:     params,
		ProposedBy: pd.ID,
		Rationale:  req.JustificationNote,
		Tenant:     stamp,
	})
	if err != nil {
		deny(AuditOutcomeFailure)
		writeServiceUnavailable(w, "exception could not be queued")
		return
	}
	emitAuditEventDetail(r, audit, pd.ID, "exception.create", "exception", created.ID, AuditOutcomePendingApproval,
		exceptionSummary(req.TargetType, req.TargetID, req.FindingCode))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"status": "pending", "pending_action_id": created.ID}})
}

// exceptionTargetAccessible checks the target exists and is the caller's to
// act on; it writes the refusal itself.
func exceptionTargetAccessible(w http.ResponseWriter, r *http.Request, pd AuthPrincipal, certs CertificateProvider, cas CAProvider, store FindingExceptionStore, req exceptionRequest, audit AuditProvider) bool {
	fail := func(outcome AuditOutcome) {
		emitAuditEvent(r, audit, pd.ID, "exception.create", req.TargetType, req.TargetID, outcome)
	}
	switch req.TargetType {
	case FindingExceptionTargetCertificate:
		_, err := authorizeCertificateResourceAccess(r.Context(), certs, pd, req.TargetID)
		switch {
		case err == nil:
			return true
		case errors.Is(err, errCertificateNotFound):
			fail(AuditOutcomeFailure)
			writeNotFound(w, "certificate not found")
		case errors.Is(err, errCertificateTeamScopeForbidden), errors.Is(err, errCertificateTenantForbidden):
			fail(AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
		default:
			fail(AuditOutcomeFailure)
			writeServiceUnavailable(w, "certificate unavailable")
		}
	case FindingExceptionTargetFile:
		files := exceptionFiles(store)
		if files == nil {
			writeServiceUnavailable(w, "discovered file lookup unavailable")
			return false
		}
		ref, found, err := files.LookupDiscoveredFile(r.Context(), req.TargetID)
		switch {
		case err != nil:
			fail(AuditOutcomeFailure)
			writeServiceUnavailable(w, "discovered file unavailable")
		case !found:
			fail(AuditOutcomeFailure)
			writeNotFound(w, "discovered file not found")
		case !stampedTenantVisible(pd, ref.Tenant):
			fail(AuditOutcomeDenied)
			writeNotFound(w, "discovered file not found")
		default:
			return true
		}
	default: // ca
		if cas == nil {
			writeServiceUnavailable(w, "ca provider unavailable")
			return false
		}
		_, found, err := cas.GetCA(r.Context(), req.TargetID)
		switch {
		case err != nil:
			fail(AuditOutcomeFailure)
			writeServiceUnavailable(w, "ca unavailable")
		case !found:
			fail(AuditOutcomeFailure)
			writeNotFound(w, "ca not found")
		case !caVisibleToTenant(r.Context(), activeTenantStore, pd, req.TargetID):
			fail(AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
		default:
			return true
		}
	}
	return false
}

// exceptionDuplicate reports an active exception or a pending proposal for
// the same (target, finding code). Both are checked across tenants on purpose:
// the target is one object, so a second claim on it is a duplicate whoever
// makes it; the response reveals nothing beyond what the caller could see.
func exceptionDuplicate(ctx context.Context, store FindingExceptionStore, pending PendingActionStore, req exceptionRequest, now time.Time) (bool, error) {
	existing, err := store.ListForTarget(ctx, req.TargetType, req.TargetID)
	if err != nil {
		return false, err
	}
	for _, e := range existing {
		if e.FindingCode == req.FindingCode && e.IsActive(now) {
			return true, nil
		}
	}
	queued, err := pending.List(ctx, "pending")
	if err != nil {
		return false, err
	}
	for _, a := range queued {
		if a.ActionType != ExceptionCreateActionType {
			continue
		}
		var p exceptionRequest
		if json.Unmarshal(a.Params, &p) == nil && p.TargetType == req.TargetType && p.TargetID == req.TargetID && p.FindingCode == req.FindingCode {
			return true, nil
		}
	}
	return false, nil
}

// newExceptionExecutor creates the exception once the queue has enforced
// approver role, no-self-approval and quorum. It fails closed: a target that
// vanished or moved to another tenant since the proposal aborts the action.
func newExceptionExecutor(store FindingExceptionStore, certs CertificateProvider, cas CAProvider, audit AuditProvider) ActionExecutor {
	return func(ctx context.Context, action PendingAction, approver AuthPrincipal) (json.RawMessage, error) {
		ts, ok := store.(findingExceptionTenantStore)
		if store == nil || !ok {
			return nil, errors.New("exception store unavailable")
		}
		var req exceptionRequest
		if err := json.Unmarshal(action.Params, &req); err != nil {
			return nil, fmt.Errorf("invalid exception params: %w", err)
		}
		now := time.Now().UTC()
		if err := validateExceptionFields(req, now, false); err != nil {
			return nil, err
		}
		tenant := action.Tenant
		if tenant == "" {
			tenant = DefaultTenant
		}
		owner, err := exceptionTargetTenant(ctx, certs, cas, activeTenantStore, exceptionFiles(store), req.TargetType, req.TargetID)
		if err != nil {
			return nil, fmt.Errorf("exception target unavailable: %w", err)
		}
		if multiTenancyEnabled() && owner != tenant {
			return nil, errors.New("exception target is no longer in the proposing tenant")
		}
		dup, err := exceptionDuplicateActive(ctx, store, req, now)
		if err != nil {
			return nil, err
		}
		if dup {
			return nil, errors.New("an active exception already exists for this finding on this target")
		}
		id, err := newFindingExceptionID()
		if err != nil {
			return nil, err
		}
		if err := ts.EnsureTenantSchema(ctx); err != nil {
			return nil, err
		}
		exc := FindingException{
			ID: id, TargetType: req.TargetType, TargetID: req.TargetID, FindingCode: req.FindingCode,
			JustificationCode: req.JustificationCode, JustificationNote: req.JustificationNote,
			CreatedBy: action.ProposedBy, CreatedAt: now.Format(time.RFC3339), ExpiresAt: req.ExpiresAt,
		}
		if err := ts.CreateWithTenant(ctx, exc, tenant); err != nil {
			return nil, fmt.Errorf("create exception: %w", err)
		}
		if audit != nil {
			if aerr := audit.AppendEntry(ctx, AuditEntry{
				Timestamp: now.Format(time.RFC3339), Action: "exception.approve", ActorType: "user", ActorID: approver.ID,
				ResourceType: "exception", ResourceID: id, Outcome: AuditOutcomeSuccess, Tenant: tenant,
				ChangeSummary: exceptionSummary(req.TargetType, req.TargetID, req.FindingCode),
			}); aerr != nil {
				logging.Errorf("exception %s created but exception.approve audit append failed: %v", id, aerr)
			}
		}
		return json.Marshal(map[string]string{"exception_id": id})
	}
}

func exceptionDuplicateActive(ctx context.Context, store FindingExceptionStore, req exceptionRequest, now time.Time) (bool, error) {
	existing, err := store.ListForTarget(ctx, req.TargetType, req.TargetID)
	if err != nil {
		return false, err
	}
	for _, e := range existing {
		if e.FindingCode == req.FindingCode && e.IsActive(now) {
			return true, nil
		}
	}
	return false, nil
}

// installExceptions mounts the exceptions API and registers its executor. It
// must run after applyServerOptions and BEFORE registerHandlers: the pending
// action handlers read cfg.actionExecutors when they are registered.
func installExceptions(cfg *ServerConfig, auth *Authenticator, certs CertificateProvider, cas CAProvider, audit AuditProvider) {
	store, err := newFindingExceptionStoreFromEnv()
	if err != nil {
		logging.Warnf("exceptions: store unavailable, API will answer 503: %v", err)
		store = nil
	}
	if store != nil {
		if ts, ok := store.(findingExceptionTenantStore); ok {
			if err := ts.EnsureTenantSchema(context.Background()); err != nil {
				logging.Warnf("exceptions: tenant stamp table unavailable, API will answer 503: %v", err)
				store = nil
			}
		}
	}
	registerExceptionHandlers(cfg.Mux, auth, certs, cas, store, NewPendingActionStoreFromEnv(), audit)
	WithActionExecutor(ExceptionCreateActionType, newExceptionExecutor(store, certs, cas, audit))(cfg)
}
