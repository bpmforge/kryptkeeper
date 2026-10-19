// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"
)

// W30-08 (FR-P20, UC-I03): anomaly findings can PROPOSE remediations. Nothing
// here mutates a CA, template or certificate on the request path: the route
// parks a PendingAction, and only the existing approval queue's executor
// (after its approver-role, no-self-approval and quorum gates) acts.

const (
	ActionAnomalySuspendCA       = "anomaly.suspend_ca"
	ActionAnomalyReactivateCA    = "anomaly.reactivate_ca"
	ActionAnomalyDisableTemplate = "anomaly.disable_template"
	ActionAnomalyEnableTemplate  = "anomaly.enable_template"
	ActionAnomalyRevokeBatch     = "anomaly.revoke_batch"
)

const (
	anomalyActionPrefix       = "anomaly."
	anomalyRevokeBatchCap     = 100
	anomalyRationaleMax       = 1000
	anomalyRevokeReasonCode   = 1 // keyCompromise: an anomalous issuance burst is treated as a suspected compromise
	anomalyFingerprintWindow  = time.Hour
	anomalyRemediationsRoute  = "/api/v1/anomalies/remediations"
	anomalyAuditProposeAction = "anomaly.remediation.propose"
	anomalyAuditApproveAction = "anomaly.remediation.approve"
	anomalyAuditRejectAction  = "anomaly.remediation.reject"
)

// anomalyActionTypes maps the request's short action name to its queue type.
var anomalyActionTypes = map[string]string{
	"suspend_ca":       ActionAnomalySuspendCA,
	"reactivate_ca":    ActionAnomalyReactivateCA,
	"disable_template": ActionAnomalyDisableTemplate,
	"enable_template":  ActionAnomalyEnableTemplate,
	"revoke_batch":     ActionAnomalyRevokeBatch,
}

type anomalyBlastRadius struct {
	CAs          int `json:"cas"`
	Templates    int `json:"templates"`
	Certificates int `json:"certificates"`
}

// anomalyParams is the queue payload. BlastRadius is stored with the proposal
// so the approver reads exactly what the proposer saw.
type anomalyParams struct {
	CAID         string             `json:"ca_id,omitempty"`
	TemplateID   string             `json:"template_id,omitempty"`
	Requester    string             `json:"requester,omitempty"`
	Fingerprints []string           `json:"fingerprints,omitempty"`
	ReasonCode   int                `json:"reason_code,omitempty"`
	ReasonText   string             `json:"reason_text,omitempty"`
	Truncated    bool               `json:"truncated,omitempty"`
	FindingKind  string             `json:"finding_kind,omitempty"`
	BlastRadius  anomalyBlastRadius `json:"blast_radius"`
}

type anomalyRemediationRequest struct {
	Action      string `json:"action"`
	CAID        string `json:"ca_id"`
	TemplateID  string `json:"template_id"`
	Requester   string `json:"requester"`
	FindingKind string `json:"finding_kind"`
	Rationale   string `json:"rationale"`
}

// FingerprintsFor returns a copy of the fingerprints requester issued in the
// last hour as of the most recent tick.
func (s *AnomalyScheduler) FingerprintsFor(requester string) []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.fingerprintsByRequester[requester]...)
}

// recentFingerprintsByRequester indexes events issued within the window.
func recentFingerprintsByRequester(events []IssuanceEvent, now time.Time) map[string][]string {
	out := map[string][]string{}
	cutoff := now.Add(-anomalyFingerprintWindow)
	for _, ev := range events {
		if ev.RequestedBy == "" || ev.Fingerprint == "" || ev.IssuedAt.Before(cutoff) {
			continue
		}
		out[ev.RequestedBy] = append(out[ev.RequestedBy], ev.Fingerprint)
	}
	for k := range out {
		sort.Strings(out[k]) // deterministic truncation at the cap
	}
	return out
}

// WithAnomalyRemediation mounts the propose/list routes and registers the
// executor for every anomaly.* queue type. Like installExceptions it must run
// before registerHandlers, which snapshots the executor map.
func WithAnomalyRemediation(auth *Authenticator, sched *AnomalyScheduler, certs CertificateProvider, cas CAProvider, tpls TemplateProvider, audit AuditProvider) ServerOption {
	return func(cfg *ServerConfig) {
		store := NewPendingActionStoreFromEnv()
		registerAnomalyRemediationHandlers(cfg.Mux, auth, sched, certs, cas, tpls, store, audit)
		exec := newAnomalyRemediationExecutor(certs, cas, tpls, audit)
		for _, t := range anomalyActionTypes {
			WithActionExecutor(t, exec)(cfg)
		}
	}
}

func registerAnomalyRemediationHandlers(mux *http.ServeMux, auth *Authenticator, sched *AnomalyScheduler, certs CertificateProvider, cas CAProvider, tpls TemplateProvider, store PendingActionStore, audit AuditProvider) {
	mux.HandleFunc("/api/v1/anomalies/remediations", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			if r.Method == http.MethodPost {
				emitAuditEvent(r, audit, "", anomalyAuditProposeAction, "anomaly-remediation", "", AuditOutcomeDenied)
			}
			writeUnauthorized(w)
			return
		}
		switch r.Method {
		case http.MethodGet:
			listAnomalyRemediations(w, r, pd, store)
		case http.MethodPost:
			proposeAnomalyRemediation(w, r, pd, sched, certs, cas, tpls, store, audit)
		default:
			writeMethodNotAllowed(w, "GET, POST")
		}
	})
}

func mayProposeAnomalyRemediation(pd AuthPrincipal) bool {
	if canApproveActions(pd.Role) {
		return true
	}
	return pd.Role == RoleMCPAgent
}

func listAnomalyRemediations(w http.ResponseWriter, r *http.Request, pd AuthPrincipal, store PendingActionStore) {
	if !canReadOperationalSummaries(pd) && !mayProposeAnomalyRemediation(pd) {
		writeForbidden(w, "your role may not read anomaly remediations")
		return
	}
	if store == nil {
		writeServiceUnavailable(w, "pending-action store unavailable")
		return
	}
	list, err := store.List(r.Context(), strings.TrimSpace(r.URL.Query().Get("status")))
	if err != nil {
		writeServiceUnavailable(w, "list failed")
		return
	}
	out := []PendingAction{}
	for _, a := range filterPendingActionsByTenant(pd, list) {
		if strings.HasPrefix(a.ActionType, anomalyActionPrefix) {
			out = append(out, a)
		}
	}
	writeJSONData(w, out)
}

func proposeAnomalyRemediation(w http.ResponseWriter, r *http.Request, pd AuthPrincipal, sched *AnomalyScheduler, certs CertificateProvider, cas CAProvider, tpls TemplateProvider, store PendingActionStore, audit AuditProvider) {
	fail := func(outcome AuditOutcome, resourceID, detail string) {
		emitAuditEventDetail(r, audit, pd.ID, anomalyAuditProposeAction, "anomaly-remediation", resourceID, outcome, detail)
	}
	if !mayProposeAnomalyRemediation(pd) {
		fail(AuditOutcomeDenied, "", "role not permitted to propose")
		writeForbidden(w, "your role may not propose anomaly remediations")
		return
	}
	if store == nil {
		fail(AuditOutcomeFailure, "", "pending-action store unavailable")
		writeServiceUnavailable(w, "pending-action store unavailable")
		return
	}
	var req anomalyRemediationRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProposalBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		if rejectOversizeBody(w, err) {
			return
		}
		fail(AuditOutcomeFailure, "", "invalid JSON")
		writeBadRequest(w, "invalid JSON")
		return
	}
	actionType, ok := anomalyActionTypes[req.Action]
	if !ok {
		fail(AuditOutcomeFailure, "", "unsupported action")
		writeBadRequest(w, "action must be one of suspend_ca, reactivate_ca, disable_template, enable_template, revoke_batch")
		return
	}
	kind := strings.TrimSpace(req.FindingKind)
	rationale := strings.TrimSpace(req.Rationale)
	if len(rationale) > anomalyRationaleMax {
		fail(AuditOutcomeFailure, "", "rationale too long")
		writeBadRequest(w, fmt.Sprintf("rationale must be at most %d characters", anomalyRationaleMax))
		return
	}
	if rationale == "" {
		rationale = "anomaly " + kind
	}

	params := anomalyParams{FindingKind: kind}
	var targetID string
	var code int
	var msg string
	var denied bool
	switch actionType {
	case ActionAnomalySuspendCA, ActionAnomalyReactivateCA:
		targetID = strings.TrimSpace(req.CAID)
		code, msg, denied = resolveRemediationCA(r.Context(), pd, cas, certs, targetID, &params)
	case ActionAnomalyDisableTemplate, ActionAnomalyEnableTemplate:
		targetID = strings.TrimSpace(req.TemplateID)
		code, msg, denied = resolveRemediationTemplate(r.Context(), pd, tpls, certs, targetID, &params)
	case ActionAnomalyRevokeBatch:
		targetID = strings.TrimSpace(req.Requester)
		code, msg, denied = resolveRemediationBatch(r.Context(), pd, sched, certs, targetID, kind, &params)
	}
	if code != 0 {
		outcome := AuditOutcomeFailure
		if denied {
			outcome = AuditOutcomeDenied
		}
		fail(outcome, targetID, req.Action+": "+msg)
		writeErrorEnvelope(w, code, errorCodeForStatus(code), msg)
		return
	}

	raw, err := json.Marshal(params)
	if err != nil {
		fail(AuditOutcomeFailure, targetID, "encode failed")
		writeServiceUnavailable(w, "could not encode proposal")
		return
	}
	created, err := store.Create(r.Context(), PendingAction{
		ActionType: actionType, Params: raw, ProposedBy: pd.ID, Rationale: rationale, Tenant: pd.Tenant,
	})
	if err != nil {
		slog.Error("anomaly remediation: queue create failed", "action", req.Action, "error", err.Error())
		fail(AuditOutcomeFailure, targetID, "queue create failed")
		writeServiceUnavailable(w, "create failed")
		return
	}
	emitAuditEventDetail(r, audit, pd.ID, anomalyAuditProposeAction, "pending-action", created.ID, AuditOutcomePendingApproval,
		fmt.Sprintf("action=%s target=%s finding=%s cas=%d templates=%d certificates=%d", req.Action, targetID, kind,
			params.BlastRadius.CAs, params.BlastRadius.Templates, params.BlastRadius.Certificates))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
		"status": "proposed", "pending_action_id": created.ID, "blast_radius": params.BlastRadius,
	}})
}

// A missing and a tenant-invisible target answer the same 404 so a tenant
// cannot probe other tenants' ids; only the audit outcome differs.
const msgRemediationNotFound = "target not found"

func errorCodeForStatus(code int) string {
	switch code {
	case http.StatusNotFound:
		return "not_found"
	case http.StatusConflict:
		return "conflict"
	case http.StatusBadRequest:
		return "bad_request"
	}
	return "unavailable"
}

func countMatchingCertificates(ctx context.Context, certs CertificateProvider, q CertificateListQuery) int {
	if certs == nil {
		return 0
	}
	q.Limit = 1
	res, err := certs.ListCertificates(ctx, q)
	if err != nil {
		return 0 // blast radius is advisory; a count failure must not block a proposal
	}
	return res.Total
}

func resolveRemediationCA(ctx context.Context, pd AuthPrincipal, cas CAProvider, certs CertificateProvider, id string, p *anomalyParams) (int, string, bool) {
	if id == "" {
		return http.StatusBadRequest, "ca_id is required", false
	}
	if cas == nil {
		return http.StatusServiceUnavailable, "CA provider unavailable", false
	}
	if !caVisibleToTenant(ctx, activeTenantStore, pd, id) {
		return http.StatusNotFound, msgRemediationNotFound, true
	}
	_, found, err := cas.GetCA(ctx, id)
	if err != nil {
		return http.StatusServiceUnavailable, "CA lookup failed", false
	}
	if !found {
		return http.StatusNotFound, msgRemediationNotFound, false
	}
	p.CAID = id
	p.BlastRadius = anomalyBlastRadius{CAs: 1, Certificates: countMatchingCertificates(ctx, certs, CertificateListQuery{CAID: id})}
	return 0, "", false
}

func resolveRemediationTemplate(ctx context.Context, pd AuthPrincipal, tpls TemplateProvider, certs CertificateProvider, id string, p *anomalyParams) (int, string, bool) {
	if id == "" {
		return http.StatusBadRequest, "template_id is required", false
	}
	if tpls == nil {
		return http.StatusServiceUnavailable, "template provider unavailable", false
	}
	if !templateVisibleToTenant(ctx, activeTenantStore, pd, id) {
		return http.StatusNotFound, msgRemediationNotFound, true
	}
	_, found, err := tpls.GetTemplate(ctx, id)
	if err != nil {
		return http.StatusServiceUnavailable, "template lookup failed", false
	}
	if !found {
		return http.StatusNotFound, msgRemediationNotFound, false
	}
	p.TemplateID = id
	p.BlastRadius = anomalyBlastRadius{Templates: 1, Certificates: countMatchingCertificates(ctx, certs, CertificateListQuery{TemplateID: id})}
	return 0, "", false
}

func resolveRemediationBatch(ctx context.Context, pd AuthPrincipal, sched *AnomalyScheduler, certs CertificateProvider, requester, kind string, p *anomalyParams) (int, string, bool) {
	if requester == "" {
		return http.StatusBadRequest, "requester is required", false
	}
	fps := sched.FingerprintsFor(requester)
	// A tenant-scoped proposer may only batch certificates whose CA they can see.
	if !tenantBypass(pd) && certs != nil {
		visible := fps[:0:0]
		for _, fp := range fps {
			d, found, err := certs.GetCertificate(ctx, fp)
			if err != nil || !found || !caVisibleToTenant(ctx, activeTenantStore, pd, d.CAID) {
				continue
			}
			visible = append(visible, fp)
		}
		fps = visible
	}
	if len(fps) == 0 {
		return http.StatusConflict, "no recent issuance by that requester", false
	}
	if len(fps) > anomalyRevokeBatchCap {
		fps = fps[:anomalyRevokeBatchCap]
		p.Truncated = true
	}
	p.Requester = requester
	p.Fingerprints = fps
	p.ReasonCode = anomalyRevokeReasonCode
	p.ReasonText = strings.TrimSpace("anomaly " + kind + " requester " + requester)
	p.BlastRadius = anomalyBlastRadius{Certificates: len(fps)}
	return 0, "", false
}

// appendAnomalyAudit records a remediation outcome from the executor, where
// no *http.Request exists. A lost row is logged loudly: the action has
// already run and the log is then the only trace.
func appendAnomalyAudit(audit AuditProvider, actorID, action, resourceID string, outcome AuditOutcome, summary, tenant string) {
	if audit == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), auditAppendTimeout)
	defer cancel()
	if err := audit.AppendEntry(ctx, AuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339), Action: action, ActorType: "user", ActorID: actorID,
		ResourceType: "anomaly-remediation", ResourceID: resourceID, Outcome: outcome, Tenant: tenant, ChangeSummary: summary,
	}); err != nil {
		slog.Error("anomaly remediation: audit append failed after action", "action", action, "resource_id", resourceID, "actor_id", actorID, "error", err.Error())
	}
}

// newAnomalyRemediationExecutor carries out an approved remediation. The queue
// has already enforced approver role, no-self-approval and quorum.
func newAnomalyRemediationExecutor(certs CertificateProvider, cas CAProvider, tpls TemplateProvider, audit AuditProvider) ActionExecutor {
	return func(ctx context.Context, action PendingAction, approver AuthPrincipal) (json.RawMessage, error) {
		var p anomalyParams
		target := ""
		result, err := func() (json.RawMessage, error) {
			// CAs and templates are instance-global: with multi-tenancy on, only
			// a platform super-admin may approve (same rule as policy loosening).
			if !tenantBypass(approver) {
				return nil, errors.New("instance-wide remediation: platform super-admin approval required when multi-tenancy is on")
			}
			if err := json.Unmarshal(action.Params, &p); err != nil {
				return nil, fmt.Errorf("invalid remediation params: %w", err)
			}
			switch action.ActionType {
			case ActionAnomalySuspendCA, ActionAnomalyReactivateCA:
				target = p.CAID
				if p.CAID == "" || cas == nil {
					return nil, errors.New("invalid remediation params: ca_id required")
				}
				var change CAStatusChange
				var err error
				if action.ActionType == ActionAnomalySuspendCA {
					change, err = cas.SuspendCA(ctx, p.CAID)
				} else {
					change, err = cas.ActivateCA(ctx, p.CAID)
				}
				if err != nil {
					return nil, err
				}
				return json.Marshal(map[string]string{"ca_id": change.ID, "status": change.Status})
			case ActionAnomalyDisableTemplate, ActionAnomalyEnableTemplate:
				target = p.TemplateID
				if p.TemplateID == "" || tpls == nil {
					return nil, errors.New("invalid remediation params: template_id required")
				}
				active := action.ActionType == ActionAnomalyEnableTemplate
				if _, err := tpls.PatchTemplate(ctx, p.TemplateID, TemplatePatchRequest{Active: &active}); err != nil {
					return nil, err
				}
				return json.Marshal(map[string]any{"template_id": p.TemplateID, "active": active})
			case ActionAnomalyRevokeBatch:
				target = p.Requester
				return executeAnomalyRevokeBatch(ctx, certs, p)
			}
			return nil, fmt.Errorf("unsupported remediation action %q", action.ActionType)
		}()
		summary := fmt.Sprintf("%s target=%s proposed_by=%s pending_action=%s", action.ActionType, target, action.ProposedBy, action.ID)
		if err != nil {
			appendAnomalyAudit(audit, approver.ID, anomalyAuditApproveAction, target, AuditOutcomeFailure, summary+": "+err.Error(), action.Tenant)
			return nil, err
		}
		appendAnomalyAudit(audit, approver.ID, anomalyAuditApproveAction, target, AuditOutcomeSuccess, summary, action.Tenant)
		return result, nil
	}
}

func executeAnomalyRevokeBatch(ctx context.Context, certs CertificateProvider, p anomalyParams) (json.RawMessage, error) {
	if certs == nil || len(p.Fingerprints) == 0 {
		return nil, errors.New("invalid remediation params: fingerprints required")
	}
	fps := p.Fingerprints
	if len(fps) > anomalyRevokeBatchCap {
		fps = fps[:anomalyRevokeBatchCap]
	}
	revoked, failed, inventoryOnly := 0, 0, 0
	for _, fp := range fps {
		res, err := certs.RevokeCertificate(ctx, fp, CertificateRevokeRequest{ReasonCode: p.ReasonCode, ReasonText: p.ReasonText})
		if err != nil {
			failed++
			slog.Warn("anomaly remediation: revoke failed", "fingerprint", fp, "error", err.Error())
			continue
		}
		revoked++
		if res.RevocationScope == RevocationScopeInventoryOnly {
			inventoryOnly++
		}
	}
	if revoked == 0 {
		return nil, fmt.Errorf("all %d revocations failed", failed)
	}
	return json.Marshal(map[string]int{"revoked": revoked, "failed": failed, "inventory_only": inventoryOnly})
}
