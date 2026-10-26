// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
	"kryptkeeper/internal/trustpush"
)

type trustBundleRequest struct {
	Name      string        `json:"name"`
	Action    string        `json:"action"`
	CertPEM   string        `json:"cert_pem"`
	Selector  TrustSelector `json:"selector"`
	Rationale string        `json:"rationale"`
}

// trustHostStatus is one targeted host's row in a bundle's status.
type trustHostStatus struct {
	AgentID    string `json:"agent_id"`
	AgentName  string `json:"agent_name"`
	Outcome    string `json:"outcome"` // applied | refused_not_opted_in | failed | pending
	Detail     string `json:"detail,omitempty"`
	ReportedAt string `json:"reported_at,omitempty"`
}

type trustBundleSummary struct {
	TrustBundle
	Targets int `json:"targets"`
	Applied int `json:"applied"`
	Refused int `json:"refused_not_opted_in"`
	Failed  int `json:"failed"`
	Pending int `json:"pending"`
}

func tallyTrustResults(b TrustBundle, results []TrustBundleResult, names map[string]string) (trustBundleSummary, []trustHostStatus) {
	byAgent := map[string]TrustBundleResult{}
	for _, r := range results {
		byAgent[r.AgentID] = r
	}
	sum := trustBundleSummary{TrustBundle: b, Targets: len(b.AgentIDs)}
	hosts := make([]trustHostStatus, 0, len(b.AgentIDs))
	for _, id := range b.AgentIDs {
		h := trustHostStatus{AgentID: id, AgentName: names[id], Outcome: "pending"}
		if r, ok := byAgent[id]; ok {
			h.Outcome, h.Detail, h.ReportedAt = r.Outcome, r.Detail, r.ReportedAt
		}
		switch h.Outcome {
		case trustpush.OutcomeApplied:
			sum.Applied++
		case trustpush.OutcomeRefused:
			sum.Refused++
		case trustpush.OutcomeFailed:
			sum.Failed++
		default:
			sum.Pending++
		}
		hosts = append(hosts, h)
	}
	return sum, hosts
}

// registerTrustBundleHandlers mounts the admin API on mux and the agent-token
// routes on agentMux, and registers the approval executor on cfg (it must run
// before the pending-action queue is mounted, like the migration executor).
//
// Creating a bundle is Critical: POST only queues a proposal (202); the bundle
// exists after a different human approves it. The write gate maps POST to
// permPropose so the MCP agent may propose and never approve (D-029).
func registerTrustBundleHandlers(cfg *ServerConfig, mux *http.ServeMux, agentMux routeRegistrar, auth *Authenticator, agents AgentStore, store TrustBundleStore, pending PendingActionStore, certs CertificateProvider, cas CAProvider, audit AuditProvider) {
	if cfg.actionExecutors == nil {
		cfg.actionExecutors = map[string]ActionExecutor{}
	}
	cfg.actionExecutors[ActionTrustBundlePush] = newTrustBundleExecutor(store, agents, audit)

	agentNames := func() map[string]string {
		m := map[string]string{}
		for _, a := range agents.list() {
			m[a.ID] = a.Name
		}
		return m
	}

	mux.HandleFunc("/api/v1/trust-bundles", func(w http.ResponseWriter, r *http.Request) {
		const action = "trust_bundle.propose"
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			emitAuditEventDetail(r, audit, "", action, "trust_bundle", "", AuditOutcomeFailure, "method not allowed")
			writeMethodNotAllowed(w, "GET, POST")
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			if r.Method == http.MethodPost {
				emitAuditEvent(r, audit, "", action, "trust_bundle", "", AuditOutcomeDenied)
			}
			writeUnauthorized(w)
			return
		}
		// D-203: agents carry no tenant, so trust bundles are instance-wide.
		if denyNonSuperAdminGlobal(w, r, audit, pd, action, "trust_bundle", "-") {
			return
		}
		if store == nil {
			emitAuditEventDetail(r, audit, pd.ID, action, "trust_bundle", "", AuditOutcomeFailure, "store unavailable")
			writeServiceUnavailable(w, "trust bundles unavailable")
			return
		}
		if r.Method == http.MethodGet {
			list, lerr := store.List(r.Context(), 100)
			if lerr != nil {
				logging.Infof("trust bundles list: %v", lerr)
				writeServiceUnavailable(w, "trust bundles unavailable")
				return
			}
			names := agentNames()
			out := make([]trustBundleSummary, 0, len(list))
			for _, b := range list {
				results, _ := store.Results(r.Context(), b.ID)
				sum, _ := tallyTrustResults(b, results, names)
				out = append(out, sum)
			}
			writeJSONData(w, out)
			return
		}

		var req trustBundleRequest
		if !decodeJSONBodyOrReject(w, r, &req, trustBundleBodyMax, "invalid request body") {
			emitAuditEventDetail(r, audit, pd.ID, action, "trust_bundle", "", AuditOutcomeFailure, "invalid request body")
			return
		}
		refuse := func(msg string) {
			emitAuditEventDetail(r, audit, pd.ID, action, "trust_bundle", "", AuditOutcomeFailure, "refused: "+codesignTruncate(msg, trustBundleDetailMax))
			writeBadRequest(w, msg)
		}
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" || len(req.Name) > trustBundleNameMax {
			refuse("name is required (at most 120 characters)")
			return
		}
		act := trustpush.Action(req.Action)
		if !act.Valid() {
			refuse("action must be add or remove")
			return
		}
		parsed, perr := trustpush.ParseCAs(req.CertPEM, time.Now(), act == trustpush.ActionAdd)
		if perr != nil {
			// The parser names the offending block type, never bytes.
			refuse(perr.Error())
			return
		}
		targets, terr := resolveTrustTargets(req.Selector, agents.list())
		if terr != nil {
			refuse(terr.Error())
			return
		}
		_, normalised := trustBundleCerts(parsed)
		p := trustBundleParams{Name: req.Name, Action: req.Action, CertPEM: normalised, Selector: req.Selector, AgentIDs: targets}
		if act == trustpush.ActionRemove {
			p.Warnings = removalWarnings(r.Context(), parsed, certs, cas, time.Now())
		}
		queued, qerr := ProposeTrustBundle(r.Context(), pending, pd, p, req.Rationale)
		if qerr != nil {
			logging.Infof("trust bundle propose: %v", qerr)
			emitAuditEventDetail(r, audit, pd.ID, action, "trust_bundle", "", AuditOutcomeFailure, "approval queue unavailable")
			writeServiceUnavailable(w, "approval queue unavailable")
			return
		}
		emitAuditEventDetail(r, audit, pd.ID, action, "trust_bundle", queued.ID, AuditOutcomePendingApproval,
			fmt.Sprintf("action=%s name=%q agents=%d certs=%d warnings=%d", req.Action, req.Name, len(targets), len(parsed), len(p.Warnings)))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"action_id": queued.ID, "status": "pending", "targets": len(targets), "warnings": p.Warnings,
		}})
	})

	mux.HandleFunc("/api/v1/trust-bundles/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/trust-bundles/")
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return
		}
		if denyNonSuperAdminGlobal(w, r, audit, pd, "trust_bundle.read", "trust_bundle", id) {
			return
		}
		if store == nil {
			writeServiceUnavailable(w, "trust bundles unavailable")
			return
		}
		b, found, gerr := store.Get(r.Context(), id)
		if gerr != nil {
			logging.Infof("trust bundle get %s: %v", id, gerr)
			writeServiceUnavailable(w, "trust bundles unavailable")
			return
		}
		if !found {
			writeNotFound(w, "trust bundle not found")
			return
		}
		results, _ := store.Results(r.Context(), id)
		sum, hosts := tallyTrustResults(b, results, agentNames())
		writeJSONData(w, map[string]any{"bundle": sum, "hosts": hosts})
	})

	// GET /api/v1/agent/trust-tasks: the bundles queued for this agent. The
	// agent opts in locally (D-319); the hub only offers.
	agentMux.HandleFunc("GET /api/v1/agent/trust-tasks", func(w http.ResponseWriter, r *http.Request) {
		agentID, token, ok := agentCredentials(r)
		if !ok {
			writeBadRequest(w, "missing X-Agent-ID or X-Agent-Token")
			return
		}
		if err := agents.verifyAgent(agentID, token); err != nil {
			writeErrorEnvelope(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
			return
		}
		if store == nil {
			writeServiceUnavailable(w, "trust bundles unavailable")
			return
		}
		pendingBundles, perr := store.PendingForAgent(r.Context(), agentID)
		if perr != nil {
			logging.Infof("trust tasks for %s: %v", agentID, perr)
			writeServiceUnavailable(w, "trust bundles unavailable")
			return
		}
		tasks := make([]map[string]string, 0, len(pendingBundles))
		for _, b := range pendingBundles {
			tasks = append(tasks, map[string]string{"bundle_id": b.ID, "name": b.Name, "action": b.Action, "cert_pem": b.CertPEM})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"tasks": tasks})
	})

	// POST /api/v1/agent/trust-result: what the agent did with a bundle.
	agentMux.HandleFunc("POST /api/v1/agent/trust-result", func(w http.ResponseWriter, r *http.Request) {
		const action = "agent.trust_result"
		agentID, token, ok := agentCredentials(r)
		if !ok {
			emitAuditEvent(r, audit, "", action, "trust_bundle", "-", AuditOutcomeDenied)
			writeBadRequest(w, "missing X-Agent-ID or X-Agent-Token")
			return
		}
		actor := "agent:" + agentID
		if err := agents.verifyAgent(agentID, token); err != nil {
			emitAuditEvent(r, audit, actor, action, "trust_bundle", "-", AuditOutcomeDenied)
			writeErrorEnvelope(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
			return
		}
		var res TrustBundleResult
		if !decodeJSONBodyOrReject(w, r, &res, 16<<10, "invalid JSON") {
			return
		}
		fail := func(code int, msg string) {
			emitAuditEventDetail(r, audit, actor, action, "trust_bundle", res.BundleID, AuditOutcomeFailure, msg)
			writeErrorEnvelope(w, code, "invalid_request", msg)
		}
		switch res.Outcome {
		case trustpush.OutcomeApplied, trustpush.OutcomeRefused, trustpush.OutcomeFailed:
		default:
			fail(http.StatusBadRequest, "outcome must be applied, refused_not_opted_in or failed")
			return
		}
		if store == nil {
			writeServiceUnavailable(w, "trust bundles unavailable")
			return
		}
		b, found, gerr := store.Get(r.Context(), res.BundleID)
		if gerr != nil {
			writeServiceUnavailable(w, "trust bundles unavailable")
			return
		}
		// An agent may only report on a bundle that targets it.
		if !found || !containsString(b.AgentIDs, agentID) {
			fail(http.StatusNotFound, "no such trust bundle for this agent")
			return
		}
		res.AgentID = agentID
		res.Detail = codesignTruncate(res.Detail, trustBundleDetailMax)
		if err := store.SaveResult(r.Context(), res); err != nil {
			logging.Infof("trust result %s/%s: %v", res.BundleID, agentID, err)
			emitAuditEventDetail(r, audit, actor, action, "trust_bundle", res.BundleID, AuditOutcomeFailure, "store error")
			writeServiceUnavailable(w, "trust bundles unavailable")
			return
		}
		outcome := AuditOutcomeSuccess
		if res.Outcome == trustpush.OutcomeFailed {
			outcome = AuditOutcomeFailure
		}
		emitAuditEventDetail(r, audit, actor, action, "trust_bundle", res.BundleID, outcome,
			fmt.Sprintf("outcome=%s action=%s", res.Outcome, b.Action))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "recorded"})
	})
}
