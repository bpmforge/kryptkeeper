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
	"strings"
	"time"
	"unicode/utf8"

	"kryptkeeper/internal/ca"
)

// W30-09 (FR-P20, UC-I04): natural-language policy drafting. Drafting never
// changes active policy. /policies/draft persists nothing; /policies/draft/submit
// stores a DISABLED row plus a pending "policy.activate" approval, and only the
// approval queue's executor (after its approver-role and proposer != approver
// gates) flips Enabled. The operator text is untrusted: it is bounded, parsed
// deterministically, never logged, and what the parser cannot place is returned.

// ActionPolicyActivate is the pending-action type of a parked draft activation.
const ActionPolicyActivate = "policy.activate"

const (
	policyDraftBodyMax = 16 << 10
	policyDraftTextMax = 2000
	policyDraftCAIDMax = 128

	policyDraftAuditDraft    = "policy.draft"
	policyDraftAuditSubmit   = "policy.submit"
	policyDraftAuditActivate = "policy.activate"
)

type policyDraftRequest struct {
	Name string `json:"name"`
	Text string `json:"text"`
	CAID string `json:"ca_id"`
}

// policyDraftParams is the queue payload: exactly what the approver reviews
// and what the executor re-verifies against the stored row.
type policyDraftParams struct {
	PolicyID     string         `json:"policy_id"`
	Name         string         `json:"name"`
	Rules        ca.PolicyRules `json:"rules"`
	Unrecognized []string       `json:"unrecognized"`
}

// policyEngineAlgorithms maps the family names the parser emits onto the
// concrete names ca.PolicyEngine matches (see policyAlgorithms). A bare
// "ecdsa" in an allow-list would match no request and turn the activated
// policy into deny-all.
var policyEngineAlgorithms = map[string][]string{
	"rsa":     {"RSA-2048", "RSA-3072", "RSA-4096"},
	"ecdsa":   {"ECDSA-P256", "ECDSA-P384"},
	"ed25519": {"Ed25519"},
}

func engineAlgorithms(families []string) []string {
	var out []string
	for _, f := range families {
		out = append(out, policyEngineAlgorithms[f]...)
	}
	return out
}

// WithPolicyDraft mounts the draft/submit routes and registers the
// policy.activate executor. A nil engine returns nil, which Run skips. cas may
// be nil (ca_id existence is then not checked). Like WithPolicyAdmin it must be
// applied before registerHandlers snapshots the executor map.
func WithPolicyDraft(auth *Authenticator, pe *ca.PolicyEngine, audit AuditProvider, cas CAProvider) ServerOption {
	if pe == nil {
		return nil
	}
	return func(c *ServerConfig) {
		store := NewPendingActionStoreFromEnv()
		WithActionExecutor(ActionPolicyActivate, newPolicyActivateExecutor(pe, audit))(c)
		WithExtraHandlers(func(mux *http.ServeMux) {
			registerPolicyDraftHandlers(mux, auth, pe, cas, store, audit)
		})(c)
	}
}

func registerPolicyDraftHandlers(mux *http.ServeMux, auth *Authenticator, pe *ca.PolicyEngine, cas CAProvider, store PendingActionStore, audit AuditProvider) {
	roles := NewCustomRoleStoreFromEnv()
	mux.HandleFunc("/api/v1/policies/draft", func(w http.ResponseWriter, r *http.Request) {
		handlePolicyDraft(w, r, auth, roles, pe, cas, audit, nil, false)
	})
	mux.HandleFunc("/api/v1/policies/draft/submit", func(w http.ResponseWriter, r *http.Request) {
		handlePolicyDraft(w, r, auth, roles, pe, cas, audit, store, true)
	})
}

// handlePolicyDraft serves both routes: they share authn/z, validation and
// parsing, and differ only in whether the result is persisted and queued.
func handlePolicyDraft(w http.ResponseWriter, r *http.Request, auth *Authenticator, roles *CustomRoleStore, pe *ca.PolicyEngine, cas CAProvider, audit AuditProvider, store PendingActionStore, submit bool) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	action := policyDraftAuditDraft
	if submit {
		action = policyDraftAuditSubmit
	}
	pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
	if err != nil {
		emitAuditEvent(r, audit, "", action, "policy", "policies", AuditOutcomeDenied)
		writeUnauthorized(w)
		return
	}
	fail := func(outcome AuditOutcome, detail string) {
		emitAuditEventDetail(r, audit, pd.ID, action, "policy", "policies", outcome, detail)
	}
	// Drafting is open to any principal that may propose (mcp-agent included);
	// the write gate already classifies both routes, this is defence in depth
	// and also keeps read-only roles out of the draft route.
	if allowed, _ := writeDecision(pd, roles, "/api/v1/policies/draft/submit"); !allowed {
		fail(AuditOutcomeDenied, "role may not draft policies")
		writeForbidden(w, "your role may not draft issuance policies")
		return
	}
	// Policies are instance-global (see handlers_policies.go).
	if denyNonSuperAdminGlobal(w, r, audit, pd, action, "policy", "policies") {
		return
	}

	var req policyDraftRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, policyDraftBodyMax))
	if err := dec.Decode(&req); err != nil { // unknown fields (e.g. "enabled") are ignored: client rules and flags are never accepted
		if rejectOversizeBody(w, err) {
			fail(AuditOutcomeFailure, "body too large")
			return
		}
		fail(AuditOutcomeFailure, "invalid JSON")
		writeBadRequest(w, "invalid JSON")
		return
	}
	name := strings.TrimSpace(req.Name)
	text := strings.TrimSpace(req.Text)
	caID := strings.TrimSpace(req.CAID)
	switch {
	case name == "" || utf8.RuneCountInString(name) > policyNameMax:
		fail(AuditOutcomeFailure, "invalid name")
		writeBadRequest(w, "name must be 1-120 characters")
		return
	case text == "" || utf8.RuneCountInString(text) > policyDraftTextMax:
		fail(AuditOutcomeFailure, "invalid text length")
		writeBadRequest(w, fmt.Sprintf("text must be 1-%d characters", policyDraftTextMax))
		return
	case len(caID) > policyDraftCAIDMax:
		fail(AuditOutcomeFailure, "invalid ca_id")
		writeBadRequest(w, "ca_id must be at most 128 characters")
		return
	}
	if caID != "" {
		if !caVisibleToTenant(r.Context(), activeTenantStore, pd, caID) {
			fail(AuditOutcomeDenied, "ca not visible")
			writeNotFound(w, "ca not found")
			return
		}
		if cas != nil {
			_, found, err := cas.GetCA(r.Context(), caID)
			if err != nil {
				fail(AuditOutcomeFailure, "ca lookup failed")
				writeServiceUnavailable(w, "CA lookup failed")
				return
			}
			if !found {
				fail(AuditOutcomeFailure, "ca not found")
				writeNotFound(w, "ca not found")
				return
			}
		}
	}

	res := ParsePolicyDraft(name, text)
	res.Policy.CAID = caID
	res.Policy.Rules.AllowedAlgorithms = engineAlgorithms(res.Policy.Rules.AllowedAlgorithms)
	unrecognized := res.Unrecognized
	if unrecognized == nil {
		unrecognized = []string{}
	}
	summary := fmt.Sprintf("rules=%d unrecognized=%d", len(res.Explanation), len(unrecognized))

	if !submit {
		if msg := validatePolicyFields(res.Policy); msg != "" && len(res.Explanation) > 0 {
			fail(AuditOutcomeFailure, "draft invalid: "+msg)
			writeErrorEnvelope(w, http.StatusUnprocessableEntity, "unprocessable", msg)
			return
		}
		fail(AuditOutcomeSuccess, summary)
		writeJSONData(w, map[string]any{
			"policy": map[string]any{
				"id": "", "name": res.Policy.Name, "enabled": false, "ca_id": res.Policy.CAID, "rules": res.Policy.Rules,
			},
			"explanation":  res.Explanation,
			"unrecognized": unrecognized,
			"persisted":    false,
		})
		return
	}

	if len(res.Explanation) == 0 {
		fail(AuditOutcomeFailure, "no rules recognized; "+summary)
		writeUnprocessable(w, "no policy rules recognized; understood phrases: validity limits (\"valid for at most 90 days\"), RSA floors (\"rsa at least 3072 bits\"), algorithm restrictions (\"only ecdsa and ed25519\"), CA-cert opt-in (\"allow ca certificates\"); unrecognized: "+strings.Join(unrecognized, " | "))
		return
	}
	if msg := validatePolicyFields(res.Policy); msg != "" {
		fail(AuditOutcomeFailure, "draft invalid: "+msg)
		writeUnprocessable(w, msg)
		return
	}
	if store == nil || pe == nil {
		fail(AuditOutcomeFailure, "pending-action store unavailable")
		writeServiceUnavailable(w, "pending-action store unavailable")
		return
	}

	saved, err := SubmitPolicyDraft(pe, res.Policy)
	if err != nil {
		code := http.StatusServiceUnavailable
		if m := strings.ToLower(err.Error()); strings.Contains(m, "unique") || strings.Contains(m, "duplicate") {
			code = http.StatusConflict
		}
		slog.Error("policy draft: store failed", "status", code, "error", err.Error())
		fail(AuditOutcomeFailure, "draft not stored")
		if code == http.StatusConflict {
			writeConflict(w, "a policy with that name already exists")
		} else {
			writeServiceUnavailable(w, "policy draft could not be stored")
		}
		return
	}
	params, err := json.Marshal(policyDraftParams{PolicyID: saved.ID, Name: saved.Name, Rules: saved.Rules, Unrecognized: unrecognized})
	var created PendingAction
	if err == nil {
		created, err = store.Create(r.Context(), PendingAction{
			ActionType: ActionPolicyActivate, Params: params, ProposedBy: pd.ID, Rationale: "NL policy draft", Tenant: pd.Tenant,
		})
	}
	if err != nil {
		// No dangling disabled row without an approval to go with it.
		if derr := pe.DeletePolicy(saved.ID); derr != nil {
			slog.Error("policy draft: cleanup failed", "policy_id", saved.ID, "error", derr.Error())
		}
		slog.Error("policy draft: queue create failed", "policy_id", saved.ID, "error", err.Error())
		fail(AuditOutcomeFailure, "queue create failed")
		writeServiceUnavailable(w, "could not file the approval")
		return
	}
	emitAuditEventDetail(r, audit, pd.ID, action, "policy", saved.ID, AuditOutcomePendingApproval,
		summary+" pending_action="+created.ID)
	writeJSONStatus(w, http.StatusAccepted, map[string]any{"data": map[string]any{
		"policy_id": saved.ID, "pending_action_id": created.ID, "status": "pending_approval",
		"enabled": false, "unrecognized": unrecognized,
	}})
}

func writeUnprocessable(w http.ResponseWriter, message string) {
	writeErrorEnvelope(w, http.StatusUnprocessableEntity, "unprocessable", message)
}

// newPolicyActivateExecutor enables a drafted policy after approval. The queue
// has already enforced approver role, no-self-approval and quorum; this adds
// the checks only it can: instance-global authority and that the stored row is
// still the disabled draft the approver was shown.
func newPolicyActivateExecutor(pe *ca.PolicyEngine, audit AuditProvider) ActionExecutor {
	versions := newPolicyVersionStore(pe)
	if err := versions.EnsureSchema(context.Background()); err != nil {
		slog.Warn("policy draft: version history unavailable; activations will not be versioned", "error", err.Error())
		versions = nil
	}
	return func(ctx context.Context, action PendingAction, approver AuthPrincipal) (json.RawMessage, error) {
		var policyID string
		result, err := func() (json.RawMessage, error) {
			if multiTenancyEnabled() && !tenantBypass(approver) {
				return nil, errors.New("instance-wide policy: platform super-admin approval required when multi-tenancy is on")
			}
			var p policyDraftParams
			if err := json.Unmarshal(action.Params, &p); err != nil {
				return nil, fmt.Errorf("invalid policy params: %w", err)
			}
			policyID = p.PolicyID
			if p.PolicyID == "" {
				return nil, errors.New("invalid policy params: policy_id required")
			}
			cur, found, err := pe.GetPolicy(p.PolicyID)
			if err != nil {
				return nil, err
			}
			if !found {
				return nil, errors.New("draft changed since proposal: policy no longer exists")
			}
			curRules, _ := json.Marshal(cur.Rules)
			wantRules, _ := json.Marshal(p.Rules)
			if cur.Enabled || cur.Name != p.Name || string(curRules) != string(wantRules) {
				return nil, errors.New("draft changed since proposal")
			}
			cur.Enabled = true
			saved, err := pe.UpsertPolicy(cur)
			if err != nil {
				return nil, err
			}
			ver := 0
			if versions != nil {
				if ver, err = versions.Append(ctx, saved, approver.ID, policyChangeUpdate); err != nil {
					slog.Error("policy draft: activated but version not recorded", "policy_id", saved.ID, "error", err.Error())
				}
			}
			return json.Marshal(map[string]any{"policy_id": saved.ID, "version": ver})
		}()
		outcome, summary := AuditOutcomeSuccess, fmt.Sprintf("activated after approval of %s (proposed by %s)", action.ID, action.ProposedBy)
		if err != nil {
			outcome, summary = AuditOutcomeFailure, fmt.Sprintf("activation of %s failed: %s", action.ID, err.Error())
		}
		appendPolicyActivateAudit(audit, approver.ID, policyID, outcome, summary)
		return result, err
	}
}

func appendPolicyActivateAudit(audit AuditProvider, actorID, policyID string, outcome AuditOutcome, summary string) {
	if audit == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), auditAppendTimeout)
	defer cancel()
	if err := audit.AppendEntry(ctx, AuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339), Action: policyDraftAuditActivate, ActorType: "user", ActorID: actorID,
		ResourceType: "policy", ResourceID: policyID, Outcome: outcome, Tenant: DefaultTenant, ChangeSummary: summary,
	}); err != nil {
		slog.Error("policy draft: audit append failed after activation", "policy_id", policyID, "actor_id", actorID, "error", err.Error())
	}
}
