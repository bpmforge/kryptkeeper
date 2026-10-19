// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"kryptkeeper/internal/logging"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/ca"
)

// W22-14 (FR-P8): the issuance-policy admin API over ca.PolicyEngine.
//
// Tenancy: issuance policies govern EVERY tenant's issuance (the engine reads
// the same rows for all of them), so they are instance-global. With
// multi-tenancy on, every route (reads and dry-run included, because a policy
// row names CAs and thresholds across tenants) requires the platform
// super-admin; a tenant-scoped admin is refused. With it off, any pki-admin.

const (
	policyNameMax        = 120
	policyMaxValidityCap = 3650
	policyDryRunMaxBody  = 256 * 1024
	policyWriteMaxBody   = 64 * 1024
)

// policyAlgorithms is the closed set the engine can actually derive from a
// request (see ca.requestedAlgorithm). An allow-list entry outside it could
// never match and would silently turn the policy into a deny-all.
var policyAlgorithms = map[string]bool{
	"RSA-2048": true, "RSA-3072": true, "RSA-4096": true, "ECDSA-P256": true, "ECDSA-P384": true, "Ed25519": true,
	"ML-DSA-44": true, "ML-DSA-65": true, "ML-DSA-87": true,
	"Hybrid-ECDSA-P256-ML-DSA-65": true, "Hybrid-ECDSA-P384-ML-DSA-87": true,
}

// WithPolicyAdmin mounts /api/v1/policies and wires the violation hook so
// every refusal leaves a policy.violation audit row. A nil engine (no core
// DB, or KRYPTKEEPER_ALLOW_NO_POLICY) returns nil, which Run skips.
func WithPolicyAdmin(auth *Authenticator, pe *ca.PolicyEngine, auditProvider AuditProvider) ServerOption {
	if pe == nil {
		return nil
	}
	pe.SetViolationHook(func(caID string, v *ca.PolicyViolationError) {
		if auditProvider == nil {
			return
		}
		// No request here (the refusal can come from ACME/EST/SCEP/API alike),
		// so the row is appended directly as a system actor.
		ctx, cancel := context.WithTimeout(context.Background(), auditAppendTimeout)
		defer cancel()
		err := auditProvider.AppendEntry(ctx, AuditEntry{
			Timestamp:     time.Now().UTC().Format(time.RFC3339),
			Action:        "policy.violation",
			ActorType:     "system",
			ActorID:       "policy-engine",
			ResourceType:  "policy",
			ResourceID:    v.PolicyID,
			Outcome:       AuditOutcomeDenied,
			ChangeSummary: v.Error(),
			Tenant:        DefaultTenant,
		})
		if err != nil {
			logging.Errorf("audit append failed action=policy.violation ca=%s policy=%s: %v", caID, v.PolicyID, err)
		}
	})
	versions := newPolicyVersionStore(pe)
	if err := versions.EnsureSchema(context.Background()); err != nil {
		logging.Warnf("policy versions: schema unavailable, policy changes will answer 503: %v", err)
		versions = nil
	}
	return func(c *ServerConfig) {
		c.policyEngine = pe // migrated templates are raised to its RSA floor (B2)
		pending := NewPendingActionStoreFromEnv()
		if versions != nil {
			WithActionExecutor(ActionPolicyLoosen, newPolicyLoosenExecutor(pe, versions, auditProvider))(c)
		}
		WithExtraHandlers(func(mux *http.ServeMux) {
			registerPolicyHandlers(mux, auth, pe, auditProvider, versions, pending)
		})(c)
	}
}

type policyRulesBody struct {
	AllowedAlgorithms *[]string `json:"allowed_algorithms"`
	MinRSABits        *int      `json:"min_rsa_bits"`
	MaxValidityDays   *int      `json:"max_validity_days"`
	AllowCACerts      *bool     `json:"allow_ca_certs"`
}

type policyWriteBody struct {
	Name     *string          `json:"name"`
	Enabled  *bool            `json:"enabled"`
	CAID     *string          `json:"ca_id"`
	Rules    *policyRulesBody `json:"rules"`
	RevertTo *int             `json:"revert_to"`
}

func validatePolicyFields(pol ca.IssuancePolicy) string {
	if n := len(strings.TrimSpace(pol.Name)); n < 1 || len(pol.Name) > policyNameMax {
		return "name must be 1-120 characters"
	}
	for _, a := range pol.Rules.AllowedAlgorithms {
		if !policyAlgorithms[a] {
			return "unknown algorithm in allowed_algorithms: " + a
		}
	}
	if m := pol.Rules.MinRSABits; m != 0 && (m < 2048 || m > 16384) {
		return "min_rsa_bits must be 0 or between 2048 and 16384"
	}
	if d := pol.Rules.MaxValidityDays; d < 0 || d > policyMaxValidityCap {
		return "max_validity_days must be between 0 and 3650"
	}
	return ""
}

// applyPolicyBody overlays the supplied fields onto pol (create starts from
// the zero value, PATCH from the stored row).
func applyPolicyBody(pol *ca.IssuancePolicy, b policyWriteBody) {
	if b.Name != nil {
		pol.Name = strings.TrimSpace(*b.Name)
	}
	if b.Enabled != nil {
		pol.Enabled = *b.Enabled
	}
	if b.CAID != nil {
		pol.CAID = strings.TrimSpace(*b.CAID)
	}
	if b.Rules != nil {
		if b.Rules.AllowedAlgorithms != nil {
			pol.Rules.AllowedAlgorithms = *b.Rules.AllowedAlgorithms
		}
		if b.Rules.MinRSABits != nil {
			pol.Rules.MinRSABits = *b.Rules.MinRSABits
		}
		if b.Rules.MaxValidityDays != nil {
			pol.Rules.MaxValidityDays = *b.Rules.MaxValidityDays
		}
		if b.Rules.AllowCACerts != nil {
			pol.Rules.AllowCACerts = *b.Rules.AllowCACerts
		}
	}
}

func decodePolicyBody(w http.ResponseWriter, r *http.Request, dst any, max int64) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, max))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeBadRequest(w, "invalid request body")
		return false
	}
	return true
}

func registerPolicyHandlers(mux *http.ServeMux, auth *Authenticator, pe *ca.PolicyEngine, auditProvider AuditProvider, versions *policyVersionStore, pending PendingActionStore) {
	// authorize authenticates, requires an admin and (multi-tenancy on) the
	// super-admin. It writes the refusal itself.
	authorize := func(w http.ResponseWriter, r *http.Request, action, resID string) (AuthPrincipal, bool) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return AuthPrincipal{}, false
		}
		if !isAdminRole(pd.Role) {
			emitAuditEvent(r, auditProvider, pd.ID, action, "policy", resID, AuditOutcomeDenied)
			writeForbidden(w, "issuance policies require the pki-admin role")
			return AuthPrincipal{}, false
		}
		if denyNonSuperAdminGlobal(w, r, auditProvider, pd, action, "policy", resID) {
			return AuthPrincipal{}, false
		}
		return pd, true
	}

	mux.HandleFunc("/api/v1/policies", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if _, ok := authorize(w, r, "policy.list", "policies"); !ok {
				return
			}
			items, err := pe.ListPolicies()
			if err != nil {
				writeServiceUnavailable(w, "policy list failed")
				return
			}
			if items == nil {
				items = []ca.IssuancePolicy{}
			}
			writeJSONData(w, items)
		case http.MethodPost:
			pd, ok := authorize(w, r, "policy.create", "policies")
			if !ok {
				return
			}
			var body policyWriteBody
			if !decodePolicyBody(w, r, &body, policyWriteMaxBody) {
				emitAuditEvent(r, auditProvider, pd.ID, "policy.create", "policy", "policies", AuditOutcomeFailure)
				return
			}
			if body.RevertTo != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "policy.create", "policy", "policies", AuditOutcomeFailure)
				writeBadRequest(w, "revert_to is only valid on PATCH")
				return
			}
			pol := ca.IssuancePolicy{Enabled: true}
			applyPolicyBody(&pol, body)
			if msg := validatePolicyFields(pol); msg != "" {
				emitAuditEvent(r, auditProvider, pd.ID, "policy.create", "policy", "policies", AuditOutcomeFailure)
				writeBadRequest(w, msg)
				return
			}
			saved, err := pe.UpsertPolicy(pol)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "policy.create", "policy", "policies", AuditOutcomeFailure)
				writeServiceUnavailable(w, "policy create failed")
				return
			}
			if versions != nil {
				if _, verr := versions.Append(r.Context(), saved, pd.ID, policyChangeCreate); verr != nil {
					logging.Infof("policy %s created but version 1 not recorded: %v", saved.ID, verr)
				}
			}
			emitAuditEventDetail(r, auditProvider, pd.ID, "policy.create", "policy", saved.ID, AuditOutcomeSuccess, policySummary(saved))
			writeJSONStatus(w, http.StatusCreated, map[string]any{"data": saved})
		default:
			writeMethodNotAllowed(w, "GET, POST")
		}
	})

	mux.HandleFunc("/api/v1/policies/dry-run", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		if _, ok := authorize(w, r, "policy.dry_run", "policies"); !ok {
			return
		}
		var body struct {
			CAID         string `json:"ca_id"`
			CSRPEM       string `json:"csr_pem"`
			Algorithm    string `json:"algorithm"`
			RSABits      int    `json:"rsa_bits"`
			ValidityDays int    `json:"validity_days"`
			IsCA         bool   `json:"is_ca"`
		}
		if !decodePolicyBody(w, r, &body, policyDryRunMaxBody) {
			return
		}
		if body.ValidityDays < 0 || body.ValidityDays > 36500 || body.RSABits < 0 || body.RSABits > 16384 {
			writeBadRequest(w, "validity_days or rsa_bits out of range")
			return
		}
		in := ca.PolicyInput{Validity: time.Duration(body.ValidityDays) * 24 * time.Hour, IsCA: body.IsCA}
		switch {
		case strings.TrimSpace(body.CSRPEM) != "":
			// The key in the CSR decides algorithm and size; client strings
			// are ignored exactly as on the real issue path.
			req, err := parsePolicyDryRunCSR(body.CSRPEM)
			if err != nil {
				writeBadRequest(w, "csr_pem is not a valid certificate request")
				return
			}
			in.Algorithm, in.RSABits = ca.RequestedAlgorithm(req)
		case body.Algorithm != "":
			if !policyAlgorithms[body.Algorithm] {
				writeBadRequest(w, "unknown algorithm")
				return
			}
			in.Algorithm, in.RSABits = body.Algorithm, body.RSABits
		default:
			writeBadRequest(w, "csr_pem or algorithm is required")
			return
		}
		verdict, err := pe.Evaluate(body.CAID, in)
		if err != nil {
			writeServiceUnavailable(w, "policy evaluation unavailable")
			return
		}
		type violation struct {
			PolicyID string `json:"policy_id"`
			Policy   string `json:"policy"`
			Rule     string `json:"rule"`
			Detail   string `json:"detail"`
			Observed string `json:"observed"`
		}
		violations := make([]violation, 0, len(verdict.Violations))
		for _, v := range verdict.Violations {
			violations = append(violations, violation{v.PolicyID, v.Policy, v.Rule, v.Detail, v.Observed})
		}
		evaluated := verdict.Evaluated
		if evaluated == nil {
			evaluated = []string{}
		}
		writeJSONData(w, map[string]any{"allowed": verdict.Allowed, "evaluated_policies": evaluated, "violations": violations})
	})

	mux.HandleFunc("/api/v1/policies/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/policies/")
		if base, ok := strings.CutSuffix(id, "/versions"); ok && base != "" && !strings.Contains(base, "/") {
			listPolicyVersions(w, r, base, authorize, pe, versions)
			return
		}
		if id == "" || strings.Contains(id, "/") {
			writeNotFound(w, "policy not found")
			return
		}
		switch r.Method {
		case http.MethodGet:
			if _, ok := authorize(w, r, "policy.get", id); !ok {
				return
			}
			pol, found, err := pe.GetPolicy(id)
			if err != nil {
				writeServiceUnavailable(w, "policy lookup failed")
				return
			}
			if !found {
				writeNotFound(w, "policy not found")
				return
			}
			writeJSONData(w, pol)
		case http.MethodPatch:
			pd, ok := authorize(w, r, "policy.update", id)
			if !ok {
				return
			}
			var body policyWriteBody
			if !decodePolicyBody(w, r, &body, policyWriteMaxBody) {
				emitAuditEvent(r, auditProvider, pd.ID, "policy.update", "policy", id, AuditOutcomeFailure)
				return
			}
			if versions == nil {
				emitAuditEvent(r, auditProvider, pd.ID, "policy.update", "policy", id, AuditOutcomeFailure)
				writeServiceUnavailable(w, "policy history unavailable")
				return
			}
			pol, found, err := pe.GetPolicy(id)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "policy.update", "policy", id, AuditOutcomeFailure)
				writeServiceUnavailable(w, "policy lookup failed")
				return
			}
			if !found {
				emitAuditEvent(r, auditProvider, pd.ID, "policy.update", "policy", id, AuditOutcomeFailure)
				writeNotFound(w, "policy not found")
				return
			}
			baseVersion, err := versions.ensureBase(r.Context(), pol)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "policy.update", "policy", id, AuditOutcomeFailure)
				writeServiceUnavailable(w, "policy history unavailable")
				return
			}
			next, kind, auditAction := pol, policyChangeUpdate, "policy.update"
			if body.RevertTo != nil {
				if body.Name != nil || body.Enabled != nil || body.CAID != nil || body.Rules != nil {
					emitAuditEvent(r, auditProvider, pd.ID, "policy.revert", "policy", id, AuditOutcomeFailure)
					writeBadRequest(w, "revert_to cannot be combined with other fields")
					return
				}
				if *body.RevertTo < 1 {
					emitAuditEvent(r, auditProvider, pd.ID, "policy.revert", "policy", id, AuditOutcomeFailure)
					writeBadRequest(w, "revert_to must be a version number >= 1")
					return
				}
				v, vfound, verr := versions.Get(r.Context(), id, *body.RevertTo)
				if verr != nil {
					emitAuditEvent(r, auditProvider, pd.ID, "policy.revert", "policy", id, AuditOutcomeFailure)
					writeServiceUnavailable(w, "policy history unavailable")
					return
				}
				if !vfound {
					emitAuditEvent(r, auditProvider, pd.ID, "policy.revert", "policy", id, AuditOutcomeFailure)
					writeNotFound(w, "policy version not found")
					return
				}
				next, kind, auditAction = v.Policy(), policyChangeRevert, "policy.revert"
			} else {
				applyPolicyBody(&next, body)
			}
			if msg := validatePolicyFields(next); msg != "" {
				emitAuditEvent(r, auditProvider, pd.ID, auditAction, "policy", id, AuditOutcomeFailure)
				writeBadRequest(w, msg)
				return
			}
			if reasons := policyLoosening(pol, next); len(reasons) > 0 {
				proposePolicyLoosening(w, r, pd, pending, auditProvider, policyLoosenParams{
					PolicyID: id, Proposed: next, Reasons: reasons, BaseVersion: baseVersion, ChangeKind: kind,
				}, auditAction)
				return
			}
			saved, err := pe.UpsertPolicy(next)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, auditAction, "policy", id, AuditOutcomeFailure)
				writeServiceUnavailable(w, "policy update failed")
				return
			}
			if _, verr := versions.Append(r.Context(), saved, pd.ID, kind); verr != nil {
				logging.Infof("policy %s changed but the version was not recorded: %v", id, verr)
			}
			summary := policySummary(saved)
			if kind == policyChangeRevert {
				b, _ := json.Marshal(map[string]int{"from": baseVersion, "to": *body.RevertTo})
				summary = string(b)
			}
			emitAuditEventDetail(r, auditProvider, pd.ID, auditAction, "policy", id, AuditOutcomeSuccess, summary)
			writeJSONData(w, saved)
		case http.MethodDelete:
			pd, ok := authorize(w, r, "policy.delete", id)
			if !ok {
				return
			}
			if _, found, err := pe.GetPolicy(id); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "policy.delete", "policy", id, AuditOutcomeFailure)
				writeServiceUnavailable(w, "policy lookup failed")
				return
			} else if !found {
				emitAuditEvent(r, auditProvider, pd.ID, "policy.delete", "policy", id, AuditOutcomeFailure)
				writeNotFound(w, "policy not found")
				return
			}
			if err := pe.DeletePolicy(id); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "policy.delete", "policy", id, AuditOutcomeFailure)
				writeServiceUnavailable(w, "policy delete failed")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "policy.delete", "policy", id, AuditOutcomeSuccess)
			w.WriteHeader(http.StatusNoContent)
		default:
			writeMethodNotAllowed(w, "GET, PATCH, DELETE")
		}
	})
}

// policySummary is the audit change summary: the resulting rules, so a
// tightening is reconstructible from the trail alone.
func policySummary(p ca.IssuancePolicy) string {
	b, err := json.Marshal(map[string]any{"name": p.Name, "enabled": p.Enabled, "ca_id": p.CAID, "rules": p.Rules})
	if err != nil {
		return ""
	}
	return string(b)
}

// parsePolicyDryRunCSR accepts classical, ML-DSA and hybrid CSRs; each
// parser verifies the self-signature, so a forged CSR cannot be classified.
func parsePolicyDryRunCSR(pemText string) (ca.IssuanceRequest, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return ca.IssuanceRequest{}, errPolicyCSR
	}
	if c, err := x509.ParseCertificateRequest(block.Bytes); err == nil {
		if err := c.CheckSignature(); err != nil {
			return ca.IssuanceRequest{}, err
		}
		return ca.IssuanceRequest{CSR: c}, nil
	}
	if c, err := ca.ParseCertificateRequestMLDSA(block.Bytes); err == nil {
		return ca.IssuanceRequest{PQCCSR: c}, nil
	}
	c, err := ca.ParseCertificateRequestHybrid(block.Bytes)
	if err != nil {
		return ca.IssuanceRequest{}, err
	}
	return ca.IssuanceRequest{HybridCSR: c}, nil
}

var errPolicyCSR = errors.New("no PEM block in csr_pem")

// proposePolicyLoosening parks a loosening in the approval queue and answers
// 202. Nothing is written to the policy row; with no queue available the
// change is refused rather than applied.
func proposePolicyLoosening(w http.ResponseWriter, r *http.Request, pd AuthPrincipal, pending PendingActionStore, audit AuditProvider, p policyLoosenParams, auditAction string) {
	if pending == nil {
		emitAuditEvent(r, audit, pd.ID, auditAction, "policy", p.PolicyID, AuditOutcomeFailure)
		writeServiceUnavailable(w, "approval queue unavailable; loosening a policy needs a second approver")
		return
	}
	params, err := json.Marshal(p)
	if err != nil {
		writeServiceUnavailable(w, "policy change could not be queued")
		return
	}
	created, err := pending.Create(r.Context(), PendingAction{
		ActionType: ActionPolicyLoosen, Params: params, ProposedBy: pd.ID, Tenant: pd.Tenant,
		Rationale: strings.Join(p.Reasons, "; "),
	})
	if err != nil {
		emitAuditEvent(r, audit, pd.ID, auditAction, "policy", p.PolicyID, AuditOutcomeFailure)
		writeServiceUnavailable(w, "policy change could not be queued")
		return
	}
	emitAuditEventDetail(r, audit, pd.ID, auditAction, "policy", p.PolicyID, AuditOutcomePendingApproval, "proposed (pending approval): "+strings.Join(p.Reasons, "; "))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
		"status": "pending_approval", "pending_action_id": created.ID, "reasons": p.Reasons,
	}})
}

func listPolicyVersions(w http.ResponseWriter, r *http.Request, id string, authorize func(http.ResponseWriter, *http.Request, string, string) (AuthPrincipal, bool), pe *ca.PolicyEngine, versions *policyVersionStore) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	if _, ok := authorize(w, r, "policy.versions", id); !ok {
		return
	}
	if versions == nil {
		writeServiceUnavailable(w, "policy history unavailable")
		return
	}
	pol, found, err := pe.GetPolicy(id)
	if err != nil {
		writeServiceUnavailable(w, "policy lookup failed")
		return
	}
	if !found {
		writeNotFound(w, "policy not found")
		return
	}
	// A pre-W22-15 policy has no history yet: show its current state as v1.
	if _, err := versions.ensureBase(r.Context(), pol); err != nil {
		writeServiceUnavailable(w, "policy history unavailable")
		return
	}
	list, err := versions.List(r.Context(), id)
	if err != nil {
		writeServiceUnavailable(w, "policy history unavailable")
		return
	}
	writeJSONData(w, list)
}
