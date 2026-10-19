// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/logging"
)

// CodeSigningCert is a certificate inventory entry for a code-signing cert,
// derived from the existing certificate inventory (EKU includes codeSigning).
type CodeSigningCert struct {
	FingerprintSHA256  string   `json:"fingerprint_sha256"`
	CommonName         string   `json:"common_name"`
	IssuerCN           string   `json:"issuer_cn"`
	TeamID             string   `json:"team_id"`
	PublicKeyAlgorithm string   `json:"public_key_algorithm"`
	KeySizeBits        int      `json:"key_size_bits"`
	ValidFrom          string   `json:"valid_from"`
	ValidUntil         string   `json:"valid_until"`
	RiskScore          int      `json:"risk_score"`
	RiskFlags          []string `json:"risk_flags"`
	Grade              string   `json:"grade"`
	Expired            bool     `json:"expired"`
	RevokedAt          *string  `json:"revoked_at,omitempty"`
}

// CodeSigningInventory is the response body for GET /api/v1/inventory/code-signing.
type CodeSigningInventory struct {
	GeneratedAt string            `json:"generated_at"`
	Total       int               `json:"total"`
	Expired     int               `json:"expired"`
	Revoked     int               `json:"revoked"`
	Certs       []CodeSigningCert `json:"certs"`
}

func isCodeSigningCert(cert CertificateItem) bool {
	for _, eku := range cert.ExtendedKeyUsage {
		e := strings.ToLower(strings.ReplaceAll(eku, " ", ""))
		if e == "codesigning" {
			return true
		}
	}
	return false
}

// registerCodeSigningHandler mounts the code-signing inventory endpoint. The
// inventory is derived live from the certificate provider — code-signing certs
// are those whose extended key usage includes codeSigning.
// buildCodeSigningInventory derives the inventory from the live
// certificate provider. Shared by the inventory endpoint and the W17-02
// policy-check endpoint so both see exactly one risk model.
func buildCodeSigningInventory(items []CertificateItem, now time.Time) CodeSigningInventory {
	inv := CodeSigningInventory{
		GeneratedAt: now.Format(time.RFC3339),
		Certs:       []CodeSigningCert{},
	}
	for _, cert := range items {
		if !isCodeSigningCert(cert) {
			continue
		}
		expired := false
		if cert.ValidUntil != "" {
			if t, perr := time.Parse(time.RFC3339, cert.ValidUntil); perr == nil && t.Before(now) {
				expired = true
			}
		}
		if expired {
			inv.Expired++
		}
		if cert.RevokedAt != nil {
			inv.Revoked++
		}
		inv.Certs = append(inv.Certs, CodeSigningCert{
			FingerprintSHA256:  cert.FingerprintSHA256,
			CommonName:         cert.CommonName,
			IssuerCN:           cert.IssuerCN,
			TeamID:             cert.TeamID,
			PublicKeyAlgorithm: cert.PublicKeyAlgorithm,
			KeySizeBits:        cert.KeySizeBits,
			ValidFrom:          cert.ValidFrom,
			ValidUntil:         cert.ValidUntil,
			RiskScore:          cert.RiskScore,
			RiskFlags:          cert.RiskFlags,
			Grade:              cert.Grade,
			Expired:            expired,
			RevokedAt:          cert.RevokedAt,
		})
	}
	inv.Total = len(inv.Certs)
	return inv
}

func registerCodeSigningHandler(mux *http.ServeMux, auth *Authenticator, certProvider CertificateProvider, auditProvider AuditProvider) {
	// W17-02: evaluate the live code-signing inventory against a
	// caller-supplied policy. Stateless by design so CI can gate a
	// release on it without a policy-CRUD subsystem.
	mux.HandleFunc("/api/v1/inventory/code-signing/policy-check", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", auditCodesignPolicy, "inventory", "code-signing", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		principal := pd.ID
		var policy CodeSigningPolicy
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&policy); err != nil {
			emitAuditEvent(r, auditProvider, principal, auditCodesignPolicy, "inventory", "code-signing", AuditOutcomeFailure)
			if rejectOversizeBody(w, err) {
				return
			}
			writeBadRequest(w, "invalid policy body")
			return
		}
		// F1: same team + tenant scope as GET /api/v1/certificates; the
		// inventory used to list every tenant's certificates.
		items, err := reportVisibleCertificates(r.Context(), pd, certProvider, reportCertificateCeiling)
		if err != nil {
			emitAuditEvent(r, auditProvider, principal, auditCodesignPolicy, "inventory", "code-signing", AuditOutcomeFailure)
			logging.Infof("code-signing policy check: list certs: %v", err)
			writeServiceUnavailable(w, "inventory unavailable")
			return
		}
		inv := buildCodeSigningInventory(items, time.Now().UTC())
		summary := summarizeCodeSigningPolicy(inv.Certs, policy)
		alertViolations(summary)
		emitAuditEvent(r, auditProvider, principal, auditCodesignPolicy, "inventory", "code-signing", AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(struct {
			Data CodeSigningPolicySummary `json:"data"`
		}{Data: summary}); err != nil {
			logging.Warnf("failed to encode code-signing policy summary: %v", err)
		}
	})

	mux.HandleFunc("/api/v1/inventory/code-signing", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "inventory.code_signing", "inventory", "code-signing", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		principal := pd.ID
		items, err := reportVisibleCertificates(r.Context(), pd, certProvider, reportCertificateCeiling)
		if err != nil {
			emitAuditEvent(r, auditProvider, principal, "inventory.code_signing", "inventory", "code-signing", AuditOutcomeFailure)
			logging.Infof("code-signing inventory: list certs: %v", err)
			writeServiceUnavailable(w, "inventory unavailable")
			return
		}

		inv := buildCodeSigningInventory(items, time.Now().UTC())

		emitAuditEvent(r, auditProvider, principal, "inventory.code_signing", "inventory", "code-signing", AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(struct {
			Data CodeSigningInventory `json:"data"`
		}{Data: inv}); err != nil {
			logging.Warnf("failed to encode code-signing inventory: %v", err)
		}
	})
}

// WithCodesignOIDC mounts W29-12: CI OIDC token + CSR -> short-lived
// code-signing certificate, and the dual-control trust-rule routes. A nil
// store or engine keeps the routes mounted and answering 503 (audited), so a
// misconfigured hub fails closed and visibly.
func WithCodesignOIDC(engine ca.Service, rec ca.IssuedCertificateRecorder, store CodesignTrustStore, pending PendingActionStore, auth *Authenticator, audit AuditProvider) ServerOption {
	return func(c *ServerConfig) {
		var issuer *CodesignIssuer
		if engine != nil && store != nil {
			issuer = NewCodesignIssuer(NewCodesignOIDCVerifier(store), engine, rec)
		}
		if store != nil {
			WithActionExecutor(ActionCodesignTrustRule, NewCodesignTrustRuleExecutor(store, audit))(c)
		}
		WithExtraHandlers(func(mux *http.ServeMux) {
			registerCodesignIssueHandler(mux, issuer, audit)
			registerCodesignTrustRuleHandlers(mux, auth, engine, store, pending, audit)
		})(c)
	}
}

const codesignBodyMax = 64 * 1024

type codesignIssueRequest struct {
	OIDCToken string `json:"oidc_token"`
	CSRPEM    string `json:"csr_pem"`
}

// registerCodesignIssueHandler mounts the unauthenticated exchange: the OIDC
// token is the credential. Every outcome is audited; the 401 body is generic
// and the refusal reason goes only to the audit trail.
func registerCodesignIssueHandler(mux *http.ServeMux, issuer *CodesignIssuer, audit AuditProvider) {
	const action = "codesign.issue"
	mux.HandleFunc("/api/v1/codesign/issue", func(w http.ResponseWriter, r *http.Request) {
		fail := func(outcome AuditOutcome, actor, detail string) {
			emitAuditEventDetail(r, audit, actor, action, "codesign", "oidc", outcome, detail)
		}
		if r.Method != http.MethodPost {
			fail(AuditOutcomeFailure, "", "method not allowed")
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		if issuer == nil {
			fail(AuditOutcomeFailure, "", "code-signing issuance unavailable")
			writeServiceUnavailable(w, "code-signing issuance unavailable")
			return
		}
		var req codesignIssueRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, codesignBodyMax)).Decode(&req); err != nil {
			fail(AuditOutcomeFailure, "", "invalid request body")
			if rejectOversizeBody(w, err) {
				return
			}
			writeBadRequest(w, "invalid request body")
			return
		}
		issued, id, chainPEM, err := issuer.Issue(r.Context(), req.OIDCToken, req.CSRPEM)
		var refusal *CodesignRefusal
		var pv *ca.PolicyViolationError
		switch {
		case err == nil:
		case errors.As(err, &refusal):
			AuditCodesignRefusal(r, audit, refusal)
			writeErrorEnvelope(w, http.StatusUnauthorized, "unauthorized", "token refused")
			return
		case errors.Is(err, errCodesignBadCSR), errors.Is(err, errCodesignWeakKey):
			fail(AuditOutcomeFailure, "", err.Error())
			writeBadRequest(w, err.Error())
			return
		case errors.As(err, &pv):
			fail(AuditOutcomeDenied, "oidc:"+id.Repo, "issuance policy: "+pv.Error())
			writeForbidden(w, pv.Error())
			return
		case errors.Is(err, ca.ErrCARevoked):
			fail(AuditOutcomeDenied, "oidc:"+id.Repo, "issuing CA revoked")
			writeServiceUnavailable(w, "issuing CA unavailable")
			return
		default:
			// Covers errCodesignRecord and engine failures alike: nothing is
			// handed out, and the cause stays in the server log.
			logging.Infof("codesign issue failed: %v", err)
			fail(AuditOutcomeFailure, "oidc:"+id.Repo, "issuance failed: "+codesignTruncate(err.Error(), codesignDetailMax))
			writeServiceUnavailable(w, "code-signing issuance failed")
			return
		}
		sum := sha256.Sum256(issued.Certificate.Raw)
		fp := hex.EncodeToString(sum[:])
		emitAuditEventDetail(r, audit, "oidc:"+id.Repo, action, "certificate", fp, AuditOutcomeSuccess,
			"repo="+quoteAudit(id.Repo)+" ref="+quoteAudit(id.Ref)+" serial="+issued.SerialNumber.Text(16)+
				" issuer="+quoteAudit(id.Issuer)+" rule="+id.Rule.ID)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"certificate_pem":    string(issued.CertPEM),
			"chain_pem":          string(chainPEM),
			"serial_number":      issued.SerialNumber.Text(16),
			"fingerprint_sha256": fp,
			"not_before":         issued.Certificate.NotBefore.UTC().Format(time.RFC3339),
			"not_after":          issued.Certificate.NotAfter.UTC().Format(time.RFC3339),
			"repo":               id.Repo,
			"ref":                id.Ref,
		}})
	})
}

func quoteAudit(s string) string {
	b, _ := json.Marshal(codesignTruncate(s, codesignIssuerMax))
	return string(b)
}

type codesignTrustRuleBody struct {
	Provider    string `json:"provider"`
	Issuer      string `json:"issuer"`
	Audience    string `json:"audience"`
	RepoPattern string `json:"repo_pattern"`
	RefPattern  string `json:"ref_pattern"`
	CAID        string `json:"ca_id"`
	Rationale   string `json:"rationale"`
}

func registerCodesignTrustRuleHandlers(mux *http.ServeMux, auth *Authenticator, engine ca.Service, store CodesignTrustStore, pending PendingActionStore, audit AuditProvider) {
	const base = "/api/v1/codesign/oidc-trust-rules"
	isAdmin := func(pd AuthPrincipal) bool {
		_, admin := principalPermissions(pd, nil)
		return admin
	}
	mux.HandleFunc("/api/v1/codesign/oidc-trust-rules", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			emitAuditEventDetail(r, audit, "", "codesign.trust_rule_propose", "codesign_trust_rule", "", AuditOutcomeFailure, "method not allowed")
			writeMethodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			if r.Method == http.MethodPost {
				emitAuditEvent(r, audit, "", "codesign.trust_rule_propose", "codesign_trust_rule", "", AuditOutcomeDenied)
			}
			writeUnauthorized(w)
			return
		}
		if r.Method == http.MethodGet {
			listCodesignTrustRules(w, r, pd, store)
			return
		}
		propose := func(outcome AuditOutcome, id, detail string) {
			emitAuditEventDetail(r, audit, pd.ID, "codesign.trust_rule_propose", "codesign_trust_rule", id, outcome, detail)
		}
		if !isAdmin(pd) {
			propose(AuditOutcomeDenied, "", "admin role required")
			writeForbidden(w, "this change needs the pki-admin role")
			return
		}
		if store == nil || pending == nil {
			propose(AuditOutcomeFailure, "", "trust store or approval queue unavailable")
			writeServiceUnavailable(w, "code-signing trust rules unavailable")
			return
		}
		var body codesignTrustRuleBody
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, codesignBodyMax)).Decode(&body); err != nil {
			propose(AuditOutcomeFailure, "", "invalid request body")
			if rejectOversizeBody(w, err) {
				return
			}
			writeBadRequest(w, "invalid request body")
			return
		}
		rule := CodesignTrustRule{Provider: body.Provider, Issuer: body.Issuer, Audience: body.Audience,
			RepoPattern: body.RepoPattern, RefPattern: body.RefPattern, CAID: body.CAID}
		if engine != nil && strings.TrimSpace(rule.CAID) != "" {
			if _, gerr := engine.GetCA(strings.TrimSpace(rule.CAID)); gerr != nil {
				propose(AuditOutcomeFailure, "", "unknown ca_id")
				writeBadRequest(w, "unknown ca_id")
				return
			}
		}
		act, err := ProposeCodesignTrustRule(r.Context(), pending, pd, rule, body.Rationale)
		if err != nil {
			propose(AuditOutcomeFailure, "", "refused: "+codesignTruncate(err.Error(), codesignDetailMax))
			writeBadRequest(w, err.Error())
			return
		}
		propose(AuditOutcomePendingApproval, act.ID, "issuer="+quoteAudit(rule.Issuer)+" audience="+quoteAudit(rule.Audience)+
			" repo="+quoteAudit(rule.RepoPattern)+" ref="+quoteAudit(rule.RefPattern)+" ca="+rule.CAID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"action_id": act.ID, "status": "pending"}})
	})

	mux.HandleFunc("/api/v1/codesign/oidc-trust-rules/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, base+"/")
		const action = "codesign.trust_rule_delete"
		if r.Method != http.MethodDelete {
			emitAuditEventDetail(r, audit, "", action, "codesign_trust_rule", id, AuditOutcomeFailure, "method not allowed")
			writeMethodNotAllowed(w, http.MethodDelete)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, audit, "", action, "codesign_trust_rule", id, AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if !isAdmin(pd) {
			emitAuditEventDetail(r, audit, pd.ID, action, "codesign_trust_rule", id, AuditOutcomeDenied, "admin role required")
			writeForbidden(w, "this change needs the pki-admin role")
			return
		}
		if store == nil {
			emitAuditEventDetail(r, audit, pd.ID, action, "codesign_trust_rule", id, AuditOutcomeFailure, "trust store unavailable")
			writeServiceUnavailable(w, "code-signing trust rules unavailable")
			return
		}
		rule, found, gerr := store.GetRule(r.Context(), id)
		// A rule in another tenant answers exactly like a missing one.
		if gerr == nil && (!found || !tenantVisible(pd, rule.Tenant)) {
			emitAuditEventDetail(r, audit, pd.ID, action, "codesign_trust_rule", id, AuditOutcomeFailure, "not found")
			writeNotFound(w, "trust rule not found")
			return
		}
		if gerr == nil {
			gerr = store.DeleteRule(r.Context(), id)
		}
		if gerr != nil {
			logging.Infof("codesign trust rule delete %s: %v", id, gerr)
			emitAuditEventDetail(r, audit, pd.ID, action, "codesign_trust_rule", id, AuditOutcomeFailure, "store error")
			writeServiceUnavailable(w, "code-signing trust rules unavailable")
			return
		}
		emitAuditEventDetail(r, audit, pd.ID, action, "codesign_trust_rule", id, AuditOutcomeSuccess,
			"issuer="+quoteAudit(rule.Issuer)+" repo="+quoteAudit(rule.RepoPattern)+" ref="+quoteAudit(rule.RefPattern))
		w.WriteHeader(http.StatusNoContent)
	})
}

func listCodesignTrustRules(w http.ResponseWriter, r *http.Request, pd AuthPrincipal, store CodesignTrustStore) {
	if store == nil {
		writeServiceUnavailable(w, "code-signing trust rules unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	rules, err := store.ListRules(ctx)
	if err != nil {
		logging.Infof("codesign trust rule list: %v", err)
		writeServiceUnavailable(w, "code-signing trust rules unavailable")
		return
	}
	out := make([]CodesignTrustRule, 0, len(rules))
	for _, rl := range rules {
		if tenantVisible(pd, rl.Tenant) {
			out = append(out, rl)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": out})
}
