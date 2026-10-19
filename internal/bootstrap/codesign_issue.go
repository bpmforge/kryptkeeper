// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"kryptkeeper/internal/logging"
	"net/http"
	"os"
	"strings"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

const (
	maxCodeSigningRequestBodyBytes int64 = 64 * 1024
	codesignProtectedEnv                 = "KRYPTKEEPER_CODESIGN_PROTECTED"

	auditCodesignDeny     = "codesign.request.deny"
	auditCodesignKeyGen   = "codesign.key.generate"
	auditCodesignPolicy   = "codesign.policy.check"
	codesignDefaultAlgo   = keystore.ECDSAP256
	codesignKeyIDPrefix   = "codesign-"
	codesignResourceType  = "template"
	codesignEKUNormalized = "codesigning"
)

// templateHasCodeSigningEKU reports whether the template can mint a
// code-signing certificate, whatever spelling the EKU was stored with.
func templateHasCodeSigningEKU(tpl TemplateItem) bool {
	for _, eku := range tpl.ExtendedKeyUsage {
		if strings.ToLower(strings.ReplaceAll(eku, " ", "")) == codesignEKUNormalized {
			return true
		}
	}
	return false
}

// templateNeedsApproval is THE approval gate: a code-signing template is
// approval-gated whatever its require_approval flag says (FR-P90), so
// clearing the flag cannot turn a signing identity into a one-person issue.
func templateNeedsApproval(tpl TemplateItem) bool {
	return tpl.RequireApproval || templateHasCodeSigningEKU(tpl)
}

// codesignProtectedMode reports whether the hub is configured to require
// hardware-protected code-signing keys (FR-P91, FR-P92).
func codesignProtectedMode() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(codesignProtectedEnv)), "true")
}

// auditCodesignRejection records an approver REJECT of a code-signing request.
// handleReject calls it; non code-signing templates are ignored.
func auditCodesignRejection(r *http.Request, audit AuditProvider, tpl TemplateItem, principal, approvalID string) {
	if !templateHasCodeSigningEKU(tpl) {
		return
	}
	emitAuditEventDetail(r, audit, principal, auditCodesignDeny, codesignResourceType, tpl.ID, AuditOutcomeDenied,
		fmt.Sprintf(`{"approval_id":%q,"reason":"approver_rejected"}`, approvalID))
}

type codesignRequest struct {
	CAID       string `json:"ca_id"`
	TemplateID string `json:"template_id"`
	CommonName string `json:"common_name"`
	TeamID     string `json:"team_id"`
	Algorithm  string `json:"algorithm"`
}

func codesignAlgorithm(s string) (keystore.Algorithm, bool) {
	if strings.TrimSpace(s) == "" {
		return codesignDefaultAlgo, true
	}
	switch a := keystore.Algorithm(strings.TrimSpace(s)); a {
	case keystore.RSA3072, keystore.RSA4096, keystore.ECDSAP256, keystore.ECDSAP384:
		return a, true
	}
	return "", false
}

// registerCodeSigningIssueHandler serves POST /api/v1/codesign/requests: the
// hub generates the key in the HSM/KMS, builds the CSR there, and queues the
// request for a second user's approval. The key never leaves the token.
func registerCodeSigningIssueHandler(mux *http.ServeMux, auth *Authenticator, certs CertificateProvider,
	templates TemplateProvider, approvals ApprovalStore, keys keystore.Store, audit AuditProvider) {
	mux.HandleFunc("/api/v1/codesign/requests", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, audit, "", auditCodesignDeny, codesignResourceType, "codesign", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		// refuse audits every non-202 outcome under the one deny action.
		refuse := func(status int, outcome AuditOutcome, resource, code, msg string) {
			emitAuditEventDetail(r, audit, pd.ID, auditCodesignDeny, codesignResourceType, resource, outcome,
				fmt.Sprintf(`{"reason":%q}`, code))
			writeJSONStatus(w, status, map[string]string{"error": code, "message": msg})
		}

		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxCodeSigningRequestBodyBytes))
		if err != nil {
			emitAuditEvent(r, audit, pd.ID, auditCodesignDeny, codesignResourceType, "codesign", AuditOutcomeFailure)
			if rejectOversizeBody(w, err) {
				return
			}
			writeBadRequest(w, "invalid request body")
			return
		}
		var req codesignRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			refuse(http.StatusBadRequest, AuditOutcomeFailure, "codesign", "bad_request", "invalid request body")
			return
		}
		req.CAID, req.TemplateID, req.CommonName = strings.TrimSpace(req.CAID), strings.TrimSpace(req.TemplateID), strings.TrimSpace(req.CommonName)
		algo, ok := codesignAlgorithm(req.Algorithm)
		if !ok || req.CAID == "" || req.TemplateID == "" || req.CommonName == "" {
			refuse(http.StatusBadRequest, AuditOutcomeFailure, "codesign", "bad_request", "ca_id, template_id and common_name are required; algorithm must be RSA-3072, RSA-4096, ECDSA-P256 or ECDSA-P384")
			return
		}
		if err := authorizeCertificateMutationRequest(pd, &req.TeamID); err != nil {
			refuse(http.StatusForbidden, AuditOutcomeDenied, req.TemplateID, "team_scope_mismatch", certificateTeamScopeDeniedMessage)
			return
		}
		if !caVisibleToTenant(r.Context(), activeTenantStore, pd, req.CAID) {
			refuse(http.StatusForbidden, AuditOutcomeDenied, req.TemplateID, "tenant_visibility", certificateCATenantDeniedMessage)
			return
		}
		if !templateVisibleToTenant(r.Context(), activeTenantStore, pd, req.TemplateID) {
			refuse(http.StatusForbidden, AuditOutcomeDenied, req.TemplateID, "tenant_visibility", certificateTemplateTenantDeniedMessage)
			return
		}
		tpl, found, terr := templates.GetTemplate(r.Context(), req.TemplateID)
		if terr != nil {
			logging.Infof("codesign request: template lookup: %v", terr)
			emitAuditEvent(r, audit, pd.ID, auditCodesignDeny, codesignResourceType, req.TemplateID, AuditOutcomeFailure)
			writeServiceUnavailable(w, "template lookup failed")
			return
		}
		if !found || !tpl.Active {
			refuse(http.StatusUnprocessableEntity, AuditOutcomeDenied, req.TemplateID, "policy_violation", "template not found or inactive")
			return
		}
		if !templateHasCodeSigningEKU(tpl) {
			refuse(http.StatusUnprocessableEntity, AuditOutcomeDenied, req.TemplateID, "not_a_codesigning_template", "template does not carry the codeSigning extended key usage")
			return
		}
		if approvals == nil {
			emitAuditEvent(r, audit, pd.ID, auditCodesignDeny, codesignResourceType, req.TemplateID, AuditOutcomeFailure)
			writeServiceUnavailable(w, "approval store not configured")
			return
		}
		approvalID, err := newApprovalID()
		if err != nil {
			logging.Infof("codesign request: approval id: %v", err)
			emitAuditEvent(r, audit, pd.ID, auditCodesignDeny, codesignResourceType, req.TemplateID, AuditOutcomeFailure)
			writeServiceUnavailable(w, "approval request failed")
			return
		}

		// The key id derives from the approval id so a rejected request's key
		// can be found and destroyed later without an extra column.
		keyID := codesignKeyIDPrefix + approvalID
		if _, backend, gerr := keystore.GenerateProtectedKey(keys, keyID, algo); gerr != nil {
			if errors.Is(gerr, keystore.ErrProtectedStoreRequired) {
				refuse(http.StatusUnprocessableEntity, AuditOutcomeDenied, req.TemplateID, "protected_store_required", "code-signing keys must be generated in an HSM or KMS backend, and none is configured")
				return
			}
			logging.Warnf("codesign request: key generation failed: %v", gerr)
			emitAuditEvent(r, audit, pd.ID, auditCodesignKeyGen, "key", keyID, AuditOutcomeFailure)
			writeServiceUnavailable(w, "key generation failed")
			return
		} else {
			emitAuditEventDetail(r, audit, pd.ID, auditCodesignKeyGen, "key", keyID, AuditOutcomeSuccess,
				fmt.Sprintf(`{"key_id":%q,"backend":%q,"algorithm":%q,"protected_mode":%t}`, keyID, backend, algo, codesignProtectedMode()))
		}
		// HSM slots are finite: every path below that does not queue the
		// request must give the key back.
		queued := false
		defer func() {
			if !queued {
				if derr := keys.Delete(keyID); derr != nil {
					logging.Infof("codesign request: deleting unused key %s: %v", keyID, derr)
				}
			}
		}()

		signer, err := keys.Signer(keyID)
		if err != nil {
			logging.Infof("codesign request: signer: %v", err)
			emitAuditEvent(r, audit, pd.ID, auditCodesignDeny, codesignResourceType, req.TemplateID, AuditOutcomeFailure)
			writeServiceUnavailable(w, "key unavailable")
			return
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: req.CommonName}}, signer)
		if err != nil {
			logging.Infof("codesign request: build CSR: %v", err)
			emitAuditEvent(r, audit, pd.ID, auditCodesignDeny, codesignResourceType, req.TemplateID, AuditOutcomeFailure)
			writeServiceUnavailable(w, "csr generation failed")
			return
		}
		csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))

		_, err = certs.IssueCertificate(context.WithValue(ca.WithCallerRole(r.Context(), pd.Role), codesignHubKeyKey{}, true), CertificateIssueRequest{
			CAID: req.CAID, TemplateID: req.TemplateID, CSRPEM: csrPEM, TeamID: req.TeamID,
		})
		switch {
		case errors.Is(err, errApprovalRequired):
			// fall through to queueing below
		case errors.Is(err, ca.ErrEnrollmentDenied):
			refuse(http.StatusForbidden, AuditOutcomeDenied, req.TemplateID, "enrollment_denied", "your role may not enroll from this template")
			return
		case errors.Is(err, ca.ErrPolicyViolation):
			refuse(http.StatusUnprocessableEntity, AuditOutcomeDenied, req.TemplateID, "policy_violation", err.Error())
			return
		case err != nil:
			logging.Infof("codesign request: issue: %v", err)
			emitAuditEvent(r, audit, pd.ID, auditCodesignDeny, codesignResourceType, req.TemplateID, AuditOutcomeFailure)
			writeServiceUnavailable(w, "certificate unavailable")
			return
		default:
			// The gate must have queued this; a direct issue means it is broken.
			logging.Infof("codesign request: certificate issued without approval for template %s", req.TemplateID)
			emitAuditEvent(r, audit, pd.ID, auditCodesignDeny, codesignResourceType, req.TemplateID, AuditOutcomeFailure)
			writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "internal", "message": "approval gate not enforced"})
			return
		}

		apr := ApprovalRequest{
			ID: approvalID, TemplateID: req.TemplateID, CAID: req.CAID, Requester: pd.ID,
			CSRPEM: csrPEM, TeamID: req.TeamID, RequestedAt: time.Now().UTC().Format(time.RFC3339),
		}
		if cerr := approvals.Create(r.Context(), apr); cerr != nil {
			logging.Infof("codesign request: approval create: %v", cerr)
			emitAuditEvent(r, audit, pd.ID, auditCodesignDeny, codesignResourceType, req.TemplateID, AuditOutcomeFailure)
			writeServiceUnavailable(w, "approval request failed")
			return
		}
		queued = true
		emitAuditEventDetail(r, audit, pd.ID, "certificate.issue", "certificate", "certificates", AuditOutcomePendingApproval,
			fmt.Sprintf(`{"approval_id":%q,"template_id":%q,"ca_id":%q,"key_id":%q}`, approvalID, req.TemplateID, req.CAID, keyID))
		w.Header().Set("Location", "/api/v1/approvals/"+approvalID)
		writeJSONStatus(w, http.StatusAccepted, map[string]string{"status": "pending_approval", "approval_id": approvalID, "key_id": keyID})
	})
}
