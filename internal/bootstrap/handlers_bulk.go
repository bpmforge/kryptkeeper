// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
)

const maxBulkBodyBytes int64 = 128 * 1024

type bulkRevokeItem struct {
	Fingerprint string `json:"fingerprint"`
	Error       string `json:"error,omitempty"`
	// RevocationScope is set on succeeded items only; see CertificateRevokeResult.
	RevocationScope string `json:"revocation_scope,omitempty"`
}

type bulkReissueItem struct {
	OldFingerprint string `json:"old_fingerprint"`
	NewFingerprint string `json:"new_fingerprint,omitempty"`
	Error          string `json:"error,omitempty"`
}

func registerBulkHandlers(mux *http.ServeMux, auth *Authenticator, provider CertificateProvider, auditProvider AuditProvider) {
	// POST /api/v1/certificates/bulk-revoke
	mux.HandleFunc("/api/v1/certificates/bulk-revoke", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "certificate.bulk_revoke", "certificate", "bulk", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		principal := pd.ID
		// S-36/S-55: role-based, no more hardcoded-principal bypass.
		if err := authorizeCertificateMutationRequest(pd, nil); err != nil {
			emitAuditEvent(r, auditProvider, principal, "certificate.bulk_revoke", "certificate", "bulk", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}

		var req struct {
			Fingerprints []string `json:"fingerprints"`
			ReasonCode   int      `json:"reason_code"`
		}
		body := http.MaxBytesReader(w, r.Body, maxBulkBodyBytes)
		defer body.Close()
		raw, err := io.ReadAll(body)
		if err != nil {
			emitAuditEvent(r, auditProvider, principal, "certificate.bulk_revoke", "certificate", "bulk", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			emitAuditEvent(r, auditProvider, principal, "certificate.bulk_revoke", "certificate", "bulk", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}
		if len(req.Fingerprints) == 0 {
			emitAuditEvent(r, auditProvider, principal, "certificate.bulk_revoke", "certificate", "bulk", AuditOutcomeFailure)
			writeBadRequest(w, "fingerprints must not be empty")
			return
		}
		if len(req.Fingerprints) > 500 {
			emitAuditEvent(r, auditProvider, principal, "certificate.bulk_revoke", "certificate", "bulk", AuditOutcomeFailure)
			writeBadRequest(w, "bulk revoke limited to 500 certificates per request")
			return
		}

		succeeded := make([]bulkRevokeItem, 0)
		failed := make([]bulkRevokeItem, 0)

		for _, fp := range req.Fingerprints {
			fp = strings.TrimSpace(fp)
			if !bulkTargetVisible(r.Context(), provider, pd, fp) {
				failed = append(failed, bulkRevokeItem{Fingerprint: fp, Error: bulkNotVisibleMessage})
				continue
			}
			revokeReq := CertificateRevokeRequest{ReasonCode: req.ReasonCode}
			res, rerr := provider.RevokeCertificate(r.Context(), fp, revokeReq)
			if rerr != nil {
				logging.Infof("bulk revoke %s: %v", fp, rerr)
				failed = append(failed, bulkRevokeItem{Fingerprint: fp, Error: rerr.Error()})
			} else {
				emitAuditEventDetail(r, auditProvider, principal, "certificate.revoke", "certificate", fp, AuditOutcomeSuccess,
					fmt.Sprintf(`{"fingerprint":%q,"reason":%d,"bulk":true,"revocation_scope":%q}`, fp, req.ReasonCode, res.RevocationScope))
				succeeded = append(succeeded, bulkRevokeItem{Fingerprint: fp, RevocationScope: res.RevocationScope})
			}
		}

		emitAuditEventDetail(r, auditProvider, principal, "certificate.bulk_revoke", "certificate", "bulk", AuditOutcomeSuccess,
			fmt.Sprintf(`{"succeeded":%d,"failed":%d}`, len(succeeded), len(failed)))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(struct {
			Succeeded []bulkRevokeItem `json:"succeeded"`
			Failed    []bulkRevokeItem `json:"failed"`
		}{Succeeded: succeeded, Failed: failed})
	})

	// POST /api/v1/certificates/bulk-reissue
	mux.HandleFunc("/api/v1/certificates/bulk-reissue", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "certificate.bulk_reissue", "certificate", "bulk", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		principal := pd.ID
		// S-36/S-55: role-based, no more hardcoded-principal bypass.
		if err := authorizeCertificateMutationRequest(pd, nil); err != nil {
			emitAuditEvent(r, auditProvider, principal, "certificate.bulk_reissue", "certificate", "bulk", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}

		var req struct {
			Fingerprints []string `json:"fingerprints"`
		}
		body := http.MaxBytesReader(w, r.Body, maxBulkBodyBytes)
		defer body.Close()
		raw, err := io.ReadAll(body)
		if err != nil {
			emitAuditEvent(r, auditProvider, principal, "certificate.bulk_reissue", "certificate", "bulk", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			emitAuditEvent(r, auditProvider, principal, "certificate.bulk_reissue", "certificate", "bulk", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}
		if len(req.Fingerprints) == 0 {
			emitAuditEvent(r, auditProvider, principal, "certificate.bulk_reissue", "certificate", "bulk", AuditOutcomeFailure)
			writeBadRequest(w, "fingerprints must not be empty")
			return
		}
		if len(req.Fingerprints) > 200 {
			emitAuditEvent(r, auditProvider, principal, "certificate.bulk_reissue", "certificate", "bulk", AuditOutcomeFailure)
			writeBadRequest(w, "bulk reissue limited to 200 certificates per request")
			return
		}

		succeeded := make([]bulkReissueItem, 0)
		failed := make([]bulkReissueItem, 0)

		for _, fp := range req.Fingerprints {
			fp = strings.TrimSpace(fp)
			if !bulkTargetVisible(r.Context(), provider, pd, fp) {
				failed = append(failed, bulkReissueItem{OldFingerprint: fp, Error: bulkNotVisibleMessage})
				continue
			}
			issued, rerr := provider.RenewCertificate(r.Context(), fp, CertificateRenewRequest{})
			if rerr != nil {
				logging.Infof("bulk reissue %s: %v", fp, rerr)
				failed = append(failed, bulkReissueItem{OldFingerprint: fp, Error: rerr.Error()})
			} else {
				emitAuditEventDetail(r, auditProvider, principal, "certificate.renew", "certificate", fp, AuditOutcomeSuccess,
					fmt.Sprintf(`{"old_fingerprint":%q,"new_fingerprint":%q,"bulk":true}`, fp, issued.FingerprintSHA256))
				succeeded = append(succeeded, bulkReissueItem{OldFingerprint: fp, NewFingerprint: issued.FingerprintSHA256})
			}
		}

		emitAuditEventDetail(r, auditProvider, principal, "certificate.bulk_reissue", "certificate", "bulk", AuditOutcomeSuccess,
			fmt.Sprintf(`{"succeeded":%d,"failed":%d}`, len(succeeded), len(failed)))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(struct {
			Succeeded []bulkReissueItem `json:"succeeded"`
			Failed    []bulkReissueItem `json:"failed"`
		}{Succeeded: succeeded, Failed: failed})
	})
}

// bulkNotVisibleMessage is deliberately identical for "exists in another
// tenant" and "does not exist" so a bulk call cannot probe other tenants.
const bulkNotVisibleMessage = "not visible in your tenant"

// bulkTargetVisible reports whether the certificate's issuing CA is visible to
// the caller (L-06). Unresolvable certificates are treated as not visible.
func bulkTargetVisible(ctx context.Context, provider CertificateProvider, pd AuthPrincipal, fingerprint string) bool {
	if tenantBypass(pd) {
		return true
	}
	item, found, err := provider.GetCertificate(ctx, fingerprint)
	if err != nil || !found {
		return false
	}
	return caVisibleToTenant(ctx, activeTenantStore, pd, item.CAID)
}
