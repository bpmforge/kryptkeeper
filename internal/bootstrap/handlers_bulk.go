// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

const maxBulkBodyBytes int64 = 128 * 1024

type bulkRevokeItem struct {
	Fingerprint string `json:"fingerprint"`
	Error       string `json:"error,omitempty"`
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
			writeBadRequest(w, "invalid request body")
			return
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			writeBadRequest(w, "invalid request body")
			return
		}
		if len(req.Fingerprints) == 0 {
			writeBadRequest(w, "fingerprints must not be empty")
			return
		}
		if len(req.Fingerprints) > 500 {
			writeBadRequest(w, "bulk revoke limited to 500 certificates per request")
			return
		}

		succeeded := make([]bulkRevokeItem, 0)
		failed := make([]bulkRevokeItem, 0)

		for _, fp := range req.Fingerprints {
			fp = strings.TrimSpace(fp)
			revokeReq := CertificateRevokeRequest{ReasonCode: req.ReasonCode}
			_, rerr := provider.RevokeCertificate(r.Context(), fp, revokeReq)
			if rerr != nil {
				log.Printf("bulk revoke %s: %v", fp, rerr)
				failed = append(failed, bulkRevokeItem{Fingerprint: fp, Error: rerr.Error()})
			} else {
				emitAuditEventDetail(r, auditProvider, principal, "certificate.revoke", "certificate", fp, AuditOutcomeSuccess,
					fmt.Sprintf(`{"fingerprint":%q,"reason":%d,"bulk":true}`, fp, req.ReasonCode))
				succeeded = append(succeeded, bulkRevokeItem{Fingerprint: fp})
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
			writeBadRequest(w, "invalid request body")
			return
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			writeBadRequest(w, "invalid request body")
			return
		}
		if len(req.Fingerprints) == 0 {
			writeBadRequest(w, "fingerprints must not be empty")
			return
		}
		if len(req.Fingerprints) > 200 {
			writeBadRequest(w, "bulk reissue limited to 200 certificates per request")
			return
		}

		succeeded := make([]bulkReissueItem, 0)
		failed := make([]bulkReissueItem, 0)

		for _, fp := range req.Fingerprints {
			fp = strings.TrimSpace(fp)
			issued, rerr := provider.RenewCertificate(r.Context(), fp, CertificateRenewRequest{})
			if rerr != nil {
				log.Printf("bulk reissue %s: %v", fp, rerr)
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
