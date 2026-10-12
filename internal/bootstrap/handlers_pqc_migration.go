// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/pqc"
)

// isCACert reports whether a cert is a CA (key usage includes cert signing).
func isCACert(c CertificateItem) bool {
	for _, ku := range c.KeyUsage {
		k := strings.ToLower(strings.ReplaceAll(ku, " ", ""))
		if k == "certsign" || k == "keycertsign" {
			return true
		}
	}
	return false
}

// toPQCCertRecord bridges a CertificateItem into the PQC planner's input shape.
func toPQCCertRecord(c CertificateItem) pqc.CertRecord {
	return pqc.CertRecord{
		Fingerprint:   c.FingerprintSHA256,
		CommonName:    c.CommonName,
		Algorithm:     c.PublicKeyAlgorithm,
		KeySize:       c.KeySizeBits,
		ValidFrom:     parseTimeOrZero(c.ValidFrom),
		ValidUntil:    parseTimeOrZero(c.ValidUntil),
		PQCReadiness:  c.PQCReadiness,
		IsCA:          isCACert(c),
		AutoRenewable: c.RenewalMethod == "acme" || c.RenewalMethod == "est" || c.RenewalMethod == "scep",
		IsCodeSigning: isCodeSigningCert(c),
		SANCount:      len(c.SubjectAltNames),
	}
}

// registerPQCMigrationHandler mounts GET /api/v1/reports/pqc-migration, which
// runs the PQC planner over the live inventory and returns a prioritized
// migration roadmap (CNSA 2.0 / NIST 800-131A deadline).
func registerPQCMigrationHandler(mux *http.ServeMux, auth *Authenticator, certProvider CertificateProvider, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/reports/pqc-migration", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "report.pqc_migration", "report", "pqc-migration", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		result, err := listAllCertificates(r.Context(), certProvider, CertificateListQuery{})
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "report.pqc_migration", "report", "pqc-migration", AuditOutcomeFailure)
			writeServiceUnavailable(w, "report unavailable")
			return
		}
		certs := reportScopeCertificates(r.Context(), pd, result.Items)
		records := make([]pqc.CertRecord, 0, len(certs))
		for _, c := range certs {
			records = append(records, toPQCCertRecord(c))
		}
		// CNSA 2.0 mandate: PQC by 2030.
		planner := pqc.NewPlanner(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
		roadmap := planner.GenerateRoadmap(records)

		emitAuditEvent(r, auditProvider, pd.ID, "report.pqc_migration", "report", "pqc-migration", AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(struct {
			Data pqc.MigrationRoadmap `json:"data"`
		}{Data: roadmap}); err != nil {
			log.Printf("failed to encode pqc migration roadmap: %v", err)
		}
	})
}
