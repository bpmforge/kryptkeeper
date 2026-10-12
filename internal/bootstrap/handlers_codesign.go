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
		principal, err := auth.AuthenticatePrincipal(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "inventory.code_signing_policy", "inventory", "code-signing", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		var policy CodeSigningPolicy
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&policy); err != nil {
			emitAuditEvent(r, auditProvider, principal, "inventory.code_signing_policy", "inventory", "code-signing", AuditOutcomeFailure)
			if rejectOversizeBody(w, err) {
				return
			}
			writeBadRequest(w, "invalid policy body")
			return
		}
		result, err := listAllCertificates(r.Context(), certProvider, CertificateListQuery{})
		if err != nil {
			emitAuditEvent(r, auditProvider, principal, "inventory.code_signing_policy", "inventory", "code-signing", AuditOutcomeFailure)
			log.Printf("code-signing policy check: list certs: %v", err)
			writeServiceUnavailable(w, "inventory unavailable")
			return
		}
		inv := buildCodeSigningInventory(result.Items, time.Now().UTC())
		summary := summarizeCodeSigningPolicy(inv.Certs, policy)
		emitAuditEvent(r, auditProvider, principal, "inventory.code_signing_policy", "inventory", "code-signing", AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(struct {
			Data CodeSigningPolicySummary `json:"data"`
		}{Data: summary}); err != nil {
			log.Printf("failed to encode code-signing policy summary: %v", err)
		}
	})

	mux.HandleFunc("/api/v1/inventory/code-signing", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		principal, err := auth.AuthenticatePrincipal(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "inventory.code_signing", "inventory", "code-signing", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		result, err := listAllCertificates(r.Context(), certProvider, CertificateListQuery{})
		if err != nil {
			emitAuditEvent(r, auditProvider, principal, "inventory.code_signing", "inventory", "code-signing", AuditOutcomeFailure)
			log.Printf("code-signing inventory: list certs: %v", err)
			writeServiceUnavailable(w, "inventory unavailable")
			return
		}

		inv := buildCodeSigningInventory(result.Items, time.Now().UTC())

		emitAuditEvent(r, auditProvider, principal, "inventory.code_signing", "inventory", "code-signing", AuditOutcomeSuccess)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(struct {
			Data CodeSigningInventory `json:"data"`
		}{Data: inv}); err != nil {
			log.Printf("failed to encode code-signing inventory: %v", err)
		}
	})
}
