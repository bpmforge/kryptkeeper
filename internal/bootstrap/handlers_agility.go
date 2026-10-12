// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"kryptkeeper/internal/pqc"
)

// W17-06: the W16-03 crypto-agility roadmap, wired.
//
// DeriveAgilityRoadmap/Progress had zero non-test callers outside their
// own file — the package was reachable but the feature was not. It
// generalizes the PQC-wave machinery to ANY algorithm transition, so
// "what do we migrate, in what order, before the 2030 RSA-2048 deadline"
// is a query rather than a spreadsheet. PQC is one instance of the
// pattern, not a special case.

// agilityRequest is the transition being planned. Deadline is RFC3339 so
// the policy is expressed the way the regulation that forces it is.
type agilityRequest struct {
	Name       string   `json:"name"`
	Algorithms []string `json:"algorithms"`
	MaxKeyBits int      `json:"max_key_bits"`
	Deadline   string   `json:"deadline"`
}

func (req agilityRequest) toPolicy() (pqc.DeprecationPolicy, error) {
	policy := pqc.DeprecationPolicy{
		Name:       req.Name,
		Algorithms: req.Algorithms,
		MaxKeyBits: req.MaxKeyBits,
	}
	if len(req.Algorithms) == 0 && req.MaxKeyBits == 0 {
		// A policy that matches nothing would report 100% migrated and a
		// clean roadmap — a false all-clear. Refuse it instead.
		return policy, fmt.Errorf("a policy must constrain algorithms, max_key_bits, or both")
	}
	if req.Deadline != "" {
		deadline, err := time.Parse(time.RFC3339, req.Deadline)
		if err != nil {
			return policy, fmt.Errorf("deadline must be RFC3339")
		}
		policy.Deadline = deadline
	}
	return policy, nil
}

// registerAgilityHandler mounts the crypto-agility roadmap + progress.
func registerAgilityHandler(mux *http.ServeMux, auth *Authenticator, certProvider CertificateProvider, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/crypto-agility/roadmap", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		principal, err := auth.AuthenticatePrincipal(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "crypto_agility.roadmap", "policy", "crypto-agility", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		var req agilityRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
			writeBadRequest(w, "invalid policy body")
			return
		}
		policy, err := req.toPolicy()
		if err != nil {
			writeBadRequest(w, err.Error())
			return
		}

		result, err := listAllCertificates(r.Context(), certProvider, CertificateListQuery{})
		if err != nil {
			emitAuditEvent(r, auditProvider, principal, "crypto_agility.roadmap", "policy", "crypto-agility", AuditOutcomeFailure)
			log.Printf("crypto agility: list certs: %v", err)
			writeServiceUnavailable(w, "inventory unavailable")
			return
		}
		records := make([]pqc.CertRecord, 0, len(result.Items))
		for _, item := range result.Items {
			records = append(records, toPQCCertRecord(item))
		}

		now := time.Now().UTC()
		roadmap := pqc.DeriveAgilityRoadmap(records, policy, now)
		progress := pqc.Progress(records, policy, now)

		emitAuditEventDetail(r, auditProvider, principal, "crypto_agility.roadmap", "policy", "crypto-agility", AuditOutcomeSuccess,
			fmt.Sprintf(`{"policy":%q,"matched":%d,"percent_migrated":%d,"overdue":%t}`,
				policy.Name, roadmap.TotalMatched, progress.PercentMigrated, progress.Overdue))

		writeJSONData(w, map[string]any{
			"roadmap":  roadmap,
			"progress": progress,
		})
	})
}
