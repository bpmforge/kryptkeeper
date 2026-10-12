// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/scep"
)

// SCEP challenge lifetimes (W20-16, D-121). NDES issues challenges valid for
// 60 minutes; a day is the most a device provisioning step should need.
const (
	scepChallengeDefaultTTL = time.Hour
	scepChallengeMaxTTL     = 24 * time.Hour
	scepChallengeMaxNames   = 20
)

// RegisterSCEPChallengeHandlers mounts the one-time SCEP challenge API:
// POST /api/v1/scep/challenges mints one (the response is the only place
// its secret ever appears), GET lists them without secrets, and
// DELETE /api/v1/scep/challenges/{id} withdraws an unused one. Minting a
// challenge is issuing a certificate in advance, so it takes an issuer role.
func RegisterSCEPChallengeHandlers(mux *http.ServeMux, auth *Authenticator, store scep.ChallengeStore, caID string, auditProvider AuditProvider) {
	if store == nil {
		return
	}
	authorize := func(w http.ResponseWriter, r *http.Request, action string) (string, bool) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", action, "scep_challenge", "-", AuditOutcomeDenied)
			writeUnauthorized(w)
			return "", false
		}
		if role := strings.TrimSpace(pd.Role); role != "pki-admin" && role != "pki-operator" {
			emitAuditEvent(r, auditProvider, pd.ID, action, "scep_challenge", "-", AuditOutcomeDenied)
			writeForbidden(w, "pki-admin or pki-operator role required for SCEP challenges")
			return "", false
		}
		return pd.ID, true
	}
	writeData := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		if err := json.NewEncoder(w).Encode(struct {
			Data any `json:"data"`
		}{Data: v}); err != nil {
			log.Printf("scep challenge response: %v", err)
		}
	}

	mux.HandleFunc("/api/v1/scep/challenges", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if _, ok := authorize(w, r, "scep.challenge.list"); !ok {
				return
			}
			list, err := store.List(r.Context())
			if err != nil {
				log.Printf("scep challenge list: %v", err)
				writeServiceUnavailable(w, "scep challenges unavailable")
				return
			}
			writeData(w, http.StatusOK, list)
		case http.MethodPost:
			principal, ok := authorize(w, r, "scep.challenge.create")
			if !ok {
				return
			}
			var req struct {
				CommonName string   `json:"common_name"`
				DNSNames   []string `json:"dns_names"`
				TTL        string   `json:"ttl"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&req); err != nil {
				emitAuditEvent(r, auditProvider, principal, "scep.challenge.create", "scep_challenge", "-", AuditOutcomeFailure)
				if rejectOversizeBody(w, err) {
					return
				}
				writeBadRequest(w, "invalid request body")
				return
			}
			c, ttl, err := validateSCEPChallengeRequest(req.CommonName, req.DNSNames, req.TTL)
			if err != nil {
				emitAuditEventDetail(r, auditProvider, principal, "scep.challenge.create", "scep_challenge", "-", AuditOutcomeFailure, err.Error())
				writeBadRequest(w, err.Error())
				return
			}
			now := time.Now().UTC()
			c.CAID, c.CreatedBy, c.CreatedAt, c.ExpiresAt = caID, principal, now, now.Add(ttl)
			created, secret, err := store.Create(r.Context(), c)
			if err != nil {
				log.Printf("scep challenge create: %v", err)
				emitAuditEvent(r, auditProvider, principal, "scep.challenge.create", "scep_challenge", "-", AuditOutcomeFailure)
				writeServiceUnavailable(w, "scep challenges unavailable")
				return
			}
			emitAuditEventDetail(r, auditProvider, principal, "scep.challenge.create", "scep_challenge", created.ID, AuditOutcomeSuccess,
				fmt.Sprintf("cn=%s dns=%s expires=%s", created.CommonName, strings.Join(created.DNSNames, ","), created.ExpiresAt.Format(time.RFC3339)))
			// The secret is in this response and nowhere else.
			writeData(w, http.StatusCreated, scepChallengeCreated{Challenge: created, Secret: secret})
		default:
			writeMethodNotAllowed(w, "GET, POST")
		}
	})

	mux.HandleFunc("/api/v1/scep/challenges/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/scep/challenges/")
		if id == "" || strings.Contains(id, "/") {
			writeNotFound(w, "scep challenge not found")
			return
		}
		if r.Method != http.MethodDelete {
			writeMethodNotAllowed(w, http.MethodDelete)
			return
		}
		principal, ok := authorize(w, r, "scep.challenge.delete")
		if !ok {
			return
		}
		if err := store.Delete(r.Context(), id); err != nil {
			emitAuditEvent(r, auditProvider, principal, "scep.challenge.delete", "scep_challenge", id, AuditOutcomeFailure)
			if errors.Is(err, scep.ErrChallengeNotFound) {
				writeNotFound(w, "no unused scep challenge with that id")
				return
			}
			writeServiceUnavailable(w, "scep challenges unavailable")
			return
		}
		emitAuditEvent(r, auditProvider, principal, "scep.challenge.delete", "scep_challenge", id, AuditOutcomeSuccess)
		w.WriteHeader(http.StatusNoContent)
	})
}

// scepChallengeCreated is a minted challenge plus its one-time secret.
type scepChallengeCreated struct {
	scep.Challenge
	Secret string `json:"challenge"`
}

// validateSCEPChallengeRequest checks the names a challenge will bind and
// returns them with its lifetime.
func validateSCEPChallengeRequest(cn string, dnsNames []string, ttl string) (scep.Challenge, time.Duration, error) {
	cn = strings.ToLower(strings.TrimSpace(cn))
	if !validDeviceName(cn) {
		return scep.Challenge{}, 0, errors.New("common_name must be a host name (no wildcards or spaces)")
	}
	if len(dnsNames) > scepChallengeMaxNames {
		return scep.Challenge{}, 0, fmt.Errorf("at most %d dns_names", scepChallengeMaxNames)
	}
	names := make([]string, 0, len(dnsNames))
	for _, n := range dnsNames {
		n = strings.ToLower(strings.TrimSpace(n))
		if !validDeviceName(n) {
			return scep.Challenge{}, 0, fmt.Errorf("dns_names: %q is not a host name (no wildcards or spaces)", n)
		}
		names = append(names, n)
	}
	d := scepChallengeDefaultTTL
	if strings.TrimSpace(ttl) != "" {
		var err error
		if d, err = time.ParseDuration(ttl); err != nil || d <= 0 {
			return scep.Challenge{}, 0, errors.New("ttl must be a positive Go duration, e.g. 30m")
		}
	}
	if d > scepChallengeMaxTTL {
		return scep.Challenge{}, 0, fmt.Errorf("ttl may be at most %s", scepChallengeMaxTTL)
	}
	return scep.Challenge{CommonName: cn, DNSNames: names}, d, nil
}

// validDeviceName accepts a DNS host name: dot-separated labels of letters,
// digits and hyphens, no wildcard.
func validDeviceName(n string) bool {
	if n == "" || len(n) > 253 {
		return false
	}
	for _, label := range strings.Split(n, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
