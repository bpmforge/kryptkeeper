// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
)

// W17-09: start the W7-01 Workload API and let operators populate the
// selector registry.
//
// startWorkloadAPIServer had no caller and SelectorRegistry could only be
// filled in tests, so the shipped attestor was unreachable. Both halves
// are needed: a listener nobody can register against serves nothing, and
// bindings with no listener attest nothing.

// SPIFFEWorkloadSocketEnv names the Unix socket the Workload API serves
// on. Unset means the listener does NOT start — a gRPC socket handing
// out SVIDs is not something to enable by accident.
const SPIFFEWorkloadSocketEnv = "SPIFFE_WORKLOAD_SOCKET"

// startWorkloadAPIIfConfigured starts the Workload API when a socket path
// is configured, and reports whether it did. The returned server is nil
// when the feature is off.
func startWorkloadAPIIfConfigured(registry *SelectorRegistry, audit AuditProvider) *grpc.Server {
	socket := strings.TrimSpace(os.Getenv(SPIFFEWorkloadSocketEnv))
	if socket == "" {
		return nil
	}
	srv, err := startWorkloadAPIServer(socket, registry, audit)
	if err != nil {
		// A failed listener must be loud but must not take the hub down:
		// the REST SVID mint path keeps working without it.
		log.Printf("SPIFFE Workload API: not started on %s: %v", socket, err)
		return nil
	}
	log.Printf("SPIFFE Workload API listening on %s", socket)
	return srv
}

// workloadSelectorRequest binds a kernel-attested UID to a SPIFFE ID.
type workloadSelectorRequest struct {
	UID      int64  `json:"uid"`
	SPIFFEID string `json:"spiffe_id"`
}

// registerWorkloadSelectorHandlers exposes the operator API over the
// registry the attestor consults.
//
// proposer≠approver holds structurally: registering a binding IS the
// human approval, and it requires the same admin capability as any other
// identity grant. A workload can never name its own identity — the
// Workload API request carries no identity field at all.
func registerWorkloadSelectorHandlers(mux *http.ServeMux, auth *Authenticator, registry *SelectorRegistry, auditProvider AuditProvider) {
	if registry == nil {
		return
	}
	mux.HandleFunc("/api/v1/spiffe/workload-selectors", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "spiffe.selector_bind", "spiffe_selector", "-", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if !canApproveActions(pd.Role) {
			emitAuditEvent(r, auditProvider, pd.ID, "spiffe.selector_bind", "spiffe_selector", "-", AuditOutcomeDenied)
			writeForbidden(w, "approver role required to bind a workload identity")
			return
		}

		switch r.Method {
		case http.MethodGet:
			writeJSONData(w, map[string]any{"selectors": registry.List()})

		case http.MethodPost:
			var req workloadSelectorRequest
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&req); err != nil {
				writeBadRequest(w, "invalid request body")
				return
			}
			if req.UID < 0 {
				writeBadRequest(w, "uid must be a non-negative integer")
				return
			}
			// The SPIFFE ID must be well-formed AND inside our trust
			// domain: binding a UID to another domain's identity would
			// mint an SVID this CA has no authority to assert.
			trustDomain := strings.TrimSpace(os.Getenv("SPIFFE_TRUST_DOMAIN"))
			if _, err := validateSPIFFEID(req.SPIFFEID, trustDomain); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "spiffe.selector_bind", "spiffe_selector", req.SPIFFEID, AuditOutcomeFailure)
				writeBadRequest(w, err.Error())
				return
			}
			registry.RegisterUID(uint32(req.UID), req.SPIFFEID)
			emitAuditEventDetail(r, auditProvider, pd.ID, "spiffe.selector_bind", "spiffe_selector", req.SPIFFEID, AuditOutcomeSuccess,
				`{"uid":`+strconv.FormatInt(req.UID, 10)+`}`)
			w.WriteHeader(http.StatusCreated)
			if err := json.NewEncoder(w).Encode(struct {
				Data workloadSelectorRequest `json:"data"`
			}{Data: req}); err != nil {
				log.Printf("failed to encode selector: %v", err)
			}

		default:
			writeMethodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
		}
	})
}
