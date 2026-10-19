// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"kryptkeeper/internal/logging"
	"net/http"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/discovery/scanner"
)

func registerDiscoveryHandlers(mux *http.ServeMux, auth *Authenticator, discoveryProvider DiscoveryProvider, bus *EventBus, auditProvider AuditProvider) {
	// Self-constructed (nil when the DB is unavailable) so this function's
	// signature, and handlers.go, stay put.
	registerDiscoveryHandlersWithTargets(mux, auth, discoveryProvider, bus, auditProvider, newManagedTargetStoreFromEnv())
}

// registerDiscoveryHandlersWithTargets is registerDiscoveryHandlers with the
// managed-target store injected: ssh scans (W24-08) and the per-target
// schedules (W24-04) both resolve targets through it.
func registerDiscoveryHandlersWithTargets(mux *http.ServeMux, auth *Authenticator, discoveryProvider DiscoveryProvider, bus *EventBus, auditProvider AuditProvider, targets ManagedTargetStore) {
	registerDiscoveryScheduleHandlers(mux, auth, discoveryProvider, newDiscoveryScheduleStoreFromEnv(), targets, auditProvider)
	registerAuthorizedIssuerHandlers(mux, auth, newAuthorizedIssuerStoreFromEnv(), discoveryProvider, auditProvider)

	mux.HandleFunc("/api/v1/discovery/summary", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "discovery.summary", "discovery", "summary", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		if !canReadOperationalSummaries(principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "discovery.summary", "discovery", "summary", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}

		summary, err := discoveryProvider.GetSummary(withDiscoveryScope(r.Context(), principal))
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "discovery.summary", "discovery", "summary", AuditOutcomeFailure)
			logging.Warnf("discovery summary unavailable: %v", err)
			writeServiceUnavailable(w, "discovery summary unavailable")
			return
		}

		emitAuditEvent(r, auditProvider, principal.ID, "discovery.summary", "discovery", "summary", AuditOutcomeSuccess)
		resp := struct {
			Data struct {
				Resource            string               `json:"resource"`
				Principal           string               `json:"principal"`
				DiscoveredEndpoints int                  `json:"discovered_endpoints"`
				MappedCertificates  int                  `json:"mapped_certificates"`
				RiskyEndpoints      int                  `json:"risky_endpoints"`
				ActiveScanJobs      int                  `json:"active_scan_jobs"`
				Findings            FindingFunnelSummary `json:"findings"`
				TrustClasses        TrustClassCounts     `json:"trust_classes"`
				InventoryClasses    InventoryClassCounts `json:"inventory_classes"`
			} `json:"data"`
		}{}

		resp.Data.Resource = "discovery-summary"
		resp.Data.Principal = principal.ID
		resp.Data.DiscoveredEndpoints = summary.DiscoveredEndpoints
		resp.Data.MappedCertificates = summary.MappedCertificates
		resp.Data.RiskyEndpoints = summary.RiskyEndpoints
		resp.Data.ActiveScanJobs = summary.ActiveScanJobs
		resp.Data.Findings = summary.Findings
		resp.Data.TrustClasses = summary.TrustClasses
		resp.Data.InventoryClasses = summary.InventoryClasses

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logging.Warnf("failed to encode /api/v1/discovery/summary response: %v", err)
		}
	})

	mux.HandleFunc("/api/v1/discovery/endpoints", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "discovery.endpoints.list", "discovery", "endpoints", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		if !canReadOperationalSummaries(principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "discovery.endpoints.list", "discovery", "endpoints", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}

		query := DiscoveryEndpointQuery{
			Protocol:  strings.TrimSpace(r.URL.Query().Get("protocol")),
			RiskyOnly: strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("risky_only")), "true") || strings.TrimSpace(r.URL.Query().Get("risky_only")) == "1",
			Limit:     parseLimit(r.URL.Query().Get("limit"), 25, 100),
			Cursor:    parseCursor(r.URL.Query().Get("cursor"), 0),
		}
		query.TrustClass = strings.TrimSpace(r.URL.Query().Get("trust_class"))
		if query.TrustClass != "" && !scanner.IsTrustClass(query.TrustClass) {
			writeBadRequest(w, "trust_class must be one of managed, public, private_other, self_signed, unknown")
			return
		}
		query.InventoryClass = strings.TrimSpace(r.URL.Query().Get("inventory_class"))
		if query.InventoryClass != "" && !IsInventoryClass(query.InventoryClass) {
			writeBadRequest(w, "inventory_class must be one of managed, ours_unmanaged, authorized_external, unknown_issuer, self_signed")
			return
		}

		result, err := discoveryProvider.ListEndpoints(withDiscoveryScope(r.Context(), principal), query)
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "discovery.endpoints.list", "discovery", "endpoints", AuditOutcomeFailure)
			logging.Warnf("discovery endpoints unavailable: %v", err)
			writeServiceUnavailable(w, "discovery endpoints unavailable")
			return
		}

		emitAuditEvent(r, auditProvider, principal.ID, "discovery.endpoints.list", "discovery", "endpoints", AuditOutcomeSuccess)
		resp := struct {
			Data struct {
				Resource  string              `json:"resource"`
				Principal string              `json:"principal"`
				Endpoints []DiscoveryEndpoint `json:"endpoints"`
			} `json:"data"`
			Meta struct {
				Total      int  `json:"total"`
				Limit      int  `json:"limit"`
				NextCursor *int `json:"next_cursor"`
				PrevCursor *int `json:"prev_cursor"`
			} `json:"meta"`
		}{}

		resp.Data.Resource = "discovery-endpoints"
		resp.Data.Principal = principal.ID
		resp.Data.Endpoints = result.Endpoints
		resp.Meta.Total = result.Total
		resp.Meta.Limit = result.Limit
		resp.Meta.NextCursor = result.NextCursor
		resp.Meta.PrevCursor = result.PrevCursor

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logging.Warnf("failed to encode /api/v1/discovery/endpoints response: %v", err)
		}
	})

	mux.HandleFunc("/api/v1/discovery/scan-jobs", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "discovery.scan_jobs.list", "discovery", "scan-jobs", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		if !canReadOperationalSummaries(principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan_jobs.list", "discovery", "scan-jobs", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}

		statusFilter := strings.TrimSpace(r.URL.Query().Get("status"))
		if statusFilter != "" {
			// Canonical DiscoveryScanJob.Status set (G-87/S-23): all three
			// providers (db/file/scanner) now emit exactly these five values.
			switch statusFilter {
			case "queued", "running", "completed", "completed_with_errors", "failed", "cancelled":
			default:
				writeBadRequest(w, "invalid status value")
				return
			}
		}
		qFilter := strings.TrimSpace(r.URL.Query().Get("q"))
		if len(qFilter) > 200 {
			writeBadRequest(w, "q parameter too long")
			return
		}
		query := DiscoveryScanJobQuery{
			Status: statusFilter,
			Q:      qFilter,
			Limit:  parseLimit(r.URL.Query().Get("limit"), 25, 100),
			Cursor: parseCursor(r.URL.Query().Get("cursor"), 0),
		}

		result, err := discoveryProvider.ListScanJobs(withDiscoveryScope(r.Context(), principal), query)
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan_jobs.list", "discovery", "scan-jobs", AuditOutcomeFailure)
			logging.Warnf("discovery scan jobs unavailable: %v", err)
			writeServiceUnavailable(w, "discovery scan jobs unavailable")
			return
		}

		emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan_jobs.list", "discovery", "scan-jobs", AuditOutcomeSuccess)
		resp := struct {
			Data struct {
				Resource  string             `json:"resource"`
				Principal string             `json:"principal"`
				ScanJobs  []DiscoveryScanJob `json:"scan_jobs"`
			} `json:"data"`
			Meta struct {
				Total      int  `json:"total"`
				Limit      int  `json:"limit"`
				NextCursor *int `json:"next_cursor"`
				PrevCursor *int `json:"prev_cursor"`
			} `json:"meta"`
		}{}

		resp.Data.Resource = "discovery-scan-jobs"
		resp.Data.Principal = principal.ID
		resp.Data.ScanJobs = result.ScanJobs
		resp.Meta.Total = result.Total
		resp.Meta.Limit = result.Limit
		resp.Meta.NextCursor = result.NextCursor
		resp.Meta.PrevCursor = result.PrevCursor

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logging.Warnf("failed to encode /api/v1/discovery/scan-jobs response: %v", err)
		}
	})

	mux.HandleFunc("/api/v1/discovery/scans", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "discovery.scan.create", "discovery", "scan", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		if !canManageDiscovery(principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan.create", "discovery", "scan", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}

		var req struct {
			ScanType string `json:"scan_type"`
			Target   string `json:"target"`
			// Ports: optional per-scan custom ports for an org that runs a
			// cert-bearing service on a non-standard port. Merged with the
			// scan type's catalogue; ignored for a host:port target.
			Ports []int `json:"ports,omitempty"`
			// JITSudoPassword (ssh scans only, W34-17): used for this job only,
			// held in memory, never stored, logged or audited.
			JITSudoPassword string `json:"jit_sudo_password,omitempty"`
		}
		reader := http.MaxBytesReader(w, r.Body, 8*1024)
		defer reader.Close()
		if err := json.NewDecoder(reader).Decode(&req); err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan.create", "discovery", "scan", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}
		req.ScanType = strings.ToLower(strings.TrimSpace(req.ScanType))
		req.Target = strings.TrimSpace(req.Target)
		if len(req.Ports) > 128 {
			emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan.create", "discovery", "scan", AuditOutcomeFailure)
			writeBadRequest(w, "too many custom ports (max 128)")
			return
		}
		for _, p := range req.Ports {
			if p < 1 || p > 65535 {
				emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan.create", "discovery", "scan", AuditOutcomeFailure)
				writeBadRequest(w, "custom port out of range (1-65535)")
				return
			}
		}
		switch req.ScanType {
		case "full", "targeted", "fast", "deep":
		// W18-12: agentless Windows store enumeration; target is a
		// managed target id whose discovery_mode is winrm.
		case scanTypeWinRM:
		// W24-08: agentless SSH enumeration; target is a managed target id
		// whose install_mode is ssh (isSSHDiscoveryTarget).
		case scanTypeSSH:
		// W19-17: cert-manager discovery scope is the env-configured
		// connector's credentials (KRYPTKEEPER_K8S_*) — same "no target"
		// shape as the cloud scan types below.
		case scanTypeK8sCertManager:
		// W5-12: reserved cloud scan types — scope is whatever account
		// the connector's credentials see, so no target.
		case "cloud_acm", "cloud_azure_kv", "cloud_gcp_cm":
		default:
			emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan.create", "discovery", "scan", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}
		if isCloudScanType(req.ScanType) || req.ScanType == scanTypeK8sCertManager {
			if req.Target != "" {
				emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan.create", "discovery", "scan", AuditOutcomeFailure)
				writeBadRequest(w, "this scan type takes no target — scope is the connector's credentials")
				return
			}
		} else if req.Target == "" || len(req.Target) > 253 {
			emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan.create", "discovery", "scan", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}

		jit := newJITSudo(req.JITSudoPassword)
		req.JITSudoPassword = ""
		if req.ScanType != scanTypeSSH && jit.text() != "" {
			jit.zero()
			emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan.create", "discovery", "scan", AuditOutcomeFailure)
			writeBadRequest(w, "jit_sudo_password applies to ssh scans only")
			return
		}
		if len(jit.text()) > maxJITSudoPasswordLen {
			jit.zero()
			emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan.create", "discovery", "scan", AuditOutcomeFailure)
			writeBadRequest(w, "jit_sudo_password is too long")
			return
		}
		if jit.text() == "" {
			jit = nil
		}
		// The job zeroizes the secret when it ends; until CreateScan hands it
		// over, every early return must.
		handedOff := false
		if jit != nil {
			time.AfterFunc(30*time.Minute, jit.zero) // backstop for a provider that never runs the job
		}
		defer func() {
			if !handedOff {
				jit.zero()
			}
		}()
		if req.ScanType == scanTypeSSH {
			if len(req.Ports) > 0 {
				emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan.create", "discovery", "scan", AuditOutcomeFailure)
				writeBadRequest(w, "ports does not apply to ssh scans")
				return
			}
			if targets == nil {
				emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan.create", "discovery", "scan", AuditOutcomeFailure)
				writeServiceUnavailable(w, "managed targets unavailable")
				return
			}
			t, err := targets.Get(r.Context(), req.Target)
			if err != nil || !targetVisibleToTenant(principal, t) {
				emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan.create", "discovery", "scan", AuditOutcomeFailure)
				writeNotFound(w, "managed target not found")
				return
			}
			if !isSSHDiscoveryTarget(t) {
				emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan.create", "discovery", "scan", AuditOutcomeFailure)
				writeBadRequest(w, "target is not an ssh-mode managed target")
				return
			}
		}

		if err := checkScanTarget(req.ScanType, req.Target, req.Ports); err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan.create", "discovery", "scan", AuditOutcomeFailure)
			if errors.Is(err, scanner.ErrTooManyTargets) {
				writeBadRequest(w, fmt.Sprintf("scan target expands to more than %d probes; narrow the range", scanner.MaxTargetsFromEnv()))
			} else {
				writeBadRequest(w, "scan target is in a denied network range")
			}
			return
		}

		result, err := discoveryProvider.CreateScan(withJITSudo(withDiscoveryScope(r.Context(), principal), jit), req.ScanType, req.Target, req.Ports)
		if err != nil {
			jit.zero()
			emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan.create", "discovery", "scan", AuditOutcomeFailure)
			logging.Warnf("discovery scan create failed: %v", err)
			if errors.Is(err, errDiscoveryScanUnsupported) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnprocessableEntity)
				body, _ := json.Marshal(map[string]string{"error": "unprocessable_entity", "message": err.Error()})
				_, _ = w.Write(body)
				return
			}
			writeServiceUnavailable(w, "discovery scan create unavailable")
			return
		}

		handedOff = true
		if jit != nil {
			emitAuditEventDetail(r, auditProvider, principal.ID, "discovery.scan.create", "discovery", result.ID, AuditOutcomeSuccess, "privilege_source=jit")
		} else {
			emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan.create", "discovery", result.ID, AuditOutcomeSuccess)
		}
		publishDiscoveryScanEvent(bus, principal.Tenant, result.ID, result.Status, fmt.Sprintf("scan queued for %s", result.Target))
		resp := struct {
			Data struct {
				Resource  string `json:"resource"`
				Principal string `json:"principal"`
				ScanJob   struct {
					ID       string `json:"id"`
					Status   string `json:"status"`
					ScanType string `json:"scan_type"`
					Target   string `json:"target"`
					QueuedAt string `json:"queued_at"`
				} `json:"scan_job"`
			} `json:"data"`
		}{}

		resp.Data.Resource = "discovery-scan"
		resp.Data.Principal = principal.ID
		resp.Data.ScanJob.ID = result.ID
		resp.Data.ScanJob.Status = result.Status
		resp.Data.ScanJob.ScanType = result.ScanType
		resp.Data.ScanJob.Target = result.Target
		resp.Data.ScanJob.QueuedAt = result.QueuedAt

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logging.Warnf("failed to encode /api/v1/discovery/scans response: %v", err)
		}
	})

	mux.HandleFunc("/api/v1/discovery/scan-jobs/cancel", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "discovery.scan_job.cancel", "discovery", "scan-job-cancel", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		if !canManageDiscovery(principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan_job.cancel", "discovery", "scan-job-cancel", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}

		var req struct {
			ScanJobID string `json:"scan_job_id"`
			Reason    string `json:"reason"`
		}
		reader := http.MaxBytesReader(w, r.Body, 8*1024)
		defer reader.Close()
		if err := json.NewDecoder(reader).Decode(&req); err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan_job.cancel", "discovery", "scan-job-cancel", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}
		req.ScanJobID = strings.TrimSpace(req.ScanJobID)
		req.Reason = strings.TrimSpace(req.Reason)
		if req.ScanJobID == "" || tooLong(req.Reason) {
			emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan_job.cancel", "discovery", "scan-job-cancel", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}

		result, err := discoveryProvider.CancelScanJob(withDiscoveryScope(r.Context(), principal), req.ScanJobID, req.Reason)
		if err != nil {
			if errors.Is(err, errDiscoveryScanJobNotFound) {
				emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan_job.cancel", "discovery", "scan-job-cancel", AuditOutcomeDenied)
				writeNotFound(w, "scan job not found")
				return
			}
			emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan_job.cancel", "discovery", "scan-job-cancel", AuditOutcomeFailure)
			logging.Warnf("discovery scan job cancel failed: %v", err)
			if errors.Is(err, errDiscoveryScanUnsupported) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnprocessableEntity)
				body, _ := json.Marshal(map[string]string{"error": "unprocessable_entity", "message": err.Error()})
				_, _ = w.Write(body)
				return
			}
			writeServiceUnavailable(w, "discovery scan job cancel unavailable")
			return
		}

		emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan_job.cancel", "discovery", req.ScanJobID, AuditOutcomeSuccess)
		if status, ok := normalizeScanJobEventStatus(result.Status); ok {
			publishDiscoveryScanEvent(bus, principal.Tenant, result.ScanJobID, status, cancelOrRequeueMessage("cancelled", result.Reason))
		}
		resp := struct {
			Data struct {
				Resource  string `json:"resource"`
				Principal string `json:"principal"`
				ScanJobID string `json:"scan_job_id"`
				Status    string `json:"status"`
				Reason    string `json:"reason"`
				UpdatedAt string `json:"updated_at"`
			} `json:"data"`
		}{}
		resp.Data.Resource = "discovery-scan-job-cancel"
		resp.Data.Principal = principal.ID
		resp.Data.ScanJobID = result.ScanJobID
		resp.Data.Status = result.Status
		resp.Data.Reason = result.Reason
		resp.Data.UpdatedAt = result.UpdatedAt

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logging.Warnf("failed to encode /api/v1/discovery/scan-jobs/cancel response: %v", err)
		}
	})

	mux.HandleFunc("/api/v1/discovery/scan-jobs/requeue", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "discovery.scan_job.requeue", "discovery", "scan-job-requeue", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		if !canManageDiscovery(principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan_job.requeue", "discovery", "scan-job-requeue", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}

		var req struct {
			ScanJobID string `json:"scan_job_id"`
			Reason    string `json:"reason"`
		}
		reader := http.MaxBytesReader(w, r.Body, 8*1024)
		defer reader.Close()
		if err := json.NewDecoder(reader).Decode(&req); err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan_job.requeue", "discovery", "scan-job-requeue", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}
		req.ScanJobID = strings.TrimSpace(req.ScanJobID)
		req.Reason = strings.TrimSpace(req.Reason)
		if req.ScanJobID == "" || tooLong(req.Reason) {
			emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan_job.requeue", "discovery", "scan-job-requeue", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}

		result, err := discoveryProvider.RequeueScanJob(withDiscoveryScope(r.Context(), principal), req.ScanJobID, req.Reason)
		if err != nil {
			if errors.Is(err, errDiscoveryScanJobNotFound) {
				emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan_job.requeue", "discovery", "scan-job-requeue", AuditOutcomeDenied)
				writeNotFound(w, "scan job not found")
				return
			}
			emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan_job.requeue", "discovery", "scan-job-requeue", AuditOutcomeFailure)
			logging.Warnf("discovery scan job requeue failed: %v", err)
			if errors.Is(err, errDiscoveryScanUnsupported) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnprocessableEntity)
				body, _ := json.Marshal(map[string]string{"error": "unprocessable_entity", "message": err.Error()})
				_, _ = w.Write(body)
				return
			}
			writeServiceUnavailable(w, "discovery scan job requeue unavailable")
			return
		}

		emitAuditEvent(r, auditProvider, principal.ID, "discovery.scan_job.requeue", "discovery", req.ScanJobID, AuditOutcomeSuccess)
		if status, ok := normalizeScanJobEventStatus(result.Status); ok {
			publishDiscoveryScanEvent(bus, principal.Tenant, result.ScanJobID, status, cancelOrRequeueMessage("requeued", result.Reason))
		}
		resp := struct {
			Data struct {
				Resource   string `json:"resource"`
				Principal  string `json:"principal"`
				PreviousID string `json:"previous_scan_job_id"`
				ScanJobID  string `json:"scan_job_id"`
				Status     string `json:"status"`
				Reason     string `json:"reason"`
				QueuedAt   string `json:"queued_at"`
			} `json:"data"`
		}{}
		resp.Data.Resource = "discovery-scan-job-requeue"
		resp.Data.Principal = principal.ID
		resp.Data.PreviousID = result.PreviousID
		resp.Data.ScanJobID = result.ScanJobID
		resp.Data.Status = result.Status
		resp.Data.Reason = result.Reason
		resp.Data.QueuedAt = result.QueuedAt

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logging.Warnf("failed to encode /api/v1/discovery/scan-jobs/requeue response: %v", err)
		}
	})
}

func parseLimit(raw string, fallback int, max int) int {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fallback
	}
	v, err := strconv.Atoi(trimmed)
	if err != nil || v <= 0 {
		return fallback
	}
	if v > max {
		return max
	}
	return v
}

func parseCursor(raw string, fallback int) int {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fallback
	}
	v, err := strconv.Atoi(trimmed)
	if err != nil || v < 0 {
		return fallback
	}
	return v
}

// publishDiscoveryScanEvent is the discovery-scan producer wired as proof
// for GET /api/v1/events (W8-14): it turns the three synchronous status
// transitions this file's write endpoints already observe (create ->
// queued, cancel -> cancelled, requeue -> queued under a new job id) into
// Event envelopes. status must already be one of OperationEvent's canonical
// values by the time it reaches here -- callers run it through
// normalizeScanJobEventStatus first, since CreateScan's own results are
// already canonical but CancelScanJob's are not (see that function's doc).
// progress is nil: none of the three write endpoints have a percentage to
// report. bus is nil-safe so callers (and tests) that don't care about SSE
// don't need a bus. Publish itself never blocks (event_bus.go), so this
// never risks the scan/cancel/requeue response on a slow or absent
// subscriber (acceptance #8).
func publishDiscoveryScanEvent(bus *EventBus, tenant, opID, status, message string) {
	if bus == nil || opID == "" {
		return
	}
	bus.Publish(tenant, Event{
		OpID:    opID,
		Kind:    EventKindScan,
		Status:  status,
		Message: message,
		Ts:      time.Now().UTC().Format(time.RFC3339),
	})
}

// canonicalScanJobEventStatuses is the OperationEvent/DiscoveryScanJob status
// enum (docs/openapi.yaml, event_bus.go's Event doc comment): queued,
// running, completed, failed, cancelled. Nothing else may reach a GET
// /api/v1/events subscriber in the status field.
var canonicalScanJobEventStatuses = map[string]bool{
	"queued":    true,
	"running":   true,
	"completed": true,
	"failed":    true,
	"cancelled": true,
}

// normalizeScanJobEventStatus maps a DiscoveryProvider write result's Status
// onto the canonical enum, reporting ok=false when the value must not be
// published. Two problems exist in the provider layer that this guards
// against: (1) every CancelScanJob implementation (discovery_db_provider.go,
// discovery_scanner_provider.go, discovery_file_provider.go) spells a
// successful cancel "canceled" (single L), not the "cancelled" (double L)
// docs/openapi.yaml's own DiscoveryScanJob and OperationEvent schemas
// declare -- normalized here rather than at each call site. (2) when the
// target job is already terminal or missing, CancelScanJob returns a nil
// error with a non-terminal sentinel status ("not_found_or_already_terminal"
// for the db providers, "not_found" for the scanner provider) instead of an
// error -- publishing that string verbatim would put a value outside the
// documented enum on the wire, so it is rejected outright rather than
// mapped: no real state transition happened, so no event should be
// delivered at all.
func normalizeScanJobEventStatus(status string) (string, bool) {
	if status == "canceled" {
		status = "cancelled"
	}
	if !canonicalScanJobEventStatuses[status] {
		return "", false
	}
	return status, true
}

func cancelOrRequeueMessage(verb, reason string) string {
	if reason == "" {
		return "scan " + verb
	}
	return fmt.Sprintf("scan %s: %s", verb, reason)
}

// checkScanTarget applies the discovery deny list and the per-scan expansion
// cap (OWASP-A10-003, A04-005) to network scan types; agentless and cloud
// scan types carry an id or no target, so there is nothing to expand.
func checkScanTarget(scanType, target string, extraPorts []int) error {
	switch scanType {
	case "full", "targeted", "fast", "deep":
	default:
		return nil
	}
	perHost := 1
	if scanType != "deep" {
		perHost = len(mergePorts(scanner.PortsForScanType(scanType), extraPorts, standingCustomPorts()))
	}
	return scanner.CheckTarget(target, perHost, scanner.DenyCIDRsFromEnv(), scanner.MaxTargetsFromEnv())
}
