// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
)

// W24-45: GET /api/v1/agents/{id}/inventory returns what one agent
// discovered, so automation need not filter the whole inventory or read the
// hub database. Authorized exactly like the other agent admin views: agents
// carry no tenant column (D-203), so under multi-tenancy it is super-admin
// only, enforced by the caller before this runs.
//
// Public facts only. Certificates are the fields the agent pushed (no PEM, no
// key); files are the host pass's path, kind, owner, mode and posture, where a
// key file is a row without bytes (W34-08). The hub keeps only the files whose
// posture is not standard or that carry findings, plus counts of all of them. Nothing here can carry key
// material because the agent never sends any.

const (
	agentInventoryDefaultLimit = 100
	agentInventoryMaxLimit     = 500
)

// AgentInventoryResponse is one page of an agent's discovered certificates and
// files. Limit and Offset apply to each list separately; the totals are the
// full counts so a client knows when to stop.
type AgentInventoryResponse struct {
	AgentID           string                `json:"agent_id"`
	Certificates      []AgentDiscoveredCert `json:"certificates"`
	TotalCertificates int                   `json:"total_certificates"`
	Files             []AgentHostFile       `json:"files"`
	TotalFiles        int                   `json:"total_files"`
	// FilePostureCounts is every file the host pass statted by posture. Files
	// lists only those the hub keeps: non-standard posture or with findings
	// (agentHostReport caps it at maxAgentReportFiles).
	FilePostureCounts map[string]int `json:"file_posture_counts,omitempty"`
	// FilesKnown is false when the agent has not sent a host pass (a pre-W34-09
	// agent, or none yet): its files are unknown, not empty.
	FilesKnown bool `json:"files_known"`
	Limit      int  `json:"limit"`
	Offset     int  `json:"offset"`
}

func pageBounds(total, offset, limit int) (lo, hi int) {
	if offset > total {
		offset = total
	}
	hi = offset + limit
	if hi > total {
		hi = total
	}
	return offset, hi
}

func writeAgentInventory(w http.ResponseWriter, r *http.Request, auditProvider AuditProvider, pd AuthPrincipal, store AgentStore, info AgentInfo) {
	limit, offset := agentInventoryDefaultLimit, 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > agentInventoryMaxLimit {
			writeBadRequest(w, "limit must be an integer from 1 to "+strconv.Itoa(agentInventoryMaxLimit))
			return
		}
		limit = n
	}
	if raw := r.URL.Query().Get("offset"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			writeBadRequest(w, "offset must be a non-negative integer")
			return
		}
		offset = n
	}

	certs := store.inventoryOf(info.ID)
	// A stable order, or pages would shuffle between requests.
	sort.Slice(certs, func(i, j int) bool {
		if certs[i].Subject != certs[j].Subject {
			return certs[i].Subject < certs[j].Subject
		}
		if certs[i].Fingerprint != certs[j].Fingerprint {
			return certs[i].Fingerprint < certs[j].Fingerprint
		}
		return certs[i].Source < certs[j].Source
	})
	var files []AgentHostFile
	filesKnown := info.HostReport != nil && info.HostReport.PostureKnown
	if info.HostReport != nil {
		files = append(files, info.HostReport.Files...)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })

	cl, ch := pageBounds(len(certs), offset, limit)
	fl, fh := pageBounds(len(files), offset, limit)
	resp := AgentInventoryResponse{
		AgentID:           info.ID,
		Certificates:      append([]AgentDiscoveredCert{}, certs[cl:ch]...),
		TotalCertificates: len(certs),
		Files:             append([]AgentHostFile{}, files[fl:fh]...),
		TotalFiles:        len(files),
		FilesKnown:        filesKnown,
		FilePostureCounts: filePostureCounts(info.HostReport),
		Limit:             limit,
		Offset:            offset,
	}
	emitAuditEvent(r, auditProvider, pd.ID, "agent.inventory", "agent", info.ID, AuditOutcomeSuccess)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func filePostureCounts(r *AgentHostReport) map[string]int {
	if r == nil || len(r.PostureCounts) == 0 {
		return nil
	}
	out := make(map[string]int, len(r.PostureCounts))
	for k, v := range r.PostureCounts {
		out[k] = v
	}
	return out
}
