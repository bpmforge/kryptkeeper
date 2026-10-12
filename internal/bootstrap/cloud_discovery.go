// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"

	"kryptkeeper/internal/cloudinventory"
)

// W5-12 (D-065/FR-P27): the cloudinventory connectors, wired into real
// scan types. The type strings are exactly the reserved scan_jobs.type
// CHECK values (000033) — cloud_acm, cloud_azure_kv, cloud_gcp_cm.

const (
	scanTypeCloudACM     = "cloud_acm"
	scanTypeCloudAzureKV = "cloud_azure_kv"
	scanTypeCloudGCPCM   = "cloud_gcp_cm"
)

func isCloudScanType(t string) bool {
	return t == scanTypeCloudACM || t == scanTypeCloudAzureKV || t == scanTypeCloudGCPCM
}

// isNetworkScanType covers the types the network scanner runs.
func isNetworkScanType(t string) bool {
	switch t {
	case "full", "targeted", "fast", "network", "deep":
		return true
	}
	return false
}

// cloudConnector is the slice of a cloudinventory connector the scan
// needs. All three connectors satisfy it.
type cloudConnector interface {
	ListCertificates(ctx context.Context) ([]cloudinventory.CloudCertificate, error)
}

// newCloudConnector builds the real connector for a scan type. Package
// var so tests inject fakes (the runDiscoveryScan precedent) — no cloud
// credentials in CI.
var newCloudConnector = func(ctx context.Context, scanType string) (cloudConnector, error) {
	switch scanType {
	case scanTypeCloudACM:
		return cloudinventory.NewACMConnector(ctx)
	case scanTypeCloudAzureKV:
		return cloudinventory.NewAzureKVConnector(ctx)
	case scanTypeCloudGCPCM:
		return cloudinventory.NewGCPCertManagerConnector(ctx)
	default:
		return nil, fmt.Errorf("unknown cloud scan type %q", scanType)
	}
}

// cloudScanSummary is what persists into scan_jobs.results_summary.
// Cloud list APIs return certificate METADATA (no PEM chains) and cloud
// certs have no ip/port, so the network endpoints table is the wrong
// home — the job row carries the results; inventory import stays with
// the W11-05 inventory-source machinery.
type cloudScanSummary struct {
	Provider     string                            `json:"provider"`
	Certificates int                               `json:"certificates"`
	Items        []cloudinventory.CloudCertificate `json:"items"`
}

// cloudScanMaxItems bounds the JSON persisted per job; the count is
// always exact.
const cloudScanMaxItems = 200

// runCloudScanAndFinalize executes one cloud scan job and finalizes its
// scan_jobs row. Shared by the sqlite and postgres stores; placeholder
// dialect is the only difference. "completed" matches the canonical
// status spelling the network path uses (G-87/S-23).
func runCloudScanAndFinalize(ctx context.Context, db *sql.DB, postgres bool, jobID, scanType string) {
	defer afterDiscoveryScanPersist(jobID)

	update := "UPDATE scan_jobs SET status = ?, results_summary = ?, error_message = ? WHERE id = ?"
	if postgres {
		update = "UPDATE scan_jobs SET status = $1, results_summary = $2, error_message = $3 WHERE id = $4"
	}
	finalize := func(status, summary, errMsg string) {
		if _, err := db.ExecContext(ctx, update, status, summary, errMsg, jobID); err != nil {
			log.Printf("cloud scan %s: finalize failed: %v", jobID, err)
		}
	}

	connector, err := newCloudConnector(ctx, scanType)
	if err != nil {
		finalize("failed", "", fmt.Sprintf("connector init: %v", err))
		return
	}
	certs, err := connector.ListCertificates(ctx)
	if err != nil {
		finalize("failed", "", fmt.Sprintf("list certificates: %v", err))
		return
	}

	summary := cloudScanSummary{Provider: scanType, Certificates: len(certs), Items: certs}
	if len(summary.Items) > cloudScanMaxItems {
		summary.Items = summary.Items[:cloudScanMaxItems]
	}
	raw, err := json.Marshal(summary)
	if err != nil {
		finalize("failed", "", fmt.Sprintf("summary marshal: %v", err))
		return
	}
	finalize("completed", string(raw), "")
	log.Printf("cloud scan %s (%s): %d certificates inventoried", jobID, scanType, len(certs))
}
