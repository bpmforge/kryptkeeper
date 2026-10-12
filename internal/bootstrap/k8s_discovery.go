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

	"kryptkeeper/internal/certmanager"
)

// W19-17: k8s-certmanager was accepted by discovery_scanner_provider.go's
// CreateScan (runCertManagerScan) but had no case in this handler's
// scan_type switch, so it was unreachable via the API under EITHER
// discovery provider -- confirmed empirically during W19-03 (both
// returned HTTP 400). scan_jobs.type's CHECK constraint already lists
// 'k8s-certmanager' (000054), so the gap was purely in Go, not the schema.

const scanTypeK8sCertManager = "k8s-certmanager"

// certManagerCertLister is the slice of certmanager.Connector a scan
// needs. A package var (the newCloudConnector precedent in
// cloud_discovery.go) so tests inject a fake -- no live cluster in CI.
type certManagerCertLister interface {
	ListCertificates(ctx context.Context) ([]certmanager.Certificate, error)
}

var newCertManagerConnectorForScan = func() (certManagerCertLister, error) {
	return certmanager.NewFromEnv()
}

// k8sCertManagerScanSummary is what persists into scan_jobs.results_summary.
// A cert-manager Certificate has no PEM chain and no ip/port -- the same
// "no network address" shape cloudScanSummary already exists for. That
// matters here for a reason cloudScanSummary's comment doesn't have to
// spell out: endpoints.ip_address is Postgres INET (000003), which
// rejects anything that isn't a real IP/CIDR literal. A synthetic
// "namespace/name" identifier would pass SQLite (no real type
// enforcement) and fail production Postgres -- so this reuses the
// job-row-carries-results home instead of forcing a fake address through
// upsertScanResults.
type k8sCertManagerScanSummary struct {
	Certificates int                       `json:"certificates"`
	Items        []certmanager.Certificate `json:"items"`
}

// k8sCertManagerScanMaxItems bounds the JSON persisted per job.
const k8sCertManagerScanMaxItems = 200

// runK8sCertManagerScanAndFinalize executes one k8s-certmanager scan job
// and finalizes its scan_jobs row -- runCloudScanAndFinalize's shape,
// since cert-manager discovery has the identical "no target, scope is the
// connector's credentials" contract the cloud scan types have. Shared by
// the sqlite and postgres stores; placeholder dialect is the only
// difference.
func runK8sCertManagerScanAndFinalize(ctx context.Context, db *sql.DB, postgres bool, jobID string) {
	defer afterDiscoveryScanPersist(jobID)

	update := "UPDATE scan_jobs SET status = ?, results_summary = ?, error_message = ? WHERE id = ?"
	if postgres {
		update = "UPDATE scan_jobs SET status = $1, results_summary = $2, error_message = $3 WHERE id = $4"
	}
	finalize := func(status, summary, errMsg string) {
		if _, err := db.ExecContext(ctx, update, status, summary, errMsg, jobID); err != nil {
			log.Printf("k8s-certmanager scan %s: finalize failed: %v", jobID, err)
		}
	}

	conn, err := newCertManagerConnectorForScan()
	if err != nil {
		finalize("failed", "", fmt.Sprintf("connector init: %v", err))
		return
	}
	certs, err := conn.ListCertificates(ctx)
	if err != nil {
		finalize("failed", "", fmt.Sprintf("list certificates: %v", err))
		return
	}

	summary := k8sCertManagerScanSummary{Certificates: len(certs), Items: certs}
	if len(summary.Items) > k8sCertManagerScanMaxItems {
		summary.Items = summary.Items[:k8sCertManagerScanMaxItems]
	}
	raw, err := json.Marshal(summary)
	if err != nil {
		finalize("failed", "", fmt.Sprintf("summary marshal: %v", err))
		return
	}
	finalize("completed", string(raw), "")
	log.Printf("k8s-certmanager scan %s: %d certificates inventoried", jobID, len(certs))
}
