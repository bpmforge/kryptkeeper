// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"kryptkeeper/internal/logging"
	"strings"

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
	Certificates int                  `json:"certificates"`
	Items        []k8sCertManagerItem `json:"items"`
	// Clusters is the per-cluster outcome (W24-23); one failing cluster
	// only fails its own row.
	Clusters []k8sClusterResult `json:"clusters"`
}

type k8sCertManagerItem struct {
	certmanager.Certificate
	Cluster string `json:"cluster"`
}

type k8sClusterResult struct {
	Name         string `json:"name"`
	Certificates int    `json:"certificates"`
	Error        string `json:"error,omitempty"`
}

// k8sCertManagerScanMaxItems bounds the JSON persisted per job.
const k8sCertManagerScanMaxItems = 200

const defaultKubeClusterName = "default"

// newCertManagerConnectorForCluster builds the lister for one configured
// cluster; a package var so tests inject fakes.
var newCertManagerConnectorForCluster = func(c kubeClusterSource) (certManagerCertLister, error) {
	conn, err := certmanager.New(certmanager.Config{APIServerURL: c.APIURL, Token: c.Token, CACert: c.CACert, Namespace: c.Namespace})
	if err != nil {
		return nil, err
	}
	return conn, nil
}

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
			logging.Warnf("k8s-certmanager scan %s: finalize failed: %v", jobID, err)
		}
	}

	clusters, err := kubeClusterSourcesLoader(ctx)
	if err != nil {
		finalize("failed", "", fmt.Sprintf("cluster config: %v", err))
		return
	}

	var summary k8sCertManagerScanSummary
	if len(clusters) == 0 {
		// Legacy single-cluster env path, unchanged messages.
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
		summary.Items = tagClusterItems(defaultKubeClusterName, certs)
		summary.Clusters = []k8sClusterResult{{Name: defaultKubeClusterName, Certificates: len(certs)}}
	} else {
		var failed []string
		for _, c := range clusters {
			res := k8sClusterResult{Name: c.Name}
			certs, err := listClusterCertificates(ctx, c)
			if err != nil {
				res.Error = err.Error()
				failed = append(failed, fmt.Sprintf("cluster %s: %s", c.Name, res.Error))
			} else {
				res.Certificates = len(certs)
				summary.Items = append(summary.Items, tagClusterItems(c.Name, certs)...)
			}
			summary.Clusters = append(summary.Clusters, res)
		}
		if len(failed) == len(clusters) {
			finalize("failed", "", strings.Join(failed, "; "))
			return
		}
		if len(failed) > 0 {
			errMsg := strings.Join(failed, "; ")
			finishK8sCertManagerScan(finalize, jobID, summary, errMsg)
			return
		}
	}
	finishK8sCertManagerScan(finalize, jobID, summary, "")
}

func tagClusterItems(cluster string, certs []certmanager.Certificate) []k8sCertManagerItem {
	items := make([]k8sCertManagerItem, 0, len(certs))
	for _, c := range certs {
		items = append(items, k8sCertManagerItem{Certificate: c, Cluster: cluster})
	}
	return items
}

func listClusterCertificates(ctx context.Context, c kubeClusterSource) ([]certmanager.Certificate, error) {
	if c.credErr != "" {
		return nil, fmt.Errorf("%s", c.credErr)
	}
	conn, err := newCertManagerConnectorForCluster(c)
	if err != nil {
		return nil, fmt.Errorf("connector init: %v", err)
	}
	certs, err := conn.ListCertificates(ctx)
	if err != nil {
		return nil, fmt.Errorf("list certificates: %v", err)
	}
	return certs, nil
}

func finishK8sCertManagerScan(finalize func(status, summary, errMsg string), jobID string, summary k8sCertManagerScanSummary, errMsg string) {
	summary.Certificates = len(summary.Items)
	if len(summary.Items) > k8sCertManagerScanMaxItems {
		summary.Items = summary.Items[:k8sCertManagerScanMaxItems]
	}
	raw, err := json.Marshal(summary)
	if err != nil {
		finalize("failed", "", fmt.Sprintf("summary marshal: %v", err))
		return
	}
	finalize("completed", string(raw), errMsg)
	logging.Infof("k8s-certmanager scan %s: %d certificates inventoried across %d cluster(s)", jobID, summary.Certificates, len(summary.Clusters))
}
