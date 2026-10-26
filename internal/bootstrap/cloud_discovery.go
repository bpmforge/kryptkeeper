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
	"time"

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
	// Scopes is the per-scope outcome of a W24-17 fan-out; empty on the
	// legacy single-connector path.
	Scopes []cloudScopeSummary `json:"scopes"`
	// Import is what the scan did to the certificate inventory (W38-05).
	Import *cloudImportSummary `json:"import,omitempty"`
}

type cloudScopeSummary struct {
	Scope        string `json:"scope"`
	Certificates int    `json:"certificates"`
	Error        string `json:"error,omitempty"`
}

// cloudProviderForScanType maps a scan type to its Scope provider.
func cloudProviderForScanType(scanType string) string {
	switch scanType {
	case scanTypeCloudACM:
		return cloudinventory.ProviderAWSACM
	case scanTypeCloudAzureKV:
		return cloudinventory.ProviderAzureKeyVault
	case scanTypeCloudGCPCM:
		return cloudinventory.ProviderGCPCertManager
	}
	return ""
}

// loadCloudScopes reads discovery.cloud_scopes (config store, else env
// KRYPTKEEPER_CLOUD_SCOPES): a JSON array of Scope. Package var so tests inject.
var loadCloudScopes = func(ctx context.Context) ([]cloudinventory.Scope, error) {
	cfg, _ := sharedDiscoveryStores.get()
	return parseCloudScopes(discoveryConfigValueFrom(ctx, cfg, "discovery.cloud_scopes"))
}

func parseCloudScopes(raw string) ([]cloudinventory.Scope, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var scopes []cloudinventory.Scope
	if err := json.Unmarshal([]byte(raw), &scopes); err != nil {
		return nil, fmt.Errorf("not a valid JSON array of scopes")
	}
	for _, sc := range scopes {
		if err := sc.Validate(); err != nil {
			return nil, err
		}
	}
	return scopes, nil
}

// newCloudScopeConnector builds the connector for one scope; package var so
// tests inject fakes.
var newCloudScopeConnector = func(ctx context.Context, s cloudinventory.Scope) (cloudConnector, error) {
	switch s.Provider {
	case cloudinventory.ProviderAWSACM:
		return cloudinventory.NewACMConnectorForScope(ctx, s)
	case cloudinventory.ProviderAzureKeyVault:
		return cloudinventory.NewAzureKVConnectorForScope(ctx, s)
	case cloudinventory.ProviderGCPCertManager:
		return cloudinventory.NewGCPCertManagerConnectorForScope(ctx, s)
	}
	return nil, fmt.Errorf("unknown cloud provider %q", s.Provider)
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
			logging.Warnf("cloud scan %s: finalize failed: %v", jobID, err)
		}
	}

	scopes, err := loadCloudScopes(ctx)
	if err != nil {
		finalize("failed", "", fmt.Sprintf("scope config: %v", err))
		return
	}
	provider := cloudProviderForScanType(scanType)
	var mine []cloudinventory.Scope
	for _, sc := range scopes {
		if sc.Provider == provider {
			mine = append(mine, sc)
		}
	}
	if len(mine) > 0 {
		runCloudScopeFanOut(ctx, db, postgres, finalize, jobID, scanType, mine)
		return
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
	imp := importScanResults(ctx, db, postgres, jobID, certs, []string{cloudScopeKeyLegacy(provider)}, provider)
	summary.Import = &imp
	finalizeCloudSummary(finalize, jobID, summary, "completed", "")
}

// importScanResults imports a finished scan's certificates under the tenant
// that owns the job. An import failure is reported in the summary and never
// fails the scan: the listing itself succeeded.
func importScanResults(ctx context.Context, db *sql.DB, postgres bool, jobID string, certs []cloudinventory.CloudCertificate, sweep []string, provider string) cloudImportSummary {
	var tenant string
	q := "SELECT COALESCE(tenant, '') FROM scan_jobs WHERE id = ?"
	if postgres {
		q = "SELECT COALESCE(tenant, '') FROM scan_jobs WHERE id = $1"
	}
	if err := db.QueryRowContext(ctx, q, jobID).Scan(&tenant); err != nil {
		return cloudImportSummary{Failed: []string{fmt.Sprintf("scan tenant: %v", err)}}
	}
	return importCloudCertificates(ctx, db, postgres, tenant, certs, sweep, provider, time.Now())
}

// runCloudScopeFanOut scans every configured scope; one failing scope only
// fails its own result. Messages carry scope keys and provider errors, never
// credentials.
func runCloudScopeFanOut(ctx context.Context, db *sql.DB, postgres bool, finalize func(status, summary, errMsg string), jobID, scanType string, scopes []cloudinventory.Scope) {
	results := cloudinventory.FanOut(ctx, scopes, func(c context.Context, s cloudinventory.Scope) (cloudinventory.Lister, error) {
		return newCloudScopeConnector(c, s)
	}, 0)
	merged := cloudinventory.MergeUnique(results)
	summary := cloudScanSummary{Provider: scanType, Certificates: len(merged), Items: merged}
	var failed []string
	for _, r := range results {
		row := cloudScopeSummary{Scope: r.Scope.Key(), Certificates: len(r.Certs), Error: r.Err}
		summary.Scopes = append(summary.Scopes, row)
		if r.Err != "" {
			failed = append(failed, row.Scope+": "+r.Err)
		}
	}
	status, errMsg := "completed", ""
	switch {
	case len(failed) == len(results):
		status, errMsg = "failed", fmt.Sprintf("%d of %d scopes failed: %s", len(failed), len(results), strings.Join(failed, "; "))
	case len(failed) > 0:
		status, errMsg = scanStatusCompletedWithErrors, fmt.Sprintf("%d of %d scopes failed: %s", len(failed), len(results), strings.Join(failed, "; "))
	}
	// Only scopes that answered are swept: silence from a scope is not
	// evidence its certificates are gone. The legacy key is swept too so a hub
	// that moves to configured scopes retires its old single-connector links.
	provider := cloudProviderForScanType(scanType)
	sweep := []string{cloudScopeKeyLegacy(provider)}
	for _, r := range results {
		if r.Err == "" {
			sweep = append(sweep, r.Scope.Key())
		}
	}
	if db != nil && len(failed) < len(results) {
		imp := importScanResults(ctx, db, postgres, jobID, merged, sweep, provider)
		summary.Import = &imp
	}
	finalizeCloudSummary(finalize, jobID, summary, status, errMsg)
}

func finalizeCloudSummary(finalize func(status, summary, errMsg string), jobID string, summary cloudScanSummary, status, errMsg string) {
	if len(summary.Items) > cloudScanMaxItems {
		summary.Items = summary.Items[:cloudScanMaxItems]
	}
	raw, err := json.Marshal(summary)
	if err != nil {
		finalize("failed", "", fmt.Sprintf("summary marshal: %v", err))
		return
	}
	finalize(status, string(raw), errMsg)
	logging.Infof("cloud scan %s (%s): %d certificates inventoried, status %s", jobID, summary.Provider, summary.Certificates, status)
}
