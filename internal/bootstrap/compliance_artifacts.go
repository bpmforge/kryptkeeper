// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"strings"

	"kryptkeeper/internal/keystore"
)

// W28-10: control-to-artifact index. Every compliance control carries the
// pass/fail rule the code applies and the evidence artifacts an auditor can
// pull to verify it. Artifact URLs are static routes that are themselves
// tenant-filtered; the only embedded data is KeyCustody, filtered by
// packKeyCustody.

// ControlArtifact points at one downloadable evidence artifact.
type ControlArtifact struct {
	Kind string `json:"kind"` // inventory_export | findings_export | audit_extract | custody_report | cbom | ca_health
	ID   string `json:"id"`
	URL  string `json:"url"`
}

var controlArtifactCatalog = map[string]ControlArtifact{
	"inventory_export": {"inventory_export", "inventory-export", "/api/v1/reports/export/inventory?format=csv"},
	"findings_export":  {"findings_export", "findings-export", "/api/v1/reports/export/findings?format=csv"},
	"audit_extract":    {"audit_extract", "audit-extract", "/api/v1/audit/export?format=csv"},
	"custody_report":   {"custody_report", "custody-report", "/api/v1/reports/key-custody"},
	"cbom":             {"cbom", "cbom", "/api/v1/cbom"},
	"ca_health":        {"ca_health", "ca-health", "/api/v1/reports/ca-health"},
}

type controlIndexEntry struct {
	rule      string
	artifacts []string
}

var controlIndex = map[string]controlIndexEntry{
	"SOC2-CC6.7":         {"pass: none expired, none expiring <30d, none unknown expiry; warn: none expired and <=10% expiring <30d; fail: otherwise", []string{"inventory_export", "audit_extract"}},
	"PCI-DSS-4.2.1.1":    {"pass: no WEAK_RSA_KEY/WEAK_EC_KEY certs; warn: <=5% of certs; fail: otherwise", []string{"inventory_export", "findings_export", "cbom"}},
	"NIST-800-57-3.6":    {"pass: no SHA-1/MD5 signatures and none valid >397d; warn: no SHA-1/MD5 signatures; fail: otherwise", []string{"findings_export", "cbom", "custody_report"}},
	"NIST-800-131A":      {"pass: no certs on sunset algorithms; warn: otherwise (never fails)", []string{"findings_export", "cbom"}},
	"DORA-Art9":          {"pass: no weak key/signature algorithms; warn: <=5% of certs; fail: otherwise", []string{"findings_export", "cbom"}},
	"DORA-Art10":         {"pass: every cert has a parseable expiry; warn: <=5% untracked; fail: otherwise", []string{"inventory_export", "audit_extract"}},
	"DORA-Art6":          {"pass: every cert has an owner; warn: at least half owned; fail: otherwise", []string{"inventory_export", "audit_extract"}},
	"NIS2-Art21-2h":      {"pass: no weak crypto and no PQC-vulnerable certs; warn: no weak crypto; fail: otherwise", []string{"cbom", "findings_export", "custody_report"}},
	"NIS2-Art21-2i":      {"pass: every cert has an owner; warn: at least half owned; fail: otherwise", []string{"inventory_export"}},
	"NIS2-Art23":         {"pass: every cert tracked; warn: some untracked (never fails while certs exist)", []string{"inventory_export", "audit_extract"}},
	"INTERNAL-CA-HEALTH": {"pass: at least one active CA; warn: otherwise (never fails)", []string{"ca_health"}},
	"FEDRAMP-SC-12":      {fedrampControlRules["FEDRAMP-SC-12"], []string{"custody_report", "cbom"}},
	"FEDRAMP-SC-13":      {fedrampControlRules["FEDRAMP-SC-13"], []string{"findings_export", "cbom"}},
	"FEDRAMP-SC-17":      {fedrampControlRules["FEDRAMP-SC-17"], []string{"inventory_export", "ca_health"}},
	"FEDRAMP-IA-5":       {fedrampControlRules["FEDRAMP-IA-5"], []string{"inventory_export", "audit_extract"}},
	"FEDRAMP-IA-5-2":     {fedrampControlRules["FEDRAMP-IA-5-2"], []string{"findings_export"}},
	"FEDRAMP-CM-8":       {fedrampControlRules["FEDRAMP-CM-8"], []string{"inventory_export"}},
}

// applyControlArtifactIndex sets Rule and Artifacts from controlIndex. An
// unknown control falls back to a generic rule and the inventory export so no
// control is ever emitted without a citation.
func applyControlArtifactIndex(c *ComplianceControl) {
	entry, ok := controlIndex[c.ID]
	if !ok {
		entry = controlIndexEntry{"see control evidence", []string{"inventory_export"}}
	}
	c.Rule = entry.rule
	c.Artifacts = make([]ControlArtifact, 0, len(entry.artifacts))
	for _, k := range entry.artifacts {
		c.Artifacts = append(c.Artifacts, controlArtifactCatalog[k])
	}
}

// packKeyCustody builds the custody section embedded in an evidence pack. It
// never errors: the note says why the section is empty. Non-admins get no
// custody data, and tenant-scoped principals only keys they provably own.
func packKeyCustody(ctx context.Context, pd AuthPrincipal, store keystore.Store, audit AuditProvider) (*KeyCustodyReport, string) {
	if store == nil {
		return nil, "no keystore is configured"
	}
	if !isAdminRole(pd.Role) {
		return nil, "key custody is restricted to administrators"
	}
	report, err := buildKeyCustodyReport(ctx, store, audit)
	if err != nil {
		return nil, "key custody evidence is unavailable"
	}
	if !tenantBypass(pd) {
		kept := make([]KeyCustodyEntry, 0, len(report.Keys))
		for _, k := range report.Keys {
			if keyVisibleToTenant(ctx, activeTenantStore, pd, k.KeyID) {
				kept = append(kept, k)
			}
		}
		report.Keys = kept
		report.EventCounts = countCustodyEvents(kept)
	}
	return &report, ""
}

// packCustodyLoader supplies custody evidence to packs rendered outside an
// HTTP request (scheduled and emailed packs). Assigned by
// registerReportsHandlers when a keystore is configured.
var packCustodyLoader func(ctx context.Context) (*KeyCustodyReport, string)

func loadPackCustody(ctx context.Context) (*KeyCustodyReport, string) {
	if packCustodyLoader == nil {
		return nil, "no keystore is configured"
	}
	return packCustodyLoader(ctx)
}

// frameworkIncludesFedramp reports whether the mapping notice applies.
func frameworkIncludesFedramp(framework string) bool {
	f := strings.ToLower(framework)
	return f == "fedramp" || f == "all"
}
