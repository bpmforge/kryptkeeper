// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strings"
)

// auditNameSources are the providers GET /api/v1/audit uses to attach a
// human-readable resource_name to each row. Every field is optional: a nil
// source simply leaves that resource type unresolved.
//
// The stored audit record is never touched (CLAUDE.md: append-only): names
// are resolved at read time, so a renamed or deleted resource shows its
// current name or none, while resource_id stays the authoritative reference.
type auditNameSources struct {
	certs     CertificateProvider
	cas       CAProvider
	templates TemplateProvider
	approvals ApprovalStore
	notifs    NotificationProvider
	discovery DiscoveryProvider
}

// auditEntryView is an AuditEntry plus the read-time-only resource_name.
type auditEntryView struct {
	AuditEntry
	ResourceName string `json:"resource_name,omitempty"`
}

// maxAuditNameLookups bounds per-row provider lookups per request; the page
// limit is 100 so this is only a guard.
const maxAuditNameLookups = 200

// resolveAuditNames returns the entries as views with ResourceName filled in
// where it can be resolved AND the caller may read the underlying resource
// (same team/tenant checks the resource's own endpoints apply). Lookups are
// deduplicated per request; unresolvable rows keep an empty name.
func (s auditNameSources) resolveAuditNames(ctx context.Context, pd AuthPrincipal, entries []AuditEntry) []auditEntryView {
	out := make([]auditEntryView, len(entries))
	cache := map[string]string{}
	lookups := 0
	// Lists are fetched at most once per request, lazily.
	var caNames, tplNames, ruleNames, scanNames map[string]string

	for i, e := range entries {
		out[i] = auditEntryView{AuditEntry: e}
		id := strings.TrimSpace(e.ResourceID)
		if id == "" {
			continue
		}
		key := e.ResourceType + "\x00" + id
		if name, ok := cache[key]; ok {
			out[i].ResourceName = name
			continue
		}
		name := ""
		switch e.ResourceType {
		case "certificate":
			if s.certs != nil && lookups < maxAuditNameLookups {
				lookups++
				if item, err := authorizeCertificateResourceAccess(ctx, s.certs, pd, id); err == nil {
					name = strings.TrimSpace(item.CommonName)
				}
			}
		case "ca":
			if s.cas != nil {
				if caNames == nil {
					caNames = s.caNameMap(ctx, pd)
				}
				name = caNames[id]
			}
		case "template":
			if s.templates != nil {
				if tplNames == nil {
					tplNames = s.templateNameMap(ctx, pd)
				}
				name = tplNames[id]
			}
		case "approval":
			if s.approvals != nil && lookups < maxAuditNameLookups {
				lookups++
				if tplNames == nil {
					tplNames = s.templateNameMap(ctx, pd)
				}
				name = s.approvalName(ctx, pd, id, tplNames)
			}
		case "notification":
			if s.notifs != nil && canReadOperationalSummaries(pd) {
				if ruleNames == nil {
					ruleNames = map[string]string{}
					if rules, err := s.notifs.ListRules(ctx); err == nil {
						for _, r := range rules {
							ruleNames[r.ID] = strings.TrimSpace(r.Name)
						}
					}
				}
				name = ruleNames[id]
			}
		case "discovery":
			if s.discovery != nil && canReadOperationalSummaries(pd) {
				if scanNames == nil {
					scanNames = map[string]string{}
					// Scan jobs have no get-by-id; one capped page covers recent scans.
					if res, err := s.discovery.ListScanJobs(ctx, DiscoveryScanJobQuery{Limit: 100}); err == nil {
						for _, j := range res.ScanJobs {
							scanNames[j.ID] = strings.TrimSpace(j.Target)
						}
					}
				}
				name = scanNames[id]
			}
		}
		cache[key] = name
		out[i].ResourceName = name
	}
	return out
}

func (s auditNameSources) caNameMap(ctx context.Context, pd AuthPrincipal) map[string]string {
	m := map[string]string{}
	res, err := s.cas.ListCAs(ctx, CAListQuery{})
	if err != nil {
		return m
	}
	for _, c := range filterCAsByTenant(ctx, activeTenantStore, pd, res.Items) {
		n := strings.TrimSpace(c.DisplayName)
		if n == "" {
			n = strings.TrimSpace(c.Name)
		}
		m[c.ID] = n
	}
	return m
}

func (s auditNameSources) templateNameMap(ctx context.Context, pd AuthPrincipal) map[string]string {
	m := map[string]string{}
	if s.templates == nil {
		return m
	}
	res, err := s.templates.ListTemplates(ctx, TemplateListQuery{})
	if err != nil {
		return m
	}
	for _, t := range filterTemplatesByTenant(ctx, activeTenantStore, pd, res.Items) {
		n := strings.TrimSpace(t.DisplayName)
		if n == "" {
			n = strings.TrimSpace(t.Name)
		}
		m[t.ID] = n
	}
	return m
}

// approvalName is "<template> for <CN or requester>", gated like the
// approvals list: non-admins only see their own requests, tenant-scoped by CA.
func (s auditNameSources) approvalName(ctx context.Context, pd AuthPrincipal, id string, tplNames map[string]string) string {
	apr, err := s.approvals.Get(ctx, id)
	if err != nil {
		return ""
	}
	if !isAdminRole(pd.Role) && apr.Requester != pd.ID {
		return ""
	}
	if len(filterApprovalsByTenant(ctx, activeTenantStore, pd, []ApprovalRequest{apr})) == 0 {
		return ""
	}
	who := csrCommonName(apr.CSRPEM)
	if who == "" {
		who = apr.Requester
	}
	tpl := tplNames[apr.TemplateID]
	switch {
	case tpl != "" && who != "":
		return tpl + " for " + who
	case who != "":
		return "Approval for " + who
	default:
		return tpl
	}
}

func csrCommonName(csrPEM string) string {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return ""
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(csr.Subject.CommonName)
}
