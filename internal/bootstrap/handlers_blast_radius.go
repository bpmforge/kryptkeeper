// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"
	"kryptkeeper/internal/logging"
	"net/http"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/blastradius"
)

// W17-05: the W16-02 blast-radius graph, wired.
//
// Answering "what breaks if I revoke this / retire that CA / disallow
// RSA-2048 in 2030" BEFORE acting is the pre-flight incumbents leave
// manual. The engine shipped complete with zero importers; this builds
// the graph from the live inventory and exposes the simulations.

// algorithmNodeID names an algorithm node as algorithm+size ("RSA-2048"),
// because deprecation deadlines are written against a key size, not a
// bare family — "RSA is disallowed" is not a policy anyone can act on.
func algorithmNodeID(algorithm string, bits int) string {
	a := strings.TrimSpace(algorithm)
	if a == "" {
		return ""
	}
	if bits > 0 {
		return fmt.Sprintf("%s-%d", a, bits)
	}
	return a
}

// buildBlastRadiusGraph derives the dependency graph from the live
// certificate inventory.
//
// Edges are DEPENDENT->DEPENDENCY:
//   - a certificate depends on its issuing CA and on its algorithm
//   - a service (each SAN) depends on the certificate that serves it
//
// SANs stand in for services because they are the names clients actually
// resolve, so the service count drives severity honestly. Discovered
// endpoints (ip:port) would refine this further and are a disclosed
// follow-up — they need the discovery join, not this graph.
func buildBlastRadiusGraph(items []CertificateItem) *blastradius.Graph {
	g := blastradius.NewGraph()
	for _, cert := range items {
		fp := cert.FingerprintSHA256
		if fp == "" {
			continue
		}
		g.AddNode(blastradius.KindCert, fp)
		if caID := strings.TrimSpace(cert.CAID); caID != "" {
			g.AddDependency(blastradius.KindCert, fp, blastradius.KindCA, caID)
		}
		if algo := algorithmNodeID(cert.PublicKeyAlgorithm, cert.KeySizeBits); algo != "" {
			g.AddDependency(blastradius.KindCert, fp, blastradius.KindAlgorithm, algo)
		}
		names := append([]string{}, cert.SubjectAltNames...)
		if cn := strings.TrimSpace(cert.CommonName); cn != "" {
			names = append(names, cn)
		}
		seen := map[string]bool{}
		for _, name := range names {
			n := strings.TrimSpace(name)
			if n == "" || seen[n] {
				continue
			}
			seen[n] = true
			g.AddDependency(blastradius.KindService, n, blastradius.KindCert, fp)
		}
	}
	return g
}

// blastRadiusEdgeBasis states what the service edges are made of, so a clean
// result is never read as "nothing else depends on this".
const blastRadiusEdgeBasis = "services are derived from certificate SANs and common names; discovered endpoints are not joined"

// addCAEdges makes a child CA depend on its parent, so retiring the parent
// reaches the child CA, its certs and their services (the chain).
func addCAEdges(g *blastradius.Graph, cas []CAListItem) {
	for _, c := range cas {
		if c.ParentCAID == nil || strings.TrimSpace(*c.ParentCAID) == "" || c.ID == "" {
			continue
		}
		g.AddDependency(blastradius.KindCA, c.ID, blastradius.KindCA, strings.TrimSpace(*c.ParentCAID))
	}
}

func buildBlastRadiusGraphWithCAs(items []CertificateItem, cas []CAListItem) *blastradius.Graph {
	g := buildBlastRadiusGraph(items)
	addCAEdges(g, cas)
	return g
}

func blastRadiusInventory(ctx context.Context, certProvider CertificateProvider) ([]CertificateItem, error) {
	result, err := listAllCertificates(ctx, certProvider, CertificateListQuery{})
	if err != nil {
		return nil, err
	}
	return result.Items, nil
}

func blastRadiusNodeKind(action string) (blastradius.NodeKind, bool) {
	switch action {
	case "revoke":
		return blastradius.KindCert, true
	case "retire_ca":
		return blastradius.KindCA, true
	case "deprecate_algorithm":
		return blastradius.KindAlgorithm, true
	}
	return "", false
}

// registerBlastRadiusHandler mounts the what-breaks-if simulation. caProvider
// may be nil (cert-only edges).
func registerBlastRadiusHandler(mux *http.ServeMux, auth *Authenticator, certProvider CertificateProvider, caProvider CAProvider, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/blast-radius", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "blast_radius.simulate", "simulation", "blast-radius", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		principal := pd.ID

		action := strings.TrimSpace(r.URL.Query().Get("action"))
		target := strings.TrimSpace(r.URL.Query().Get("target"))
		if target == "" {
			writeBadRequest(w, "target is required")
			return
		}
		kind, ok := blastRadiusNodeKind(action)
		if !ok {
			writeBadRequest(w, "action must be revoke, retire_ca or deprecate_algorithm")
			return
		}

		fail := func(outcome AuditOutcome) {
			emitAuditEvent(r, auditProvider, principal, "blast_radius.simulate", "simulation", "blast-radius", outcome)
		}

		items, err := blastRadiusInventory(r.Context(), certProvider)
		if err != nil {
			fail(AuditOutcomeFailure)
			logging.Infof("blast radius: list certs: %v", err)
			writeServiceUnavailable(w, "inventory unavailable")
			return
		}
		var cas []CAListItem
		if caProvider != nil {
			list, lerr := caProvider.ListCAs(r.Context(), CAListQuery{Limit: 1000})
			if lerr != nil {
				// Degrade to cert-only edges rather than refuse a pre-flight.
				logging.Infof("blast radius: list CAs, falling back to cert-only edges: %v", lerr)
			} else {
				cas = list.Items
			}
		}
		bypass := tenantBypass(pd)
		full := buildBlastRadiusGraphWithCAs(items, cas)

		// 404 for targets absent everywhere; a target that exists in another
		// tenant is 403 (decided on the unfiltered graph). Algorithms carry no
		// tenant, so for scoped principals their existence is judged on the
		// filtered graph below.
		exists := full.HasNode(kind, target)
		if !exists && kind == blastradius.KindCA && caProvider != nil {
			// A real CA with no certs is a valid, zero-impact simulation.
			_, found, gerr := caProvider.GetCA(r.Context(), target)
			if gerr != nil {
				fail(AuditOutcomeFailure)
				logging.Infof("blast radius: get CA: %v", gerr)
				writeServiceUnavailable(w, "ca unavailable")
				return
			}
			exists = found
		}
		if !exists {
			fail(AuditOutcomeFailure)
			writeNotFound(w, "target not found")
			return
		}

		if !bypass {
			switch kind {
			case blastradius.KindCert:
				for _, it := range items {
					if it.FingerprintSHA256 == target && !caVisibleToTenant(r.Context(), activeTenantStore, pd, it.CAID) {
						fail(AuditOutcomeDenied)
						writeForbidden(w, "forbidden")
						return
					}
				}
			case blastradius.KindCA:
				if !caVisibleToTenant(r.Context(), activeTenantStore, pd, target) {
					fail(AuditOutcomeDenied)
					writeForbidden(w, "forbidden")
					return
				}
			}
		}

		graph := full
		if !bypass {
			// A tenant must not learn another tenant's certs/services through a
			// shared algorithm or parent CA.
			scopedItems := filterCertificatesByTenant(r.Context(), activeTenantStore, pd, items)
			scopedCAs := filterCAsByTenant(r.Context(), activeTenantStore, pd, cas)
			graph = buildBlastRadiusGraphWithCAs(scopedItems, scopedCAs)
			items = scopedItems
			if kind == blastradius.KindAlgorithm && !graph.HasNode(kind, target) {
				fail(AuditOutcomeFailure)
				writeNotFound(w, "target not found")
				return
			}
		}

		var impact blastradius.Impact
		switch kind {
		case blastradius.KindCert:
			impact = graph.SimulateRevoke(target)
		case blastradius.KindCA:
			impact = graph.SimulateRetireCA(target)
		default:
			impact = graph.SimulateDeprecateAlgorithm(target)
		}

		emitAuditEventDetail(r, auditProvider, principal, "blast_radius.simulate", "simulation", "blast-radius", AuditOutcomeSuccess,
			fmt.Sprintf(`{"action":%q,"target":%q,"affected":%d,"severity":%q}`, action, target, impact.TotalAffected, impact.Severity))

		affected := map[string][]string{}
		for k, ids := range impact.AffectedByKind {
			affected[string(k)] = ids
		}
		cov := graph.Coverage()
		writeJSONData(w, map[string]any{
			"action":           action,
			"target":           impact.Target,
			"total_affected":   impact.TotalAffected,
			"severity":         impact.Severity,
			"affected_by_kind": affected,
			"graph_size":       strconv.Itoa(len(items)) + " certificates",
			"edge_coverage": map[string]any{
				"certs_total":             cov.CertsTotal,
				"certs_with_ca_edge":      cov.CertsWithCAEdge,
				"certs_with_service_edge": cov.CertsWithServiceEdge,
				"basis":                   blastRadiusEdgeBasis,
			},
		})
	})
}
