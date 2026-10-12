// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"
	"log"
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

func blastRadiusInventory(ctx context.Context, certProvider CertificateProvider) ([]CertificateItem, error) {
	result, err := listAllCertificates(ctx, certProvider, CertificateListQuery{})
	if err != nil {
		return nil, err
	}
	return result.Items, nil
}

// registerBlastRadiusHandler mounts the what-breaks-if simulation.
func registerBlastRadiusHandler(mux *http.ServeMux, auth *Authenticator, certProvider CertificateProvider, auditProvider AuditProvider) {
	mux.HandleFunc("/api/v1/blast-radius", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		principal, err := auth.AuthenticatePrincipal(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "blast_radius.simulate", "simulation", "blast-radius", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}

		action := strings.TrimSpace(r.URL.Query().Get("action"))
		target := strings.TrimSpace(r.URL.Query().Get("target"))
		if target == "" {
			writeBadRequest(w, "target is required")
			return
		}

		items, err := blastRadiusInventory(r.Context(), certProvider)
		if err != nil {
			emitAuditEvent(r, auditProvider, principal, "blast_radius.simulate", "simulation", "blast-radius", AuditOutcomeFailure)
			log.Printf("blast radius: list certs: %v", err)
			writeServiceUnavailable(w, "inventory unavailable")
			return
		}
		graph := buildBlastRadiusGraph(items)

		var impact blastradius.Impact
		switch action {
		case "revoke":
			impact = graph.SimulateRevoke(target)
		case "retire_ca":
			impact = graph.SimulateRetireCA(target)
		case "deprecate_algorithm":
			impact = graph.SimulateDeprecateAlgorithm(target)
		default:
			writeBadRequest(w, "action must be revoke, retire_ca or deprecate_algorithm")
			return
		}

		emitAuditEventDetail(r, auditProvider, principal, "blast_radius.simulate", "simulation", "blast-radius", AuditOutcomeSuccess,
			fmt.Sprintf(`{"action":%q,"target":%q,"affected":%d,"severity":%q}`, action, target, impact.TotalAffected, impact.Severity))

		affected := map[string][]string{}
		for kind, ids := range impact.AffectedByKind {
			affected[string(kind)] = ids
		}
		writeJSONData(w, map[string]any{
			"action":           action,
			"target":           impact.Target,
			"total_affected":   impact.TotalAffected,
			"severity":         impact.Severity,
			"affected_by_kind": affected,
			"graph_size":       strconv.Itoa(len(items)) + " certificates",
		})
	})
}
