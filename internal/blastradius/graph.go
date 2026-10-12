// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package blastradius links certificates to what depends on them and
// answers "what breaks if…" BEFORE a revoke, CA retirement, or
// algorithm deprecation executes (W16-02). Operators cause the 83%
// outage stat because they cannot see consequences before acting; this
// makes the blast radius a pre-flight fact. Pure graph, no dependency.
package blastradius

import (
	"sort"
	"strings"
)

// NodeKind classifies a node in the dependency graph.
type NodeKind string

const (
	KindCert      NodeKind = "cert"
	KindEndpoint  NodeKind = "endpoint"
	KindService   NodeKind = "service"
	KindKey       NodeKind = "key"
	KindCA        NodeKind = "ca"
	KindAlgorithm NodeKind = "algorithm"
)

// nodeID is the internal "kind:id" key.
func nodeID(kind NodeKind, id string) string { return string(kind) + ":" + id }

// Graph is a dependency graph. Edges point DEPENDENT→DEPENDENCY, so
// breaking a node propagates downstream to its transitive dependents.
type Graph struct {
	kinds      map[string]NodeKind // nodeID -> kind
	dependents map[string][]string // dependency nodeID -> dependent nodeIDs
}

func NewGraph() *Graph {
	return &Graph{kinds: map[string]NodeKind{}, dependents: map[string][]string{}}
}

func (g *Graph) addNode(kind NodeKind, id string) string {
	nid := nodeID(kind, id)
	g.kinds[nid] = kind
	return nid
}

// AddDependency records that `dependent` needs `dependency`: if the
// dependency breaks, the dependent is in the blast radius.
func (g *Graph) AddDependency(depKind NodeKind, depID string, needsKind NodeKind, needsID string) {
	dep := g.addNode(depKind, depID)
	needs := g.addNode(needsKind, needsID)
	g.dependents[needs] = append(g.dependents[needs], dep)
}

// Impact is one simulation's result.
type Impact struct {
	Target         string                `json:"target"`
	AffectedByKind map[NodeKind][]string `json:"affected_by_kind"`
	TotalAffected  int                   `json:"total_affected"`
	Severity       string                `json:"severity"` // none|low|medium|high|critical
}

// simulate returns the transitive dependents of the target node. BFS
// with a visited set — a cyclic dependency cannot hang the pre-flight.
func (g *Graph) simulate(targetNodeID string) Impact {
	visited := map[string]bool{targetNodeID: true}
	byKind := map[NodeKind][]string{}
	queue := []string{targetNodeID}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, dep := range g.dependents[cur] {
			if visited[dep] {
				continue
			}
			visited[dep] = true
			queue = append(queue, dep)
			kind := g.kinds[dep]
			// Strip the "kind:" prefix for the reported id.
			byKind[kind] = append(byKind[kind], strings.TrimPrefix(dep, string(kind)+":"))
		}
	}
	total := 0
	for k := range byKind {
		sort.Strings(byKind[k])
		total += len(byKind[k])
	}
	return Impact{
		Target:         targetNodeID,
		AffectedByKind: byKind,
		TotalAffected:  total,
		Severity:       severityFromServices(len(byKind[KindService])),
	}
}

// severityFromServices rates blast radius by the number of business-
// facing services affected — the consequence an approver cares about.
func severityFromServices(services int) string {
	switch {
	case services == 0:
		return "none"
	case services <= 2:
		return "low"
	case services <= 5:
		return "medium"
	case services <= 20:
		return "high"
	default:
		return "critical"
	}
}

// SimulateRevoke reports what breaks if a certificate is revoked.
func (g *Graph) SimulateRevoke(certFP string) Impact {
	return g.simulate(nodeID(KindCert, certFP))
}

// SimulateRetireCA reports what breaks if a CA is retired — every
// certificate it issued and their downstream.
func (g *Graph) SimulateRetireCA(caID string) Impact {
	return g.simulate(nodeID(KindCA, caID))
}

// SimulateDeprecateAlgorithm reports what breaks when an algorithm is
// disallowed — every cert/key on it and their downstream. This is the
// PQC migration planning question ("what breaks when RSA-2048 is
// disallowed in 2030") as a query.
func (g *Graph) SimulateDeprecateAlgorithm(algorithm string) Impact {
	return g.simulate(nodeID(KindAlgorithm, algorithm))
}
