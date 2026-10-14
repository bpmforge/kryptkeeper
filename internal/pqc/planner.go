// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package pqc

import (
	"sort"
	"strconv"
	"time"
)

// MigrationPriority classifies urgency of PQC migration.
type MigrationPriority string

const (
	PriorityCritical MigrationPriority = "critical" // long-lived + harvest-now-decrypt-later risk
	PriorityHigh     MigrationPriority = "high"     // >1 year validity, classical algo
	PriorityMedium   MigrationPriority = "medium"   // short-lived but classical
	PriorityLow      MigrationPriority = "low"      // already migration_ready or quantum_safe
)

// CertRecord is a certificate record for PQC migration analysis.
type CertRecord struct {
	Fingerprint   string    `json:"fingerprint"`
	CommonName    string    `json:"common_name"`
	Algorithm     string    `json:"algorithm"`
	KeySize       int       `json:"key_size"`
	ValidFrom     time.Time `json:"valid_from"`
	ValidUntil    time.Time `json:"valid_until"`
	PQCReadiness  string    `json:"pqc_readiness"`
	IsCA          bool      `json:"is_ca"`
	AutoRenewable bool      `json:"auto_renewable"`
	// HNDL (harvest-now-decrypt-later) signals.
	IsCodeSigning bool `json:"is_code_signing"` // long-lived trust anchor
	SANCount      int  `json:"san_count"`       // breadth of exposure
}

// MigrationItem is a single entry in the migration roadmap.
type MigrationItem struct {
	Fingerprint string            `json:"fingerprint"`
	CommonName  string            `json:"common_name"`
	Priority    MigrationPriority `json:"priority"`
	Reason      string            `json:"reason"`
	Action      string            `json:"action"`
	Deadline    time.Time         `json:"deadline"`
}

// MigrationRoadmap is the PQC migration plan output.
type MigrationRoadmap struct {
	GeneratedAt         time.Time       `json:"generated_at"`
	TotalCerts          int             `json:"total_certs"`
	Vulnerable          int             `json:"vulnerable"`
	MigrationReady      int             `json:"migration_ready"`
	QuantumSafe         int             `json:"quantum_safe"`
	QuantumSafeLeafOnly int             `json:"quantum_safe_leaf_only"` // G-70/D-104: leaf key is PQC, issuing chain is still classical (mirrors bootstrap.pqcReadinessLeafOnly)
	NotApplicable       int             `json:"not_applicable"`
	PQCScorePercent     int             `json:"pqc_score_percent"`    // see ReadinessTally
	QuantumSafePercent  int             `json:"quantum_safe_percent"` // see ReadinessTally
	Items               []MigrationItem `json:"items"`
}

// Planner generates PQC migration roadmaps from certificate inventory.
type Planner struct {
	pqcDeadline time.Time // CNSA 2.0 mandate: 2030
}

// NewPlanner creates a PQC migration planner.
func NewPlanner(pqcDeadline time.Time) *Planner {
	if pqcDeadline.IsZero() {
		pqcDeadline = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	return &Planner{pqcDeadline: pqcDeadline}
}

// GenerateRoadmap analyzes certificates and produces a prioritized migration plan.
func (p *Planner) GenerateRoadmap(certs []CertRecord) MigrationRoadmap {
	roadmap := MigrationRoadmap{
		GeneratedAt: time.Now().UTC(),
		TotalCerts:  len(certs),
	}

	var tally ReadinessTally
	for _, cert := range certs {
		tally.Add(cert.PQCReadiness)
		switch cert.PQCReadiness {
		case ReadinessQuantumSafe, ReadinessHybrid:
			continue
		case ReadinessLeafOnly:
			// Leaf key is already PQC (G-70/D-104) -- no roadmap action for
			// THIS cert; chain-level PQC needs CA rotation, out of this
			// planner's per-cert scope.
			continue
		}

		item := p.classifyCert(cert)
		roadmap.Items = append(roadmap.Items, item)
	}

	tally.Finalize(len(certs))
	roadmap.QuantumSafe = tally.QuantumSafe
	roadmap.QuantumSafeLeafOnly = tally.QuantumSafeLeafOnly
	roadmap.MigrationReady = tally.MigrationReady
	roadmap.Vulnerable = tally.Vulnerable
	roadmap.NotApplicable = tally.NotApplicable
	roadmap.PQCScorePercent = tally.PQCScorePercent
	roadmap.QuantumSafePercent = tally.QuantumSafePercent

	sort.Slice(roadmap.Items, func(i, j int) bool {
		return priorityOrder(roadmap.Items[i].Priority) < priorityOrder(roadmap.Items[j].Priority)
	})

	return roadmap
}

func (p *Planner) classifyCert(cert CertRecord) MigrationItem {
	validity := cert.ValidUntil.Sub(cert.ValidFrom)
	item := MigrationItem{
		Fingerprint: cert.Fingerprint,
		CommonName:  cert.CommonName,
		Deadline:    p.pqcDeadline,
	}

	if cert.IsCA {
		item.Priority = PriorityCritical
		item.Reason = "CA certificate — compromises entire chain if quantum-broken"
		item.Action = "Plan CA key ceremony with ML-DSA algorithm; issue new CA cert; cross-sign for transition"
		return item
	}

	if cert.IsCodeSigning {
		item.Priority = PriorityCritical
		item.Reason = "Code-signing certificate — signatures are long-lived trust anchors; a quantum break enables forged software signatures (harvest-now-forge-later)"
		item.Action = "Migrate to ML-DSA code-signing ahead of CNSA 2.0 (2030); re-sign critical artifacts"
		return item
	}

	if validity > 365*24*time.Hour {
		item.Priority = PriorityHigh
		item.Reason = "Long-lived certificate (>1 year) with classical algorithm — harvest-now-decrypt-later risk"
		if cert.SANCount > 25 {
			item.Reason += "; broad SAN exposure (" + strconv.Itoa(cert.SANCount) + " names)"
		}
		item.Action = "Reduce validity period or migrate to ML-DSA at next renewal"
		return item
	}

	if cert.AutoRenewable {
		item.Priority = PriorityLow
		item.Reason = "Short-lived, auto-renewable — will rotate naturally before PQC deadline"
		item.Action = "Update ACME/EST enrollment to request ML-DSA when available; no immediate action"
		return item
	}

	item.Priority = PriorityMedium
	item.Reason = "Classical algorithm, manual renewal — plan migration before PQC deadline"
	item.Action = "Schedule renewal with ML-DSA algorithm before " + p.pqcDeadline.Format("2006-01-02")
	return item
}

func priorityOrder(p MigrationPriority) int {
	switch p {
	case PriorityCritical:
		return 0
	case PriorityHigh:
		return 1
	case PriorityMedium:
		return 2
	case PriorityLow:
		return 3
	default:
		return 4
	}
}
