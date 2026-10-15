// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/certmanager"
	"kryptkeeper/internal/discovery/scanner"
)

// scannerDiscoveryProvider wraps the real network scanner behind the DiscoveryProvider interface.
// It is the minimal in-memory mode (APP_DISCOVERY_PROVIDER=scanner), not the
// default: port 443 only, scan_type and custom ports ignored, nothing
// persisted, no flags or posture. The full-featured provider is "db".
type scannerDiscoveryProvider struct {
	scanner *scanner.Scanner
	mu      sync.RWMutex
	// In-memory storage of scan results — production uses DB.
	endpoints []DiscoveryEndpoint
	scanJobs  []DiscoveryScanJob
}

// NewScannerDiscoveryProvider creates a discovery provider backed by the real scanner.
func NewScannerDiscoveryProvider(defaultTargets []string, concurrency int) DiscoveryProvider {
	s := scanner.New(scanner.ScanConfig{
		Targets:     defaultTargets,
		Concurrency: concurrency,
		Timeout:     10 * time.Second,
	})
	return &scannerDiscoveryProvider{scanner: s}
}

func (p *scannerDiscoveryProvider) GetSummary(_ context.Context) (DiscoverySummary, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	risky := 0
	for _, ep := range p.endpoints {
		if endpointIsRisky(ep) {
			risky++
		}
	}
	active := 0
	for _, j := range p.scanJobs {
		if j.Status == "running" || j.Status == "queued" {
			active++
		}
	}
	return DiscoverySummary{
		DiscoveredEndpoints: len(p.endpoints),
		RiskyEndpoints:      risky,
		ActiveScanJobs:      active,
	}, nil
}

func (p *scannerDiscoveryProvider) ListEndpoints(_ context.Context, q DiscoveryEndpointQuery) (DiscoveryEndpointResult, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	filtered := make([]DiscoveryEndpoint, 0, len(p.endpoints))
	for _, ep := range p.endpoints {
		if q.Protocol != "" && !strings.EqualFold(ep.Protocol, q.Protocol) {
			continue
		}
		ep.Risky = endpointIsRisky(ep)
		if q.RiskyOnly && !ep.Risky {
			continue
		}
		filtered = append(filtered, ep)
	}
	result := paginate(filtered, q.Limit, q.Cursor, 25, 100)
	return DiscoveryEndpointResult{
		Endpoints:  result.Items,
		Total:      result.Total,
		Limit:      result.Limit,
		NextCursor: result.NextCursor,
		PrevCursor: result.PrevCursor,
	}, nil
}

func (p *scannerDiscoveryProvider) ListScanJobs(_ context.Context, q DiscoveryScanJobQuery) (DiscoveryScanJobResult, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	filtered := make([]DiscoveryScanJob, 0, len(p.scanJobs))
	for _, j := range p.scanJobs {
		if q.Status != "" && !strings.EqualFold(j.Status, q.Status) {
			continue
		}
		filtered = append(filtered, j)
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].QueuedAt > filtered[j].QueuedAt })
	result := paginate(filtered, q.Limit, q.Cursor, 25, 100)
	return DiscoveryScanJobResult{
		ScanJobs:   result.Items,
		Total:      result.Total,
		Limit:      result.Limit,
		NextCursor: result.NextCursor,
		PrevCursor: result.PrevCursor,
	}, nil
}

func (p *scannerDiscoveryProvider) CreateScan(ctx context.Context, scanType string, target string, extraPorts []int) (DiscoveryScanCreateResult, error) {
	now := time.Now().UTC()
	jobID := fmt.Sprintf("scan-%d", now.UnixNano())

	job := DiscoveryScanJob{
		ID:       jobID,
		ScanType: scanType,
		Target:   target,
		Status:   "running",
		QueuedAt: now.Format(time.RFC3339),
	}

	p.mu.Lock()
	p.scanJobs = append(p.scanJobs, job)
	p.mu.Unlock()

	// W19-17 finding: net/http cancels a request's context as soon as its
	// handler returns, and this goroutine outlives that return by design
	// (the handler responds 201 immediately, the scan finishes later) --
	// so passing the request-scoped ctx through silently canceled every
	// real HTTP-triggered scan almost immediately (context.Canceled from
	// the connector/scanner, logged, job marked failed, zero endpoints).
	// Unit tests calling CreateScan directly with context.Background()
	// never exercised this path, which is exactly why k8s-certmanager
	// being newly reachable via the API (this ticket) is what surfaced it
	// live rather than a compile-time or unit-test failure. The DB
	// provider's CreateScan already does this correctly (see its own
	// "must use its own context, not the (about-to-be-canceled) request
	// context" comment) -- this brings the scanner provider in line.
	if scanType == scanTypeK8sCertManager {
		go p.runCertManagerScan(context.Background(), jobID, target)
	} else {
		go p.runNetworkScan(context.Background(), jobID, target)
	}

	return DiscoveryScanCreateResult{
		ID:       jobID,
		Status:   "running",
		ScanType: scanType,
		Target:   target,
		QueuedAt: now.Format(time.RFC3339),
	}, nil
}

func (p *scannerDiscoveryProvider) CancelScanJob(_ context.Context, scanJobID string, reason string) (DiscoveryScanJobActionResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i := range p.scanJobs {
		if p.scanJobs[i].ID == scanJobID {
			p.scanJobs[i].Status = "cancelled"
			return DiscoveryScanJobActionResult{
				ScanJobID: scanJobID,
				Status:    "canceled",
				Reason:    reason,
				UpdatedAt: time.Now().UTC().Format(time.RFC3339),
			}, nil
		}
	}
	return DiscoveryScanJobActionResult{ScanJobID: scanJobID, Status: "not_found"}, nil
}

func (p *scannerDiscoveryProvider) RequeueScanJob(ctx context.Context, scanJobID string, reason string) (DiscoveryScanJobActionResult, error) {
	p.mu.RLock()
	var target, scanType string
	for _, j := range p.scanJobs {
		if j.ID == scanJobID {
			target = j.Target
			scanType = j.ScanType
			break
		}
	}
	p.mu.RUnlock()

	if target == "" {
		return DiscoveryScanJobActionResult{}, fmt.Errorf("scan job %s not found", scanJobID)
	}

	result, err := p.CreateScan(ctx, scanType, target, nil)
	if err != nil {
		return DiscoveryScanJobActionResult{}, err
	}

	return DiscoveryScanJobActionResult{
		PreviousID: scanJobID,
		ScanJobID:  result.ID,
		Status:     "queued",
		Reason:     reason,
		QueuedAt:   result.QueuedAt,
	}, nil
}

func (p *scannerDiscoveryProvider) runNetworkScan(ctx context.Context, jobID string, target string) {
	s := scanner.New(scanner.ScanConfig{
		Targets:     []string{target},
		Concurrency: 50,
		Timeout:     10 * time.Second,
	})
	result := s.Scan(ctx, jobID)

	p.mu.Lock()
	defer p.mu.Unlock()

	for i := range p.scanJobs {
		if p.scanJobs[i].ID == jobID {
			p.scanJobs[i].Status = result.Status
			break
		}
	}
	for _, ep := range result.Endpoints {
		if ep.Error != "" {
			continue
		}
		riskScore := 0
		if len(ep.Certs) > 0 {
			riskScore = ep.Certs[0].RiskScore
		}
		p.upsertEndpointLocked(DiscoveryEndpoint{
			ID:         fmt.Sprintf("ep-%s-%d", ep.Host, ep.Port),
			Hostname:   ep.Host,
			Port:       ep.Port,
			Protocol:   ep.Protocol,
			RiskScore:  riskScore,
			LastSeenAt: ep.ScannedAt.Format(time.RFC3339),
		})
	}
	log.Printf("scan %s completed: %d endpoints, %d certs found", jobID, result.TotalScanned, result.CertsFound)
}

// upsertEndpointLocked replaces an existing in-memory endpoint entry with
// the same ID (re-scan of the same host:port) instead of appending a
// duplicate — W2-05/D-032/R-D2: a re-scan must dedup, not accumulate. Caller
// must hold p.mu.
func (p *scannerDiscoveryProvider) upsertEndpointLocked(ep DiscoveryEndpoint) {
	for i := range p.endpoints {
		if p.endpoints[i].ID == ep.ID {
			p.endpoints[i] = ep
			return
		}
	}
	p.endpoints = append(p.endpoints, ep)
}

func (p *scannerDiscoveryProvider) runCertManagerScan(ctx context.Context, jobID string, _ string) {
	conn, err := certmanager.NewFromEnv()
	if err != nil {
		log.Printf("scan %s: cert-manager connector init failed: %v", jobID, err)
		p.updateScanJobStatus(jobID, "failed")
		return
	}

	certs, err := conn.ListCertificates(ctx)
	if err != nil {
		log.Printf("scan %s: cert-manager list failed: %v", jobID, err)
		p.updateScanJobStatus(jobID, "failed")
		return
	}

	now := time.Now().UTC()
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, cert := range certs {
		riskScore := 0
		if !cert.NotAfter.IsZero() && cert.NotAfter.Before(now.Add(30*24*time.Hour)) {
			riskScore = 80
		} else if !cert.Ready {
			riskScore = 60
		}
		p.upsertEndpointLocked(DiscoveryEndpoint{
			ID:         fmt.Sprintf("k8s-%s-%s", cert.Namespace, cert.Name),
			Hostname:   cert.CommonName,
			Port:       0,
			Protocol:   "k8s-certmanager",
			RiskScore:  riskScore,
			LastSeenAt: now.Format(time.RFC3339),
		})
	}

	p.updateScanJobStatusLocked(jobID, "completed")
	log.Printf("scan %s (k8s-certmanager) completed: %d certs discovered", jobID, len(certs))
}

func (p *scannerDiscoveryProvider) updateScanJobStatus(jobID string, status string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.updateScanJobStatusLocked(jobID, status)
}

func (p *scannerDiscoveryProvider) updateScanJobStatusLocked(jobID string, status string) {
	for i := range p.scanJobs {
		if p.scanJobs[i].ID == jobID {
			p.scanJobs[i].Status = status
			return
		}
	}
}
