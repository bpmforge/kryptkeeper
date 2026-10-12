// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/notifications/delivery"
)

// W12-03: the wiring W7-04 disclosed. The pure AnomalyDetector runs on
// a schedule over inventory-derived issuance events; NEW findings page
// the delivery channel (transition-latched, the W7-03 semantics reused
// deliberately) and the latest tick is served on a report endpoint.

const haLockAnomalyScheduler = "anomaly-scheduler"

// AnomalyScheduler periodically scans issuance patterns.
type AnomalyScheduler struct {
	certProvider CertificateProvider
	detector     *AnomalyDetector
	channel      delivery.Channel
	target       string
	pollInterval time.Duration

	// nil when unavailable (soft-fail) — single-replica behavior.
	haCoordinator *HACoordinator

	mu        sync.Mutex
	latest    []AnomalyFinding
	scannedAt time.Time
	// previous tick's finding keys — only NEW findings page.
	seen map[string]bool

	stop chan struct{}
	once sync.Once
}

// NewAnomalySchedulerFromEnv builds the scheduler
// (KRYPTKEEPER_ANOMALY_SWEEP_MINUTES, default 30). channel may be nil:
// detection and the report surface never depend on paging.
func NewAnomalySchedulerFromEnv(certProvider CertificateProvider, channel delivery.Channel, target string) *AnomalyScheduler {
	minutes := 30
	if raw := strings.TrimSpace(os.Getenv("KRYPTKEEPER_ANOMALY_SWEEP_MINUTES")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			minutes = n
		}
	}
	return &AnomalyScheduler{
		certProvider:  certProvider,
		detector:      NewAnomalyDetector(),
		channel:       channel,
		target:        target,
		pollInterval:  time.Duration(minutes) * time.Minute,
		haCoordinator: newHACoordinatorFromEnvLogged(),
		seen:          map[string]bool{},
		stop:          make(chan struct{}),
	}
}

func (s *AnomalyScheduler) Start() {
	go func() {
		ticker := time.NewTicker(s.pollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-ticker.C:
				s.tick(context.Background(), time.Now())
			}
		}
	}()
}

func (s *AnomalyScheduler) Stop() { s.once.Do(func() { close(s.stop) }) }

// issuanceEvents derives detector input from the inventory. ValidFrom
// is the issuance instant; RequestedBy maps from TeamID — the closest
// requester-shaped field the inventory carries today (when a real
// requester field lands on CertificateItem this tightens without
// touching the detector).
func (s *AnomalyScheduler) issuanceEvents(ctx context.Context) ([]IssuanceEvent, error) {
	var events []IssuanceEvent
	err := ForEachCertificate(ctx, s.certProvider, CertificateListQuery{}, func(item CertificateItem) error {
		issued, err := time.Parse(time.RFC3339, item.ValidFrom)
		if err != nil {
			return nil
		}
		events = append(events, IssuanceEvent{
			Subject:     item.CommonName,
			CAID:        item.CAID,
			RequestedBy: item.TeamID,
			IssuedAt:    issued,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return events, nil
}

func anomalyKey(f AnomalyFinding) string {
	ev := ""
	if len(f.Evidence) > 0 {
		ev = f.Evidence[0]
	}
	return f.Kind + ":" + ev
}

func (s *AnomalyScheduler) tick(ctx context.Context, now time.Time) {
	// HA gate: only the lease holder scans; lock errors fail closed
	// (skip) — two holders would double-page every new finding.
	if s.haCoordinator != nil {
		ok, err := s.haCoordinator.TryAcquire(ctx, haLockAnomalyScheduler, 2*s.pollInterval)
		if err != nil {
			log.Printf("anomaly scheduler: ha lock check failed, skipping this tick: %v", err)
			return
		}
		if !ok {
			return
		}
	}

	events, err := s.issuanceEvents(ctx)
	if err != nil {
		log.Printf("anomaly scheduler: inventory sweep failed: %v", err)
		return
	}
	findings := s.detector.Scan(events, now)

	s.mu.Lock()
	current := map[string]bool{}
	var fresh []AnomalyFinding
	for _, f := range findings {
		k := anomalyKey(f)
		current[k] = true
		if !s.seen[k] {
			fresh = append(fresh, f)
		}
	}
	s.seen = current
	s.latest = findings
	s.scannedAt = now
	s.mu.Unlock()

	if s.channel == nil {
		return
	}
	for _, f := range fresh {
		ev := delivery.Event{
			ID:        fmt.Sprintf("anomaly-%s-%d", anomalyKey(f), now.Unix()),
			Channel:   s.channel.Name(),
			Target:    s.target,
			Subject:   "Issuance anomaly: " + f.Kind,
			Message:   f.Detail,
			Priority:  "high",
			CreatedAt: now,
		}
		if err := s.channel.Send(ctx, ev); err != nil {
			log.Printf("anomaly scheduler: notify failed for %s: %v", anomalyKey(f), err)
		}
	}
}

// Snapshot returns the latest tick's findings for the report surface.
func (s *AnomalyScheduler) Snapshot() ([]AnomalyFinding, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AnomalyFinding, len(s.latest))
	copy(out, s.latest)
	return out, s.scannedAt
}

// RegisterAnomalyHandlers is the exported registrar main.go's extra-
// handlers option uses (the ceremony-handlers pattern).
func RegisterAnomalyHandlers(mux *http.ServeMux, auth *Authenticator, scheduler *AnomalyScheduler) {
	registerAnomalyHandlers(mux, auth, scheduler)
}

// registerAnomalyHandlers serves the latest anomaly findings.
func registerAnomalyHandlers(mux *http.ServeMux, auth *Authenticator, scheduler *AnomalyScheduler) {
	mux.HandleFunc("/api/v1/reports/anomalies", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		if _, err := auth.AuthenticatePrincipalDetails(r, time.Now()); err != nil {
			writeUnauthorized(w)
			return
		}
		findings, at := scheduler.Snapshot()
		if findings == nil {
			findings = []AnomalyFinding{}
		}
		scanned := ""
		if !at.IsZero() {
			scanned = at.UTC().Format(time.RFC3339)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Data struct {
				Findings  []AnomalyFinding `json:"findings"`
				ScannedAt string           `json:"scanned_at,omitempty"`
			} `json:"data"`
		}{Data: struct {
			Findings  []AnomalyFinding `json:"findings"`
			ScannedAt string           `json:"scanned_at,omitempty"`
		}{Findings: findings, ScannedAt: scanned}})
	})
}
