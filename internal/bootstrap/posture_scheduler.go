// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// haLockPostureScheduler names this scheduler's lease row in
// ha_scheduler_locks (ha_coordinator.go, W6-01/PE-9/D-048).
const haLockPostureScheduler = "posture-scheduler"

// PostureScheduler periodically captures a crypto-posture snapshot so the
// dashboard can chart posture trends over time. It de-dupes within a UTC day so
// restarts don't create duplicate rows.
type PostureScheduler struct {
	certProvider CertificateProvider
	store        PostureSnapshotStore

	// exceptionStore is nil when the finding-exception DB is unavailable
	// (soft-fail — see newFindingExceptionStoreFromEnv), which degrades a
	// captured snapshot's Findings to raw==effective rather than blocking
	// capture entirely.
	exceptionStore FindingExceptionStore

	pollInterval time.Duration

	// haCoordinator is nil when unavailable (soft-fail — see
	// newHACoordinatorFromEnvLogged), which preserves the pre-W6-01
	// single-replica behavior of always capturing.
	haCoordinator *HACoordinator

	stop chan struct{}
	once sync.Once
}

// NewPostureSchedulerFromEnv creates a PostureScheduler using environment config.
//
// POSTURE_SNAPSHOT_HOURS — how often to capture a snapshot (default: 24).
//
// exceptionStore (W2-12) is self-constructed from env here rather than
// threaded through this constructor's signature — this constructor's own
// call site (cmd/kryptkeeper/main.go) is outside this ticket's write_scope,
// matching the precedent registerReportsHandlers already set for the
// crypto-posture handler's own findingExceptionStore. Keeping it a
// constructor-injected field (not fetched inside capture/computeCryptoPosture)
// is what keeps capture's DB read visible and testable — see
// posture_scheduler_test.go, which sets exceptionStore directly on a literal
// PostureScheduler and never calls this constructor.
func NewPostureSchedulerFromEnv(certProvider CertificateProvider, store PostureSnapshotStore) *PostureScheduler {
	pollHours := 24
	if raw := strings.TrimSpace(os.Getenv("POSTURE_SNAPSHOT_HOURS")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			pollHours = n
		}
	}
	exceptionStore, _ := newFindingExceptionStoreFromEnv()
	return &PostureScheduler{
		certProvider:   certProvider,
		store:          store,
		exceptionStore: exceptionStore,
		pollInterval:   time.Duration(pollHours) * time.Hour,
		haCoordinator:  newHACoordinatorFromEnvLogged(),
		stop:           make(chan struct{}),
	}
}

// Start launches the snapshot loop in a goroutine. Call Stop to shut it down.
func (s *PostureScheduler) Start() {
	go func() {
		s.capture()

		ticker := time.NewTicker(s.pollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.capture()
			case <-s.stop:
				return
			}
		}
	}()
}

// Stop shuts down the snapshot loop.
func (s *PostureScheduler) Stop() {
	s.once.Do(func() { close(s.stop) })
}

// capture computes the current posture and stores a snapshot, skipping if one
// already exists for today.
func (s *PostureScheduler) capture() {
	if s.store == nil || s.certProvider == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// HA gate (W6-01/PE-9/D-048): on >=2 replicas, only the lease holder
	// proceeds. A lock error is treated as "not leader" — failing closed
	// here is what keeps this a no-double-run guarantee rather than a
	// best-effort one; a coordinator that is simply unavailable (nil) is
	// the separate, deliberate single-replica fallback set at construction.
	if s.haCoordinator != nil {
		ok, err := s.haCoordinator.TryAcquire(ctx, haLockPostureScheduler, 2*s.pollInterval)
		if err != nil {
			log.Printf("posture scheduler: ha lock check failed, skipping this tick: %v", err)
			return
		}
		if !ok {
			return
		}
	}

	now := time.Now().UTC()

	// One snapshot per UTC day.
	if latest, ok, err := s.store.Latest(ctx); err == nil && ok {
		if dayKey(latest.CapturedAt) == dayKey(now.Format(time.RFC3339)) {
			return
		}
	} else if err != nil {
		log.Printf("posture scheduler: latest lookup failed: %v", err)
	}

	result, err := listAllCertificates(ctx, s.certProvider, CertificateListQuery{})
	if err != nil {
		log.Printf("posture scheduler: list certs failed: %v", err)
		return
	}

	report := computeCryptoPostureReport(result.Items, activeFindingExceptions(ctx, s.exceptionStore))
	id, err := newPostureSnapshotID()
	if err != nil {
		log.Printf("posture scheduler: id generation failed: %v", err)
		return
	}
	snap := snapshotFromReport(id, now.Format(time.RFC3339), report)
	if err := s.store.Save(ctx, snap); err != nil {
		log.Printf("posture scheduler: save failed: %v", err)
		return
	}
	log.Printf("posture scheduler: captured snapshot %s (%d certs, PQC %d%%, automation %d%%)",
		id, snap.TotalCerts, snap.PQCScorePercent, snap.AutomationPercent)
}
