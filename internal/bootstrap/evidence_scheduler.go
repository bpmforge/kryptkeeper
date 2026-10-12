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

// haLockEvidenceScheduler names this scheduler's lease row in
// ha_scheduler_locks (ha_coordinator.go, W6-01/PE-9/D-048).
const haLockEvidenceScheduler = "evidence-scheduler"

// EvidenceScheduler periodically renders and emails due evidence packs.
type EvidenceScheduler struct {
	certProvider CertificateProvider
	caProvider   CAProvider
	store        EvidenceScheduleStore
	mailer       *EvidenceMailer

	pollInterval time.Duration

	// haCoordinator is nil when unavailable (soft-fail — see
	// newHACoordinatorFromEnvLogged), which preserves the pre-W6-01
	// single-replica behavior of always scanning.
	haCoordinator *HACoordinator

	stop chan struct{}
	once sync.Once
}

// NewEvidenceSchedulerFromEnv builds the scheduler (EVIDENCE_POLL_HOURS, default 6).
func NewEvidenceSchedulerFromEnv(certProvider CertificateProvider, caProvider CAProvider, store EvidenceScheduleStore, mailer *EvidenceMailer) *EvidenceScheduler {
	pollHours := 6
	if raw := strings.TrimSpace(os.Getenv("EVIDENCE_POLL_HOURS")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			pollHours = n
		}
	}
	return &EvidenceScheduler{
		certProvider:  certProvider,
		caProvider:    caProvider,
		store:         store,
		mailer:        mailer,
		pollInterval:  time.Duration(pollHours) * time.Hour,
		haCoordinator: newHACoordinatorFromEnvLogged(),
		stop:          make(chan struct{}),
	}
}

// Start launches the delivery loop. Call Stop to shut it down.
func (s *EvidenceScheduler) Start() {
	go func() {
		s.scan()
		ticker := time.NewTicker(s.pollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.scan()
			case <-s.stop:
				return
			}
		}
	}()
}

// Stop shuts down the delivery loop.
func (s *EvidenceScheduler) Stop() {
	s.once.Do(func() { close(s.stop) })
}

// scan sends any due schedules.
func (s *EvidenceScheduler) scan() {
	if s.store == nil || s.mailer == nil || !s.mailer.Enabled() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// HA gate (W6-01/PE-9/D-048): on >=2 replicas, only the lease holder
	// proceeds — see posture_scheduler.go's capture() for why a lock error
	// fails closed (skip) rather than open (run anyway).
	if s.haCoordinator != nil {
		ok, err := s.haCoordinator.TryAcquire(ctx, haLockEvidenceScheduler, 2*s.pollInterval)
		if err != nil {
			log.Printf("evidence scheduler: ha lock check failed, skipping this tick: %v", err)
			return
		}
		if !ok {
			return
		}
	}

	schedules, err := s.store.List(ctx)
	if err != nil {
		log.Printf("evidence scheduler: list failed: %v", err)
		return
	}
	now := time.Now().UTC()
	for _, sched := range schedules {
		if !sched.isDue(now) {
			continue
		}
		pdfBytes, filename, err := renderEvidencePackForFramework(ctx, s.certProvider, s.caProvider, sched.Framework, now)
		if err != nil {
			log.Printf("evidence scheduler: render %s failed: %v", sched.ID, err)
			continue
		}
		subject, body := evidenceEmailSubjectBody(sched.Framework, now)
		if err := s.mailer.Send(sched.Recipients, subject, body, pdfBytes, filename); err != nil {
			log.Printf("evidence scheduler: send %s failed: %v", sched.ID, err)
			continue
		}
		if err := s.store.MarkSent(ctx, sched.ID, now.Format(time.RFC3339)); err != nil {
			log.Printf("evidence scheduler: mark-sent %s failed: %v", sched.ID, err)
		}
		log.Printf("evidence scheduler: sent %s pack to %d recipient(s)", sched.Framework, len(sched.Recipients))
	}
}
