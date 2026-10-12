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

	"kryptkeeper/internal/metrics"
	"kryptkeeper/internal/notifications/delivery"
)

// W12-02: the wiring W7-03 disclosed. Each tick sweeps the inventory
// into the time-to-expiry histogram, then evaluates the SLO set and
// pages the delivery channel on ok→breach transitions.

const haLockSLOScheduler = "slo-scheduler"

// SLOScheduler periodically feeds and evaluates the PKI SLOs.
type SLOScheduler struct {
	certProvider CertificateProvider
	set          *metrics.SLOSet
	channel      delivery.Channel
	target       string
	pollInterval time.Duration

	// nil when unavailable (soft-fail) — single-replica behavior.
	haCoordinator *HACoordinator

	stop chan struct{}
	once sync.Once
}

// NewSLOSchedulerFromEnv builds the scheduler
// (KRYPTKEEPER_SLO_SWEEP_MINUTES, default 15). channel may be nil:
// evaluation still runs and breaches still count in the metric —
// paging is additive, never load-bearing for detection.
func NewSLOSchedulerFromEnv(certProvider CertificateProvider, channel delivery.Channel, target string) *SLOScheduler {
	minutes := 15
	if raw := strings.TrimSpace(os.Getenv("KRYPTKEEPER_SLO_SWEEP_MINUTES")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			minutes = n
		}
	}
	return &SLOScheduler{
		certProvider:  certProvider,
		set:           metrics.DefaultPKISLOs(),
		channel:       channel,
		target:        target,
		pollInterval:  time.Duration(minutes) * time.Minute,
		haCoordinator: newHACoordinatorFromEnvLogged(),
		stop:          make(chan struct{}),
	}
}

// Start launches the sweep loop. Call Stop to shut it down.
func (s *SLOScheduler) Start() {
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

func (s *SLOScheduler) Stop() { s.once.Do(func() { close(s.stop) }) }

// tick runs one sweep + evaluation. Exported-for-tests via the
// _test file only; kept unexported here.
func (s *SLOScheduler) tick(ctx context.Context, now time.Time) {
	// HA gate: on >=2 replicas only the lease holder proceeds; a lock
	// error fails closed (skip) — two holders would double-page every
	// breach transition (see posture_scheduler.go's rationale).
	if s.haCoordinator != nil {
		ok, err := s.haCoordinator.TryAcquire(ctx, haLockSLOScheduler, 2*s.pollInterval)
		if err != nil {
			log.Printf("slo scheduler: ha lock check failed, skipping this tick: %v", err)
			return
		}
		if !ok {
			return
		}
	}

	s.sweepExpiry(ctx, now)

	_, errs := s.set.EvaluateAndNotify(ctx, now, s.channel, s.target)
	for _, err := range errs {
		log.Printf("slo scheduler: breach alert failed: %v", err)
	}
}

// sweepExpiry feeds every certificate's remaining lifetime into the
// expiry histogram. Unparseable ValidUntil values are skipped — one
// malformed row must not stall the sweep.
func (s *SLOScheduler) sweepExpiry(ctx context.Context, now time.Time) {
	err := ForEachCertificate(ctx, s.certProvider, CertificateListQuery{}, func(item CertificateItem) error {
		until, err := time.Parse(time.RFC3339, item.ValidUntil)
		if err != nil {
			return nil
		}
		metrics.ObserveTimeToExpiry(until.Sub(now))
		return nil
	})
	if err != nil {
		log.Printf("slo scheduler: inventory sweep failed: %v", err)
	}
}
