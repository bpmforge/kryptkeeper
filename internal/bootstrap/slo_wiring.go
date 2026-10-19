// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"kryptkeeper/internal/logging"
	"log/slog"
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

	// configStore supplies runtime objective overrides; nil means env only.
	configStore ConfigStore

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
	set := metrics.DefaultPKISLOs()
	set.RegisterMetrics(metrics.Default)
	return &SLOScheduler{
		certProvider:  certProvider,
		set:           set,
		channel:       channel,
		target:        target,
		pollInterval:  time.Duration(minutes) * time.Minute,
		configStore:   newConfigStoreFromEnv(),
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
			logging.Warnf("slo scheduler: ha lock check failed, skipping this tick: %v", err)
			return
		}
		if !ok {
			return
		}
	}

	s.applyObjectives(ctx)
	s.sweepExpiry(ctx, now)
	s.set.Observe(now)

	fired, errs := s.set.EvaluateAndNotify(ctx, now, s.channel, s.target)
	for _, b := range fired {
		slog.Warn("slo scheduler: error budget breach", "slo", b.SLO, "objective", b.Objective, "actual", b.Actual)
	}
	for _, err := range errs {
		slog.Error("slo scheduler: breach alert failed", "err", delivery.RedactURLs(err.Error()))
	}
	publishSLOStatus(s.set.Status(now))
}

// sloObjectiveKeys maps an SLO name to the config key and env var that tune it.
var sloObjectiveKeys = map[string]struct{ Key, Env string }{
	"renewal-success-rate":  {"slo.renewal_success_objective", "KRYPTKEEPER_SLO_RENEWAL_OBJECTIVE"},
	"issuance-success-rate": {"slo.issuance_success_objective", "KRYPTKEEPER_SLO_ISSUANCE_OBJECTIVE"},
	"issuance-latency-p95":  {"slo.issuance_latency_p95_seconds", "KRYPTKEEPER_SLO_LATENCY_P95_SECONDS"},
}

// applyObjectives re-resolves every objective (DB override, else env, else the
// shipped default) so a config change takes effect on the next sweep without
// a restart. Invalid values are logged and fall back to the default; they can
// only arrive via the env var, since the store validates on Set.
func (s *SLOScheduler) applyObjectives(ctx context.Context) {
	for name, src := range sloObjectiveKeys {
		raw, from := "", ""
		if s.configStore != nil {
			if e, ok, err := s.configStore.Get(ctx, src.Key); err != nil {
				slog.Warn("slo scheduler: config store read failed", "key", src.Key, "err", err)
			} else if ok && e.HasValue {
				raw, from = e.Value, "config"
			}
		}
		if from == "" {
			if env := strings.TrimSpace(os.Getenv(src.Env)); env != "" {
				raw, from = env, "env"
			}
		}
		if from == "" {
			s.set.ResetObjective(name)
			continue
		}
		if err := validateConfigValue(src.Key, raw); err != nil {
			slog.Warn("slo scheduler: invalid objective ignored, using default", "slo", name, "source", from, "err", err)
			s.set.ResetObjective(name)
			continue
		}
		v, _ := strconv.ParseFloat(strings.TrimSpace(raw), 64)
		s.set.SetObjective(name, v)
	}
}

var (
	sloStatusMu     sync.RWMutex
	sloStatusLatest []metrics.SLOStatus
)

// publishSLOStatus stores the scheduler's latest error-budget snapshot for
// the renewal-SLO report (same package-level snapshot pattern as
// publishRenewalStatus).
func publishSLOStatus(st []metrics.SLOStatus) {
	sloStatusMu.Lock()
	defer sloStatusMu.Unlock()
	sloStatusLatest = st
}

func latestSLOStatus() []metrics.SLOStatus {
	sloStatusMu.RLock()
	defer sloStatusMu.RUnlock()
	return append([]metrics.SLOStatus(nil), sloStatusLatest...)
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
		logging.Warnf("slo scheduler: inventory sweep failed: %v", err)
	}
}

// FanOutChannel delivers one event on every member channel. Send never stops at
// the first failure: every member is attempted, and the returned error joins
// the individual failures so callers still see that something failed.
type FanOutChannel struct{ members []delivery.Channel }

// NewFanOutChannel accepts nil/empty members; Send is then a no-op.
func NewFanOutChannel(members []delivery.Channel) *FanOutChannel {
	return &FanOutChannel{members: members}
}

func (f *FanOutChannel) Name() string { return "fanout" }

func (f *FanOutChannel) Members() int { return len(f.members) }

// Send is sequential: each member's own timeout bounds it and alert volume is
// tiny. Members that report themselves unconfigured are skipped, not failed.
func (f *FanOutChannel) Send(ctx context.Context, ev delivery.Event) error {
	var errs []error
	attempted := 0
	for _, m := range f.members {
		if c, ok := m.(delivery.Configurable); ok && !c.Configured(ctx) {
			continue
		}
		attempted++
		e := ev
		e.Channel = m.Name()
		// The delivery log keys on ID, so each channel needs its own.
		e.ID = ev.ID + "#" + m.Name()
		if err := m.Send(ctx, e); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", m.Name(), err))
		}
	}
	if attempted == 0 {
		// Reporting success here would let callers (CT) mark a finding as
		// notified when nothing was delivered.
		return ErrNoConfiguredChannel
	}
	return errors.Join(errs...)
}

// ErrNoConfiguredChannel is returned by FanOutChannel.Send when no member
// channel is configured, so the event was delivered nowhere.
var ErrNoConfiguredChannel = errors.New("fanout: no configured notification channel")
