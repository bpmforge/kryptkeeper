// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"kryptkeeper/internal/logging"
)

// W5-12: recurring agentless discovery. One ticker over the provider
// interface — each tick files one network scan per configured target and
// one cloud scan per configured cloud type. Per-scan failures are
// logged, never fatal to the loop.

// DiscoveryScheduler drives recurring scans through a DiscoveryProvider.
type DiscoveryScheduler struct {
	provider   DiscoveryProvider
	interval   time.Duration
	targets    []string
	cloudTypes []string
	// managedTargets, when set, adds one winrm/ssh scan per managed target
	// whose discovery mode asks for it (W18-12, W24-08).
	managedTargets ManagedTargetStore
	// store persists per-target interval overrides and last-run times
	// (W24-04). Defaults to an in-memory store.
	store discoveryScheduleStore
	// tick is how often the loop wakes to check which targets are due;
	// now is the clock (tests inject both).
	tick    time.Duration
	now     func() time.Time
	skipped atomic.Int64
}

// WithScheduleStore swaps in the persistent schedule store.
func (s *DiscoveryScheduler) WithScheduleStore(st discoveryScheduleStore) *DiscoveryScheduler {
	if s != nil && st != nil {
		s.store = st
	}
	return s
}

// WithManagedTargets enables recurring WinRM discovery for managed targets.
func (s *DiscoveryScheduler) WithManagedTargets(store ManagedTargetStore) *DiscoveryScheduler {
	if s != nil {
		s.managedTargets = store
	}
	return s
}

// NewDiscoverySchedulerFromEnv builds the scheduler, or nil when
// KRYPTKEEPER_DISCOVERY_SCAN_INTERVAL is unset/unparseable (scheduling
// is opt-in). Sub-minute intervals are clamped loudly — a tight scan
// loop against production networks is an accident, not a posture.
//
//	KRYPTKEEPER_DISCOVERY_SCAN_INTERVAL  time.ParseDuration (e.g. 12h, 30m)
//	KRYPTKEEPER_DISCOVERY_SCAN_TARGETS   CSV of network targets (host/CIDR)
//	KRYPTKEEPER_DISCOVERY_CLOUD_TYPES    CSV of cloud_acm|cloud_azure_kv|cloud_gcp_cm
func NewDiscoverySchedulerFromEnv(provider DiscoveryProvider) *DiscoveryScheduler {
	return newDiscoverySchedulerFromEnv(provider, false)
}

// NewDiscoverySchedulerWithTargetsFromEnv is NewDiscoverySchedulerFromEnv
// plus recurring WinRM discovery of managed targets: an interval alone is
// enough to enable it, since the target list lives in the store.
func NewDiscoverySchedulerWithTargetsFromEnv(provider DiscoveryProvider, targets ManagedTargetStore) *DiscoveryScheduler {
	return newDiscoverySchedulerFromEnv(provider, targets != nil).WithManagedTargets(targets)
}

// globalDiscoveryInterval parses KRYPTKEEPER_DISCOVERY_SCAN_INTERVAL,
// logging why when it is set but unusable. Sub-minute values clamp to 1m.
func globalDiscoveryInterval() (time.Duration, bool) {
	return readGlobalDiscoveryInterval(logging.Warnf)
}

// globalDiscoveryIntervalQuiet is globalDiscoveryInterval without logging,
// for request handlers.
func globalDiscoveryIntervalQuiet() (time.Duration, bool) {
	return readGlobalDiscoveryInterval(func(string, ...any) {})
}

func readGlobalDiscoveryInterval(logf func(string, ...any)) (time.Duration, bool) {
	raw := strings.TrimSpace(os.Getenv("KRYPTKEEPER_DISCOVERY_SCAN_INTERVAL"))
	if raw == "" {
		return 0, false
	}
	interval, err := time.ParseDuration(raw)
	if err != nil || interval <= 0 {
		logf("discovery scheduler: invalid KRYPTKEEPER_DISCOVERY_SCAN_INTERVAL=%q — scheduling disabled", raw)
		return 0, false
	}
	if interval < time.Minute {
		logf("discovery scheduler: interval %s clamped to 1m", interval)
		interval = time.Minute
	}
	return interval, true
}

// envDiscoveryTargets is the KRYPTKEEPER_DISCOVERY_SCAN_TARGETS CSV.
func envDiscoveryTargets() []string {
	var targets []string
	for _, t := range strings.Split(os.Getenv("KRYPTKEEPER_DISCOVERY_SCAN_TARGETS"), ",") {
		if t = strings.TrimSpace(t); t != "" {
			targets = append(targets, t)
		}
	}
	return targets
}

func newDiscoverySchedulerFromEnv(provider DiscoveryProvider, winrmTargetsPossible bool) *DiscoveryScheduler {
	if provider == nil {
		return nil
	}
	interval, ok := globalDiscoveryInterval()
	if !ok {
		return nil
	}
	targets := envDiscoveryTargets()
	var cloudTypes []string
	for _, c := range strings.Split(os.Getenv("KRYPTKEEPER_DISCOVERY_CLOUD_TYPES"), ",") {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		if !isCloudScanType(c) {
			logging.Infof("discovery scheduler: unknown cloud type %q skipped (valid: cloud_acm, cloud_azure_kv, cloud_gcp_cm)", c)
			continue
		}
		cloudTypes = append(cloudTypes, c)
	}
	if len(targets) == 0 && len(cloudTypes) == 0 && !winrmTargetsPossible {
		logging.Info("discovery scheduler: interval set but no targets or cloud types configured — scheduling disabled")
		return nil
	}
	return newDiscoveryScheduler(provider, interval, targets, cloudTypes)
}

// newDiscoveryScheduler is the test constructor — no env, no clamping.
func newDiscoveryScheduler(provider DiscoveryProvider, interval time.Duration, targets, cloudTypes []string) *DiscoveryScheduler {
	return &DiscoveryScheduler{
		provider: provider, interval: interval, targets: targets, cloudTypes: cloudTypes,
		store: newMemoryDiscoveryScheduleStore(), tick: min(interval, time.Minute), now: time.Now,
	}
}

// scheduledScan is one thing the scheduler may file on a tick. perTarget
// scans carry an overridable interval and an API row; cloud scans use the
// global interval only.
type scheduledScan struct {
	key, scanType, target string
	perTarget             bool
}

// scheduledScans lists every scan this tick may file: env network targets,
// then managed targets that opt in, then cloud types.
func (s *DiscoveryScheduler) scheduledScans(ctx context.Context) []scheduledScan {
	var out []scheduledScan
	for _, target := range s.targets {
		out = append(out, scheduledScan{key: target, scanType: "targeted", target: target, perTarget: true})
	}
	if s.managedTargets != nil {
		list, err := s.managedTargets.List(ctx)
		if err != nil {
			logging.Warnf("discovery scheduler: managed targets unavailable: %v", err)
		}
		for _, t := range list {
			if scanType, ok := scheduledManagedScanType(t); ok {
				out = append(out, scheduledScan{key: t.ID, scanType: scanType, target: t.ID, perTarget: true})
			}
		}
	}
	for _, cloudType := range s.cloudTypes {
		out = append(out, scheduledScan{key: "cloud:" + cloudType, scanType: cloudType})
	}
	return out
}

// scheduledManagedScanType says which scan type a managed target is
// scheduled under, if any.
func scheduledManagedScanType(t ManagedTarget) (string, bool) {
	if t.DiscoveryMode == "winrm" {
		return scanTypeWinRM, true
	}
	if isSSHDiscoveryTarget(t) {
		return scanTypeSSH, true
	}
	return "", false
}

// findRunningScanJob returns an in-flight (running or queued) job for the
// exact scan type and target.
func findRunningScanJob(ctx context.Context, p DiscoveryProvider, scanType, target string) (DiscoveryScanJob, bool, error) {
	for _, status := range []string{"running", "queued"} {
		res, err := p.ListScanJobs(ctx, DiscoveryScanJobQuery{Status: status, Q: target, Limit: 100})
		if err != nil {
			return DiscoveryScanJob{}, false, err
		}
		for _, j := range res.ScanJobs {
			if j.ScanType == scanType && j.Target == target {
				return j, true, nil
			}
		}
	}
	return DiscoveryScanJob{}, false, nil
}

// runOnce files every scan that is due on this tick.
func (s *DiscoveryScheduler) runOnce(ctx context.Context) {
	rows, err := s.store.List(ctx)
	if err != nil {
		logging.Warnf("discovery scheduler: schedule store unavailable, using global interval: %v", err)
		rows = nil
	}
	now := s.now()
	for _, sc := range s.scheduledScans(ctx) {
		row := rows[sc.key]
		effective := s.interval
		if sc.perTarget && row.Interval != nil {
			effective = *row.Interval
		}
		// tick/2 slack: a loop that wakes every tick must not miss a due
		// time by a few microseconds of ticker jitter.
		if !row.LastRunAt.IsZero() && now.Sub(row.LastRunAt)+s.tick/2 < effective {
			continue
		}
		if job, running, err := findRunningScanJob(ctx, s.provider, sc.scanType, sc.target); err != nil {
			logging.Warnf("discovery scheduler: cannot check running jobs for %s %s: %v", sc.scanType, sc.target, err)
		} else if running {
			s.skipped.Add(1)
			logging.Infof("discovery scheduler: skipping %s %s: job %s still %s", sc.scanType, sc.target, job.ID, job.Status)
			continue
		}
		result, err := s.provider.CreateScan(ctx, sc.scanType, sc.target, nil)
		if err != nil {
			logging.Warnf("discovery scheduler: %s scan of %s failed to start: %v", sc.scanType, sc.target, err)
			continue
		}
		if err := s.store.RecordRun(ctx, sc.key, sc.scanType, sc.target, result.ID, now); err != nil {
			logging.Warnf("discovery scheduler: recording run of %s failed: %v", sc.key, err)
		}
	}
}

// Start launches the recurring loop until ctx ends.
func (s *DiscoveryScheduler) Start(ctx context.Context) {
	logging.Infof("discovery scheduler: every %s — %d network target(s), %d cloud type(s), managed winrm targets: %t",
		s.interval, len(s.targets), len(s.cloudTypes), s.managedTargets != nil)
	go func() {
		ticker := time.NewTicker(s.tick)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.runOnce(ctx)
			}
		}
	}()
}
