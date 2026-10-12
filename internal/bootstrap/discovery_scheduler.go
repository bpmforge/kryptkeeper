// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"log"
	"os"
	"strings"
	"time"
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
	// managedTargets, when set, adds one winrm scan per managed target
	// whose discovery_mode is winrm (W18-12).
	managedTargets ManagedTargetStore
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

func newDiscoverySchedulerFromEnv(provider DiscoveryProvider, winrmTargetsPossible bool) *DiscoveryScheduler {
	raw := strings.TrimSpace(os.Getenv("KRYPTKEEPER_DISCOVERY_SCAN_INTERVAL"))
	if raw == "" || provider == nil {
		return nil
	}
	interval, err := time.ParseDuration(raw)
	if err != nil || interval <= 0 {
		log.Printf("discovery scheduler: invalid KRYPTKEEPER_DISCOVERY_SCAN_INTERVAL=%q — scheduling disabled", raw)
		return nil
	}
	if interval < time.Minute {
		log.Printf("discovery scheduler: interval %s clamped to 1m", interval)
		interval = time.Minute
	}

	var targets []string
	for _, t := range strings.Split(os.Getenv("KRYPTKEEPER_DISCOVERY_SCAN_TARGETS"), ",") {
		if t = strings.TrimSpace(t); t != "" {
			targets = append(targets, t)
		}
	}
	var cloudTypes []string
	for _, c := range strings.Split(os.Getenv("KRYPTKEEPER_DISCOVERY_CLOUD_TYPES"), ",") {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		if !isCloudScanType(c) {
			log.Printf("discovery scheduler: unknown cloud type %q skipped (valid: cloud_acm, cloud_azure_kv, cloud_gcp_cm)", c)
			continue
		}
		cloudTypes = append(cloudTypes, c)
	}
	if len(targets) == 0 && len(cloudTypes) == 0 && !winrmTargetsPossible {
		log.Print("discovery scheduler: interval set but no targets or cloud types configured — scheduling disabled")
		return nil
	}
	return &DiscoveryScheduler{provider: provider, interval: interval, targets: targets, cloudTypes: cloudTypes}
}

// newDiscoveryScheduler is the test constructor — no env, no clamping.
func newDiscoveryScheduler(provider DiscoveryProvider, interval time.Duration, targets, cloudTypes []string) *DiscoveryScheduler {
	return &DiscoveryScheduler{provider: provider, interval: interval, targets: targets, cloudTypes: cloudTypes}
}

// runOnce files every configured scan for one tick.
func (s *DiscoveryScheduler) runOnce(ctx context.Context) {
	for _, target := range s.targets {
		if _, err := s.provider.CreateScan(ctx, "targeted", target, nil); err != nil {
			log.Printf("discovery scheduler: network scan of %s failed to start: %v", target, err)
		}
	}
	for _, cloudType := range s.cloudTypes {
		if _, err := s.provider.CreateScan(ctx, cloudType, "", nil); err != nil {
			log.Printf("discovery scheduler: %s scan failed to start: %v", cloudType, err)
		}
	}
	if s.managedTargets == nil {
		return
	}
	list, err := s.managedTargets.List(ctx)
	if err != nil {
		log.Printf("discovery scheduler: managed targets unavailable: %v", err)
		return
	}
	for _, t := range list {
		if t.DiscoveryMode != "winrm" {
			continue
		}
		if _, err := s.provider.CreateScan(ctx, scanTypeWinRM, t.ID, nil); err != nil {
			log.Printf("discovery scheduler: winrm scan of %s failed to start: %v", t.ID, err)
		}
	}
}

// Start launches the recurring loop until ctx ends.
func (s *DiscoveryScheduler) Start(ctx context.Context) {
	log.Printf("discovery scheduler: every %s — %d network target(s), %d cloud type(s), managed winrm targets: %t",
		s.interval, len(s.targets), len(s.cloudTypes), s.managedTargets != nil)
	go func() {
		ticker := time.NewTicker(s.interval)
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
