// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/notifications/delivery"
)

// W30-27: backup staleness alert for the DR drill (W30-23).
//
// Key backups are operator-triggered (POST /api/v1/admin/backup, audited as
// backup.create); there is no backup schedule or enable flag to read. The
// honest rule is therefore: staleness is measured from the newest SUCCESSFUL
// backup.create audit entry, and when none exists at all there is no baseline,
// so backups are treated as not in use and nothing alerts. Audit archival that
// purges every backup.create row returns the estate to that "no baseline" state.

const (
	backupStaleAlertName     = "backup.stale"
	backupStaleDefaultHours  = 24.0
	haLockBackupStaleSweeper = "backup-stale-sweeper"
	backupStaleMaxInterval   = 15 * time.Minute
)

// BackupStaleSweeper alerts once per stale episode and re-arms after a fresh backup.
type BackupStaleSweeper struct {
	audit     AuditProvider
	channel   delivery.Channel
	target    string
	threshold time.Duration
	interval  time.Duration

	ha *HACoordinator // nil = single replica

	mu      sync.Mutex
	latched bool

	stop chan struct{}
	once sync.Once
}

// NewBackupStaleSweeperFromEnv reads KRYPTKEEPER_BACKUP_STALE_HOURS (float
// hours, default 24, 0 disables). It returns nil when disabled or when there is
// no audit trail to read backups from.
func NewBackupStaleSweeperFromEnv(audit AuditProvider, channel delivery.Channel, target string) *BackupStaleSweeper {
	hours := backupStaleDefaultHours
	if raw := strings.TrimSpace(os.Getenv("KRYPTKEEPER_BACKUP_STALE_HOURS")); raw != "" {
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil || v < 0 {
			slog.Warn("backup stale sweeper: invalid KRYPTKEEPER_BACKUP_STALE_HOURS, using default", "value", raw)
		} else {
			hours = v
		}
	}
	if hours == 0 || audit == nil {
		return nil
	}
	s := newBackupStaleSweeper(audit, channel, target, time.Duration(hours*float64(time.Hour)))
	s.ha = newHACoordinatorFromEnvLogged()
	return s
}

func newBackupStaleSweeper(audit AuditProvider, channel delivery.Channel, target string, threshold time.Duration) *BackupStaleSweeper {
	interval := threshold / 4
	if interval > backupStaleMaxInterval {
		interval = backupStaleMaxInterval
	}
	if interval < time.Second {
		interval = time.Second
	}
	return &BackupStaleSweeper{
		audit: audit, channel: channel, target: target,
		threshold: threshold, interval: interval, stop: make(chan struct{}),
	}
}

// Start launches the sweep loop; Stop ends it.
func (s *BackupStaleSweeper) Start() {
	go func() {
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-ticker.C:
				s.tick(context.Background(), time.Now().UTC())
			}
		}
	}()
}

func (s *BackupStaleSweeper) Stop() { s.once.Do(func() { close(s.stop) }) }

func (s *BackupStaleSweeper) tick(ctx context.Context, now time.Time) {
	if s.ha != nil {
		ok, err := s.ha.TryAcquire(ctx, haLockBackupStaleSweeper, 2*s.interval)
		if err != nil {
			slog.Warn("backup stale sweeper: ha lock check failed, skipping tick", "err", err)
			return
		}
		if !ok {
			return
		}
	}

	res, err := s.audit.ListEntries(ctx, AuditListQuery{
		Action: "backup.create", Outcome: AuditOutcomeSuccess, Order: "desc", Limit: 1,
	})
	if err != nil {
		slog.Warn("backup stale sweeper: audit query failed", "err", err)
		return
	}
	var newest time.Time
	for _, e := range res.Entries {
		if t, perr := time.Parse(time.RFC3339, e.Timestamp); perr == nil && t.After(newest) {
			newest = t
		}
	}
	if newest.IsZero() {
		return // no baseline: backups not in use
	}

	age := now.Sub(newest)
	s.mu.Lock()
	defer s.mu.Unlock()
	if age <= s.threshold {
		s.latched = false // fresh backup re-arms the alert
		return
	}
	if s.latched {
		return
	}
	slog.Warn("backup stale sweeper: newest successful backup is stale",
		"newest", newest.Format(time.RFC3339), "age_hours", age.Hours(), "threshold_hours", s.threshold.Hours())
	if s.channel == nil || s.target == "" {
		s.latched = true // nowhere to send; do not re-log every tick
		return
	}
	sendCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	err = s.channel.Send(sendCtx, delivery.Event{
		ID:       fmt.Sprintf("%s:%d", backupStaleAlertName, newest.Unix()),
		Target:   s.target,
		Subject:  backupStaleAlertName,
		Priority: "high",
		Message: fmt.Sprintf("%s: newest successful key backup is %.1fh old (threshold %.1fh, taken %s)",
			backupStaleAlertName, age.Hours(), s.threshold.Hours(), newest.Format(time.RFC3339)),
		CreatedAt: now,
	})
	if err != nil {
		// Not latched: retry next tick.
		slog.Error("backup stale sweeper: alert failed", "err", delivery.RedactURLs(err.Error()))
		return
	}
	s.latched = true
}
