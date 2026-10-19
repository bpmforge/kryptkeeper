// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"kryptkeeper/internal/notifications/delivery"
)

// W30-27: failover signals for the DR drill (W30-23). A takeover is a
// TryAcquire that wins a lease row previously held by a DIFFERENT holder; the
// first-ever acquire of a lock (no row) and a holder renewing its own lease are
// not takeovers. A lock released on graceful shutdown deletes its row, so a
// planned handover also reads as a first acquire and does not alert.

const (
	haFailoverAuditAction = "ha.failover"
	haFailoverAlertName   = "scheduler.failover"
)

// HAFailover describes one lease takeover.
type HAFailover struct {
	LockName               string
	PreviousHolder         string
	NewHolder              string
	PreviousAcquiredAt     time.Time
	PreviousLeaseExpiresAt time.Time
	At                     time.Time
}

// HAFailoverObserver is called once per takeover, by the replica that won it.
type HAFailoverObserver func(ctx context.Context, ev HAFailover)

// haFailoverObserver holds the process-wide observer; atomic so installing it
// is race-safe against schedulers already ticking.
var haFailoverObserver atomic.Pointer[HAFailoverObserver]

// SetHAFailoverObserver installs the process-wide takeover observer (nil
// clears it). Every HACoordinator in the process reports through it.
func SetHAFailoverObserver(fn HAFailoverObserver) {
	if fn == nil {
		haFailoverObserver.Store(nil)
		return
	}
	haFailoverObserver.Store(&fn)
}

func currentHAFailoverObserver() HAFailoverObserver {
	if p := haFailoverObserver.Load(); p != nil {
		return *p
	}
	return nil
}

// haFailoverAlertWindow is how long one previous holder's takeover suppresses
// further scheduler.failover alerts (audit rows are never suppressed).
const haFailoverAlertWindow = 10 * time.Minute

type haLeaseRow struct {
	holder     string
	acquiredAt time.Time
	expiresAt  time.Time
}

// readLease returns the current lease row for lockName, or nil when there is
// none (or it cannot be read: failover reporting is best-effort and must never
// affect lease arbitration).
func (c *HACoordinator) readLease(ctx context.Context, lockName string) *haLeaseRow {
	var holder, acquired, expires string
	q := fmt.Sprintf(`SELECT holder_id, acquired_at, lease_expires_at FROM ha_scheduler_locks WHERE lock_name = %s`, c.ph(1))
	err := c.db.QueryRowContext(ctx, q, lockName).Scan(&holder, &acquired, &expires)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			slog.Warn("ha coordinator: lease pre-read failed, failover not reported", "lock", lockName, "err", err)
		}
		return nil
	}
	row := &haLeaseRow{holder: holder}
	row.acquiredAt, _ = time.Parse(time.RFC3339, acquired)
	row.expiresAt, _ = time.Parse(time.RFC3339, expires)
	return row
}

// HAFailoverNotifier turns takeovers into an audit entry plus one alert.
// Each lock is arbitrated separately, so a hub dying with N scheduler locks
// yields N audit rows but ONE alert per previous holder per window.
type HAFailoverNotifier struct {
	audit   AuditProvider
	channel delivery.Channel
	target  string

	mu      sync.Mutex
	alerted map[string]time.Time // previous holder -> last alert time
}

// NewHAFailoverNotifier: audit and channel may be nil (that leg is skipped).
func NewHAFailoverNotifier(audit AuditProvider, channel delivery.Channel, target string) *HAFailoverNotifier {
	return &HAFailoverNotifier{audit: audit, channel: channel, target: target, alerted: map[string]time.Time{}}
}

// Observe is an HAFailoverObserver.
func (n *HAFailoverNotifier) Observe(ctx context.Context, ev HAFailover) {
	ctx = context.WithoutCancel(ctx)
	leaseAge := int64(ev.At.Sub(ev.PreviousAcquiredAt).Seconds())
	expiredFor := int64(ev.At.Sub(ev.PreviousLeaseExpiresAt).Seconds())
	slog.Warn("ha failover: lease taken over", "lock", ev.LockName,
		"previous_holder", ev.PreviousHolder, "new_holder", ev.NewHolder, "lease_age_seconds", leaseAge)

	if n.audit != nil {
		detail, _ := json.Marshal(map[string]any{
			"lock":                  ev.LockName,
			"previous_holder":       ev.PreviousHolder,
			"new_holder":            ev.NewHolder,
			"lease_age_seconds":     leaseAge,
			"lease_expired_seconds": expiredFor,
		})
		err := n.audit.AppendEntry(ctx, AuditEntry{
			Timestamp:     ev.At.Format(time.RFC3339),
			Action:        haFailoverAuditAction,
			ActorType:     "system",
			ActorID:       ev.NewHolder,
			ResourceType:  "scheduler_lock",
			ResourceID:    ev.LockName,
			Outcome:       AuditOutcomeSuccess,
			ChangeSummary: string(detail),
		})
		if err != nil {
			slog.Error("ha failover: audit append failed", "lock", ev.LockName, "err", err)
		}
	}

	if n.channel == nil || n.target == "" || !n.claimAlert(ev) {
		return
	}
	sendCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	err := n.channel.Send(sendCtx, delivery.Event{
		ID:       fmt.Sprintf("%s:%s:%s:%d", haFailoverAlertName, ev.LockName, ev.NewHolder, ev.At.Unix()),
		Target:   n.target,
		Subject:  haFailoverAlertName,
		Priority: "high",
		Message: fmt.Sprintf("%s: %s took over scheduler lock %q from %s (first of possibly several locks; previous lease age %ds, expired %ds ago)",
			haFailoverAlertName, ev.NewHolder, ev.LockName, ev.PreviousHolder, leaseAge, expiredFor),
		CreatedAt: ev.At,
	})
	if err != nil {
		slog.Error("ha failover: alert failed", "lock", ev.LockName, "err", delivery.RedactURLs(err.Error()))
	}
}

// claimAlert reports whether this takeover should alert, recording it so other
// locks taken from the same previous holder inside the window stay quiet.
func (n *HAFailoverNotifier) claimAlert(ev HAFailover) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	for h, t := range n.alerted {
		if ev.At.Sub(t) >= haFailoverAlertWindow {
			delete(n.alerted, h)
		}
	}
	if _, seen := n.alerted[ev.PreviousHolder]; seen {
		return false
	}
	n.alerted[ev.PreviousHolder] = ev.At
	return true
}
