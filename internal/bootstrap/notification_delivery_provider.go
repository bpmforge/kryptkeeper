// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"kryptkeeper/internal/notifications/delivery"
)

// deliveryNotificationProvider wraps the real delivery engine behind the NotificationProvider interface.
type deliveryNotificationProvider struct {
	worker *delivery.Worker
	rules  notificationRuleStore
	mu     sync.RWMutex
	// In-memory delivery log, bounded to deliveryLogMax entries (oldest
	// dropped): it is a recent-activity view, not durable history.
	log *deliveryLog

	// Sends run on a fixed pool fed by a bounded queue, so a burst (a wide
	// rule matching a whole estate) cannot spawn a goroutine per message;
	// TestDelivery blocks on a full queue, throttling the caller.
	poolOnce sync.Once
	jobs     chan deliveryJob
}

type deliveryJob struct {
	id    string
	event delivery.Event
}

const (
	// deliveryLogMax bounds the in-memory delivery log (ring buffer).
	deliveryLogMax = 10000
	// deliverySendWorkers is the number of concurrent sends to the relay.
	deliverySendWorkers = 8
	// deliveryQueueDepth is how many accepted-but-unsent messages may wait.
	deliveryQueueDepth = 1024
)

// deliveryLog is a fixed-capacity ring of deliveries, oldest first. Not
// goroutine-safe: callers hold the provider's mutex.
type deliveryLog struct {
	buf   []NotificationDelivery
	start int
	n     int
}

func newDeliveryLog(capacity int) *deliveryLog {
	return &deliveryLog{buf: make([]NotificationDelivery, capacity)}
}

func (l *deliveryLog) add(d NotificationDelivery) {
	if l.n < len(l.buf) {
		l.buf[(l.start+l.n)%len(l.buf)] = d
		l.n++
		return
	}
	l.buf[l.start] = d // overwrite the oldest
	l.start = (l.start + 1) % len(l.buf)
}

func (l *deliveryLog) at(i int) *NotificationDelivery { return &l.buf[(l.start+i)%len(l.buf)] }

func (l *deliveryLog) find(id string) *NotificationDelivery {
	for i := 0; i < l.n; i++ {
		if d := l.at(i); d.ID == id {
			return d
		}
	}
	return nil
}

// each visits entries oldest first.
func (l *deliveryLog) each(fn func(NotificationDelivery)) {
	for i := 0; i < l.n; i++ {
		fn(*l.at(i))
	}
}

var errNotificationRulesUnavailable = errors.New("notification rule store unavailable")

// notificationRuleStore is the rule-CRUD slice of NotificationProvider.
type notificationRuleStore interface {
	ListRules(ctx context.Context) ([]NotificationRule, error)
	CreateRule(ctx context.Context, name string, thresholdDays int, channel string, target string) (NotificationRule, error)
	UpdateRule(ctx context.Context, id string, enabled bool, target string) (NotificationRule, error)
	DeleteRule(ctx context.Context, id string) error
}

// NewDeliveryNotificationProvider creates a notification provider backed by
// real delivery channels, with alert rules persisted in the notification
// database (the same store APP_NOTIFICATION_PROVIDER=db uses).
func NewDeliveryNotificationProvider(channels []delivery.Channel, maxRetries int) NotificationProvider {
	return newDeliveryNotificationProvider(channels, maxRetries, newDBNotificationProviderFromEnv())
}

func newDeliveryNotificationProvider(channels []delivery.Channel, maxRetries int, rules notificationRuleStore) *deliveryNotificationProvider {
	worker := delivery.NewWorker(channels, maxRetries, 5*time.Second)
	return &deliveryNotificationProvider{worker: worker, rules: rules, log: newDeliveryLog(deliveryLogMax)}
}

func (p *deliveryNotificationProvider) GetSummary(_ context.Context) (NotificationSummary, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	pending, failures := 0, 0
	cutoff := time.Now().Add(-24 * time.Hour)
	p.log.each(func(d NotificationDelivery) {
		switch d.Status {
		case "queued", "sending":
			pending++
		case "failed":
			if t, err := time.Parse(time.RFC3339, d.QueuedAt); err == nil && t.After(cutoff) {
				failures++
			}
		}
	})
	return NotificationSummary{
		PendingNotifications: pending,
		DeliveryFailures24h:  failures,
	}, nil
}

func (p *deliveryNotificationProvider) ListDeliveries(_ context.Context, q NotificationDeliveryQuery) (NotificationDeliveryResult, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	filtered := make([]NotificationDelivery, 0, p.log.n)
	p.log.each(func(d NotificationDelivery) {
		if q.Status != "" && d.Status != q.Status {
			return
		}
		if q.Channel != "" && d.Channel != q.Channel {
			return
		}
		filtered = append(filtered, d)
	})
	result := paginate(filtered, q.Limit, q.Cursor, 25, 100)
	return NotificationDeliveryResult{
		Deliveries: result.Items,
		Total:      result.Total,
		Limit:      result.Limit,
		NextCursor: result.NextCursor,
		PrevCursor: result.PrevCursor,
	}, nil
}

func (p *deliveryNotificationProvider) AckDelivery(_ context.Context, deliveryID string, note string) (NotificationDeliveryActionResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if d := p.log.find(deliveryID); d != nil {
		d.Status = "acknowledged"
		return NotificationDeliveryActionResult{
			DeliveryID: deliveryID,
			Status:     "acknowledged",
			Note:       note,
			UpdatedAt:  time.Now().UTC().Format(time.RFC3339),
		}, nil
	}
	return NotificationDeliveryActionResult{}, fmt.Errorf("delivery %s not found", deliveryID)
}

func (p *deliveryNotificationProvider) RetryDelivery(ctx context.Context, deliveryID string, reason string) (NotificationDeliveryActionResult, error) {
	p.mu.RLock()
	var original NotificationDelivery
	found := false
	if d := p.log.find(deliveryID); d != nil {
		original, found = *d, true
	}
	p.mu.RUnlock()

	if !found {
		return NotificationDeliveryActionResult{}, fmt.Errorf("delivery %s not found", deliveryID)
	}

	result, err := p.TestDelivery(ctx, original.Channel, original.Target, reason)
	if err != nil {
		return NotificationDeliveryActionResult{}, err
	}

	return NotificationDeliveryActionResult{
		DeliveryID: deliveryID,
		RetryJobID: result.ID,
		Status:     "queued",
		Reason:     reason,
		QueuedAt:   result.QueuedAt,
	}, nil
}

// Delivers is true: TestDelivery hands the message to the delivery worker.
func (p *deliveryNotificationProvider) Delivers() bool { return true }

func (p *deliveryNotificationProvider) Name() string { return notificationProviderDelivery }

func (p *deliveryNotificationProvider) TestDelivery(ctx context.Context, channel string, target string, message string) (NotificationTestDeliveryResult, error) {
	now := time.Now().UTC()
	id := fmt.Sprintf("notif-%d", now.UnixNano())

	d := NotificationDelivery{
		ID:       id,
		Channel:  channel,
		Target:   target,
		Status:   "queued",
		QueuedAt: now.Format(time.RFC3339),
	}
	p.startPool()
	job := deliveryJob{id: id, event: delivery.Event{
		ID:        id,
		Channel:   channel,
		Target:    target,
		Subject:   "Kryptkeeper notification",
		Message:   message,
		CreatedAt: now,
	}}

	// Log before enqueueing so the worker's status update always finds the
	// entry.
	p.mu.Lock()
	p.log.add(d)
	p.mu.Unlock()

	select {
	case p.jobs <- job:
	case <-ctx.Done():
		p.setStatus(id, "failed")
		return NotificationTestDeliveryResult{}, ctx.Err()
	}

	return NotificationTestDeliveryResult{
		ID:       id,
		Channel:  channel,
		Target:   target,
		Status:   "queued",
		QueuedAt: now.Format(time.RFC3339),
		// Enqueued, not yet sent: the final outcome lands in the delivery log.
		Dispatched: true,
	}, nil
}

// startPool launches the fixed send workers on first use. They live for the
// process, like the provider.
func (p *deliveryNotificationProvider) startPool() {
	p.poolOnce.Do(func() {
		p.jobs = make(chan deliveryJob, deliveryQueueDepth)
		for i := 0; i < deliverySendWorkers; i++ {
			go func() {
				for job := range p.jobs {
					result := p.worker.Deliver(context.Background(), job.event)
					status := "failed"
					if result.Status == "sent" {
						status = "sent"
					}
					p.setStatus(job.id, status)
				}
			}()
		}
	})
}

// setStatus updates a delivery still in the bounded log; an entry already
// dropped from the ring is ignored.
func (p *deliveryNotificationProvider) setStatus(id, status string) {
	p.mu.Lock()
	if d := p.log.find(id); d != nil {
		d.Status = status
	}
	p.mu.Unlock()
}

// Rule CRUD is delegated to a durable store: rules created through the API
// must survive a restart and be visible to the renewal scheduler, which reads
// them through this same provider.
func (p *deliveryNotificationProvider) ListRules(ctx context.Context) ([]NotificationRule, error) {
	if p.rules == nil {
		return nil, errNotificationRulesUnavailable
	}
	return p.rules.ListRules(ctx)
}

func (p *deliveryNotificationProvider) CreateRule(ctx context.Context, name string, thresholdDays int, channel string, target string) (NotificationRule, error) {
	if p.rules == nil {
		return NotificationRule{}, errNotificationRulesUnavailable
	}
	return p.rules.CreateRule(ctx, name, thresholdDays, channel, target)
}

func (p *deliveryNotificationProvider) UpdateRule(ctx context.Context, id string, enabled bool, target string) (NotificationRule, error) {
	if p.rules == nil {
		return NotificationRule{}, errNotificationRulesUnavailable
	}
	return p.rules.UpdateRule(ctx, id, enabled, target)
}

func (p *deliveryNotificationProvider) DeleteRule(ctx context.Context, id string) error {
	if p.rules == nil {
		return errNotificationRulesUnavailable
	}
	return p.rules.DeleteRule(ctx, id)
}
