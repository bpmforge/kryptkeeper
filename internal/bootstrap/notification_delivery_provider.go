// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/egress"
	"kryptkeeper/internal/notifications/delivery"
)

// deliveryNotificationProvider wraps the real delivery engine behind the NotificationProvider interface.
type deliveryNotificationProvider struct {
	// retrier wraps every channel's Send with persisted, backed-off retries
	// (W32-31); channel types are invisible to it.
	retrier *delivery.Retrier
	// retryPoll is how often due retries are claimed.
	retryPoll time.Duration
	// audit receives each final delivery outcome (W32-31); nil = none.
	audit AuditProvider
	rules notificationRuleStore
	mu    sync.RWMutex
	// In-memory delivery log, bounded to deliveryLogMax entries (oldest
	// dropped): it is a recent-activity view, not durable history.
	log *deliveryLog

	// Sends run on a fixed pool fed by a bounded queue, so a burst (a wide
	// rule matching a whole estate) cannot spawn a goroutine per message;
	// TestDelivery blocks on a full queue, throttling the caller.
	poolOnce sync.Once
	jobs     chan deliveryJob

	// escalate, when set, names a second channel to alert when a delivery
	// exhausts its retry budget. warnOnce keeps the "unconfigured" log to one
	// line rather than one per failure.
	escalate EscalationResolver
	warnOnce sync.Once
}

// EscalationResolver returns the escalation channel and target, resolved per
// call so config changes apply without a restart.
type EscalationResolver func(ctx context.Context) (channel, target string)

const (
	escalationIDPrefix  = "esc-"
	escalationSubject   = "Kryptkeeper notification delivery failed"
	escalationRowTarget = "escalation"
)

type deliveryJob struct {
	id    string
	event delivery.Event
}

const (
	auditActionDeliverySettled = "notification.delivery.settled"
	// retryPollInterval is the production cadence for claiming due retries.
	retryPollInterval = 5 * time.Second
)

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

// NewDeliveryNotificationProviderWithEscalation creates a notification provider
// backed by delivery channels. Every send is retried per policy with state in
// store, so a restart resumes pending retries; a delivery that exhausts its
// attempts is audited and raises one alert on the channel resolve names.
func NewDeliveryNotificationProviderWithEscalation(channels []delivery.Channel, policy delivery.Policy, store delivery.Store, audit AuditProvider, resolve EscalationResolver) NotificationProvider {
	// Poll finer than the base delay, or short delays would round up to the poll.
	poll := min(retryPollInterval, max(250*time.Millisecond, policy.Base/2))
	p := newDeliveryProvider(channels, policy, store, time.Now, newDBNotificationProviderFromEnv(), poll)
	p.escalate = resolve
	p.audit = audit
	// Eager: entries persisted before a restart are due without any new send.
	p.startPool()
	return p
}

func newDeliveryProvider(channels []delivery.Channel, policy delivery.Policy, store delivery.Store, now func() time.Time, rules notificationRuleStore, poll time.Duration) *deliveryNotificationProvider {
	p := &deliveryNotificationProvider{
		retrier:   delivery.NewRetrier(channels, policy, store, now),
		retryPoll: poll,
		rules:     rules,
		log:       newDeliveryLog(deliveryLogMax),
	}
	p.retrier.OnSettled = p.onSettled
	return p
}

func newDeliveryNotificationProviderForTest(channels []delivery.Channel, maxRetries int, retryDelay time.Duration, rules notificationRuleStore, resolve EscalationResolver) *deliveryNotificationProvider {
	pol := delivery.Policy{MaxAttempts: maxRetries, Base: retryDelay, Cap: retryDelay, Jitter: 0, Lease: time.Minute}
	p := newDeliveryProvider(channels, pol, nil, nil, rules, time.Millisecond)
	p.escalate = resolve
	return p
}

func newDeliveryNotificationProvider(channels []delivery.Channel, maxRetries int, rules notificationRuleStore) *deliveryNotificationProvider {
	pol := delivery.Policy{MaxAttempts: maxRetries, Base: 5 * time.Second, Cap: time.Minute}
	return newDeliveryProvider(channels, pol, nil, nil, rules, retryPollInterval)
}

// onSettled records a final outcome: the log row, an audit entry, and, for a
// failure, the single escalation alert. It also runs for deliveries resumed
// after a restart, which have no log row (setStatus ignores those).
func (p *deliveryNotificationProvider) onSettled(ctx context.Context, ev delivery.Event, res delivery.Result) {
	status := delivery.StatusFailed
	if res.Status == delivery.StatusSent {
		status = delivery.StatusSent
	}
	if reason, ok := egress.ExplainBlocked(res.Error); ok && status == delivery.StatusFailed {
		p.setFailureReason(ev.ID, reason)
	}
	p.setStatus(ev.ID, status)
	p.auditSettled(ctx, ev, res)
	if status == delivery.StatusFailed {
		p.escalateFailure(deliveryJob{id: ev.ID, event: ev}, res)
	}
}

func (p *deliveryNotificationProvider) auditSettled(ctx context.Context, ev delivery.Event, res delivery.Result) {
	if p.audit == nil {
		return
	}
	outcome := AuditOutcomeSuccess
	if res.Status != delivery.StatusSent {
		outcome = AuditOutcomeFailure
	}
	// The target is omitted: it may embed a webhook credential.
	detail := fmt.Sprintf("channel=%s attempts=%d", ev.Channel, res.Attempts)
	if res.Error != "" {
		detail += " error=" + delivery.RedactURLs(res.Error)
	}
	err := p.audit.AppendEntry(ctx, AuditEntry{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Action:        auditActionDeliverySettled,
		ActorType:     "system",
		ActorID:       "notification-delivery",
		ResourceType:  "notification",
		ResourceID:    ev.ID,
		Outcome:       outcome,
		ChangeSummary: detail,
	})
	if err != nil {
		slog.Warn("delivery audit append failed", "error", err.Error())
	}
}

func (p *deliveryNotificationProvider) GetSummary(_ context.Context) (NotificationSummary, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	pending, failures := 0, 0
	cutoff := time.Now().Add(-24 * time.Hour)
	p.log.each(func(d NotificationDelivery) {
		switch d.Status {
		case "queued", "sending", delivery.StatusRetrying:
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
	return p.SendEvent(ctx, delivery.Event{
		Channel: channel,
		Target:  target,
		Subject: "Kryptkeeper notification",
		Message: message,
	})
}

// SendEvent queues ev for delivery on ev.Channel/ev.Target. An empty ev.ID gets
// a generated one; callers sending several events must keep IDs unique because
// the delivery log is keyed by them.
func (p *deliveryNotificationProvider) SendEvent(ctx context.Context, ev delivery.Event) (NotificationTestDeliveryResult, error) {
	return p.enqueue(ctx, ev, ev.Target, false)
}

// enqueue logs and queues ev; rowTarget is what the delivery log shows, which
// escalations mask because the real target may embed a credential.
func (p *deliveryNotificationProvider) enqueue(ctx context.Context, ev delivery.Event, rowTarget string, nonBlocking bool) (NotificationTestDeliveryResult, error) {
	now := time.Now().UTC()
	id := ev.ID
	if id == "" {
		id = fmt.Sprintf("notif-%d", now.UnixNano())
	}
	ev.ID = id
	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = now
	}

	d := NotificationDelivery{
		ID:       id,
		Channel:  ev.Channel,
		Target:   rowTarget,
		Status:   "queued",
		QueuedAt: now.Format(time.RFC3339),
	}
	p.startPool()
	job := deliveryJob{id: id, event: ev}

	// Log before enqueueing so the worker's status update always finds the
	// entry.
	p.mu.Lock()
	p.log.add(d)
	p.mu.Unlock()

	if nonBlocking {
		select {
		case p.jobs <- job:
		default:
			p.setStatus(id, "failed")
			return NotificationTestDeliveryResult{}, errors.New("delivery queue full")
		}
		return NotificationTestDeliveryResult{ID: id, Channel: ev.Channel, Target: rowTarget, Status: "queued", QueuedAt: now.Format(time.RFC3339), Dispatched: true}, nil
	}
	select {
	case p.jobs <- job:
	case <-ctx.Done():
		p.setStatus(id, "failed")
		return NotificationTestDeliveryResult{}, ctx.Err()
	}

	return NotificationTestDeliveryResult{
		ID:       id,
		Channel:  ev.Channel,
		Target:   rowTarget,
		Status:   "queued",
		QueuedAt: now.Format(time.RFC3339),
		// Enqueued, not yet sent: the final outcome lands in the delivery log.
		Dispatched: true,
	}, nil
}

// QueueDashboard records an unrouted alert in the in-memory delivery log only,
// so it shows in GET /notifications/deliveries and pending_notifications while
// nothing is sent externally. The log is a bounded ring: under heavy traffic a
// queued row can be evicted before an operator sees it, which is acceptable
// for a recent-activity view (the audit trail keeps the durable record).
func (p *deliveryNotificationProvider) QueueDashboard(_ context.Context, _, _ string) NotificationDelivery {
	now := time.Now().UTC()
	d := NotificationDelivery{
		ID:       fmt.Sprintf("dash-%d", now.UnixNano()),
		Channel:  "dashboard",
		Target:   "unrouted",
		Status:   "queued",
		QueuedAt: now.Format(time.RFC3339),
	}
	p.mu.Lock()
	p.log.add(d)
	p.mu.Unlock()
	return d
}

// startPool launches the fixed send workers and the retry loop on first use.
// They live for the process, like the provider.
func (p *deliveryNotificationProvider) startPool() {
	p.poolOnce.Do(func() {
		p.jobs = make(chan deliveryJob, deliveryQueueDepth)
		for i := 0; i < deliverySendWorkers; i++ {
			go func() {
				for job := range p.jobs {
					// The first attempt runs here; later ones belong to the
					// retry loop. A non-final result leaves the row "retrying".
					res := p.retrier.Deliver(context.Background(), job.event)
					if res.Status == delivery.StatusRetrying {
						p.setStatusIf(job.id, "queued", delivery.StatusRetrying)
					}
				}
			}()
		}
		go p.retrier.Run(context.Background(), p.retryPoll)
	})
}

// escalateFailure alerts a second channel about an exhausted delivery. The
// alert is enqueued without blocking this worker (a full queue drops it with a
// log line rather than stalling the pool), never carries the failed event's
// body, and an escalation's own failure never escalates again.
func (p *deliveryNotificationProvider) escalateFailure(job deliveryJob, result delivery.Result) {
	if strings.HasPrefix(job.id, escalationIDPrefix) {
		return
	}
	if p.escalate == nil {
		p.warnOnce.Do(func() {
			slog.Warn("delivery failed and no escalation channel is configured", "channel", job.event.Channel)
		})
		return
	}
	ch, target := p.escalate(context.Background())
	if ch == "" || target == "" || ch == job.event.Channel {
		p.warnOnce.Do(func() {
			slog.Warn("delivery failed and escalation is unset or targets the failing channel", "channel", job.event.Channel)
		})
		return
	}
	rowTarget := escalationRowTarget
	if ch == "email" {
		rowTarget = target
	}
	ev := delivery.Event{
		ID:       escalationIDPrefix + job.id,
		Channel:  ch,
		Target:   target,
		Subject:  escalationSubject,
		Message:  fmt.Sprintf("channel %s failed after %d attempt(s): %s", result.Channel, result.Attempts, delivery.RedactURLs(result.Error)),
		Priority: "high",
	}
	if _, err := p.enqueue(context.Background(), ev, rowTarget, true); err != nil {
		slog.Warn("escalation dropped", "channel", ch, "error", err.Error())
	}
}

func (p *deliveryNotificationProvider) setFailureReason(id, reason string) {
	p.mu.Lock()
	if d := p.log.find(id); d != nil {
		d.FailureReason = reason
	}
	p.mu.Unlock()
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

// setStatusIf moves a row from one status to another only if it still has the
// first: the retry loop may already have settled it by the time the first
// attempt's caller reports "retrying".
func (p *deliveryNotificationProvider) setStatusIf(id, from, to string) {
	p.mu.Lock()
	if d := p.log.find(id); d != nil && d.Status == from {
		d.Status = to
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

func (p *deliveryNotificationProvider) CreateRuleForTenant(ctx context.Context, tenant, name string, thresholdDays int, channel string, target string) (NotificationRule, error) {
	if p.rules == nil {
		return NotificationRule{}, errNotificationRulesUnavailable
	}
	// A rule store that cannot record the owner must not silently create an
	// unowned (default-tenant) rule on a tenant's behalf.
	tc, ok := p.rules.(tenantRuleCreator)
	if !ok {
		return NotificationRule{}, errNotificationRulesUnavailable
	}
	return tc.CreateRuleForTenant(ctx, tenant, name, thresholdDays, channel, target)
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
