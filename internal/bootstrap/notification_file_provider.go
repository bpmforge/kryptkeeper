// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type fileNotificationProvider struct {
	mu    sync.Mutex
	rules map[string]NotificationRule
}

func newFileNotificationProvider() NotificationProvider {
	return &fileNotificationProvider{rules: make(map[string]NotificationRule)}
}

func (p *fileNotificationProvider) GetSummary(_ context.Context) (NotificationSummary, error) {
	return NotificationSummary{
		PendingNotifications: envInt("APP_NOTIFICATIONS_PENDING", 0),
		OwnershipEscalations: envInt("APP_NOTIFICATIONS_ESCALATIONS", 0),
		DeliveryFailures24h:  envInt("APP_NOTIFICATIONS_FAILURES_24H", 0),
	}, nil
}

func (p *fileNotificationProvider) ListDeliveries(_ context.Context, query NotificationDeliveryQuery) (NotificationDeliveryResult, error) {
	deliveries := seedNotificationDeliveries()
	filtered := make([]NotificationDelivery, 0, len(deliveries))
	for _, d := range deliveries {
		if query.Status != "" && !strings.EqualFold(d.Status, query.Status) {
			continue
		}
		if query.Channel != "" && !strings.EqualFold(d.Channel, query.Channel) {
			continue
		}
		filtered = append(filtered, d)
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].QueuedAt > filtered[j].QueuedAt
	})

	result := paginate(filtered, query.Limit, query.Cursor, 25, 100)
	return NotificationDeliveryResult{
		Deliveries: result.Items,
		Total:      result.Total,
		Limit:      result.Limit,
		NextCursor: result.NextCursor,
		PrevCursor: result.PrevCursor,
	}, nil
}

func (p *fileNotificationProvider) AckDelivery(_ context.Context, deliveryID string, note string) (NotificationDeliveryActionResult, error) {
	return NotificationDeliveryActionResult{
		DeliveryID: deliveryID,
		Status:     "acknowledged",
		Note:       note,
		UpdatedAt:  time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (p *fileNotificationProvider) RetryDelivery(_ context.Context, deliveryID string, reason string) (NotificationDeliveryActionResult, error) {
	now := time.Now().UTC()
	return NotificationDeliveryActionResult{
		DeliveryID: deliveryID,
		RetryJobID: fmt.Sprintf("retry-%d", now.UnixNano()),
		Status:     "queued",
		Reason:     reason,
		QueuedAt:   now.Format(time.RFC3339),
	}, nil
}

// Delivers is false: the file provider keeps rules and a seeded delivery
// fixture in memory and sends nothing.
func (p *fileNotificationProvider) Delivers() bool { return false }

func (p *fileNotificationProvider) Name() string { return notificationProviderFile }

func (p *fileNotificationProvider) TestDelivery(_ context.Context, channel string, target string, _ string) (NotificationTestDeliveryResult, error) {
	now := time.Now().UTC()
	return NotificationTestDeliveryResult{
		ID:         fmt.Sprintf("notif-%d", now.UnixNano()),
		Channel:    channel,
		Target:     target,
		Status:     "queued",
		QueuedAt:   now.Format(time.RFC3339),
		Dispatched: false,
		Note:       notDispatchedNote(notificationProviderFile),
	}, nil
}

func (p *fileNotificationProvider) ListRules(_ context.Context) ([]NotificationRule, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]NotificationRule, 0, len(p.rules))
	for _, r := range p.rules {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out, nil
}

func (p *fileNotificationProvider) CreateRule(ctx context.Context, name string, thresholdDays int, channel string, target string) (NotificationRule, error) {
	return p.CreateRuleForTenant(ctx, "", name, thresholdDays, channel, target)
}

func (p *fileNotificationProvider) CreateRuleForTenant(_ context.Context, tenant, name string, thresholdDays int, channel string, target string) (NotificationRule, error) {
	now := time.Now().UTC()
	r := NotificationRule{
		ID:            fmt.Sprintf("rule-%d", now.UnixNano()),
		Name:          name,
		ThresholdDays: thresholdDays,
		Channel:       channel,
		Target:        target,
		Enabled:       true,
		CreatedAt:     now.Format(time.RFC3339),
		Tenant:        tenant,
	}
	p.mu.Lock()
	p.rules[r.ID] = r
	p.mu.Unlock()
	return r, nil
}

func (p *fileNotificationProvider) UpdateRule(_ context.Context, id string, enabled bool, target string) (NotificationRule, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r, ok := p.rules[id]
	if !ok {
		return NotificationRule{}, fmt.Errorf("rule %q not found", id)
	}
	r.Enabled = enabled
	r.Target = target
	p.rules[id] = r
	return r, nil
}

func (p *fileNotificationProvider) DeleteRule(_ context.Context, id string) error {
	p.mu.Lock()
	delete(p.rules, id)
	p.mu.Unlock()
	return nil
}

func seedNotificationDeliveries() []NotificationDelivery {
	return []NotificationDelivery{
		{ID: "notif-failed-1", Channel: "email", Target: "ops@ops.internal", Status: "failed", QueuedAt: "2026-04-07T01:10:00Z"},
		{ID: "notif-queued-1", Channel: "slack", Target: "#ops-internal", Status: "queued", QueuedAt: "2026-04-07T01:05:00Z"},
		{ID: "notif-delivered-1", Channel: "webhook", Target: "https://hooks.internal/notify", Status: "delivered", QueuedAt: "2026-04-07T01:00:00Z"},
	}
}
