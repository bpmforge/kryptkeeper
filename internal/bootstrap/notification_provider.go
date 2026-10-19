// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"os"
	"strings"

	"kryptkeeper/internal/logging"
)

const notificationProviderEnv = "APP_NOTIFICATION_PROVIDER"

const (
	notificationProviderFile = "file"
	notificationProviderDB   = "db"
	// notificationProviderDelivery is wired in cmd/kryptkeeper/main.go.
	notificationProviderDelivery = "delivery"
)

var notificationProviderWarnf = logging.Warnf

type NotificationSummary struct {
	PendingNotifications int `json:"pending_notifications"`
	OwnershipEscalations int `json:"ownership_escalations"`
	DeliveryFailures24h  int `json:"delivery_failures_24h"`
}

type NotificationDelivery struct {
	ID       string `json:"id"`
	Channel  string `json:"channel"`
	Target   string `json:"target"`
	Status   string `json:"status"`
	QueuedAt string `json:"queued_at"`
	// FailureReason is set only for failures with a known operator-actionable
	// cause (today: the egress guard refusing the destination). Raw delivery
	// errors stay in the log.
	FailureReason string `json:"failure_reason,omitempty"`
}

type NotificationDeliveryQuery struct {
	Status  string
	Channel string
	Limit   int
	Cursor  int
}

type NotificationDeliveryResult struct {
	Deliveries []NotificationDelivery
	Total      int
	Limit      int
	NextCursor *int
	PrevCursor *int
}

type NotificationDeliveryActionResult struct {
	DeliveryID string `json:"delivery_id"`
	Status     string `json:"status"`
	Note       string `json:"note,omitempty"`
	Reason     string `json:"reason,omitempty"`
	RetryJobID string `json:"retry_job_id,omitempty"`
	UpdatedAt  string `json:"updated_at,omitempty"`
	QueuedAt   string `json:"queued_at,omitempty"`
}

type NotificationTestDeliveryResult struct {
	ID       string `json:"id"`
	Channel  string `json:"channel"`
	Target   string `json:"target"`
	Status   string `json:"status"`
	QueuedAt string `json:"queued_at"`
	// Dispatched is true only when the message was handed to a provider that
	// actually sends (asynchronously: the final outcome is in the delivery
	// log). False means it was merely recorded, and Note says why.
	Dispatched bool   `json:"dispatched"`
	Note       string `json:"note,omitempty"`
}

// notDispatchedNote explains a Dispatched=false result.
func notDispatchedNote(provider string) string {
	return "not delivered: notification provider " + provider +
		" only records messages and never sends; set APP_NOTIFICATION_PROVIDER=delivery to send"
}

type NotificationRule struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ThresholdDays int    `json:"threshold_days"`
	Channel       string `json:"channel"`
	Target        string `json:"target"`
	Enabled       bool   `json:"enabled"`
	CreatedAt     string `json:"created_at"`
	// Tenant is the creator's tenant ("" on legacy rows = default tenant). Not
	// serialised: ownership is enforced server-side, not shown to clients.
	Tenant string `json:"-"`
}

// tenantRuleCreator is implemented by providers that persist a rule's owning
// tenant. Optional so providers that cannot (test doubles) keep working; every
// production provider implements it.
type tenantRuleCreator interface {
	CreateRuleForTenant(ctx context.Context, tenant, name string, thresholdDays int, channel, target string) (NotificationRule, error)
}

type NotificationProvider interface {
	GetSummary(context.Context) (NotificationSummary, error)
	ListDeliveries(context.Context, NotificationDeliveryQuery) (NotificationDeliveryResult, error)
	AckDelivery(ctx context.Context, deliveryID string, note string) (NotificationDeliveryActionResult, error)
	RetryDelivery(ctx context.Context, deliveryID string, reason string) (NotificationDeliveryActionResult, error)
	TestDelivery(ctx context.Context, channel string, target string, message string) (NotificationTestDeliveryResult, error)
	// Delivers reports whether TestDelivery actually sends through a channel.
	// Providers that only record (file, db) return false, and callers that
	// would otherwise report an alert as sent (the renewal scheduler) must
	// not.
	Delivers() bool
	// Name is the provider's APP_NOTIFICATION_PROVIDER value, for messages.
	Name() string
	ListRules(ctx context.Context) ([]NotificationRule, error)
	CreateRule(ctx context.Context, name string, thresholdDays int, channel string, target string) (NotificationRule, error)
	UpdateRule(ctx context.Context, id string, enabled bool, target string) (NotificationRule, error)
	DeleteRule(ctx context.Context, id string) error
}

func NewNotificationProviderFromEnv() NotificationProvider {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv(notificationProviderEnv)))
	switch mode {
	case "", notificationProviderFile:
		return newFileNotificationProvider()
	case notificationProviderDB:
		return newDBNotificationProviderFromEnv()
	default:
		notificationProviderWarnf("warning: unknown APP_NOTIFICATION_PROVIDER=%q; falling back to file", mode)
		return newFileNotificationProvider()
	}
}
