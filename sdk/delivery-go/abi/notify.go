// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package abi

// OpNotifySend is the one operation of the notify kind: deliver one alert to
// the plugin's service (Teams, PagerDuty, Opsgenie, ...).
const OpNotifySend = "notify.send"

// ResolvedSuffix marks an event class that clears an earlier alert with the
// same DedupeKey instead of raising one ("certificate.expiry.resolved"). The
// request has no separate flag, so incident services that can close an alert
// (PagerDuty resolve, Opsgenie close) key off this; chat services post it as
// an ordinary message.
const ResolvedSuffix = ".resolved"

// Severities a notify request carries, the hub's priority vocabulary.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// NotifySendRequest is one alert. Fields are non-secret context rows (common
// name, fingerprint, expiry); the hub never puts key material or credentials
// in them. DedupeKey is stable per underlying problem, so services that
// de-duplicate (PagerDuty dedup_key, Opsgenie alias) fold repeats into one.
type NotifySendRequest struct {
	Invocation
	EventClass string            `json:"event_class"`
	Severity   string            `json:"severity"`
	Title      string            `json:"title"`
	Body       string            `json:"body,omitempty"`
	Fields     map[string]string `json:"fields,omitempty"`
	DeepLink   string            `json:"deep_link,omitempty"`
	DedupeKey  string            `json:"dedupe_key"`
}

// NotifySendResult reports what the service said. Delivered is false when the
// service refused or could not take the alert; RetryAfterSeconds carries a
// service rate-limit hint (Retry-After) for the retry logic of W38-03.
type NotifySendResult struct {
	Delivered         bool   `json:"delivered"`
	ProviderID        string `json:"provider_id,omitempty"`
	RetryAfterSeconds int    `json:"retry_after_seconds,omitempty"`
	// Detail is a short reason when Delivered is false.
	Detail string `json:"detail,omitempty"`
}
