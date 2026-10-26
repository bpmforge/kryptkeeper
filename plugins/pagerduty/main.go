// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command pagerduty is a notify plugin that raises and clears PagerDuty
// alerts through the Events API v2.
//
// Trigger: POST {api_base}/v2/enqueue with routing_key, event_action
// "trigger", dedup_key and payload{summary, source, severity, custom_details}.
// An event class ending in ".resolved" sends event_action "resolve" with the
// same dedup_key, which closes the alert. summary is limited to 1024
// characters and dedup_key to 255; severity is one of critical, error,
// warning, info; 202 means accepted, 400 is not retried, 429 and 5xx are.
// https://docs.pagerduty.com/developer/send-alert-event
// https://docs.pagerduty.com/developer/events-api-v2-overview
//
// api_base defaults to https://events.pagerduty.com and is a credential field
// so a stand-in receiver can be targeted; the host it names is the only one
// the plugin may reach.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strings"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/notify"
)

func init() { notify.Register(pd{}) }

func main() {}

type pd struct{}

const (
	maxSummary = 1024
	maxDedup   = 255
	source     = "kryptkeeper"
)

// severity maps the hub's vocabulary onto the Events API's.
func severity(s string) string {
	switch s {
	case abi.SeverityCritical:
		return "critical"
	case abi.SeverityHigh:
		return "error"
	case abi.SeverityMedium:
		return "warning"
	}
	return "info"
}

// dedupKey keeps the caller's key when it fits, and otherwise a stable hash of
// it, so two long keys sharing a prefix never fold into one alert.
func dedupKey(k string) string {
	if len(k) <= maxDedup {
		return k
	}
	sum := sha256.Sum256([]byte(k))
	return "kk-" + hex.EncodeToString(sum[:])
}

type event struct {
	RoutingKey  string   `json:"routing_key"`
	EventAction string   `json:"event_action"`
	DedupKey    string   `json:"dedup_key,omitempty"`
	Payload     *payload `json:"payload,omitempty"`
	Links       []link   `json:"links,omitempty"`
}

type payload struct {
	Summary       string         `json:"summary"`
	Source        string         `json:"source"`
	Severity      string         `json:"severity"`
	Class         string         `json:"class,omitempty"`
	CustomDetails map[string]any `json:"custom_details,omitempty"`
}

type link struct {
	Href string `json:"href"`
	Text string `json:"text,omitempty"`
}

func build(req abi.NotifySendRequest) (event, error) {
	key := dedupKey(req.DedupeKey)
	if key == "" {
		return event{}, errors.New("dedupe_key is required so PagerDuty can fold repeats and resolve the alert")
	}
	ev := event{RoutingKey: req.Credential["routing_key"], DedupKey: key, EventAction: "trigger"}
	if strings.HasSuffix(req.EventClass, abi.ResolvedSuffix) {
		ev.EventAction = "resolve"
		return ev, nil
	}
	summary := req.Title
	if req.Body != "" {
		summary += ": " + req.Body
	}
	details := map[string]any{}
	for k, v := range req.Fields {
		details[k] = v
	}
	ev.Payload = &payload{
		Summary: notify.Truncate(summary, maxSummary), Source: source, Severity: severity(req.Severity),
		Class: req.EventClass, CustomDetails: details,
	}
	if u, err := url.Parse(req.DeepLink); err == nil && u.Scheme == "https" {
		ev.Links = []link{{Href: req.DeepLink, Text: "Open in Kryptkeeper"}}
	}
	return ev, nil
}

func (pd) Send(h *delivery.Host, req abi.NotifySendRequest) (abi.NotifySendResult, error) {
	ev, err := build(req)
	if err != nil {
		return abi.NotifySendResult{}, err
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return abi.NotifySendResult{}, err
	}
	resp, err := h.HTTP(abi.HTTPRequest{
		Method:  "POST",
		URL:     strings.TrimRight(req.Credential["api_base"], "/") + "/v2/enqueue",
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    body,
	})
	if err != nil {
		return abi.NotifySendResult{}, err
	}
	switch {
	case resp.Status == 202 || resp.Status == 200:
		// The response may echo a generated dedup_key; ours was supplied, so it
		// is the provider id either way.
		return abi.NotifySendResult{Delivered: true, ProviderID: ev.DedupKey}, nil
	case resp.Status == 400:
		return notify.Refused(resp, "the event was rejected as malformed (not retried by PagerDuty's guidance)"), nil
	case resp.Status == 429:
		return notify.Refused(resp, "rate limited"), nil
	}
	return notify.Refused(resp, "PagerDuty did not accept the event"), nil
}
