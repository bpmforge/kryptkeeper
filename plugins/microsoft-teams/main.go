// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command microsoft-teams is a notify plugin that posts an alert to a Teams
// channel through a Workflows webhook: the Power Automate trigger "When a
// Teams webhook request is received". Office 365 Connector webhooks are
// retired, so the payload is not a MessageCard; it is the Workflows format,
//
//	{"type":"message","attachments":[{"contentType":
//	  "application/vnd.microsoft.card.adaptive","contentUrl":null,
//	  "content":{ ...Adaptive Card... }}]}
//
// POSTed to the flow's callback URL, which is the credential (it carries a
// signature, so it is secret). The trigger answers 2xx (202 for a typical
// flow) and has no alert identity, so provider_id is empty and a ".resolved"
// class is posted as one more card rather than clearing anything.
// https://learn.microsoft.com/en-us/connectors/teams/ (TeamsIncomingWebhookTrigger)
// https://adaptivecards.io/explorer/ (card schema, version 1.2)
package main

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/notify"
)

func init() { notify.Register(teams{}) }

func main() {}

type teams struct{}

const (
	maxTitle = 300
	maxBody  = 4000
	maxFacts = 20
	maxValue = 500
)

// color is an Adaptive Card TextBlock color.
func color(sev string, resolved bool) string {
	switch {
	case resolved:
		return "Good"
	case sev == abi.SeverityCritical || sev == abi.SeverityHigh:
		return "Attention"
	case sev == abi.SeverityMedium:
		return "Warning"
	}
	return "Accent"
}

type fact struct {
	Title string `json:"title"`
	Value string `json:"value"`
}

func card(req abi.NotifySendRequest) map[string]any {
	resolved := strings.HasSuffix(req.EventClass, abi.ResolvedSuffix)
	title := req.Title
	if resolved {
		title = "Resolved: " + title
	}
	body := []map[string]any{{
		"type": "TextBlock", "text": notify.Truncate(title, maxTitle), "weight": "Bolder", "size": "Medium",
		"wrap": true, "color": color(req.Severity, resolved),
	}}
	if req.Body != "" {
		body = append(body, map[string]any{"type": "TextBlock", "text": notify.Truncate(req.Body, maxBody), "wrap": true})
	}
	keys := make([]string, 0, len(req.Fields))
	for k := range req.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	facts := []fact{}
	for _, k := range keys {
		if len(facts) == maxFacts {
			break
		}
		facts = append(facts, fact{Title: notify.Truncate(k, 100), Value: notify.Truncate(req.Fields[k], maxValue)})
	}
	if len(facts) > 0 {
		body = append(body, map[string]any{"type": "FactSet", "facts": facts})
	}
	c := map[string]any{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"type":    "AdaptiveCard",
		"version": "1.2",
		"body":    body,
	}
	if u, err := url.Parse(req.DeepLink); err == nil && u.Scheme == "https" {
		c["actions"] = []map[string]any{{"type": "Action.OpenUrl", "title": "Open in Kryptkeeper", "url": req.DeepLink}}
	}
	return c
}

func (teams) Send(h *delivery.Host, req abi.NotifySendRequest) (abi.NotifySendResult, error) {
	raw, err := json.Marshal(map[string]any{
		"type": "message",
		"attachments": []map[string]any{{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"contentUrl":  nil,
			"content":     card(req),
		}},
	})
	if err != nil {
		return abi.NotifySendResult{}, err
	}
	resp, err := h.HTTP(abi.HTTPRequest{
		Method:  "POST",
		URL:     req.Credential["webhook_url"],
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    raw,
	})
	if err != nil {
		return abi.NotifySendResult{}, err
	}
	switch {
	case resp.Status >= 200 && resp.Status < 300:
		return abi.NotifySendResult{Delivered: true}, nil
	case resp.Status == 429:
		return notify.Refused(resp, "rate limited"), nil
	case resp.Status == 401 || resp.Status == 403:
		return notify.Refused(resp, "the flow refused the request (check who may trigger it)"), nil
	}
	return notify.Refused(resp, "the flow did not accept the card"), nil
}
