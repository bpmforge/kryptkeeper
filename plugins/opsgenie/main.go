// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Command opsgenie is a notify plugin that creates and closes Opsgenie
// alerts through the Alerts API.
//
// Create: POST {api_base}/v2/alerts with Authorization "GenieKey <key>" and
// {message (<=130), alias (<=512, also the de-duplication key), description
// (<=15000), priority P1..P5, details (<=8000 characters in all), source
// (<=100)}; 202 means accepted and the body carries a requestId.
// Close: POST {api_base}/v2/alerts/{alias}/close?identifierType=alias with
// {source, note}; the alias is URL-encoded in the path.
// https://docs.opsgenie.com/docs/alert-api
//
// api_base defaults to the US instance, https://api.opsgenie.com; set
// https://api.eu.opsgenie.com for the EU instance.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strings"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/notify"
)

func init() { notify.Register(og{}) }

func main() {}

type og struct{}

const (
	maxMessage     = 130
	maxAlias       = 512
	maxDescription = 15000
	maxDetails     = 8000
	source         = "kryptkeeper"
)

// priority maps the hub's vocabulary onto P1 (highest) to P5.
func priority(s string) string {
	switch s {
	case abi.SeverityCritical:
		return "P1"
	case abi.SeverityHigh:
		return "P2"
	case abi.SeverityMedium:
		return "P3"
	}
	return "P4"
}

// alias keeps the caller's key when it fits and otherwise a stable hash, so
// long keys sharing a prefix never fold into one alert.
func alias(k string) string {
	if len(k) <= maxAlias {
		return k
	}
	sum := sha256.Sum256([]byte(k))
	return "kk-" + hex.EncodeToString(sum[:])
}

// details keeps the fields that fit in the 8000-character budget, in key
// order, so the cut is the same every time.
func details(fields map[string]string) map[string]string {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := map[string]string{}
	used := 0
	for _, k := range keys {
		if used+len(k)+len(fields[k]) > maxDetails {
			break
		}
		used += len(k) + len(fields[k])
		out[k] = fields[k]
	}
	return out
}

type createBody struct {
	Message     string            `json:"message"`
	Alias       string            `json:"alias"`
	Description string            `json:"description,omitempty"`
	Priority    string            `json:"priority"`
	Details     map[string]string `json:"details,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Source      string            `json:"source"`
}

type closeBody struct {
	Source string `json:"source"`
	Note   string `json:"note,omitempty"`
}

func (og) Send(h *delivery.Host, req abi.NotifySendRequest) (abi.NotifySendResult, error) {
	a := alias(req.DedupeKey)
	if a == "" {
		return abi.NotifySendResult{}, errors.New("dedupe_key is required so Opsgenie can fold repeats and close the alert")
	}
	base := strings.TrimRight(req.Credential["api_base"], "/")
	var target string
	var body any
	if strings.HasSuffix(req.EventClass, abi.ResolvedSuffix) {
		target = base + "/v2/alerts/" + url.PathEscape(a) + "/close?identifierType=alias"
		body = closeBody{Source: source, Note: notify.Truncate(req.Title, 1000)}
	} else {
		desc := req.Body
		if req.DeepLink != "" {
			desc += "\n" + req.DeepLink
		}
		body = createBody{
			Message: notify.Truncate(req.Title, maxMessage), Alias: a, Description: notify.Truncate(strings.TrimSpace(desc), maxDescription),
			Priority: priority(req.Severity), Details: details(req.Fields), Tags: []string{"kryptkeeper"}, Source: source,
		}
		target = base + "/v2/alerts"
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return abi.NotifySendResult{}, err
	}
	resp, err := h.HTTP(abi.HTTPRequest{
		Method:  "POST",
		URL:     target,
		Headers: map[string]string{"Authorization": "GenieKey " + req.Credential["api_key"], "Content-Type": "application/json"},
		Body:    raw,
	})
	if err != nil {
		return abi.NotifySendResult{}, err
	}
	switch {
	case resp.Status == 202 || resp.Status == 200:
		var ok struct {
			RequestID string `json:"requestId"`
		}
		_ = json.Unmarshal(resp.Body, &ok)
		id := ok.RequestID
		if id == "" {
			id = a
		}
		return abi.NotifySendResult{Delivered: true, ProviderID: id}, nil
	case resp.Status == 401 || resp.Status == 403:
		return notify.Refused(resp, "the API key was refused"), nil
	case resp.Status == 429:
		return notify.Refused(resp, "rate limited"), nil
	}
	return notify.Refused(resp, "Opsgenie did not accept the request"), nil
}
