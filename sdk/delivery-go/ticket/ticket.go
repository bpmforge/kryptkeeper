// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package ticket is the Go SDK for Kryptkeeper ticket plugins (kind "ticket",
// D-326): a plugin that opens, checks and closes tickets in an ITSM or help
// desk (Zendesk, Freshservice, ...). It shares the sandbox, Host and ABI of
// delivery plugins; only the operations differ (abi.OpTicket*). A plugin
// implements Plugin, registers it in init, and builds for wasip1 exactly like
// a delivery plugin.
package ticket

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

// Plugin is one ticket service. Each method reports a service refusal in the
// result's TicketFailure (use Failed) and returns an error only for a
// transport failure; the hub retries both, a permanent failure aside.
type Plugin interface {
	Create(h *delivery.Host, req abi.TicketCreateRequest) (abi.TicketCreateResult, error)
	// Exists must answer {Exists:false}, not a failure, for a ticket the
	// service does not have (404, or a deleted/trashed flag), including the
	// hub's probe key abi.ProbeTicketKey.
	Exists(h *delivery.Host, req abi.TicketExistsRequest) (abi.TicketExistsResult, error)
	Resolve(h *delivery.Host, req abi.TicketResolveRequest) (abi.TicketResolveResult, error)
}

// Register sets the plugin this module serves. Call it from init.
func Register(p Plugin) {
	delivery.RegisterHandler(func(h *delivery.Host, op string, in []byte) (json.RawMessage, error) {
		return Handle(p, h, op, in)
	})
}

// Handle runs one operation on p. It is exported for plugin tests that drive
// a plugin without WebAssembly.
func Handle(p Plugin, h *delivery.Host, op string, in []byte) (json.RawMessage, error) {
	var res any
	var err error
	switch op {
	case abi.OpTicketCreate:
		var req abi.TicketCreateRequest
		if err = json.Unmarshal(in, &req); err == nil {
			res, err = p.Create(h, req)
		}
	case abi.OpTicketExists:
		var req abi.TicketExistsRequest
		if err = json.Unmarshal(in, &req); err == nil {
			res, err = p.Exists(h, req)
		}
	case abi.OpTicketResolve:
		var req abi.TicketResolveRequest
		if err = json.Unmarshal(in, &req); err == nil {
			res, err = p.Resolve(h, req)
		}
	default:
		return nil, fmt.Errorf("unknown operation %q for a ticket plugin", op)
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(res)
}

// MaxRetryAfterSeconds caps a service's rate-limit hint so a hostile or
// confused service cannot park the hub's retries for days.
const MaxRetryAfterSeconds = 3600

// RetryAfter reads a Retry-After header given in seconds (the form Zendesk
// and Freshservice document; an HTTP-date is ignored) and caps it.
func RetryAfter(headers map[string]string) int {
	for k, v := range headers {
		if !strings.EqualFold(k, "Retry-After") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n < 0 {
			return 0
		}
		return min(n, MaxRetryAfterSeconds)
	}
	return 0
}

// Failed classifies a non-success answer: 408, 429 and 5xx are temporary (with
// the service's rate-limit hint), everything else is permanent because
// retrying the same request will not change the answer. The response body is
// never echoed, because services can reflect the request, which carries the
// credential.
func Failed(resp abi.HTTPResponse, why string) abi.TicketFailure {
	class := abi.FailurePermanent
	if resp.Status == 408 || resp.Status == 429 || resp.Status >= 500 {
		class = abi.FailureTemporary
	}
	return abi.TicketFailure{
		Failure:           class,
		Detail:            fmt.Sprintf("service answered %d: %s", resp.Status, why),
		RetryAfterSeconds: RetryAfter(resp.Headers),
	}
}

// Truncate cuts s to at most n bytes on a rune boundary.
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut]
}

// BaseURL returns the credential's service address without a trailing slash,
// or "" when it is not an https URL, so a plugin never sends a credential over
// plain http (the sandbox refuses it too; this gives a clearer message).
func BaseURL(raw string) string {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if !strings.HasPrefix(raw, "https://") || len(raw) == len("https://") {
		return ""
	}
	return raw
}
