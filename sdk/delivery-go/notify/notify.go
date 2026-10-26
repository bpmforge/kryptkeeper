// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package notify is the Go SDK for Kryptkeeper notify plugins (kind "notify",
// D-321): a plugin that delivers one alert to a chat or incident service. It
// shares the sandbox, Host and ABI of delivery plugins; only the operation
// differs (abi.OpNotifySend). A plugin implements Plugin, registers it in
// init, and builds for wasip1 exactly like a delivery plugin.
package notify

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

// Plugin delivers alerts. Send returns Delivered=false (with Detail, and
// RetryAfterSeconds when the service gave a hint) when the service did not
// take the alert, or an error for a transport failure; the hub treats both
// as a failed delivery.
type Plugin interface {
	Send(h *delivery.Host, req abi.NotifySendRequest) (abi.NotifySendResult, error)
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
	if op != abi.OpNotifySend {
		return nil, fmt.Errorf("unknown operation %q for a notify plugin", op)
	}
	var req abi.NotifySendRequest
	if err := json.Unmarshal(in, &req); err != nil {
		return nil, err
	}
	res, err := p.Send(h, req)
	if err != nil {
		return nil, err
	}
	return json.Marshal(res)
}

// Truncate cuts s to at most n bytes on a rune boundary, for services with
// field length limits.
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !isRuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

// MaxRetryAfterSeconds caps a service's rate-limit hint so a hostile or
// confused service cannot park the hub's retries for days.
const MaxRetryAfterSeconds = 3600

// RetryAfter reads a Retry-After header given in seconds (the form every
// supported service uses; an HTTP-date is ignored) and caps it.
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

// Refused builds the result for a service that answered but did not take the
// alert: the status, the caller's short reason and the rate-limit hint. The
// response body is never echoed, because services can reflect the request,
// which carries the credential.
func Refused(resp abi.HTTPResponse, why string) abi.NotifySendResult {
	return abi.NotifySendResult{
		Detail:            fmt.Sprintf("service answered %d: %s", resp.Status, why),
		RetryAfterSeconds: RetryAfter(resp.Headers),
	}
}
