// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"context"
	"fmt"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
)

const maxProviderID = 128

// NotifyError is a failed notify.send: the plugin's service did not take the
// alert, or the plugin could not reach it. RetryAfterSeconds is the service's
// rate-limit hint, kept for the retry logic of W38-03; this wave does not act
// on it.
type NotifyError struct {
	Detail            string
	RetryAfterSeconds int
}

func (e *NotifyError) Error() string {
	if e.RetryAfterSeconds > 0 {
		return fmt.Sprintf("%s (retry after %ds)", e.Detail, e.RetryAfterSeconds)
	}
	return e.Detail
}

// Notify sends one alert through a notify plugin and returns what its service
// reported. Every failure comes back as an error so a caller handles a plugin
// channel like any other channel failure; a *NotifyError carries the retry
// hint. The hub caps what the plugin says (provider id and detail) and
// redacts the credential values it handed over.
func (p *Plugin) Notify(ctx context.Context, env Env, req abi.NotifySendRequest) (abi.NotifySendResult, error) {
	if p.manifest.Kind != abi.KindNotify {
		return abi.NotifySendResult{}, fmt.Errorf("%w: %q on a %s plugin", ErrOpNotForKind, abi.OpNotifySend, p.manifest.Kind)
	}
	st := p.state(env)
	req.Invocation = invocation(env)
	var res abi.NotifySendResult
	if err := p.run(ctx, env, st, abi.OpNotifySend, req, &res); err != nil {
		return abi.NotifySendResult{}, err
	}
	res.ProviderID = sanitize(res.ProviderID, st.redact)
	if len(res.ProviderID) > maxProviderID {
		res.ProviderID = res.ProviderID[:maxProviderID]
	}
	res.Detail = sanitize(res.Detail, st.redact)
	if res.RetryAfterSeconds < 0 {
		res.RetryAfterSeconds = 0
	}
	if !res.Delivered {
		detail := res.Detail
		if detail == "" {
			detail = "the service did not accept the alert"
		}
		return res, &NotifyError{Detail: detail, RetryAfterSeconds: res.RetryAfterSeconds}
	}
	return res, nil
}
