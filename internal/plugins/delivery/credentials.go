// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"context"
	"errors"
	"fmt"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
)

// CredentialsGet asks a credentials plugin for one credential and returns
// what its secret manager said (W38-07, D-324). The returned fields are the
// secret, so unlike every other plugin output they are not sanitized; what is
// bounded is their size, and what is redacted is everything else the plugin
// said during the call.
//
// Events (http, log, refused) arrive while the call runs, before the result
// exists, so a plugin that logged the password it was fetching would leak it
// through an event. They are held until the call returns and every returned
// value is then redacted from them before they reach env.Events.
func (p *Plugin) CredentialsGet(ctx context.Context, env Env, reference map[string]string) (abi.CredentialsGetResult, error) {
	if p.manifest.Kind != abi.KindCredentials {
		return abi.CredentialsGetResult{}, fmt.Errorf("%w: %q on a %s plugin", ErrOpNotForKind, abi.OpCredentialsGet, p.manifest.Kind)
	}
	sink := env.Events
	var held []Event
	env.Events = func(e Event) { held = append(held, e) }

	st := p.state(env)
	var res abi.CredentialsGetResult
	err := p.run(ctx, env, st, abi.OpCredentialsGet,
		abi.CredentialsGetRequest{Invocation: invocation(env), Reference: reference}, &res)

	redact := append([]string(nil), st.redact...)
	for _, v := range res.Fields {
		redact = append(redact, v)
	}
	flushRedacted(sink, held, redact)
	if err != nil {
		return abi.CredentialsGetResult{}, err
	}
	if err := checkCredentialFields(res.Fields); err != nil {
		return abi.CredentialsGetResult{}, err
	}
	if res.LeaseSeconds < 0 {
		res.LeaseSeconds = 0
	}
	return res, nil
}

// flushRedacted hands held events to sink with every secret value removed.
func flushRedacted(sink func(Event), held []Event, redact []string) {
	if sink == nil {
		return
	}
	for _, e := range held {
		e.Detail = sanitize(e.Detail, redact)
		sink(e)
	}
}

// ErrCredentialResult means a plugin returned a result the hub will not use.
var ErrCredentialResult = errors.New("credentials plugin returned an unusable result")

func checkCredentialFields(fields map[string]string) error {
	if len(fields) == 0 {
		return fmt.Errorf("%w: no fields", ErrCredentialResult)
	}
	if len(fields) > abi.MaxCredentialFields {
		return fmt.Errorf("%w: more than %d fields", ErrCredentialResult, abi.MaxCredentialFields)
	}
	for k, v := range fields {
		// Field names are the plugin's, so they are echoed; values never are.
		if k == "" || len(k) > 128 {
			return fmt.Errorf("%w: a field name is empty or too long", ErrCredentialResult)
		}
		if len(v) > abi.MaxCredentialFieldBytes {
			return fmt.Errorf("%w: field %q is larger than %d bytes", ErrCredentialResult, k, abi.MaxCredentialFieldBytes)
		}
	}
	return nil
}
