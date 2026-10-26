// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
)

const (
	maxTicketKey    = 128
	maxTicketURL    = 512
	maxTicketDetail = 300
)

// TicketError is a ticket op the plugin's service did not take. Temporary says
// whether retrying can help; the hub's ITSM service maps it onto its own
// ErrTemporary and ErrPermanent so plugin tickets share the native retry path.
type TicketError struct {
	Detail            string
	Temporary         bool
	RetryAfterSeconds int
}

func (e *TicketError) Error() string { return e.Detail }

// ticketFailure turns a plugin-reported failure into a TicketError, capping and
// redacting what the plugin said. A nil result means the op succeeded.
func ticketFailure(f abi.TicketFailure, redact []string) error {
	if f.Failure == "" {
		return nil
	}
	detail := sanitize(f.Detail, redact)
	if len(detail) > maxTicketDetail {
		detail = detail[:maxTicketDetail]
	}
	if detail == "" {
		detail = "the ticket service did not accept the request"
	}
	// Anything not explicitly permanent is retried: an unknown class from a
	// plugin must not silently drop a ticket.
	return &TicketError{Detail: detail, Temporary: f.Failure != abi.FailurePermanent, RetryAfterSeconds: max(0, f.RetryAfterSeconds)}
}

func (p *Plugin) ticketOp(ctx context.Context, env Env, op string, req, out any) (*callState, error) {
	if p.manifest.Kind != abi.KindTicket {
		return nil, fmt.Errorf("%w: %q on a %s plugin", ErrOpNotForKind, op, p.manifest.Kind)
	}
	st := p.state(env)
	return st, p.run(ctx, env, st, op, req, out)
}

// TicketCreate opens one ticket through a ticket plugin. The key and URL the
// plugin returns are checked here: a missing key is a permanent failure (the
// hub could never find the ticket again), and only an https URL is kept.
func (p *Plugin) TicketCreate(ctx context.Context, env Env, ev abi.TicketEvent) (abi.TicketCreateResult, error) {
	var res abi.TicketCreateResult
	st, err := p.ticketOp(ctx, env, abi.OpTicketCreate, abi.TicketCreateRequest{Invocation: invocation(env), Event: ev}, &res)
	if err != nil {
		return abi.TicketCreateResult{}, err
	}
	if err := ticketFailure(res.TicketFailure, st.redact); err != nil {
		return abi.TicketCreateResult{}, err
	}
	res.Key = strings.TrimSpace(sanitize(res.Key, st.redact))
	if res.Key == "" || len(res.Key) > maxTicketKey {
		return abi.TicketCreateResult{}, &TicketError{Detail: "the plugin returned no usable ticket key"}
	}
	res.URL = safeTicketURL(res.URL)
	return res, nil
}

// TicketExists asks whether a ticket still exists.
func (p *Plugin) TicketExists(ctx context.Context, env Env, key, ticketURL string) (bool, error) {
	var res abi.TicketExistsResult
	st, err := p.ticketOp(ctx, env, abi.OpTicketExists, abi.TicketExistsRequest{Invocation: invocation(env), Key: key, URL: ticketURL}, &res)
	if err != nil {
		return false, err
	}
	if err := ticketFailure(res.TicketFailure, st.redact); err != nil {
		return false, err
	}
	return res.Exists, nil
}

// TicketResolve closes a ticket with a comment.
func (p *Plugin) TicketResolve(ctx context.Context, env Env, key, ticketURL, comment string) error {
	var res abi.TicketResolveResult
	st, err := p.ticketOp(ctx, env, abi.OpTicketResolve, abi.TicketResolveRequest{Invocation: invocation(env), Key: key, URL: ticketURL, Comment: comment}, &res)
	if err != nil {
		return err
	}
	return ticketFailure(res.TicketFailure, st.redact)
}

// safeTicketURL keeps an https URL without userinfo: the link is stored and
// rendered as a clickable href, so a javascript: or credential-bearing URL
// from a plugin must never reach it.
func safeTicketURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(raw) > maxTicketURL {
		return ""
	}
	return u.String()
}
