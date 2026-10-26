// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package abi

// Operations of the ticket kind (D-326). They mirror the hub's native ITSM
// connector (Create, Exists, Resolve). There is no find op and no approval op:
// approval sync stays native-only in 1.1, and a ticket made just before a hub
// crash is not adopted, so a plugin's create should be as idempotent as its
// service allows.
const (
	OpTicketCreate  = "ticket.create"
	OpTicketExists  = "ticket.exists"
	OpTicketResolve = "ticket.resolve"
)

// ProbeTicketKey is the key the hub sends to ticket.exists for "test
// connection". No real ticket has it, so a plugin that answers {exists:false}
// for it has proven the service is reachable and the credential works, without
// the hub creating anything.
const ProbeTicketKey = "0"

// Failure classes a ticket result may carry.
const (
	FailureTemporary = "temporary" // 5xx, 429, timeout: the hub retries with backoff
	FailurePermanent = "permanent" // 4xx the service will keep refusing: the event is marked failed
)

// TicketFailure is how a ticket op reports that the service refused or could
// not take it. An empty Failure means success. A plugin that returns an error
// instead of a classified failure is treated as temporary.
type TicketFailure struct {
	Failure           string `json:"failure,omitempty"`
	Detail            string `json:"detail,omitempty"`
	RetryAfterSeconds int    `json:"retry_after_seconds,omitempty"`
}

// TicketEvent is what the hub wants a ticket for. Fields are non-secret
// context rows; ID is the correlation id the plugin should stamp on the ticket
// (Zendesk external_id, a Freshservice tag) so a human can trace it back to
// the hub.
type TicketEvent struct {
	ID          string `json:"id"`
	Class       string `json:"class"`
	CN          string `json:"cn,omitempty"`
	Serial      string `json:"serial,omitempty"`
	Risk        string `json:"risk,omitempty"`
	DeepLink    string `json:"deep_link,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	NotAfter    string `json:"not_after,omitempty"` // RFC 3339
	// TicketType is the connection's per-class ticket type, free text the
	// plugin interprets (a Zendesk ticket type, a Freshservice type). Empty
	// means the plugin's default.
	TicketType string `json:"ticket_type,omitempty"`
}

// TicketCreateRequest asks for one ticket.
type TicketCreateRequest struct {
	Invocation
	Event TicketEvent `json:"event"`
}

// TicketCreateResult names the ticket made. Key identifies it for later
// exists and resolve calls; URL is the link a person opens (https only; the
// hub drops anything else).
type TicketCreateResult struct {
	TicketFailure
	Key string `json:"key,omitempty"`
	URL string `json:"url,omitempty"`
}

// TicketExistsRequest asks whether a ticket the hub made still exists. URL is
// echoed from create for convenience; a plugin builds the API request from its
// credential and Key, never from URL.
type TicketExistsRequest struct {
	Invocation
	Key string `json:"key"`
	URL string `json:"url,omitempty"`
}

// TicketExistsResult: Exists is false for a ticket that is gone (deleted or
// trashed). A missing ticket is not a failure.
type TicketExistsResult struct {
	TicketFailure
	Exists bool `json:"exists"`
}

// TicketResolveRequest closes a ticket, with a comment saying why.
type TicketResolveRequest struct {
	Invocation
	Key     string `json:"key"`
	URL     string `json:"url,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// TicketResolveResult carries only a failure; success is an empty Failure.
type TicketResolveResult struct {
	TicketFailure
}
