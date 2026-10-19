// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package itsm turns hub events into tickets in an external ITSM exactly
// once, remembers the ticket, and rides out ITSM outages with a durable
// backoff queue. ServiceNow (W32-11) and Jira (W32-14) plug in as Connectors.
package itsm

import (
	"context"
	"errors"
	"time"
)

// Event is what the hub wants a ticket for. ID is the idempotency key and the
// correlation id a connector stamps on the ticket.
type Event struct {
	ID          string    `json:"id"`
	Class       string    `json:"class"`
	CN          string    `json:"cn"`
	Serial      string    `json:"serial"`
	Risk        string    `json:"risk"`
	DeepLink    string    `json:"deep_link"`
	Fingerprint string    `json:"fingerprint"`
	Tenant      string    `json:"tenant"`
	NotAfter    time.Time `json:"not_after"`
	// TicketType is the connection's per-class ticket type (ServiceNow
	// incident|change_request, Jira issue-type name). Empty means the
	// connector default.
	TicketType string `json:"ticket_type,omitempty"`
}

// TicketRef points at a ticket in the external system.
type TicketRef struct{ Key, URL string }

var (
	// ErrTemporary marks a failure worth retrying: 5xx, timeout, 429.
	ErrTemporary = errors.New("itsm: temporary failure")
	// ErrPermanent marks a failure retrying cannot fix: 4xx other than 404/429.
	ErrPermanent = errors.New("itsm: permanent failure")
)

// Connector is one ticketing system. Implementations must wrap ErrTemporary
// or ErrPermanent, and must never put credentials in an error.
type Connector interface {
	Kind() string // "servicenow" | "jira"
	// Find looks a ticket up by correlation id; nil, nil when there is none.
	Find(ctx context.Context, eventID string) (*TicketRef, error)
	// Create MUST set the ticket's correlation id to ev.ID.
	Create(ctx context.Context, ev Event) (TicketRef, error)
	Exists(ctx context.Context, ref TicketRef) (bool, error)
	Resolve(ctx context.Context, ref TicketRef, comment string) error
}

// CredentialResolver is satisfied by the hub's outbound credential store.
// itsm cannot import internal/bootstrap (cycle), so it names what it needs.
// The returned plaintext is radioactive: never log, audit or return it.
type CredentialResolver interface {
	Resolve(ctx context.Context, id string) ([]byte, error)
}

// AuditRecord is one background audit entry; the wiring layer maps it onto
// the hub's audit trail.
type AuditRecord struct {
	Action        string
	ResourceID    string // event id, or connection id for connection actions
	Outcome       string // "success" | "failure"
	Tenant        string
	ChangeSummary string
}

const (
	ActionTicketCreate      = "itsm.ticket.create"
	ActionTicketResolve     = "itsm.ticket.resolve"
	ActionConnectionCreate  = "itsm.connection.create"
	ActionConnectionDelete  = "itsm.connection.delete"
	OutcomeSuccess          = "success"
	OutcomeFailure          = "failure"
	AlertUnreachable        = "itsm_unreachable"
	AlertTicketDeletedAgain = "itsm_ticket_deleted_again"
)

// Event statuses.
const (
	StatusPending  = "pending"
	StatusCreated  = "created"
	StatusResolved = "resolved"
	StatusFailed   = "failed"
)

// Connection is a configured ticketing system. CredentialRef names an entry in
// the outbound credential store; the secret itself is never held here.
type Connection struct {
	ID            string       `json:"id"`
	Kind          string       `json:"kind"`
	Name          string       `json:"name"`
	BaseURL       string       `json:"base_url"`
	CredentialRef string       `json:"credential_ref"`
	EventClasses  []EventClass `json:"event_classes"`
	Enabled       bool         `json:"enabled"`
	Tenant        string       `json:"tenant"`
	CreatedAt     time.Time    `json:"created_at"`
	UpdatedAt     time.Time    `json:"updated_at"`
}

// EventRow is one event's ticket link and queue state.
type EventRow struct {
	EventID       string    `json:"event_id"`
	ConnectionID  string    `json:"connection_id"`
	Class         string    `json:"class"`
	Fingerprint   string    `json:"fingerprint"`
	Payload       string    `json:"-"`
	Status        string    `json:"status"`
	TicketKey     string    `json:"ticket_key"`
	TicketURL     string    `json:"ticket_url"`
	Attempts      int       `json:"attempts"`
	NextAttemptAt time.Time `json:"next_attempt_at"`
	LastError     string    `json:"last_error"`
	Recreated     bool      `json:"recreated"`
	Tenant        string    `json:"tenant"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// EventClass subscribes a connection to one event class and says which ticket
// type that class opens (W32-25).
type EventClass struct {
	Class      string `json:"class"`
	TicketType string `json:"ticket_type"`
}

// TicketTypeFor returns the ticket type configured for class, and whether the
// connection subscribes to it. An empty EventClasses list subscribes to all
// classes with the connector default (empty) ticket type.
func (c Connection) TicketTypeFor(class string) (ticketType string, subscribed bool) {
	if len(c.EventClasses) == 0 {
		return "", true
	}
	for _, ec := range c.EventClasses {
		if ec.Class == class {
			return ec.TicketType, true
		}
	}
	return "", false
}
