// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import "sync"

// Event kinds recognized by GET /api/v1/events (W8-14 acceptance #2). Only
// EventKindScan has a producer wired today (discovery scan, in
// handlers_discovery.go) -- renew/install/migrate are follow-up tickets, but
// the envelope and kind vocabulary are fixed now so those producers slot in
// without a wire-format change.
const (
	EventKindScan    = "scan"
	EventKindRenew   = "renew"
	EventKindInstall = "install"
	EventKindMigrate = "migrate"
)

// Event is the stable SSE envelope every operation-status event carries
// (W8-14 acceptance #2). Status deliberately reuses
// DiscoveryScanJob.Status's vocabulary (discovery_provider.go) verbatim --
// queued/running/completed/failed/cancelled, the same set
// handlers_discovery.go's own status-filter switch validates -- rather than
// inventing a second, parallel one.
type Event struct {
	OpID     string `json:"op_id"`
	Kind     string `json:"kind"`
	Status   string `json:"status"`
	Progress *int   `json:"progress"`
	Message  string `json:"message"`
	Ts       string `json:"ts"`
}

// eventSubscriberBuffer bounds how many undelivered events a single stream
// will hold before Publish starts dropping new ones for it. Sized for a
// bursty producer against a briefly slow reader, not for a large backlog --
// a stream this far behind is better served by heartbeat-driven keepalive
// and a future reconnect than by an unbounded queue.
const eventSubscriberBuffer = 16

// tenantEvent pairs an Event with the tenant it belongs to. EventBus fans
// every published event out to every current subscriber, tagged with its
// tenant; each subscriber's own serving goroutine (handlers_sse.go) applies
// the connected principal's tenant visibility to it on receipt. This is
// deliberate: acceptance #3 requires an op_id the receiving principal never
// started to still be delivered as long as it is in-tenant, so delivery is
// scoped by tenant, not by which principal happened to start the operation.
// tenant is never serialized into the SSE payload -- only Event is.
type tenantEvent struct {
	tenant string
	event  Event
}

type eventSubscriber struct {
	ch chan tenantEvent
}

// EventBus is an in-process, best-effort pub/sub for operation-status
// events, scoped to a single hub instance's memory (no cross-instance
// fanout). Publish never blocks and never returns an error: a full or
// absent subscriber simply has the event dropped for it, so a slow or dead
// SSE consumer can never apply backpressure to whatever called Publish
// (W8-14 acceptance #8).
type EventBus struct {
	mu              sync.Mutex
	subsByPrincipal map[string]map[*eventSubscriber]struct{}
	maxPerPrincipal int
}

// NewEventBus constructs an EventBus that allows at most maxStreamsPerPrincipal
// concurrent subscriptions for any one principal ID (W8-14 acceptance #5).
func NewEventBus(maxStreamsPerPrincipal int) *EventBus {
	if maxStreamsPerPrincipal <= 0 {
		maxStreamsPerPrincipal = 1
	}
	return &EventBus{
		subsByPrincipal: make(map[string]map[*eventSubscriber]struct{}),
		maxPerPrincipal: maxStreamsPerPrincipal,
	}
}

// Subscribe registers a new stream for principalID. ok is false when
// principalID already holds the configured maximum of concurrent streams --
// the caller must respond 429 and must leave every one of the principal's
// existing streams untouched (acceptance #5: exceeding the cap does not
// silently drop the oldest stream).
func (b *EventBus) Subscribe(principalID string) (sub *eventSubscriber, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	existing := b.subsByPrincipal[principalID]
	if len(existing) >= b.maxPerPrincipal {
		return nil, false
	}
	sub = &eventSubscriber{ch: make(chan tenantEvent, eventSubscriberBuffer)}
	if existing == nil {
		existing = make(map[*eventSubscriber]struct{})
		b.subsByPrincipal[principalID] = existing
	}
	existing[sub] = struct{}{}
	return sub, true
}

// Unsubscribe removes sub, freeing its slot in principalID's cap, and closes
// its channel. Safe to call at most once per successful Subscribe (the SSE
// handler does so via defer).
func (b *EventBus) Unsubscribe(principalID string, sub *eventSubscriber) {
	b.mu.Lock()
	defer b.mu.Unlock()

	existing := b.subsByPrincipal[principalID]
	if _, ok := existing[sub]; !ok {
		return
	}
	delete(existing, sub)
	if len(existing) == 0 {
		delete(b.subsByPrincipal, principalID)
	}
	close(sub.ch)
}

// Publish delivers evt to every currently subscribed stream across every
// principal, tagged with tenant for that stream's own delivery-time tenant
// filter. Best-effort and non-blocking: a subscriber whose buffer is full
// has evt dropped for it rather than stalling the publisher, so Publish is
// safe to call inline from a request-handling goroutine.
func (b *EventBus) Publish(tenant string, evt Event) {
	b.mu.Lock()
	defer b.mu.Unlock()

	te := tenantEvent{tenant: tenant, event: evt}
	for _, subs := range b.subsByPrincipal {
		for sub := range subs {
			select {
			case sub.ch <- te:
			default:
				// Best-effort: drop rather than block the publisher.
			}
		}
	}
}
