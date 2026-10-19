// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"sync"
	"sync/atomic"
	"time"
)

// Event kinds recognized by GET /api/v1/events (W8-14 acceptance #2). Every
// kind has a producer: scan (handlers_discovery.go), renew
// (handlers_renewal_execute.go), install (handlers_agents.go) and migrate
// (pqc_wave_execute.go), the last three via publishOperationEvent (W30-13).
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
//
// seq is the bus-wide monotonic id written as the SSE `id:` line so a
// reconnecting client can resume with Last-Event-ID; it is deliberately not
// part of Event, whose wire shape is fixed at six fields.
type tenantEvent struct {
	seq    uint64
	tenant string
	event  Event
}

// eventReplayBuffer bounds the replay ring. A client that was away longer
// than this many events misses the oldest; the stream is best-effort.
const eventReplayBuffer = 256

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
	seq             uint64
	ring            []tenantEvent
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
	return b.subscribeLocked(principalID)
}

// SubscribeWithReplay is Subscribe plus the ring entries with seq > lastSeq,
// captured under the same lock that registers the subscriber so no event can
// fall between the replay and the live feed. The caller must still apply
// tenant visibility to every replayed entry: the ring holds all tenants.
func (b *EventBus) SubscribeWithReplay(principalID string, lastSeq uint64) (sub *eventSubscriber, replay []tenantEvent, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	sub, ok = b.subscribeLocked(principalID)
	if !ok {
		return nil, nil, false
	}
	for _, te := range b.ring {
		if te.seq > lastSeq {
			replay = append(replay, te)
		}
	}
	return sub, replay, true
}

func (b *EventBus) subscribeLocked(principalID string) (sub *eventSubscriber, ok bool) {
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

	b.seq++
	te := tenantEvent{seq: b.seq, tenant: tenant, event: evt}
	if len(b.ring) >= eventReplayBuffer {
		b.ring = append(b.ring[:0], b.ring[1:]...)
	}
	b.ring = append(b.ring, te)
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

// activeEventBus is the bus the operation producers publish to. It is set
// once by registerSSEHandlers rather than injected, because the renew,
// install and migrate handlers are registered from call sites that never
// see the bus (same precedent as activeTenantStore). Atomic so a test
// resetting it cannot race a handler goroutine.
var activeEventBus atomic.Pointer[EventBus]

func setActiveEventBus(b *EventBus) { activeEventBus.Store(b) }

// publishOperationEvent is the shared renew/install/migrate producer. It is
// a no-op with no bus or no op id, and Publish never blocks, so an operation
// succeeds identically with zero subscribers. message must be a generic
// class, never an error string that could carry credentials.
func publishOperationEvent(tenant, kind, opID, status string, progress *int, message string) {
	bus := activeEventBus.Load()
	if bus == nil || opID == "" {
		return
	}
	bus.Publish(tenant, Event{
		OpID:     opID,
		Kind:     kind,
		Status:   status,
		Progress: progress,
		Message:  message,
		Ts:       time.Now().UTC().Format(time.RFC3339),
	})
}
