// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"sync"
	"testing"
	"time"
)

func TestEventBus_PublishDeliversToSubscriber(t *testing.T) {
	bus := NewEventBus(3)
	sub, ok := bus.Subscribe("principal-a")
	if !ok {
		t.Fatal("expected Subscribe to succeed")
	}

	progress := 42
	bus.Publish("acme", Event{OpID: "scan-1", Kind: EventKindScan, Status: "running", Progress: &progress, Message: "hi", Ts: "2026-07-29T00:00:00Z"})

	select {
	case got := <-sub.ch:
		if got.tenant != "acme" || got.event.OpID != "scan-1" || got.event.Status != "running" || got.event.Progress == nil || *got.event.Progress != 42 {
			t.Fatalf("unexpected delivered event: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for published event")
	}
}

// TestEventBus_PublishWithNoSubscriberDoesNotBlockOrPanic is the bus-level
// half of acceptance #8: a publisher with zero subscribers must return
// immediately, never block or panic. This is proven again end-to-end via a
// real HTTP handler in handlers_discovery_test.go.
func TestEventBus_PublishWithNoSubscriberDoesNotBlockOrPanic(t *testing.T) {
	bus := NewEventBus(3)
	done := make(chan struct{})
	go func() {
		bus.Publish("acme", Event{OpID: "scan-1", Kind: EventKindScan, Status: "queued"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Publish with no subscriber blocked")
	}
}

// TestEventBus_PublishToFullBufferDropsRatherThanBlocks proves the
// non-blocking half of acceptance #8 against a slow/dead consumer: once a
// subscriber's buffer is full, further Publish calls must still return
// immediately instead of stalling the caller.
func TestEventBus_PublishToFullBufferDropsRatherThanBlocks(t *testing.T) {
	bus := NewEventBus(3)
	sub, ok := bus.Subscribe("principal-a")
	if !ok {
		t.Fatal("expected Subscribe to succeed")
	}

	// Fill and overflow the subscriber's buffer without ever reading it.
	done := make(chan struct{})
	go func() {
		for i := 0; i < eventSubscriberBuffer*2; i++ {
			bus.Publish("acme", Event{OpID: "scan-1", Kind: EventKindScan, Status: "running"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Publish against a full subscriber buffer blocked instead of dropping")
	}

	if len(sub.ch) != eventSubscriberBuffer {
		t.Fatalf("expected buffer to be full at %d, got %d", eventSubscriberBuffer, len(sub.ch))
	}
}

// TestEventBus_SubscribeCapEnforcedWithoutDroppingExisting is the bus-level
// half of acceptance #5: once a principal holds the configured maximum of
// concurrent streams, a further Subscribe must fail (ok=false) rather than
// evicting one of the existing streams.
func TestEventBus_SubscribeCapEnforcedWithoutDroppingExisting(t *testing.T) {
	bus := NewEventBus(2)

	sub1, ok := bus.Subscribe("principal-a")
	if !ok {
		t.Fatal("first Subscribe should succeed")
	}
	sub2, ok := bus.Subscribe("principal-a")
	if !ok {
		t.Fatal("second Subscribe should succeed")
	}
	if _, ok := bus.Subscribe("principal-a"); ok {
		t.Fatal("third Subscribe should be rejected by the cap")
	}

	// The cap rejection must not have touched either existing stream.
	bus.Publish("acme", Event{OpID: "scan-1", Kind: EventKindScan, Status: "queued"})
	for i, sub := range []*eventSubscriber{sub1, sub2} {
		select {
		case <-sub.ch:
		case <-time.After(time.Second):
			t.Fatalf("existing subscription %d did not receive event after cap rejection -- it was silently dropped", i+1)
		}
	}

	// A different principal is unaffected by principal-a's cap.
	if _, ok := bus.Subscribe("principal-b"); !ok {
		t.Fatal("a different principal must have its own independent cap")
	}
}

func TestEventBus_UnsubscribeFreesCapSlotAndClosesChannel(t *testing.T) {
	bus := NewEventBus(1)

	sub, ok := bus.Subscribe("principal-a")
	if !ok {
		t.Fatal("first Subscribe should succeed")
	}
	if _, ok := bus.Subscribe("principal-a"); ok {
		t.Fatal("expected the cap to reject a second concurrent stream")
	}

	bus.Unsubscribe("principal-a", sub)

	if _, ok := <-sub.ch; ok {
		t.Fatal("expected sub.ch to be closed after Unsubscribe")
	}
	if _, ok := bus.Subscribe("principal-a"); !ok {
		t.Fatal("expected Unsubscribe to free the cap slot")
	}
}

// TestEventBus_ConcurrentUse is a race-detector regression: Subscribe,
// Publish, and Unsubscribe running concurrently from many goroutines must
// not corrupt EventBus's internal maps (run with -race).
func TestEventBus_ConcurrentUse(t *testing.T) {
	bus := NewEventBus(50)
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			sub, ok := bus.Subscribe("principal-a")
			if !ok {
				return
			}
			defer bus.Unsubscribe("principal-a", sub)
			for j := 0; j < 5; j++ {
				select {
				case <-sub.ch:
				default:
				}
			}
		}(i)
	}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bus.Publish("acme", Event{OpID: "scan-1", Kind: EventKindScan, Status: "running"})
		}()
	}
	wg.Wait()
}
