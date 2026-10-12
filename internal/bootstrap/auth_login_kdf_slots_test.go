// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestKDFSlots_BoundedAndContextAware(t *testing.T) {
	hash, err := HashLoginPassword("correct-password", "pepper")
	if err != nil {
		t.Fatal(err)
	}
	auth := newLoginAuth(hash)

	slots := auth.kdfSlot()
	if cap(slots) < 1 || cap(slots) > loginKDFConcurrency {
		t.Fatalf("slot cap %d outside [1,%d]", cap(slots), loginKDFConcurrency)
	}

	// Saturate every slot: a queued login must give up when its context ends
	// instead of waiting forever.
	for range cap(slots) {
		slots <- struct{}{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, _, _, _, _, err := auth.LoginContext(ctx, "admin@example.com", "wrong", time.Now()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued login: err = %v, want deadline exceeded", err)
	}
	for range cap(slots) {
		<-slots
	}
}

func TestKDFSlots_NeverExceedCapUnderParallelBadLogins(t *testing.T) {
	auth := newLoginAuth("")
	var cur, peak atomic.Int32
	var wg sync.WaitGroup
	for range 30 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = auth.withKDFSlot(context.Background(), func() {
				n := cur.Add(1)
				for {
					p := peak.Load()
					if n <= p || peak.CompareAndSwap(p, n) {
						break
					}
				}
				time.Sleep(5 * time.Millisecond)
				cur.Add(-1)
			})
		}()
	}
	wg.Wait()
	if got, limit := int(peak.Load()), cap(auth.kdfSlot()); got > limit {
		t.Fatalf("peak concurrent KDF runs %d exceeds cap %d", got, limit)
	}
}
