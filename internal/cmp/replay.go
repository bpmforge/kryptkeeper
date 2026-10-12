// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package cmp

import (
	"strconv"
	"sync"
	"time"
)

const (
	// replayWindow bounds how long a seen transactionID+senderNonce is
	// remembered. A message replayed after it has aged out is not caught
	// here; the cache is per-process and in-memory, so a restart (or a
	// second replica) also forgets. The MAC covers the header, so an
	// attacker cannot mint a fresh nonce for a captured message.
	replayWindow = 15 * time.Minute
	// replayMaxEntries bounds memory. Only MAC-verified messages are
	// recorded, so growth requires the shared secret; at capacity the oldest
	// entry is dropped (a replay of a message older than replayMaxEntries
	// newer ones then gets through, which is the cost of a bounded cache).
	replayMaxEntries = 10000
)

// replayCache remembers recently seen (transactionID, senderNonce) pairs.
type replayCache struct {
	mu    sync.Mutex
	max   int
	ttl   time.Duration
	now   func() time.Time
	seen  map[string]time.Time
	order []string // insertion order, oldest first
}

func newReplayCache(max int, ttl time.Duration) *replayCache {
	return &replayCache{max: max, ttl: ttl, now: time.Now, seen: make(map[string]time.Time)}
}

// firstUse records the pair and reports true, or reports false when it was
// already seen inside the window. An empty transactionID or senderNonce
// cannot be tracked, so it is refused rather than waved through.
func (c *replayCache) firstUse(transactionID, senderNonce []byte) bool {
	if len(transactionID) == 0 || len(senderNonce) == 0 {
		return false
	}
	// Length-prefix the first part so ("ab","c") and ("a","bc") differ.
	key := strconv.Itoa(len(transactionID)) + ":" + string(transactionID) + string(senderNonce)
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.order) > 0 {
		oldest := c.order[0]
		at, ok := c.seen[oldest]
		if ok && now.Sub(at) <= c.ttl && len(c.order) < c.max {
			break
		}
		delete(c.seen, oldest)
		c.order = c.order[1:]
	}
	if at, ok := c.seen[key]; ok && now.Sub(at) <= c.ttl {
		return false
	}
	c.seen[key] = now
	c.order = append(c.order, key)
	return true
}

func (c *replayCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}
