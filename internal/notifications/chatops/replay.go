// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package chatops

import (
	"sync"
	"time"
)

// ReplayGuard remembers verified signatures for MaxSkew so a captured request
// cannot be replayed inside the timestamp window. Only call it with signatures
// that already passed VerifySlackSignature, so unauthenticated callers cannot
// grow it.
type ReplayGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func NewReplayGuard() *ReplayGuard { return &ReplayGuard{seen: map[string]time.Time{}} }

// Seen reports whether sig was already used inside MaxSkew; otherwise it
// records it. Expired entries are evicted on every call.
func (g *ReplayGuard) Seen(sig string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, at := range g.seen {
		if now.Sub(at) > MaxSkew {
			delete(g.seen, k)
		}
	}
	if _, dup := g.seen[sig]; dup {
		return true
	}
	g.seen[sig] = now
	return false
}
