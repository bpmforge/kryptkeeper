// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ctmonitor

import (
	"context"
	"strings"
	"sync"
	"time"
)

// W12-01: the Inventory adapter the W9-11 seam anticipated. It wraps a
// ListSerials closure supplied by the wiring (main builds it over the
// real CertificateProvider) so this package still depends on nothing
// in bootstrap.

// NormalizeSerial canonicalizes a certificate serial for comparison:
// lowercase hex, colons stripped, leading zeros trimmed. crt.sh and
// the inventory disagree on formatting, and a false "unknown" would
// page a human about a certificate we issued.
func NormalizeSerial(s string) string {
	s = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), ":", ""))
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}

// ProviderInventory implements Inventory over a serial-listing
// closure, with a TTL cache so a scan over N CT entries costs one
// inventory walk, not N.
type ProviderInventory struct {
	// ListSerials returns every known certificate serial (any
	// formatting; normalization happens here).
	ListSerials func(ctx context.Context) (map[string]struct{}, error)
	// TTL bounds cache staleness (default 5m).
	TTL time.Duration

	mu        sync.Mutex
	serials   map[string]struct{}
	fetchedAt time.Time
	now       func() time.Time
}

func NewProviderInventory(list func(ctx context.Context) (map[string]struct{}, error)) *ProviderInventory {
	return &ProviderInventory{ListSerials: list, TTL: 5 * time.Minute, now: time.Now}
}

// HasSerial reports whether the inventory knows the serial. A listing
// error propagates — an unreadable inventory must make the monitor
// SKIP flagging (the caller reports the error), never mark everything
// rogue.
func (p *ProviderInventory) HasSerial(ctx context.Context, serial string) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now
	if p.now != nil {
		now = p.now
	}
	ttl := p.TTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if p.serials == nil || now().Sub(p.fetchedAt) > ttl {
		raw, err := p.ListSerials(ctx)
		if err != nil {
			return false, err
		}
		normalized := make(map[string]struct{}, len(raw))
		for s := range raw {
			normalized[NormalizeSerial(s)] = struct{}{}
		}
		p.serials = normalized
		p.fetchedAt = now()
	}
	_, ok := p.serials[NormalizeSerial(serial)]
	return ok, nil
}
