// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
)

// NonceService generates and validates replay nonces per RFC 8555 §7.2.
type NonceService struct {
	mu     sync.Mutex
	active map[string]bool
	// order holds nonces oldest-first. Consumed nonces stay in it until they
	// reach the head, so eviction is O(1) amortised.
	order []string
	size  int
}

// NewNonceService creates a nonce service with the given max active nonces.
func NewNonceService(maxActive int) *NonceService {
	if maxActive <= 0 {
		maxActive = 10000
	}
	return &NonceService{
		active: make(map[string]bool),
		size:   maxActive,
	}
}

// New generates a fresh nonce.
func (ns *NonceService) New() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	nonce := base64.RawURLEncoding.EncodeToString(b)

	ns.mu.Lock()
	defer ns.mu.Unlock()

	// FIFO eviction: drop only the oldest nonces so one client flooding
	// newNonce cannot invalidate everyone else's recent nonces.
	for len(ns.active) >= ns.size && len(ns.order) > 0 {
		delete(ns.active, ns.order[0])
		ns.order[0] = ""
		ns.order = ns.order[1:]
	}
	if len(ns.order) > 2*ns.size {
		live := make([]string, 0, len(ns.active)+1)
		for _, n := range ns.order {
			if ns.active[n] {
				live = append(live, n)
			}
		}
		ns.order = live
	}
	ns.active[nonce] = true
	ns.order = append(ns.order, nonce)
	return nonce, nil
}

// Consume validates and removes a nonce. Returns true if valid.
func (ns *NonceService) Consume(nonce string) bool {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	if ns.active[nonce] {
		delete(ns.active, nonce)
		return true
	}
	return false
}
