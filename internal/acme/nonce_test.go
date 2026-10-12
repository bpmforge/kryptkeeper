// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

import "testing"

func newNonces(t *testing.T, ns *NonceService, n int) []string {
	t.Helper()
	out := make([]string, n)
	for i := range out {
		v, err := ns.New()
		if err != nil {
			t.Fatal(err)
		}
		out[i] = v
	}
	return out
}

// OWASP-A04-004: reaching the cap used to wipe every nonce, so any client
// could invalidate everyone else's by flooding newNonce. Only the oldest
// nonces may be evicted.
func TestNonceEvictionKeepsNewestValid(t *testing.T) {
	ns := NewNonceService(3)
	n := newNonces(t, ns, 5)

	for i, nonce := range n {
		wantValid := i >= 2
		if got := ns.Consume(nonce); got != wantValid {
			t.Errorf("nonce %d: valid=%v, want %v", i, got, wantValid)
		}
	}
}

func TestNonceConsumeIsSingleUseAndFreesCapacity(t *testing.T) {
	ns := NewNonceService(2)
	a := newNonces(t, ns, 2)
	if !ns.Consume(a[0]) || ns.Consume(a[0]) {
		t.Fatal("nonce must be valid exactly once")
	}
	// One slot is free again, so adding a nonce must not evict a[1].
	b := newNonces(t, ns, 1)
	if !ns.Consume(a[1]) || !ns.Consume(b[0]) {
		t.Fatal("a nonce was evicted although capacity was available")
	}
}

func TestNonceQueueStaysBounded(t *testing.T) {
	ns := NewNonceService(4)
	for i := 0; i < 200; i++ {
		v := newNonces(t, ns, 1)[0]
		if i%2 == 0 {
			ns.Consume(v)
		}
	}
	ns.mu.Lock()
	defer ns.mu.Unlock()
	if len(ns.active) > 4 || len(ns.order) > 2*4+1 {
		t.Fatalf("active=%d order=%d: queue not bounded", len(ns.active), len(ns.order))
	}
}
