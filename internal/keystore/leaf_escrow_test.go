// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"crypto/ecdsa"
	"testing"
	"time"
)

// W15-03: opt-in leaf-key escrow. Endpoint-key custody conflicts with
// the key-boundary law UNLESS a tenant explicitly adopts it, so the
// gate is the feature: nothing is escrowed by default, and every touch
// is audited.

type recordingLeafAudit struct{ events []LeafEscrowEvent }

func (r *recordingLeafAudit) Record(ev LeafEscrowEvent) { r.events = append(r.events, ev) }

func (r *recordingLeafAudit) has(action, outcome string) bool {
	for _, e := range r.events {
		if e.Action == action && e.Outcome == outcome {
			return true
		}
	}
	return false
}

var (
	leafPassA = []byte("leaf-custodian-alpha")
	leafPassB = []byte("leaf-custodian-bravo")
)

// Default posture: a tenant that never opted in escrows NOTHING, and the
// refusal is audited. This is the load-bearing "never default" guard.
func TestLeafEscrowRefusedWithoutOptIn(t *testing.T) {
	store := newEscrowTestStore(t)
	if _, err := store.GenerateKey("leaf-1", ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	policy := NewLeafEscrowPolicy() // zero opt-ins
	audit := &recordingLeafAudit{}

	_, err := EscrowLeafKey(store, policy, audit, "tenant-a", "leaf-1", leafPassA, leafPassB, time.Now())
	if err == nil {
		t.Fatal("leaf escrow must be refused for a tenant that never opted in")
	}
	if !audit.has("leaf_escrow.deposit", "denied") {
		t.Fatalf("a refused deposit must be audited: %+v", audit.events)
	}
}

// Opt-in path: escrow then dual-control recover, and every touch audited.
func TestLeafEscrowOptInDepositAndRecover(t *testing.T) {
	store := newEscrowTestStore(t)
	if _, err := store.GenerateKey("leaf-2", ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, _ := store.Signer("leaf-2")
	originalPub := signer.Public().(*ecdsa.PublicKey)

	policy := NewLeafEscrowPolicy()
	policy.OptIn("tenant-a") // explicit adoption
	audit := &recordingLeafAudit{}

	bundle, err := EscrowLeafKey(store, policy, audit, "tenant-a", "leaf-2", leafPassA, leafPassB, time.Now())
	if err != nil {
		t.Fatalf("opted-in deposit must succeed: %v", err)
	}
	if !audit.has("leaf_escrow.deposit", "success") {
		t.Fatalf("a successful deposit must be audited: %+v", audit.events)
	}

	if err := store.Delete("leaf-2"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	id, err := RecoverLeafKey(store, policy, audit, "tenant-a", bundle, leafPassA, leafPassB, time.Now())
	if err != nil || id != "leaf-2" {
		t.Fatalf("dual-control recover failed: id=%q err=%v", id, err)
	}
	if !audit.has("leaf_escrow.recover", "success") {
		t.Fatalf("a successful recovery must be audited: %+v", audit.events)
	}
	// The recovered key is the same key.
	rec, err := store.Signer("leaf-2")
	if err != nil {
		t.Fatalf("recovered signer: %v", err)
	}
	recPub := rec.Public().(*ecdsa.PublicKey)
	if recPub.X.Cmp(originalPub.X) != 0 || recPub.Y.Cmp(originalPub.Y) != 0 {
		t.Fatal("recovered key must match the pre-escrow key")
	}
}

// Recovery requires the SAME dual-control ceremony — a single controller
// (empty second custodian) is refused and audited.
func TestLeafEscrowRecoverRefusesSingleController(t *testing.T) {
	store := newEscrowTestStore(t)
	if _, err := store.GenerateKey("leaf-3", ECDSAP256); err != nil {
		t.Fatalf("generate: %v", err)
	}
	policy := NewLeafEscrowPolicy()
	policy.OptIn("tenant-a")
	audit := &recordingLeafAudit{}
	bundle, err := EscrowLeafKey(store, policy, audit, "tenant-a", "leaf-3", leafPassA, leafPassB, time.Now())
	if err != nil {
		t.Fatalf("deposit: %v", err)
	}
	_ = store.Delete("leaf-3")

	// Single controller: no second custodian secret.
	if _, err := RecoverLeafKey(store, policy, audit, "tenant-a", bundle, leafPassA, nil, time.Now()); err == nil {
		t.Fatal("recovery with a single controller must be refused")
	}
	if !audit.has("leaf_escrow.recover", "denied") {
		t.Fatalf("a refused recovery must be audited: %+v", audit.events)
	}
}
