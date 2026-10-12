// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"crypto/subtle"
	"fmt"
	"time"
)

// W15-03 (FR-P13 follow-up): opt-in escrow of endpoint (leaf) keys.
//
// Holding leaf private keys conflicts with the key-boundary law unless a
// tenant EXPLICITLY adopts custody — so the opt-in gate is the feature,
// not a convenience. Nothing is escrowed by default; a tenant that never
// opted in gets a refusal, audited. Once adopted, deposit and recovery
// reuse the W9-12 dual-control machinery unchanged (two differing
// custodian secrets or nothing), and every touch — success or refusal —
// is recorded, because custody of a leaf key that leaves no audit trail
// is exactly the boundary violation this feature must not become.

// LeafEscrowPolicy records which tenants have opted in. The zero value
// (via NewLeafEscrowPolicy) escrows nothing — custody is never the
// default.
type LeafEscrowPolicy struct {
	optedIn map[string]bool
}

func NewLeafEscrowPolicy() *LeafEscrowPolicy {
	return &LeafEscrowPolicy{optedIn: map[string]bool{}}
}

// OptIn is the explicit per-tenant adoption of leaf-key custody.
func (p *LeafEscrowPolicy) OptIn(tenant string) { p.optedIn[tenant] = true }

// OptOut revokes future custody. It does NOT strand already-escrowed
// material: recovery of an existing bundle stays possible (else opting
// out would destroy keys), gated on dual control and audited.
func (p *LeafEscrowPolicy) OptOut(tenant string) { delete(p.optedIn, tenant) }

func (p *LeafEscrowPolicy) Enabled(tenant string) bool {
	return p != nil && p.optedIn[tenant]
}

// LeafEscrowEvent is one custody touch. It NEVER carries key or custodian
// secret material — only who/what/when/outcome.
type LeafEscrowEvent struct {
	Tenant  string
	KeyID   string
	Action  string // leaf_escrow.deposit | leaf_escrow.recover
	Outcome string // success | denied | failure
	At      time.Time
}

// LeafEscrowAudit sinks custody events into the append-only audit trail.
type LeafEscrowAudit interface {
	Record(ev LeafEscrowEvent)
}

const (
	actionLeafDeposit = "leaf_escrow.deposit"
	actionLeafRecover = "leaf_escrow.recover"
)

func record(audit LeafEscrowAudit, tenant, keyID, action, outcome string, now time.Time) {
	if audit == nil {
		return
	}
	audit.Record(LeafEscrowEvent{Tenant: tenant, KeyID: keyID, Action: action, Outcome: outcome, At: now.UTC()})
}

// requireDualControl enforces the two-secret ceremony at the leaf layer
// too (not only inside EscrowKey), so a refused ceremony is caught and
// audited before any key material is touched.
func requireDualControl(a, b []byte) error {
	if len(a) == 0 || len(b) == 0 {
		return fmt.Errorf("dual control requires two custodian secrets")
	}
	if subtle.ConstantTimeCompare(a, b) == 1 {
		return fmt.Errorf("dual control requires two DIFFERENT custodian secrets")
	}
	return nil
}

// EscrowLeafKey deposits endpoint key keyID under dual control — REFUSED
// unless tenant has explicitly opted in. Reuses the W9-12 machinery.
func EscrowLeafKey(store Store, policy *LeafEscrowPolicy, audit LeafEscrowAudit, tenant, keyID string, custodianA, custodianB []byte, now time.Time) ([]byte, error) {
	if !policy.Enabled(tenant) {
		record(audit, tenant, keyID, actionLeafDeposit, "denied", now)
		return nil, fmt.Errorf("leaf-key escrow is not enabled for tenant %q — custody must be explicitly opted in", tenant)
	}
	if err := requireDualControl(custodianA, custodianB); err != nil {
		record(audit, tenant, keyID, actionLeafDeposit, "denied", now)
		return nil, err
	}
	bundle, err := EscrowKey(store, keyID, custodianA, custodianB)
	if err != nil {
		record(audit, tenant, keyID, actionLeafDeposit, "failure", now)
		return nil, err
	}
	record(audit, tenant, keyID, actionLeafDeposit, "success", now)
	return bundle, nil
}

// RecoverLeafKey rebuilds an escrowed leaf key. Recovery requires the
// same dual-control ceremony as deposit and every touch is audited. It
// is intentionally NOT gated on the current opt-in state, so opting out
// never strands already-escrowed material.
func RecoverLeafKey(store Store, policy *LeafEscrowPolicy, audit LeafEscrowAudit, tenant string, bundleJSON, custodianA, custodianB []byte, now time.Time) (string, error) {
	if err := requireDualControl(custodianA, custodianB); err != nil {
		record(audit, tenant, "", actionLeafRecover, "denied", now)
		return "", err
	}
	id, err := RecoverEscrowedKey(store, bundleJSON, custodianA, custodianB)
	if err != nil {
		record(audit, tenant, id, actionLeafRecover, "failure", now)
		return "", err
	}
	record(audit, tenant, id, actionLeafRecover, "success", now)
	return id, nil
}
