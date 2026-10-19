// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"math/big"
	"time"
)

// ErrNotCancellable: there is no scheduled deletion to cancel for the key
// (software key, never deleted, or the provider's recovery window has passed).
var ErrNotCancellable = errors.New("key deletion cannot be cancelled")

// DeletionCanceller is implemented by backends whose provider keeps a deleted
// key recoverable for a window (cloud KMS). Callers type-assert a Store.
type DeletionCanceller interface {
	// CanCancelDeletion reports whether id is inside a provider
	// pending-deletion window at now.
	CanCancelDeletion(id string, now time.Time) (bool, error)
	// CancelDeletion restores the provider key to Enabled and drops the
	// tombstone. ErrNotCancellable when there is no tombstone or the window
	// has passed.
	CancelDeletion(ctx context.Context, id string) error
}

// PendingDeletionLister is implemented by backends that can list keys inside a
// provider recovery window, so an operator can see and cancel them. It is
// separate from Store.List on purpose: List callers (rotation, inventory,
// signing) must never see a key that is not usable.
type PendingDeletionLister interface {
	PendingDeletions(now time.Time) []KeyMetadata
}

// W9-07 (G-40/D-085): secure key destruction. Deleting a key used to be
// os.Remove for software keys and a map-delete for cloud references —
// decrypted signers stayed live in the cache, and the cloud key itself was
// orphaned: still billable, still able to sign.
//
// HONESTY NOTE on zeroization: Go's garbage collector may hold earlier
// copies of key material (stack copies, big.Int growth reallocations), and
// nothing here can reach those. Zeroizing the live structures shrinks the
// exposure window substantially; it is not a guarantee of absence from
// memory. RISKS.md's "memory-zeroed" claim is true in exactly this
// qualified form.

// zeroizeBytes overwrites a byte slice in place.
func zeroizeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// zeroizeBigInt overwrites a big.Int's backing words and resets the value.
func zeroizeBigInt(n *big.Int) {
	if n == nil {
		return
	}
	words := n.Bits()
	for i := range words {
		words[i] = 0
	}
	n.SetInt64(0)
}

// ZeroizeSigner best-effort wipes the private material of the concrete key
// types this codebase caches. It reports whether the signer's type was
// recognized and wiped — an unknown type is left untouched and reported
// false, never a panic path.
func ZeroizeSigner(signer crypto.Signer) bool {
	switch key := signer.(type) {
	case *ecdsa.PrivateKey:
		zeroizeBigInt(key.D)
		return true
	case *rsa.PrivateKey:
		zeroizeBigInt(key.D)
		for _, prime := range key.Primes {
			zeroizeBigInt(prime)
		}
		zeroizeBigInt(key.Precomputed.Dp)
		zeroizeBigInt(key.Precomputed.Dq)
		zeroizeBigInt(key.Precomputed.Qinv)
		for _, crt := range key.Precomputed.CRTValues {
			zeroizeBigInt(crt.Exp)
			zeroizeBigInt(crt.Coeff)
			zeroizeBigInt(crt.R)
		}
		return true
	case ed25519.PrivateKey:
		zeroizeBytes(key)
		return true
	default:
		return false
	}
}
