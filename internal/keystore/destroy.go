// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"math/big"
)

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
