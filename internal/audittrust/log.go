// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package audittrust layers an RFC 6962 Merkle transparency log OVER
// the audit trail (W16-01). Private CT for the PKI: an auditor holding
// only a record, its inclusion proof, and a signed checkpoint can
// CRYPTOGRAPHICALLY PROVE nothing was retro-tampered — no trust in the
// server required. All stdlib crypto; the existing audit write path is
// untouched (the tree is built over exported records, not inline).
package audittrust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// RFC 6962 domain separators guard against second-preimage attacks:
// a leaf hash can never collide with an interior node hash.
const (
	leafPrefix = 0x00
	nodePrefix = 0x01
)

// HashLeaf computes the RFC 6962 leaf hash of a record.
func HashLeaf(record []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(record)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// hashChildren computes the RFC 6962 interior node hash.
func hashChildren(left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{nodePrefix})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// MerkleLog is an ordered, append-only log of leaf hashes.
type MerkleLog struct {
	leaves [][32]byte
}

// Append adds a record and returns its zero-based index.
func (l *MerkleLog) Append(record []byte) int {
	l.leaves = append(l.leaves, HashLeaf(record))
	return len(l.leaves) - 1
}

// Size returns the number of leaves.
func (l *MerkleLog) Size() int { return len(l.leaves) }

// largestPowerOfTwoLessThan returns the largest power of two strictly
// less than n (n >= 2).
func largestPowerOfTwoLessThan(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// mth is the RFC 6962 Merkle Tree Hash over leaves[lo:hi].
func mth(leaves [][32]byte) [32]byte {
	n := len(leaves)
	switch n {
	case 0:
		var empty [32]byte
		copy(empty[:], sha256.New().Sum(nil))
		return empty
	case 1:
		return leaves[0]
	default:
		k := largestPowerOfTwoLessThan(n)
		return hashChildren(mth(leaves[:k]), mth(leaves[k:]))
	}
}

// Root returns the current Merkle Tree Hash.
func (l *MerkleLog) Root() [32]byte { return mth(l.leaves) }

// InclusionProof returns the RFC 6962 audit path for the leaf at index
// m in a tree of the log's current size.
func (l *MerkleLog) InclusionProof(m int) ([][32]byte, error) {
	if m < 0 || m >= len(l.leaves) {
		return nil, fmt.Errorf("index %d out of range [0,%d)", m, len(l.leaves))
	}
	return inclusionPath(m, l.leaves), nil
}

func inclusionPath(m int, leaves [][32]byte) [][32]byte {
	n := len(leaves)
	if n == 1 {
		return nil
	}
	k := largestPowerOfTwoLessThan(n)
	if m < k {
		return append(inclusionPath(m, leaves[:k]), mth(leaves[k:]))
	}
	return append(inclusionPath(m-k, leaves[k:]), mth(leaves[:k]))
}

// VerifyInclusion recomputes the root from a leaf hash and its audit
// path and compares it to the expected root — the external check an
// auditor runs with no access to the tree.
func VerifyInclusion(index, size int, leafHash, root [32]byte, proof [][32]byte) bool {
	if index < 0 || index >= size {
		return false
	}
	computed, ok := rootFromInclusion(index, size, leafHash, proof)
	return ok && computed == root
}

func rootFromInclusion(index, size int, leafHash [32]byte, proof [][32]byte) ([32]byte, bool) {
	if size == 1 {
		return leafHash, len(proof) == 0
	}
	k := largestPowerOfTwoLessThan(size)
	if index < k {
		if len(proof) == 0 {
			return [32]byte{}, false
		}
		left, ok := rootFromInclusion(index, k, leafHash, proof[:len(proof)-1])
		if !ok {
			return [32]byte{}, false
		}
		return hashChildren(left, proof[len(proof)-1]), true
	}
	if len(proof) == 0 {
		return [32]byte{}, false
	}
	right, ok := rootFromInclusion(index-k, size-k, leafHash, proof[:len(proof)-1])
	if !ok {
		return [32]byte{}, false
	}
	return hashChildren(proof[len(proof)-1], right), true
}

// ConsistencyProof returns the RFC 6962 consistency proof between an
// earlier size m and the log's current size.
func (l *MerkleLog) ConsistencyProof(m int) ([][32]byte, error) {
	n := len(l.leaves)
	if m < 1 || m > n {
		return nil, fmt.Errorf("consistency size %d out of range [1,%d]", m, n)
	}
	return subProof(m, l.leaves, true), nil
}

func subProof(m int, leaves [][32]byte, computeM bool) [][32]byte {
	n := len(leaves)
	if m == n {
		if computeM {
			return nil
		}
		return [][32]byte{mth(leaves)}
	}
	k := largestPowerOfTwoLessThan(n)
	if m <= k {
		return append(subProof(m, leaves[:k], computeM), mth(leaves[k:]))
	}
	return append(subProof(m-k, leaves[k:], false), mth(leaves[:k]))
}

// VerifyConsistency verifies an RFC 6962 consistency proof between two
// tree heads — the proof that the newer log is an append-only
// extension of the older one (no retro-tamper).
func VerifyConsistency(m, n int, oldRoot, newRoot [32]byte, proof [][32]byte) bool {
	if m < 1 || m > n {
		return false
	}
	if m == n {
		return len(proof) == 0 && oldRoot == newRoot
	}
	// RFC 6962 §2.1.2 verification.
	var seed [32]byte
	var path [][32]byte
	if isPowerOfTwo(m) {
		seed = oldRoot
		path = proof
	} else {
		if len(proof) == 0 {
			return false
		}
		seed = proof[0]
		path = proof[1:]
	}
	fn, sn := m-1, n-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	oldHash, newHash := seed, seed
	for _, p := range path {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			oldHash = hashChildren(p, oldHash)
			newHash = hashChildren(p, newHash)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			newHash = hashChildren(newHash, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return oldHash == oldRoot && newHash == newRoot && sn == 0
}

func isPowerOfTwo(n int) bool { return n > 0 && n&(n-1) == 0 }

// SignedCheckpoint is a signed commitment to a tree head.
type SignedCheckpoint struct {
	Size      int    `json:"size"`
	RootB64   string `json:"root"`
	Signature string `json:"signature"`
}

// checkpointMessage is the canonical bytes an Ed25519 checkpoint signs.
func checkpointMessage(size int, root [32]byte) []byte {
	return []byte(fmt.Sprintf("kryptkeeper-audit-log\n%d\n%s\n", size, base64.StdEncoding.EncodeToString(root[:])))
}

// SignCheckpoint signs the current tree head with an Ed25519 key.
func (l *MerkleLog) SignCheckpoint(priv ed25519.PrivateKey) SignedCheckpoint {
	root := l.Root()
	sig := ed25519.Sign(priv, checkpointMessage(l.Size(), root))
	return SignedCheckpoint{
		Size:      l.Size(),
		RootB64:   base64.StdEncoding.EncodeToString(root[:]),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
}

// VerifyCheckpoint verifies a checkpoint's Ed25519 signature and
// returns the committed root — the auditor's trust anchor.
func VerifyCheckpoint(pub ed25519.PublicKey, cp SignedCheckpoint) ([32]byte, error) {
	rootBytes, err := base64.StdEncoding.DecodeString(cp.RootB64)
	if err != nil || len(rootBytes) != 32 {
		return [32]byte{}, errors.New("checkpoint root is not a 32-byte hash")
	}
	sig, err := base64.StdEncoding.DecodeString(cp.Signature)
	if err != nil {
		return [32]byte{}, errors.New("checkpoint signature is not base64")
	}
	var root [32]byte
	copy(root[:], rootBytes)
	if !ed25519.Verify(pub, checkpointMessage(cp.Size, root), sig) {
		return [32]byte{}, errors.New("checkpoint signature does not verify")
	}
	return root, nil
}

// EqualRoots is a constant-time-ish helper for external verifiers.
func EqualRoots(a, b [32]byte) bool { return bytes.Equal(a[:], b[:]) }
