// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package audittrust

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
)

// W16-01: RFC 6962 transparency log — inclusion, consistency, signed
// checkpoints, and the external-verify no-retro-tamper property.

func buildLog(t *testing.T, n int) (*MerkleLog, [][]byte) {
	t.Helper()
	l := &MerkleLog{}
	records := make([][]byte, n)
	for i := 0; i < n; i++ {
		records[i] = []byte(fmt.Sprintf("audit-record-%d: action=key.rotate outcome=success", i))
		l.Append(records[i])
	}
	return l, records
}

func TestInclusionProofsVerifyForEveryLeaf(t *testing.T) {
	for _, n := range []int{1, 2, 3, 5, 8, 13, 100} {
		l, records := buildLog(t, n)
		root := l.Root()
		for i := 0; i < n; i++ {
			proof, err := l.InclusionProof(i)
			if err != nil {
				t.Fatalf("n=%d proof(%d): %v", n, i, err)
			}
			if !VerifyInclusion(i, n, HashLeaf(records[i]), root, proof) {
				t.Fatalf("n=%d: inclusion proof for leaf %d did not verify", n, i)
			}
		}
	}
}

func TestTamperedRecordFailsInclusion(t *testing.T) {
	l, records := buildLog(t, 20)
	root := l.Root()
	proof, _ := l.InclusionProof(7)
	// An auditor checks a record they were handed; a tampered copy must
	// fail against the honest root.
	tampered := append([]byte{}, records[7]...)
	tampered[0] ^= 0xFF
	if VerifyInclusion(7, 20, HashLeaf(tampered), root, proof) {
		t.Fatal("a tampered record must not verify against the true root")
	}
	if !VerifyInclusion(7, 20, HashLeaf(records[7]), root, proof) {
		t.Fatal("the true record must still verify")
	}
}

func TestConsistencyProvesAppendOnly(t *testing.T) {
	l, _ := buildLog(t, 7)
	oldRoot := l.Root()
	oldSize := l.Size()
	// Extend the log.
	for i := 7; i < 19; i++ {
		l.Append([]byte(fmt.Sprintf("later-record-%d", i)))
	}
	newRoot := l.Root()
	proof, err := l.ConsistencyProof(oldSize)
	if err != nil {
		t.Fatalf("consistency proof: %v", err)
	}
	if !VerifyConsistency(oldSize, l.Size(), oldRoot, newRoot, proof) {
		t.Fatal("valid consistency proof must verify (append-only extension)")
	}
	// A forged old root must fail — i.e. you cannot claim a different
	// history led to the same new root.
	var forged [32]byte
	forged[0] = oldRoot[0] ^ 0x01
	copy(forged[1:], oldRoot[1:])
	if VerifyConsistency(oldSize, l.Size(), forged, newRoot, proof) {
		t.Fatal("a forged old root must fail consistency (retro-tamper caught)")
	}
}

func TestSignedCheckpointRoundTrip(t *testing.T) {
	l, records := buildLog(t, 10)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cp := l.SignCheckpoint(priv)

	// An auditor with ONLY the public key + checkpoint recovers the
	// trusted root and verifies a record against it.
	root, err := VerifyCheckpoint(pub, cp)
	if err != nil {
		t.Fatalf("checkpoint verify: %v", err)
	}
	proof, _ := l.InclusionProof(3)
	if !VerifyInclusion(3, cp.Size, HashLeaf(records[3]), root, proof) {
		t.Fatal("record must verify against the checkpoint-committed root")
	}

	// A flipped signature byte must fail.
	bad := cp
	sig := []byte(bad.Signature)
	sig[len(sig)-1] ^= 0x01
	bad.Signature = string(sig)
	if _, err := VerifyCheckpoint(pub, bad); err == nil {
		t.Fatal("a tampered checkpoint signature must not verify")
	}
	// A different key must not verify the honest checkpoint.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := VerifyCheckpoint(otherPub, cp); err == nil {
		t.Fatal("checkpoint must not verify under a foreign key")
	}
}
