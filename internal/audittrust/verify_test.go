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

func entryJSON(i int, action string) []byte {
	return []byte(fmt.Sprintf(`{"id":%d,"timestamp":"2026-08-20T00:00:0%dZ","action":%q,"actor_type":"user","actor_id":"alice","resource_type":"certificate","resource_id":"fp-%d","outcome":"success","tenant":"default","user_agent":"x"}`, i+1, i%10, action, i))
}

func buildEntryLog(t *testing.T, n int, tamper int) (*MerkleLog, [][]byte) {
	t.Helper()
	l := &MerkleLog{}
	var leaves [][]byte
	for i := 0; i < n; i++ {
		action := "cert.issue"
		if i == tamper {
			action = "cert.revoke"
		}
		leaf, err := CanonicalLeaf(entryJSON(i, action))
		if err != nil {
			t.Fatal(err)
		}
		leaves = append(leaves, leaf)
		l.Append(leaf)
	}
	return l, leaves
}

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestCanonicalLeafIgnoresNonCanonicalFields(t *testing.T) {
	a, _ := CanonicalLeaf(entryJSON(1, "x"))
	b, _ := CanonicalLeaf([]byte(`{"tenant":"default","outcome":"success","resource_id":"fp-1","resource_type":"certificate","actor_id":"alice","actor_type":"user","action":"x","timestamp":"2026-08-20T00:00:01Z","id":2}`))
	if string(a) != string(b) {
		t.Fatalf("leaf must not depend on key order or extra fields:\n%s\n%s", a, b)
	}
}

func TestVerifyRecordOK(t *testing.T) {
	priv := newKey(t)
	l, leaves := buildEntryLog(t, 5, -1)
	cp := l.SignCheckpoint(priv)
	proof, _ := l.InclusionProof(3)
	if err := VerifyRecord(priv.Public().(ed25519.PublicKey), cp, leaves[3], 3, proof); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRecordWrongPubkey(t *testing.T) {
	priv := newKey(t)
	l, leaves := buildEntryLog(t, 5, -1)
	cp := l.SignCheckpoint(priv)
	proof, _ := l.InclusionProof(0)
	other := newKey(t).Public().(ed25519.PublicKey)
	if err := VerifyRecord(other, cp, leaves[0], 0, proof); err == nil {
		t.Fatal("a checkpoint signed by another key must not verify")
	}
}

func TestVerifyRecordTamperedLeaf(t *testing.T) {
	priv := newKey(t)
	l, _ := buildEntryLog(t, 5, -1)
	cp := l.SignCheckpoint(priv)
	proof, _ := l.InclusionProof(2)
	forged, _ := CanonicalLeaf(entryJSON(2, "cert.revoke"))
	if err := VerifyRecord(priv.Public().(ed25519.PublicKey), cp, forged, 2, proof); err == nil {
		t.Fatal("tampered leaf must fail")
	}
}

func TestVerifyPairOK(t *testing.T) {
	priv := newKey(t)
	l3, _ := buildEntryLog(t, 3, -1)
	l5, _ := buildEntryLog(t, 5, -1)
	proof, _ := l5.ConsistencyProof(3)
	if err := VerifyPair(priv.Public().(ed25519.PublicKey), l3.SignCheckpoint(priv), l5.SignCheckpoint(priv), proof); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyPairTamperedHistory(t *testing.T) {
	priv := newKey(t)
	l3, _ := buildEntryLog(t, 3, -1)
	cpA := l3.SignCheckpoint(priv)  // published before the tamper
	l5, _ := buildEntryLog(t, 5, 1) // leaf 1 rewritten afterwards
	proof, _ := l5.ConsistencyProof(3)
	if err := VerifyPair(priv.Public().(ed25519.PublicKey), cpA, l5.SignCheckpoint(priv), proof); err == nil {
		t.Fatal("rewriting history under a later checkpoint must be detected")
	}
}

func TestDecodeProofRejectsGarbage(t *testing.T) {
	if _, err := DecodeProof([]string{"not-base64!"}); err == nil {
		t.Fatal("expected error")
	}
	if _, err := DecodeProof([]string{"AAAA"}); err == nil {
		t.Fatal("short hash must be rejected")
	}
}
