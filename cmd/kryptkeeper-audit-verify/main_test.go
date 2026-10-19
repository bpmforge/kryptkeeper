// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kryptkeeper/internal/audittrust"
)

func entry(i int, action string) string {
	return fmt.Sprintf(`{"id":%d,"timestamp":"2026-08-20T00:00:00Z","action":%q,"actor_type":"user","actor_id":"alice","resource_type":"certificate","resource_id":"fp-%d","outcome":"success","tenant":"default"}`, i+1, action, i)
}

func logOf(t *testing.T, n, tamper int) *audittrust.MerkleLog {
	t.Helper()
	l := &audittrust.MerkleLog{}
	for i := 0; i < n; i++ {
		a := "cert.issue"
		if i == tamper {
			a = "cert.revoke"
		}
		leaf, err := audittrust.CanonicalLeaf([]byte(entry(i, a)))
		if err != nil {
			t.Fatal(err)
		}
		l.Append(leaf)
	}
	return l
}

func writeJSON(t *testing.T, dir, name string, v any) string {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"data": v}) // the API envelope
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func b64(p [][32]byte) []string {
	out := []string{}
	for _, h := range p {
		out = append(out, base64.StdEncoding.EncodeToString(h[:]))
	}
	return out
}

func TestRecordVerifyExitCodes(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	dir := t.TempDir()
	l := logOf(t, 5, -1)
	cp := writeJSON(t, dir, "cp.json", l.SignCheckpoint(priv))
	proof, _ := l.InclusionProof(2)
	pf := writeJSON(t, dir, "inc.json", map[string]any{"audit_path": b64(proof)})
	good := filepath.Join(dir, "entry.json")
	_ = os.WriteFile(good, []byte(entry(2, "cert.issue")), 0o600)
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte(entry(2, "cert.revoke")), 0o600)

	args := func(entryFile string, extra ...string) []string {
		return append([]string{"record", "--checkpoint", cp, "--entry", entryFile, "--index", "2", "--proof", pf}, extra...)
	}
	var out, errb bytes.Buffer
	if c := run(args(good, "--pubkey", pubB64), &out, &errb); c != 0 || !strings.HasPrefix(out.String(), "OK") {
		t.Fatalf("valid record: code %d out=%q err=%q", c, out.String(), errb.String())
	}
	out.Reset()
	if c := run(args(bad, "--pubkey", pubB64), &out, &errb); c != 1 || !strings.HasPrefix(out.String(), "FAIL:") {
		t.Fatalf("tampered record: code %d out=%q", c, out.String())
	}
	if c := run(args(good), &out, &errb); c != 2 {
		t.Fatalf("missing --pubkey must be a usage error, got %d", c)
	}
	// An attacker's key from the same response must not be trusted:
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if c := run(args(good, "--pubkey", base64.StdEncoding.EncodeToString(other)), &out, &errb); c != 1 {
		t.Fatalf("wrong pinned key must fail verification, got %d", c)
	}
}

func TestPairTamperedHistoryExitsNonZero(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	dir := t.TempDir()
	old := writeJSON(t, dir, "old.json", logOf(t, 3, -1).SignCheckpoint(priv))

	honest := logOf(t, 5, -1)
	forged := logOf(t, 5, 1) // leaf 1 rewritten after checkpoint A
	run1 := func(l *audittrust.MerkleLog, name string) int {
		nf := writeJSON(t, dir, name+"-new.json", l.SignCheckpoint(priv))
		proof, _ := l.ConsistencyProof(3)
		pf := writeJSON(t, dir, name+"-proof.json", map[string]any{"proof": b64(proof)})
		var out, errb bytes.Buffer
		return run([]string{"pair", "--pubkey", pubB64, "--old", old, "--new", nf, "--proof", pf}, &out, &errb)
	}
	if c := run1(honest, "honest"); c != 0 {
		t.Fatalf("honest pair: %d", c)
	}
	if c := run1(forged, "forged"); c != 1 {
		t.Fatalf("tampered history must exit 1, got %d", c)
	}
}

func TestUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if c := run(nil, &out, &errb); c != 2 {
		t.Fatal(c)
	}
	if c := run([]string{"bogus"}, &out, &errb); c != 2 {
		t.Fatal(c)
	}
}
