// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package audittrust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func archiveLeaf(e []byte) ([]byte, error) { return CanonicalLeaf(e) }

func writeArchive(t *testing.T, n int, priv ed25519.PrivateKey) (*bytes.Buffer, ArchiveTrailer) {
	t.Helper()
	var buf bytes.Buffer
	w := NewArchiveWriter(&buf, ArchiveHeader{CreatedAt: "2026-10-15T00:00:00Z", BeforeTS: "2026-01-01T00:00:00Z"}, archiveLeaf, priv)
	for i := 0; i < n; i++ {
		if err := w.Write(entryJSON(i, "cert.issue")); err != nil {
			t.Fatal(err)
		}
	}
	trl, err := w.Close()
	if err != nil {
		t.Fatal(err)
	}
	return &buf, trl
}

func TestArchiveRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	buf, trl := writeArchive(t, 7, priv)
	h, entries, got, err := ReadArchive(bytes.NewReader(buf.Bytes()), pub, archiveLeaf)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 7 || got.Count != 7 || got.FirstID != 1 || got.LastID != 7 || got.ChainHead != trl.ChainHead {
		t.Fatalf("unexpected result: %d entries, trailer %+v", len(entries), got)
	}
	if h.Version != ArchiveVersion || h.BeforeTS == "" {
		t.Fatalf("header %+v", h)
	}
}

func TestArchiveDetectsChainBreak(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	buf, _ := writeArchive(t, 5, priv)
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	lines[3] = strings.Replace(lines[3], "cert.issue", "cert.revoke", 1) // edit one row in place
	_, _, _, err := ReadArchive(strings.NewReader(strings.Join(lines, "\n")+"\n"), pub, archiveLeaf)
	if err == nil || !strings.Contains(err.Error(), "chain") {
		t.Fatalf("want chain error, got %v", err)
	}
	// Dropping a line must also fail (count / chain mismatch).
	dropped := append(append([]string{}, lines[:3]...), lines[4:]...)
	if _, _, _, err := ReadArchive(strings.NewReader(strings.Join(dropped, "\n")+"\n"), pub, archiveLeaf); err == nil {
		t.Fatal("dropped record must be detected")
	}
}

func TestArchiveDetectsBadSignature(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	buf, _ := writeArchive(t, 3, priv)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, _, _, err := ReadArchive(bytes.NewReader(buf.Bytes()), other, archiveLeaf); err == nil {
		t.Fatal("archive signed by another key must not verify")
	}
}

func TestArchiveDetectsTruncation(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	buf, _ := writeArchive(t, 3, priv)
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	cut := strings.Join(lines[:len(lines)-1], "\n") + "\n"
	if _, _, _, err := ReadArchive(strings.NewReader(cut), pub, archiveLeaf); err == nil {
		t.Fatal("missing trailer must be detected")
	}
}

func TestArchiveCheckpointMatchesMerkleLog(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	buf, trl := writeArchive(t, 6, priv)
	want := &MerkleLog{}
	for i := 0; i < 6; i++ {
		leaf, _ := CanonicalLeaf(entryJSON(i, "cert.issue"))
		want.Append(leaf)
	}
	root, err := VerifyCheckpoint(pub, trl.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if !EqualRoots(root, want.Root()) || trl.Checkpoint.Size != 6 {
		t.Fatal("archive checkpoint must equal the Merkle log over the archived leaves")
	}
	if _, _, _, err := ReadArchive(bytes.NewReader(buf.Bytes()), pub, archiveLeaf); err != nil {
		t.Fatal(err)
	}
}

func TestArchiveEmptyRefused(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	w := NewArchiveWriter(&bytes.Buffer{}, ArchiveHeader{}, archiveLeaf, priv)
	if _, err := w.Close(); err == nil {
		t.Fatal("an empty archive must be refused")
	}
}
