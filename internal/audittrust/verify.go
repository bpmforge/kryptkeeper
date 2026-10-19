// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package audittrust

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Offline verification helpers. They take only data the auditor holds
// plus a PINNED public key; nothing here may consult a server or trust a
// key embedded in the material being checked.

// canonicalLeafFields mirrors the server's leaf encoding (field order is
// the contract: a different order hashes to a different leaf).
type canonicalLeafFields struct {
	ID           int64  `json:"id"`
	Timestamp    string `json:"timestamp"`
	Action       string `json:"action"`
	ActorType    string `json:"actor_type"`
	ActorID      string `json:"actor_id"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Outcome      string `json:"outcome"`
	Tenant       string `json:"tenant"`
}

// CanonicalLeaf re-encodes an audit entry (as returned by the API) into
// the exact bytes that were hashed into the transparency tree. Only the
// nine tamper-relevant fields participate, so volatile or optional
// fields (user agent, change summary) cannot break a proof.
func CanonicalLeaf(entryJSON []byte) ([]byte, error) {
	var f canonicalLeafFields
	if err := json.Unmarshal(entryJSON, &f); err != nil {
		return nil, fmt.Errorf("entry is not valid audit JSON: %w", err)
	}
	return json.Marshal(f)
}

// DecodeProof decodes the base64 audit_path / proof arrays from the API.
func DecodeProof(b64 []string) ([][32]byte, error) {
	out := make([][32]byte, 0, len(b64))
	for i, s := range b64 {
		raw, err := base64.StdEncoding.DecodeString(s)
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("proof element %d is not a base64 32-byte hash", i)
		}
		var h [32]byte
		copy(h[:], raw)
		out = append(out, h)
	}
	return out, nil
}

// VerifyRecord proves leaf is entry `index` of the tree committed by a
// checkpoint signed by pub.
func VerifyRecord(pub ed25519.PublicKey, cp SignedCheckpoint, leaf []byte, index int, proof [][32]byte) error {
	root, err := VerifyCheckpoint(pub, cp)
	if err != nil {
		return err
	}
	if index < 0 || index >= cp.Size {
		return fmt.Errorf("index %d is outside the checkpoint (size %d)", index, cp.Size)
	}
	if !VerifyInclusion(index, cp.Size, HashLeaf(leaf), root, proof) {
		return errors.New("inclusion proof does not verify against the checkpoint root")
	}
	return nil
}

// VerifyPair proves the tree behind newer is an append-only extension of
// the tree behind older (no retro-tamper between the two checkpoints).
func VerifyPair(pub ed25519.PublicKey, older, newer SignedCheckpoint, proof [][32]byte) error {
	oldRoot, err := VerifyCheckpoint(pub, older)
	if err != nil {
		return fmt.Errorf("older checkpoint: %w", err)
	}
	newRoot, err := VerifyCheckpoint(pub, newer)
	if err != nil {
		return fmt.Errorf("newer checkpoint: %w", err)
	}
	if older.Size < 1 || older.Size > newer.Size {
		return fmt.Errorf("checkpoint sizes out of order (%d, %d)", older.Size, newer.Size)
	}
	if !VerifyConsistency(older.Size, newer.Size, oldRoot, newRoot, proof) {
		return errors.New("consistency proof does not verify: history was altered")
	}
	return nil
}
