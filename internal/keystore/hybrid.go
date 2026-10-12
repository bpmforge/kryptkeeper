// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keystore

// hybrid.go — Hybrid key pair management for ECDSA+ML-DSA composite certificates.
//
// A hybrid key consists of two separately stored keys:
//   - Primary: ECDSA (P-256 or P-384) — appears in SubjectPublicKeyInfo, backward compatible
//   - Secondary: ML-DSA (65 or 87) — stored in alt-signature extensions
//
// Storage: a small JSON metadata file {id}.hybrid.json records the two key IDs.
// The actual private keys are stored separately using the existing classical and
// ML-DSA storage paths.
//
// Spec reference: draft-ounsworth-x509-alt-sig-alg-07 (RFC 9480 profiles)
// OIDs used:
//   id-ce-subjectAltPublicKeyInfo  2.5.29.72
//   id-ce-altSignatureAlgorithm    2.5.29.73
//   id-ce-altSignatureValue        2.5.29.74

import (
	"crypto"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// HybridKeyPair holds the two signers that make up a hybrid key.
type HybridKeyPair struct {
	PrimaryID   string        // ECDSA key ID
	SecondaryID string        // ML-DSA key ID
	Primary     crypto.Signer // ECDSA signer
	Secondary   crypto.Signer // ML-DSA signer
	Algo        Algorithm
}

// hybridMeta is persisted to {id}.hybrid.json.
type hybridMeta struct {
	Algo        string `json:"algo"`
	PrimaryID   string `json:"primary_id"`
	SecondaryID string `json:"secondary_id"`
}

// isHybrid reports whether algo is a hybrid algorithm.
func isHybrid(algo Algorithm) bool {
	return algo == HybridECDSAP256MLDSA65 || algo == HybridECDSAP384MLDSA87
}

// IsHybrid is the exported form for use in internal/ca.
func IsHybrid(algo Algorithm) bool { return isHybrid(algo) }

// HybridComponents returns the classical and ML-DSA component algorithms for a hybrid.
// Exported so internal/ca can build the cert signing pipeline.
func HybridComponents(algo Algorithm) (classical, mldsa Algorithm, ok bool) {
	return hybridComponents(algo)
}

// hybridComponents returns the classical and ML-DSA component algorithms for a hybrid.
func hybridComponents(algo Algorithm) (classical, mldsa Algorithm, ok bool) {
	switch algo {
	case HybridECDSAP256MLDSA65:
		return ECDSAP256, MLDSA65, true
	case HybridECDSAP384MLDSA87:
		return ECDSAP384, MLDSA87, true
	}
	return "", "", false
}

// hybridMetaPath returns the path to the hybrid metadata file.
func (s *SoftwareStore) hybridMetaPath(id string) string {
	safe := filepath.Base(id)
	return filepath.Join(s.dir, safe+".hybrid.json")
}

// generateHybridKey creates a classical + ML-DSA key pair, persists both, and
// returns a HybridKeyPair.
func (s *SoftwareStore) generateHybridKey(id string, algo Algorithm) (HybridKeyPair, error) {
	classicalAlgo, mldsaAlgo, ok := hybridComponents(algo)
	if !ok {
		return HybridKeyPair{}, fmt.Errorf("not a hybrid algorithm: %s", algo)
	}

	primaryID := id + "-primary"
	secondaryID := id + "-secondary"

	// Generate classical key.
	if _, err := s.GenerateKey(primaryID, classicalAlgo); err != nil {
		return HybridKeyPair{}, fmt.Errorf("generate primary key: %w", err)
	}

	// Generate ML-DSA key.
	if _, err := s.GenerateKey(secondaryID, mldsaAlgo); err != nil {
		_ = s.Delete(primaryID) // clean up
		return HybridKeyPair{}, fmt.Errorf("generate secondary key: %w", err)
	}

	// Persist hybrid metadata.
	meta := hybridMeta{Algo: string(algo), PrimaryID: primaryID, SecondaryID: secondaryID}
	b, err := json.Marshal(meta)
	if err != nil {
		return HybridKeyPair{}, fmt.Errorf("marshal hybrid meta: %w", err)
	}
	metaPath := s.hybridMetaPath(id)
	if err := os.WriteFile(metaPath, b, 0o600); err != nil {
		return HybridKeyPair{}, fmt.Errorf("write hybrid meta: %w", err)
	}

	primary, err := s.Signer(primaryID)
	if err != nil {
		return HybridKeyPair{}, fmt.Errorf("get primary signer: %w", err)
	}
	secondary, err := s.Signer(secondaryID)
	if err != nil {
		return HybridKeyPair{}, fmt.Errorf("get secondary signer: %w", err)
	}

	return HybridKeyPair{
		PrimaryID: primaryID, SecondaryID: secondaryID,
		Primary: primary, Secondary: secondary,
		Algo: algo,
	}, nil
}

// loadHybridKeyPair loads both signers for a hybrid key from their stored IDs.
func (s *SoftwareStore) loadHybridKeyPair(id string) (HybridKeyPair, error) {
	metaPath := s.hybridMetaPath(id)
	b, err := os.ReadFile(metaPath)
	if os.IsNotExist(err) {
		return HybridKeyPair{}, ErrKeyNotFound
	}
	if err != nil {
		return HybridKeyPair{}, fmt.Errorf("read hybrid meta: %w", err)
	}

	var meta hybridMeta
	if err := json.Unmarshal(b, &meta); err != nil {
		return HybridKeyPair{}, fmt.Errorf("parse hybrid meta: %w", err)
	}

	primary, err := s.Signer(meta.PrimaryID)
	if err != nil {
		return HybridKeyPair{}, fmt.Errorf("load primary signer: %w", err)
	}
	secondary, err := s.Signer(meta.SecondaryID)
	if err != nil {
		return HybridKeyPair{}, fmt.Errorf("load secondary signer: %w", err)
	}

	return HybridKeyPair{
		PrimaryID: meta.PrimaryID, SecondaryID: meta.SecondaryID,
		Primary: primary, Secondary: secondary,
		Algo: Algorithm(meta.Algo),
	}, nil
}

// isHybridID reports whether there is a hybrid metadata file for the given ID.
func (s *SoftwareStore) isHybridID(id string) bool {
	_, err := os.Stat(s.hybridMetaPath(id))
	return err == nil
}

// deleteHybridKey removes the metadata file and both component keys.
func (s *SoftwareStore) deleteHybridKey(id string) error {
	pair, err := s.loadHybridKeyPair(id)
	if err != nil {
		return err
	}
	_ = s.Delete(pair.PrimaryID)   // cleanup of partial state; original error is what matters
	_ = s.Delete(pair.SecondaryID) // cleanup of partial state; original error is what matters
	return os.Remove(s.hybridMetaPath(id))
}

// exportHybridEncryptedKey backs up both components of a hybrid key (W9-03).
// There is no single hybrid private key to marshal (see the file header) —
// each component is exported through the normal single-key path (ECDSA via
// PKCS#8, ML-DSA via its raw form) and the two resulting PEM blocks are
// concatenated behind a leading hybrid-meta block that records how to
// reassemble them on import.
func (s *SoftwareStore) exportHybridEncryptedKey(id string, backupPassphrase []byte) ([]byte, error) {
	pair, err := s.loadHybridKeyPair(id)
	if err != nil {
		return nil, fmt.Errorf("export: %w", err)
	}

	primaryPEM, err := s.exportSingleEncryptedKey(pair.PrimaryID, pair.Primary, backupPassphrase)
	if err != nil {
		return nil, fmt.Errorf("export hybrid primary: %w", err)
	}
	secondaryPEM, err := s.exportSingleEncryptedKey(pair.SecondaryID, pair.Secondary, backupPassphrase)
	if err != nil {
		return nil, fmt.Errorf("export hybrid secondary: %w", err)
	}

	metaBlock := pem.EncodeToMemory(&pem.Block{
		Type: "KRYPTKEEPER BACKUP HYBRID META",
		Headers: map[string]string{
			"Key-ID": id,
			"Algo":   string(pair.Algo),
		},
	})

	out := make([]byte, 0, len(metaBlock)+len(primaryPEM)+len(secondaryPEM))
	out = append(out, metaBlock...)
	out = append(out, primaryPEM...)
	out = append(out, secondaryPEM...)
	return out, nil
}

// importHybridEncryptedKey reverses exportHybridEncryptedKey: decodes the two
// component blocks following the hybrid-meta block, imports each under a
// fresh "{id}-primary"/"{id}-secondary" ID, then writes the hybrid metadata
// sidecar. Any partial failure rolls back the components already persisted.
func (s *SoftwareStore) importHybridEncryptedKey(id string, metaBlock *pem.Block, rest []byte, backupPassphrase []byte) error {
	if s.isHybridID(id) {
		return ErrKeyExists
	}

	algo := Algorithm(metaBlock.Headers["Algo"])

	primaryBlock, rest2 := pem.Decode(rest)
	if primaryBlock == nil {
		return fmt.Errorf("invalid backup PEM data: missing hybrid primary block")
	}
	secondaryBlock, _ := pem.Decode(rest2)
	if secondaryBlock == nil {
		return fmt.Errorf("invalid backup PEM data: missing hybrid secondary block")
	}

	primaryID := id + "-primary"
	secondaryID := id + "-secondary"

	primaryKey, err := decryptBackupBlock(primaryBlock, backupPassphrase)
	if err != nil {
		return fmt.Errorf("import hybrid primary: %w", err)
	}
	if err := s.persistImportedSingleKey(primaryID, primaryKey); err != nil {
		return fmt.Errorf("import hybrid primary: %w", err)
	}

	secondaryKey, err := decryptBackupBlock(secondaryBlock, backupPassphrase)
	if err != nil {
		_ = s.Delete(primaryID) // cleanup of partial state; original error is what matters
		return fmt.Errorf("import hybrid secondary: %w", err)
	}
	if err := s.persistImportedSingleKey(secondaryID, secondaryKey); err != nil {
		_ = s.Delete(primaryID) // cleanup of partial state; original error is what matters
		return fmt.Errorf("import hybrid secondary: %w", err)
	}

	meta := hybridMeta{Algo: string(algo), PrimaryID: primaryID, SecondaryID: secondaryID}
	b, err := json.Marshal(meta)
	if err != nil {
		_ = s.Delete(primaryID)   // cleanup of partial state; original error is what matters
		_ = s.Delete(secondaryID) // cleanup of partial state; original error is what matters
		return fmt.Errorf("marshal hybrid meta: %w", err)
	}
	if err := os.WriteFile(s.hybridMetaPath(id), b, 0o600); err != nil {
		_ = s.Delete(primaryID)   // cleanup of partial state; original error is what matters
		_ = s.Delete(secondaryID) // cleanup of partial state; original error is what matters
		return fmt.Errorf("write hybrid meta: %w", err)
	}
	return nil
}

// hybridMetaAlgo reads the Algorithm from the metadata file without loading keys.
func (s *SoftwareStore) hybridMetaAlgo(id string) (Algorithm, error) {
	b, err := os.ReadFile(s.hybridMetaPath(id))
	if err != nil {
		return "", ErrKeyNotFound
	}
	var meta hybridMeta
	if err := json.Unmarshal(b, &meta); err != nil {
		return "", fmt.Errorf("parse hybrid meta: %w", err)
	}
	return Algorithm(meta.Algo), nil
}

// listHybridIDs returns the hybrid key IDs visible in the store directory.
func (s *SoftwareStore) listHybridIDs() []string {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil
	}
	var ids []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".hybrid.json") {
			ids = append(ids, strings.TrimSuffix(e.Name(), ".hybrid.json"))
		}
	}
	return ids
}
