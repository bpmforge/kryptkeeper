// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package sshkeys

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"
)

// KeyType represents an SSH key algorithm.
type KeyType string

const (
	RSA     KeyType = "ssh-rsa"
	Ed25519 KeyType = "ssh-ed25519"
	ECDSA   KeyType = "ecdsa-sha2-nistp256"
)

// SSHKey represents a discovered SSH key.
type SSHKey struct {
	Fingerprint  string        `json:"fingerprint"`
	KeyType      KeyType       `json:"key_type"`
	BitSize      int           `json:"bit_size"`
	Comment      string        `json:"comment"`
	Host         string        `json:"host"`
	Path         string        `json:"path"`
	IsAuthorized bool          `json:"is_authorized"`
	LastRotated  *time.Time    `json:"last_rotated,omitempty"`
	CreatedAt    time.Time     `json:"created_at"`
	StaleAfter   time.Duration `json:"-"`
	RiskScore    int           `json:"risk_score"`
	RiskFlags    []string      `json:"risk_flags"`
}

// IsStale returns true if the key hasn't been rotated within its staleness window.
func (k *SSHKey) IsStale(now time.Time) bool {
	if k.LastRotated == nil {
		return true
	}
	stale := k.StaleAfter
	if stale == 0 {
		stale = 90 * 24 * time.Hour // default 90 days
	}
	return now.Sub(*k.LastRotated) > stale
}

// Inventory manages the SSH key inventory.
type Inventory struct {
	keys map[string]*SSHKey // keyed by fingerprint
}

// NewInventory creates an SSH key inventory.
func NewInventory() *Inventory {
	return &Inventory{keys: make(map[string]*SSHKey)}
}

// Add registers a discovered SSH key.
func (inv *Inventory) Add(key SSHKey) {
	key.RiskScore, key.RiskFlags = computeSSHRisk(key)
	inv.keys[key.Fingerprint] = &key
}

// List returns all inventoried SSH keys.
func (inv *Inventory) List() []SSHKey {
	result := make([]SSHKey, 0, len(inv.keys))
	for _, k := range inv.keys {
		result = append(result, *k)
	}
	return result
}

// StaleKeys returns keys that haven't been rotated within their window.
func (inv *Inventory) StaleKeys(now time.Time) []SSHKey {
	var stale []SSHKey
	for _, k := range inv.keys {
		if k.IsStale(now) {
			stale = append(stale, *k)
		}
	}
	return stale
}

// Stats returns inventory summary statistics.
func (inv *Inventory) Stats(now time.Time) InventoryStats {
	stats := InventoryStats{Total: len(inv.keys)}
	for _, k := range inv.keys {
		if k.IsStale(now) {
			stats.Stale++
		}
		if k.KeyType == RSA && k.BitSize < 2048 {
			stats.WeakKeys++
		}
		switch k.KeyType {
		case RSA:
			stats.RSACount++
		case Ed25519:
			stats.Ed25519Count++
		case ECDSA:
			stats.ECDSACount++
		}
	}
	return stats
}

// InventoryStats holds SSH key inventory summary.
type InventoryStats struct {
	Total        int `json:"total"`
	Stale        int `json:"stale"`
	WeakKeys     int `json:"weak_keys"`
	RSACount     int `json:"rsa_count"`
	Ed25519Count int `json:"ed25519_count"`
	ECDSACount   int `json:"ecdsa_count"`
}

// ScanFunc discovers SSH keys on a host.
type ScanFunc func(ctx context.Context, host string) ([]SSHKey, error)

// FingerprintPublicKey computes SHA-256 fingerprint of an SSH public key.
func FingerprintPublicKey(pubKeyBytes []byte) string {
	hash := sha256.Sum256(pubKeyBytes)
	return fmt.Sprintf("SHA256:%x", hash)
}

func computeSSHRisk(key SSHKey) (int, []string) {
	score := 0
	var flags []string

	if key.KeyType == RSA && key.BitSize < 2048 {
		score += 40
		flags = append(flags, "WEAK_KEY_SIZE")
	}
	if key.KeyType == RSA || key.KeyType == ECDSA {
		score += 10
		flags = append(flags, "PQC_VULNERABLE")
	}
	if key.LastRotated == nil {
		score += 20
		flags = append(flags, "NEVER_ROTATED")
	}
	if score > 100 {
		score = 100
	}
	return score, flags
}
