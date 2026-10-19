// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package keyinventory

import (
	"context"
	"fmt"
	"strings"
	"time"

	"kryptkeeper/internal/sshkeys"
)

// W24-33: SSH host keys (from discovery) and user keys (from sshkeys.Inventory)
// join the cloud keys in one inventory. Metadata only: no key material.

// SSHHostKeyRecord is one scanned SSH endpoint and the host-key algorithms it offered.
type SSHHostKeyRecord struct {
	Host        string
	Port        int
	Algorithms  []string
	LastScanned string
}

// SSHHostKeyLister supplies scanned SSH endpoints.
type SSHHostKeyLister interface {
	ListSSHHostKeys(ctx context.Context) ([]SSHHostKeyRecord, error)
}

type sshHostKeySource struct{ l SSHHostKeyLister }

// NewSSHHostKeySource lists one row per (endpoint, host-key algorithm).
func NewSSHHostKeySource(l SSHHostKeyLister) KeySource { return sshHostKeySource{l: l} }

func (sshHostKeySource) Provider() string { return "ssh-host" }

func (s sshHostKeySource) ListKeys(ctx context.Context) ([]Key, error) {
	recs, err := s.l.ListSSHHostKeys(ctx)
	if err != nil {
		return nil, err
	}
	var keys []Key
	for _, r := range recs {
		loc := fmt.Sprintf("%s:%d", r.Host, r.Port)
		for _, alg := range r.Algorithms {
			keys = append(keys, Key{
				Provider: "ssh-host", KeyType: "host", Location: loc, KeyID: loc + "/" + alg,
				Algorithm: sshAlgorithmLabel(alg, 0), State: "active",
				// The scanner records no rotation data, so RotationEnabled and Stale stay false.
				RotationEnabled: false, Stale: false,
				CreatedAt: r.LastScanned, PQCReadiness: sshKeyPQC(alg),
			})
		}
	}
	return keys, nil
}

type sshUserKeySource struct {
	inv *sshkeys.Inventory
	now func() time.Time
}

// NewSSHUserKeySource lists the user keys held in an sshkeys.Inventory.
func NewSSHUserKeySource(inv *sshkeys.Inventory, now func() time.Time) KeySource {
	return sshUserKeySource{inv: inv, now: now}
}

func (sshUserKeySource) Provider() string { return "ssh-user" }

func (s sshUserKeySource) ListKeys(context.Context) ([]Key, error) {
	if s.inv == nil {
		return nil, nil
	}
	now := s.now()
	var keys []Key
	for _, k := range s.inv.List() {
		loc := k.Host
		if k.Path != "" {
			loc += ":" + k.Path
		}
		state := "unauthorized"
		if k.IsAuthorized {
			state = "authorized"
		}
		created := ""
		if !k.CreatedAt.IsZero() {
			created = k.CreatedAt.UTC().Format(time.RFC3339)
		}
		keys = append(keys, Key{
			Provider: "ssh-user", KeyType: "user", Location: loc, KeyID: k.Fingerprint,
			Algorithm: sshAlgorithmLabel(string(k.KeyType), k.BitSize), State: state,
			Stale: k.IsStale(now), CreatedAt: created, PQCReadiness: sshKeyPQC(string(k.KeyType)),
		})
	}
	return keys, nil
}

func sshAlgorithmLabel(keyType string, bits int) string {
	t := strings.ToLower(keyType)
	if sshKeyPQC(t) == "quantum_safe" { // "mldsa" contains "dsa": never label a PQC key DSA
		return keyType
	}
	switch {
	case strings.Contains(t, "rsa"):
		if bits > 0 {
			return fmt.Sprintf("RSA_%d", bits)
		}
		return "RSA"
	case strings.Contains(t, "ed25519"):
		return "Ed25519"
	case strings.Contains(t, "nistp256"):
		return "ECDSA_P256"
	case strings.Contains(t, "nistp384"):
		return "ECDSA_P384"
	case strings.Contains(t, "nistp521"):
		return "ECDSA_P521"
	case strings.Contains(t, "dss"), strings.Contains(t, "dsa"):
		return "DSA"
	}
	return keyType
}

// sshKeyPQC is separate from scoreKeyPQC, which reports Ed25519 as unknown.
func sshKeyPQC(algorithm string) string {
	a := strings.ToLower(algorithm)
	for _, p := range []string{"ml-dsa", "mldsa", "slh-dsa", "sphincs", "dilithium", "falcon"} {
		if strings.Contains(a, p) {
			return "quantum_safe"
		}
	}
	for _, p := range []string{"rsa", "ecdsa", "ed25519", "dsa", "dss"} {
		if strings.Contains(a, p) {
			return "vulnerable"
		}
	}
	return "unknown"
}
