// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package pqc

import (
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// Wave member outcome statuses, shared by the migrate-wave executor and its
// consumers so a status string is never retyped.
const (
	MemberMigrated            = "migrated"
	MemberFailed              = "failed"
	MemberSkipped             = "skipped"
	MemberDeliveryUnsupported = "delivery_unsupported"
)

const (
	readinessQuantumSafe         = "quantum_safe"
	readinessQuantumSafeLeafOnly = "quantum_safe_leaf_only"
)

// ReadinessIsPQC reports whether a PQCReadiness label means the leaf key is
// post-quantum (full chain or leaf-only).
func ReadinessIsPQC(label string) bool {
	return label == readinessQuantumSafe || label == readinessQuantumSafeLeafOnly
}

// MigratedKey is the result of generating a fresh ML-DSA or hybrid keypair
// and CSR for a certificate being re-issued by a migration wave. The CSR
// itself carries dnsNames/ipAddresses (see ca.CreateCertificateRequestMLDSA/
// CreateCertificateRequestHybrid) -- the caller doesn't need to thread them
// separately.
type MigratedKey struct {
	KeyID  string
	CSRPEM string
}

// BuildMigrationCSR generates a new ML-DSA or hybrid keypair for algo under
// keys, then builds and PEM-encodes a CSR with the given subject and SANs.
// keyID must be unique (caller's responsibility, e.g.
// "pqc-migrate-{fingerprint}-{timestamp}").
func BuildMigrationCSR(keys keystore.Store, keyID string, algo keystore.Algorithm, subject pkix.Name, dnsNames []string, ipAddresses []net.IP) (MigratedKey, error) {
	if _, err := keys.GenerateKey(keyID, algo); err != nil {
		return MigratedKey{}, fmt.Errorf("generate key: %w", err)
	}

	switch {
	case keystore.IsMLDSA(algo):
		signer, err := keys.Signer(keyID)
		if err != nil {
			return MigratedKey{}, fmt.Errorf("load signer: %w", err)
		}
		der, err := ca.CreateCertificateRequestMLDSA(subject, dnsNames, ipAddresses, signer, algo)
		if err != nil {
			return MigratedKey{}, fmt.Errorf("create CSR: %w", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "ML-DSA CERTIFICATE REQUEST", Bytes: der})
		return MigratedKey{KeyID: keyID, CSRPEM: string(pemBytes)}, nil

	case keystore.IsHybrid(algo):
		loader, ok := keys.(keystore.HybridKeyLoader)
		if !ok {
			return MigratedKey{}, fmt.Errorf("key store does not support hybrid keys")
		}
		pair, err := loader.LoadHybridKeyPair(keyID)
		if err != nil {
			return MigratedKey{}, fmt.Errorf("load hybrid key pair: %w", err)
		}
		der, err := ca.CreateCertificateRequestHybrid(subject, dnsNames, ipAddresses, pair.Primary, pair.Secondary, algo)
		if err != nil {
			return MigratedKey{}, fmt.Errorf("create CSR: %w", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "HYBRID CERTIFICATE REQUEST", Bytes: der})
		return MigratedKey{KeyID: keyID, CSRPEM: string(pemBytes)}, nil

	default:
		return MigratedKey{}, fmt.Errorf("algorithm %s is neither ML-DSA nor hybrid", algo)
	}
}
