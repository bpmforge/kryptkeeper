// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package pqc

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"slices"

	"kryptkeeper/internal/keystore"
)

// TransitionTargets are the classical algorithms a wave may re-issue to; PQC
// targets are accepted through keystore.IsMLDSA/IsHybrid. RSA-2048 is absent on
// purpose: it is the legacy source of a transition, not a sensible target.
var TransitionTargets = []keystore.Algorithm{keystore.RSA3072, keystore.RSA4096,
	keystore.ECDSAP256, keystore.ECDSAP384, keystore.Ed25519}

// IsTransitionTarget reports whether a wave may re-issue members to a.
func IsTransitionTarget(a keystore.Algorithm) bool {
	return keystore.IsMLDSA(a) || keystore.IsHybrid(a) || slices.Contains(TransitionTargets, a)
}

// BuildTransitionCSR generates a keypair for algo under keys and returns its
// PEM CSR. PQC algorithms delegate to BuildMigrationCSR unchanged; classical
// ones are signed through the keystore signer so the key never leaves it.
func BuildTransitionCSR(keys keystore.Store, keyID string, algo keystore.Algorithm, subject pkix.Name, dnsNames []string, ipAddresses []net.IP) (MigratedKey, error) {
	if keystore.IsMLDSA(algo) || keystore.IsHybrid(algo) {
		return BuildMigrationCSR(keys, keyID, algo, subject, dnsNames, ipAddresses)
	}
	// Checked before GenerateKey so a rejected algorithm leaves no orphan key.
	if !slices.Contains(TransitionTargets, algo) {
		return MigratedKey{}, fmt.Errorf("algorithm %s is not a supported transition target", algo)
	}
	if _, err := keys.GenerateKey(keyID, algo); err != nil {
		return MigratedKey{}, fmt.Errorf("generate key: %w", err)
	}
	signer, err := keys.Signer(keyID)
	if err != nil {
		return MigratedKey{}, fmt.Errorf("load signer: %w", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     subject,
		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,
	}, signer)
	if err != nil {
		return MigratedKey{}, fmt.Errorf("create CSR: %w", err)
	}
	return MigratedKey{KeyID: keyID, CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))}, nil
}
