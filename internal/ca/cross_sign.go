// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"time"

	"kryptkeeper/internal/keystore"
)

// W6-07 (D-054/FR-P16): cross-signing for zero-downtime key rollover.
// RotateCA re-keys in place; every relying party pinning the OLD
// certificate would break the moment leaves carry the new signature. The
// bridge certificate carries the NEW CA identity (subject, public key,
// SKI) under the OLD key's signature, so during the transition a leaf
// issued by the new key chains EITHER directly to the new self-signed
// certificate OR through the bridge to the old one.

// CrossSignResult is a completed rollover with its bridge.
type CrossSignResult struct {
	// RolledCA is the re-keyed CA (new key, new self-signed certificate).
	RolledCA *CA
	// CrossCertPEM is the bridge: new identity, old signature.
	CrossCertPEM []byte
	// OldCertPEM is the retired self-signed certificate relying parties
	// may still trust during the window.
	OldCertPEM []byte
	// OldKeyID is the retired key's on-disk reference.
	OldKeyID string
	// Rotation is the ledger entry RotateCA recorded for this re-key.
	Rotation KeyRotation
}

// CrossSignRotate re-keys caID via RotateCA and issues the bridge. Both
// chains are VERIFIED before returning — a cross-sign whose paths don't
// build is an error, never a result.
func (e *Engine) CrossSignRotate(caID string, opts RotateCAOptions) (CrossSignResult, error) {
	// Capture the outgoing identity before rotation replaces it.
	oldCA, err := e.GetCA(caID)
	if err != nil {
		return CrossSignResult{}, err
	}
	if oldCA.Certificate == nil {
		return CrossSignResult{}, fmt.Errorf("cross-sign: CA %s has no certificate on record", caID)
	}
	oldCert := oldCA.Certificate
	oldCertPEM := append([]byte(nil), oldCA.CertPEM...)

	// The bridge is built inside RotateCA's probe-verify step so a failure
	// there rolls the whole rotation back instead of leaving a re-keyed CA
	// without its bridge.
	var crossPEM []byte
	opts.afterProbe = func(newCA *CA, retiredKeyID string) error {
		bridgePEM, err := e.buildAndVerifyBridge(newCA, oldCert, retiredKeyID)
		crossPEM = bridgePEM
		return err
	}
	rotated, err := e.RotateCA(caID, opts)
	if err != nil {
		return CrossSignResult{}, err
	}
	return CrossSignResult{
		RolledCA:     rotated.CA,
		CrossCertPEM: crossPEM,
		OldCertPEM:   oldCertPEM,
		OldKeyID:     rotated.OldKeyID,
		Rotation:     rotated.Rotation,
	}, nil
}

// buildAndVerifyBridge signs the bridge with the retired key and verifies both
// chains. Must be called with e.mu held.
func (e *Engine) buildAndVerifyBridge(newCA *CA, oldCert *x509.Certificate, retiredKeyID string) ([]byte, error) {
	newCert := newCA.Certificate
	// The retired key still exists on disk under retiredKeyID — it signs the
	// bridge, with the old certificate as parent (AKI = old SKI).
	oldSigner, err := e.keys.Signer(retiredKeyID)
	if err != nil {
		return nil, fmt.Errorf("cross-sign: retired key %s unavailable: %w", retiredKeyID, err)
	}
	oldAlgo := e.oldKeyAlgorithm(retiredKeyID, oldCert)

	serial, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("cross-sign: serial: %w", err)
	}
	now := time.Now().UTC()
	// Cap the bridge at the OLD certificate's own lifetime: a cross-sign
	// outliving its issuer builds paths verifiers reject anyway, and the
	// cap makes the transition window explicit.
	notAfter := newCert.NotAfter
	if oldCert.NotAfter.Before(notAfter) {
		notAfter = oldCert.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               newCert.Subject,
		NotBefore:             now,
		NotAfter:              notAfter,
		IsCA:                  true,
		MaxPathLen:            newCert.MaxPathLen,
		MaxPathLenZero:        newCert.MaxPathLenZero,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          newCert.SubjectKeyId,
		// Subject == issuer here, so x509.CreateCertificate omits the AKI it would
		// otherwise copy from the parent. Without it OpenSSL classifies the bridge
		// as self-signed (error 19) and refuses the old-anchor path (W23-19).
		AuthorityKeyId: oldCert.SubjectKeyId,
	}

	crossDER, err := createCertDER(template, oldCert, oldAlgo, newCert.PublicKey, oldSigner)
	if err != nil {
		return nil, fmt.Errorf("cross-sign: create bridge certificate: %w", err)
	}
	crossCert, err := x509.ParseCertificate(crossDER)
	if err != nil {
		return nil, fmt.Errorf("cross-sign: parse bridge certificate: %w", err)
	}

	// Acceptance #2, enforced here rather than only in tests: both chains
	// must validate for a probe leaf issued under the NEW key.
	probe, err := e.issueProbeLeafLocked(newCA)
	if err != nil {
		return nil, fmt.Errorf("cross-sign: issue probe leaf: %w", err)
	}
	if err := verifyRolloverChains(probe, newCert, oldCert, crossCert); err != nil {
		return nil, fmt.Errorf("cross-sign: rollover chain verification failed: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crossDER}), nil
}

// oldKeyAlgorithm resolves the retired key's algorithm for signature
// dispatch — metadata first, falling back to the old certificate's own
// public-key algorithm.
func (e *Engine) oldKeyAlgorithm(oldKeyID string, oldCert *x509.Certificate) keystore.Algorithm {
	if meta, err := e.keys.Metadata(oldKeyID); err == nil && meta.Algorithm != "" {
		return meta.Algorithm
	}
	switch oldCert.PublicKeyAlgorithm {
	case x509.RSA:
		if pub, ok := oldCert.PublicKey.(*rsa.PublicKey); ok {
			switch bits := pub.N.BitLen(); {
			case bits <= 2048:
				return keystore.RSA2048
			case bits <= 3072:
				return keystore.RSA3072
			}
		}
		return keystore.RSA4096
	case x509.Ed25519:
		return keystore.Ed25519
	default:
		return keystore.ECDSAP256
	}
}

// verifyRolloverChains builds both paths for a probe leaf issued under the new
// key: directly to the new self-signed certificate, and via the bridge to the
// old one.
func verifyRolloverChains(probe, newCert, oldCert, crossCert *x509.Certificate) error {
	newRoots := x509.NewCertPool()
	newRoots.AddCert(newCert)
	if _, err := probe.Verify(x509.VerifyOptions{Roots: newRoots}); err != nil {
		return fmt.Errorf("new-root chain: %w", err)
	}

	oldRoots := x509.NewCertPool()
	oldRoots.AddCert(oldCert)
	bridge := x509.NewCertPool()
	bridge.AddCert(crossCert)
	if _, err := probe.Verify(x509.VerifyOptions{Roots: oldRoots, Intermediates: bridge}); err != nil {
		return fmt.Errorf("old-root chain via bridge: %w", err)
	}
	return nil
}

// issueProbeLeaf signs a minimal short-lived leaf with the CA's CURRENT
// key, purely to prove path building. It is never persisted.
func (e *Engine) issueProbeLeaf(caID string) (*x509.Certificate, error) {
	e.mu.Lock()
	ca, ok := e.get(caID)
	e.mu.Unlock()
	if !ok {
		return nil, ErrCANotFound
	}
	return e.issueProbeLeafLocked(ca)
}

// issueProbeLeafLocked is issueProbeLeaf for a caller already holding e.mu.
func (e *Engine) issueProbeLeafLocked(ca *CA) (*x509.Certificate, error) {
	signer, err := e.keys.Signer(ca.KeyID)
	if err != nil {
		return nil, err
	}
	meta, err := e.keys.Metadata(ca.KeyID)
	if err != nil {
		return nil, err
	}
	serial, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		// A distinct subject: a probe reusing the CA's own subject is
		// self-issued-shaped (RawIssuer == RawSubject) and Go's chain
		// builder treats those specially.
		Subject:   pkix.Name{CommonName: "kryptkeeper-rollover-probe"},
		NotBefore: now,
		NotAfter:  now.Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	der, err := createCertDER(template, ca.Certificate, meta.Algorithm, signer.Public(), signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}
