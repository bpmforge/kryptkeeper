// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

// mixed_cert.go — certificate creation for a classical/Ed25519-keyed CA
// issuing a non-stdlib (ML-DSA) leaf (G-69/W4-08).
//
// stdlib x509.CreateCertificate's SPKI-marshal step rejects an ML-DSA leaf
// public key outright, confirmed empirically during W4-07 ("x509:
// unsupported public key type"). CreateCertificateMLDSA's hand-rolled ASN.1
// already handles this SPKI encoding for any leaf type, but its signing
// step hardcodes ML-DSA's full-message-sign convention -- a classical
// crypto.Signer.Sign() needs a pre-hashed digest instead, or the resulting
// signature is cryptographically garbage, not an error. This file
// generalizes the signing step; everything else is reused as-is from
// mldsa_cert.go (same package).

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"

	"kryptkeeper/internal/keystore"
)

// classicalSignatureAlgOID returns the AlgorithmIdentifier OID and hash
// function for a classical keystore.Algorithm's default signature scheme.
// hash == 0 signals full-message signing (Ed25519's convention, same as
// ML-DSA), otherwise the TBS bytes are hashed first and the digest is signed.
func classicalSignatureAlgOID(algo keystore.Algorithm) (asn1.ObjectIdentifier, crypto.Hash, bool) {
	switch algo {
	case keystore.ECDSAP256:
		return asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}, crypto.SHA256, true // ecdsa-with-SHA256
	case keystore.ECDSAP384:
		return asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}, crypto.SHA384, true // ecdsa-with-SHA384
	case keystore.RSA2048, keystore.RSA3072, keystore.RSA4096:
		return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, crypto.SHA256, true // sha256WithRSAEncryption
	case keystore.Ed25519:
		return asn1.ObjectIdentifier{1, 3, 101, 112}, crypto.Hash(0), true // id-Ed25519, full-message
	}
	return nil, 0, false
}

// signTBS signs tbsDER with signer using algo's standard signature scheme --
// hash-then-sign for ECDSA/RSA (a plain crypto.Hash opts value, not
// *rsa.PSSOptions, selects PKCS1v15 for RSA, matching sha256WithRSAEncryption's
// wire format), full-message signing for Ed25519 (matching ML-DSA's own
// convention).
func signTBS(signer crypto.Signer, tbsDER []byte, hash crypto.Hash) ([]byte, error) {
	if hash == 0 {
		return signer.Sign(rand.Reader, tbsDER, crypto.Hash(0))
	}
	h := hash.New()
	h.Write(tbsDER)
	digest := h.Sum(nil)
	return signer.Sign(rand.Reader, digest, hash)
}

// CreateCertificateMixedLeaf creates a leaf certificate whose public key
// (pub) is non-stdlib (ML-DSA), signed by a CA whose own signing algorithm
// is classical or Ed25519 (signerAlgo). Mirrors CreateCertificateMLDSA's
// hand-rolled ASN.1 structure (same tbsCert/outerCert/certSPKI/certAlgID
// types, same encodeLeafSPKI/encodeDN/buildMLDSAExtensions helpers) but
// generalizes the signing step.
func CreateCertificateMixedLeaf(
	template, parent *x509.Certificate,
	pub crypto.PublicKey,
	signer crypto.Signer,
	signerAlgo keystore.Algorithm,
) ([]byte, error) {
	oid, hash, ok := classicalSignatureAlgOID(signerAlgo)
	if !ok {
		return nil, fmt.Errorf("no signature algorithm OID for %s", signerAlgo)
	}

	spki, err := encodeLeafSPKI(pub)
	if err != nil {
		return nil, fmt.Errorf("encode leaf public key: %w", err)
	}
	issuerRaw, err := encodeDN(parent)
	if err != nil {
		return nil, fmt.Errorf("encode issuer DN: %w", err)
	}
	subjectRaw, err := encodeDN(template)
	if err != nil {
		return nil, fmt.Errorf("encode subject DN: %w", err)
	}
	exts, err := buildMLDSAExtensions(template) // fully generic despite the name -- reused as-is
	if err != nil {
		return nil, fmt.Errorf("build extensions: %w", err)
	}

	tbs := tbsCert{
		Version:            2,
		SerialNumber:       template.SerialNumber,
		SignatureAlgorithm: certAlgID{Algorithm: oid},
		Issuer:             issuerRaw,
		Validity: certValidity{
			NotBefore: template.NotBefore.UTC().Truncate(time.Second),
			NotAfter:  template.NotAfter.UTC().Truncate(time.Second),
		},
		Subject:    subjectRaw,
		PublicKey:  spki,
		Extensions: exts,
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("marshal TBSCertificate: %w", err)
	}

	sig, err := signTBS(signer, tbsDER, hash)
	if err != nil {
		return nil, fmt.Errorf("sign TBSCertificate: %w", err)
	}

	outer := outerCert{
		TBSCertificate:     asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: certAlgID{Algorithm: oid},
		Signature:          asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	}
	return asn1.Marshal(outer)
}

// verifyClassicalCSRSignature independently verifies sig over msg with pub,
// dispatching on algo/hash the same way signTBS dispatched signing --
// hash-then-verify for ECDSA/RSA (PKCS1v15 for RSA, matching
// sha256WithRSAEncryption's wire format, not PSS), full-message verify for
// Ed25519. Used by ParseCertificateRequestHybrid (hybrid_csr.go) to verify
// the primary (classical) half of a hybrid CSR's self-signature.
func verifyClassicalCSRSignature(algo keystore.Algorithm, hash crypto.Hash, pub crypto.PublicKey, msg, sig []byte) bool {
	switch algo {
	case keystore.ECDSAP256, keystore.ECDSAP384:
		ecdsaPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		h := hash.New()
		h.Write(msg)
		return ecdsa.VerifyASN1(ecdsaPub, h.Sum(nil), sig)
	case keystore.RSA2048, keystore.RSA3072, keystore.RSA4096:
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return false
		}
		h := hash.New()
		h.Write(msg)
		return rsa.VerifyPKCS1v15(rsaPub, hash, h.Sum(nil), sig) == nil
	case keystore.Ed25519:
		ed25519Pub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return false
		}
		return ed25519.Verify(ed25519Pub, msg, sig)
	}
	return false
}
