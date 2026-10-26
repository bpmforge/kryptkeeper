// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package trustpush applies hub-pushed CA certificates to a host's OS trust
// store (W40-03, D-318/D-319). The hub validates a bundle with ParseCAs before
// it is queued; the agent validates again before touching the host, and the
// privileged side (a root helper reached through one exact sudoers rule on
// Linux and macOS) validates a third time, so no single layer is trusted to
// have been honest.
package trustpush

import (
	"crypto/sha1" // #nosec G505 -- certutil and macOS security identify certificates by SHA-1; never used for a trust decision
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Limits keep one task small enough to read in an approval screen and to
// apply in one pass.
const (
	MaxCerts    = 20
	MaxPEMBytes = 256 << 10
)

// Action is what a bundle does to the target trust stores.
type Action string

const (
	ActionAdd    Action = "add"
	ActionRemove Action = "remove"
)

// Valid reports whether a is a known action.
func (a Action) Valid() bool { return a == ActionAdd || a == ActionRemove }

// CA is one parsed CA certificate of a bundle.
type CA struct {
	DER    []byte
	Cert   *x509.Certificate
	SHA256 string // lowercase hex of the DER: the identity used everywhere else
	SHA1   string // uppercase hex, the match token certutil and security accept
}

// IsRoot reports whether the certificate is self-issued (goes to the Root
// store); anything else is an intermediate.
func (c CA) IsRoot() bool {
	return string(c.Cert.RawIssuer) == string(c.Cert.RawSubject) && c.Cert.CheckSignatureFrom(c.Cert) == nil
}

// PEM re-encodes the certificate from its DER, so what is written to a host is
// always exactly one certificate and never the caller's original text.
func (c CA) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.DER})
}

// ParseCAs parses a PEM bundle and refuses anything that is not a pure list of
// CA certificates: every block must be a CERTIFICATE (so a bundle carrying any
// key block is rejected whole, and no key bytes are ever echoed), each must
// assert basicConstraints CA:TRUE, and, when requireValid is set, none may be
// expired or not yet valid. Removal bundles pass requireValid=false: dropping
// an expired root is housekeeping, not a risk.
func ParseCAs(pemData string, now time.Time, requireValid bool) ([]CA, error) {
	if len(pemData) == 0 {
		return nil, errors.New("no certificates supplied")
	}
	if len(pemData) > MaxPEMBytes {
		return nil, fmt.Errorf("bundle exceeds %d bytes", MaxPEMBytes)
	}
	var out []CA
	seen := map[string]bool{}
	rest := []byte(pemData)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			// The block type is a label, never key material.
			return nil, fmt.Errorf("only CERTIFICATE blocks are accepted; found a %q block", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certificate %d is not valid X.509: %w", len(out)+1, err)
		}
		if !cert.BasicConstraintsValid || !cert.IsCA {
			return nil, fmt.Errorf("certificate %q is not a CA certificate", cert.Subject.String())
		}
		if requireValid {
			if now.After(cert.NotAfter) {
				return nil, fmt.Errorf("certificate %q expired %s", cert.Subject.String(), cert.NotAfter.UTC().Format(time.RFC3339))
			}
			if now.Before(cert.NotBefore) {
				return nil, fmt.Errorf("certificate %q is not valid until %s", cert.Subject.String(), cert.NotBefore.UTC().Format(time.RFC3339))
			}
		}
		s256 := sha256.Sum256(block.Bytes)
		s1 := sha1.Sum(block.Bytes) // #nosec G401 -- see import
		ca := CA{DER: block.Bytes, Cert: cert, SHA256: hex.EncodeToString(s256[:]), SHA1: strings.ToUpper(hex.EncodeToString(s1[:]))}
		if seen[ca.SHA256] {
			continue
		}
		seen[ca.SHA256] = true
		out = append(out, ca)
		if len(out) > MaxCerts {
			return nil, fmt.Errorf("bundle holds more than %d certificates", MaxCerts)
		}
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("bundle holds text that is not a PEM block")
	}
	if len(out) == 0 {
		return nil, errors.New("no certificates found")
	}
	return out, nil
}
