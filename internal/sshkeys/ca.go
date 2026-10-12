// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package sshkeys

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// W11-07: the SSH certificate authority — short-lived SSH certs under the
// platform spine. This file is pure signing/policy logic: the caller
// supplies the ssh.Signer (backed by the platform keystore) and persists /
// audits the result. Ceilings are enforced by REFUSAL, never clamping — a
// silently shortened cert is a support ticket, a refused one is a policy
// conversation.

const (
	UserCertDefaultTTL = 8 * time.Hour
	UserCertMaxTTL     = 24 * time.Hour
	HostCertDefaultTTL = 30 * 24 * time.Hour
	HostCertMaxTTL     = 30 * 24 * time.Hour
)

// standardUserExtensions mirrors OpenSSH's defaults for user certificates.
var standardUserExtensions = map[string]string{
	"permit-pty":              "",
	"permit-user-rc":          "",
	"permit-port-forwarding":  "",
	"permit-agent-forwarding": "",
	"permit-X11-forwarding":   "",
}

// CertRequest is one SSH certificate issuance request.
type CertRequest struct {
	// PublicKey is the subject key in authorized_keys format.
	PublicKey string
	// CertType is "user" or "host".
	CertType string
	// KeyID names the identity (audited and logged by sshd).
	KeyID string
	// Principals: user names (user certs, required) or host names (host
	// certs, required).
	Principals []string
	// TTL of zero uses the per-type default; above the per-type ceiling is
	// refused.
	TTL time.Duration
}

// IssuedCert is the signed result plus the fields the caller persists.
type IssuedCert struct {
	Serial               uint64
	CertType             string
	KeyID                string
	Principals           []string
	ValidAfter           time.Time
	ValidBefore          time.Time
	SubjectFingerprint   string // SHA256:… of the subject key (inventory link)
	AuthorityFingerprint string // SHA256:… of the CA key
	// CertificateLine is the signed certificate in authorized_keys format
	// (what the requester installs).
	CertificateLine string
}

var errCertRequestInvalid = errors.New("invalid ssh certificate request")

// IssueCert validates the request against policy and signs it with the
// authority.
func IssueCert(authority ssh.Signer, req CertRequest) (IssuedCert, error) {
	subject, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		return IssuedCert{}, fmt.Errorf("%w: public_key must be authorized_keys format: %v", errCertRequestInvalid, err)
	}
	if strings.TrimSpace(req.KeyID) == "" {
		return IssuedCert{}, fmt.Errorf("%w: key_id is required (it is what sshd logs)", errCertRequestInvalid)
	}
	if len(req.Principals) == 0 {
		return IssuedCert{}, fmt.Errorf("%w: principals are required — a cert valid for every principal is authorized_keys sprawl with extra steps", errCertRequestInvalid)
	}

	var certType uint32
	var defaultTTL, maxTTL time.Duration
	var extensions map[string]string
	switch req.CertType {
	case "user":
		certType = ssh.UserCert
		defaultTTL, maxTTL = UserCertDefaultTTL, UserCertMaxTTL
		extensions = standardUserExtensions
	case "host":
		certType = ssh.HostCert
		defaultTTL, maxTTL = HostCertDefaultTTL, HostCertMaxTTL
		extensions = nil
	default:
		return IssuedCert{}, fmt.Errorf("%w: cert_type must be user or host", errCertRequestInvalid)
	}

	ttl := req.TTL
	if ttl <= 0 {
		ttl = defaultTTL
	}
	if ttl > maxTTL {
		return IssuedCert{}, fmt.Errorf("%w: ttl %s exceeds the %s ceiling for %s certificates", errCertRequestInvalid, ttl, maxTTL, req.CertType)
	}

	var serialBytes [8]byte
	if _, err := rand.Read(serialBytes[:]); err != nil {
		return IssuedCert{}, err
	}
	serial := binary.BigEndian.Uint64(serialBytes[:])

	now := time.Now().UTC().Add(-time.Minute) // small clock-skew allowance
	validBefore := now.Add(ttl + time.Minute)

	cert := &ssh.Certificate{
		Key:             subject,
		Serial:          serial,
		CertType:        certType,
		KeyId:           req.KeyID,
		ValidPrincipals: append([]string(nil), req.Principals...),
		ValidAfter:      uint64(now.Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
	}
	if extensions != nil {
		cert.Permissions = ssh.Permissions{Extensions: extensions}
	}
	if err := cert.SignCert(rand.Reader, authority); err != nil {
		return IssuedCert{}, fmt.Errorf("ssh cert signing: %w", err)
	}

	return IssuedCert{
		Serial:               serial,
		CertType:             req.CertType,
		KeyID:                req.KeyID,
		Principals:           cert.ValidPrincipals,
		ValidAfter:           now,
		ValidBefore:          validBefore,
		SubjectFingerprint:   ssh.FingerprintSHA256(subject),
		AuthorityFingerprint: ssh.FingerprintSHA256(authority.PublicKey()),
		CertificateLine:      string(ssh.MarshalAuthorizedKey(cert)),
	}, nil
}

// AuthorityLine renders the CA public key in authorized_keys format — what
// sshd consumes via TrustedUserCAKeys, and known_hosts via @cert-authority.
func AuthorityLine(authority ssh.Signer) string {
	return string(ssh.MarshalAuthorizedKey(authority.PublicKey()))
}
