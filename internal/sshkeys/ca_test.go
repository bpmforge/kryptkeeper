// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package sshkeys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// W11-07: the signature chain is VERIFIED with ssh.CertChecker against the
// authority — not just field equality (the S-59 lesson for SSH).

func newTestAuthority(t *testing.T) ssh.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("authority key: %v", err)
	}
	signer, err := ssh.NewSignerFromSigner(key)
	if err != nil {
		t.Fatalf("authority signer: %v", err)
	}
	return signer
}

func newTestSubjectKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("subject key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("subject ssh pub: %v", err)
	}
	return string(ssh.MarshalAuthorizedKey(sshPub))
}

func TestIssueUserCertVerifiesAgainstAuthority(t *testing.T) {
	authority := newTestAuthority(t)
	issued, err := IssueCert(authority, CertRequest{
		PublicKey:  newTestSubjectKey(t),
		CertType:   "user",
		KeyID:      "alice@example.com",
		Principals: []string{"alice", "deploy"},
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(issued.CertificateLine))
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatalf("issued line is not a certificate: %T", parsed)
	}

	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return ssh.FingerprintSHA256(auth) == ssh.FingerprintSHA256(authority.PublicKey())
		},
	}
	if err := checker.CheckCert("alice", cert); err != nil {
		t.Fatalf("certificate does not verify against the authority: %v", err)
	}
	if cert.Permissions.Extensions["permit-pty"] != "" {
		t.Fatal("user cert missing standard permit-pty extension")
	}
	// Short-lived by default: hours, not years.
	ttl := time.Unix(int64(cert.ValidBefore), 0).Sub(time.Unix(int64(cert.ValidAfter), 0))
	if ttl > UserCertMaxTTL+2*time.Minute {
		t.Fatalf("default user cert TTL too long: %s", ttl)
	}
	if issued.SubjectFingerprint == "" || !strings.HasPrefix(issued.SubjectFingerprint, "SHA256:") {
		t.Fatalf("subject fingerprint missing/wrong format: %q", issued.SubjectFingerprint)
	}
}

func TestIssueRefusesTTLAboveCeiling(t *testing.T) {
	authority := newTestAuthority(t)
	_, err := IssueCert(authority, CertRequest{
		PublicKey:  newTestSubjectKey(t),
		CertType:   "user",
		KeyID:      "bob",
		Principals: []string{"bob"},
		TTL:        48 * time.Hour, // above the 24h user ceiling
	})
	if err == nil || !strings.Contains(err.Error(), "ceiling") {
		t.Fatalf("expected ceiling refusal, got %v", err)
	}
}

func TestIssueRequiresPrincipals(t *testing.T) {
	authority := newTestAuthority(t)
	_, err := IssueCert(authority, CertRequest{
		PublicKey: newTestSubjectKey(t),
		CertType:  "user",
		KeyID:     "carol",
	})
	if err == nil {
		t.Fatal("a cert without principals must be refused")
	}
}

func TestIssueHostCertHasNoUserExtensions(t *testing.T) {
	authority := newTestAuthority(t)
	issued, err := IssueCert(authority, CertRequest{
		PublicKey:  newTestSubjectKey(t),
		CertType:   "host",
		KeyID:      "web-1.example.com",
		Principals: []string{"web-1.example.com"},
	})
	if err != nil {
		t.Fatalf("issue host cert: %v", err)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(issued.CertificateLine))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cert := parsed.(*ssh.Certificate)
	if len(cert.Permissions.Extensions) != 0 {
		t.Fatalf("host cert must carry no user extensions: %v", cert.Permissions.Extensions)
	}
	if cert.CertType != ssh.HostCert {
		t.Fatalf("cert type = %d, want host", cert.CertType)
	}
}
