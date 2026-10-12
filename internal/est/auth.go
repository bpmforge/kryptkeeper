// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package est

// EST authentication (W20-14, D-112). RFC 7030 3.2.3 and 3.3.2 allow two
// client credentials and the hub accepts both:
//
//   - HTTP Basic over TLS, against a configured user list. Each user may
//     enroll only names under its own DNS suffixes: the CSR's CN and DNS
//     SANs must all match, nothing else may be requested, and the subject
//     is reduced to that CN.
//   - A TLS client certificate that chains to an operator-configured trust
//     anchor (for example a device manufacturer CA). The new certificate
//     takes the presented certificate's subject and DNS SANs; the CSR only
//     proves the key.
//
// Re-enrollment needs a certificate this hub issued (ca.CheckHubClientCertificate,
// shared with WSTEP renewal) and keeps its subject and SANs.

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"kryptkeeper/internal/ca"
)

// User is one HTTP Basic credential.
type User struct {
	Username           string   `json:"username"`
	BcryptHash         string   `json:"bcrypt_hash"`
	AllowedDNSSuffixes []string `json:"allowed_dns_suffixes"`
}

// LoadUsersFile reads a JSON array of User. Hashes are bcrypt (for example
// `htpasswd -nbB user pass`, the part after the colon).
func LoadUsersFile(path string) ([]User, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var users []User
	if err := json.Unmarshal(raw, &users); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return users, nil
}

// AuditEvent is one EST authentication outcome.
type AuditEvent struct {
	Action   string // "est.enroll" or "est.reenroll"
	Actor    string // Basic username or certificate subject; empty when unknown
	Outcome  string // "success" or "denied"
	SourceIP string
	Detail   string
}

// AuditFunc records an AuditEvent; main adapts it to the hub's audit log.
type AuditFunc func(ctx context.Context, ev AuditEvent)

// identity is who an enrollment is for, from the credential, never the CSR.
type identity struct {
	method   string // "basic" or "certificate"
	actor    string
	subject  pkix.Name
	dnsNames []string
}

// dummyHash makes an unknown username cost the same bcrypt work as a known
// one, so response timing does not reveal which usernames exist.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("kryptkeeper-est-dummy"), bcrypt.DefaultCost)

// WithBasicUsers enables HTTP Basic enrollment for users. Every user needs a
// bcrypt hash and at least one DNS suffix, each starting with "." so a
// suffix can only ever match whole labels.
func (s *Server) WithBasicUsers(users []User) error {
	m := make(map[string]User, len(users))
	for _, u := range users {
		if u.Username == "" {
			return errors.New("est user with an empty username")
		}
		if _, err := bcrypt.Cost([]byte(u.BcryptHash)); err != nil {
			return fmt.Errorf("est user %q: bcrypt_hash: %w", u.Username, err)
		}
		if len(u.AllowedDNSSuffixes) == 0 {
			return fmt.Errorf("est user %q: allowed_dns_suffixes is empty", u.Username)
		}
		for i, sfx := range u.AllowedDNSSuffixes {
			sfx = strings.ToLower(strings.TrimSpace(sfx))
			if len(sfx) < 2 || !strings.HasPrefix(sfx, ".") || strings.Contains(sfx, "*") {
				return fmt.Errorf("est user %q: suffix %q must look like .devices.example.com", u.Username, u.AllowedDNSSuffixes[i])
			}
			u.AllowedDNSSuffixes[i] = sfx
		}
		if _, dup := m[u.Username]; dup {
			return fmt.Errorf("est user %q listed twice", u.Username)
		}
		m[u.Username] = u
	}
	s.users = m
	return nil
}

// WithClientCertAnchors enables enrollment by TLS client certificates that
// chain to roots. The listener must request client certificates
// (KRYPTKEEPER_TLS_REQUEST_CLIENT_CERT) for any to arrive.
func (s *Server) WithClientCertAnchors(roots *x509.CertPool) *Server {
	s.clientRoots = roots
	return s
}

// WithReenrollment enables simplereenroll for certificates this CA issued,
// checked against rev for revocation.
func (s *Server) WithReenrollment(rev ca.RevocationChecker) *Server {
	s.revocation = rev
	return s
}

// WithAuditFunc records enrollment outcomes.
func (s *Server) WithAuditFunc(fn AuditFunc) *Server {
	s.audit = fn
	return s
}

// EnrollmentConfigured reports whether any enrollment credential is set up.
func (s *Server) EnrollmentConfigured() bool {
	return len(s.users) > 0 || s.clientRoots != nil
}

func (s *Server) emit(r *http.Request, ev AuditEvent) {
	if s.audit == nil {
		return
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ev.SourceIP = host
	} else {
		ev.SourceIP = r.RemoteAddr
	}
	s.audit(r.Context(), ev)
}

// authenticateEnroll establishes the identity for simpleenroll, or writes
// the refusal and returns false. csr is needed only to check a Basic user's
// requested names.
func (s *Server) authenticateEnroll(w http.ResponseWriter, r *http.Request, csr *x509.CertificateRequest) (identity, bool) {
	// RFC 7030 3.2.3: credentials only over TLS. A plaintext request is
	// refused before its Authorization header is read, and is not
	// challenged, so no client is invited to send a password in the clear.
	if r.TLS == nil {
		http.Error(w, "EST requires TLS", http.StatusForbidden)
		return identity{}, false
	}

	// A client certificate that chains to a configured anchor is the
	// credential. One that does not is ignored, not refused: clients may
	// offer unrelated certificates, and Basic may still follow.
	if s.clientRoots != nil && len(r.TLS.PeerCertificates) > 0 {
		leaf := r.TLS.PeerCertificates[0]
		inter := x509.NewCertPool()
		for _, c := range r.TLS.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots: s.clientRoots, Intermediates: inter, CurrentTime: s.now(),
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}); err == nil {
			return identity{method: "certificate", actor: leaf.Subject.String(), subject: leaf.Subject, dnsNames: leaf.DNSNames}, true
		}
	}

	if len(s.users) == 0 {
		http.Error(w, "EST enrollment requires a client certificate from a trusted issuer", http.StatusForbidden)
		return identity{}, false
	}
	user, pass, ok := r.BasicAuth()
	if !ok {
		// The bare challenge starts every Basic exchange: not audited.
		w.Header().Set("WWW-Authenticate", `Basic realm="est"`)
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return identity{}, false
	}
	u, known := s.users[user]
	hash := dummyHash
	if known {
		hash = []byte(u.BcryptHash)
	}
	if err := bcrypt.CompareHashAndPassword(hash, []byte(pass)); err != nil || !known {
		s.emit(r, AuditEvent{Action: "est.enroll", Actor: user, Outcome: "denied", Detail: "invalid credentials"})
		w.Header().Set("WWW-Authenticate", `Basic realm="est"`)
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return identity{}, false
	}
	id, err := basicIdentity(u, csr)
	if err != nil {
		s.emit(r, AuditEvent{Action: "est.enroll", Actor: user, Outcome: "denied", Detail: err.Error()})
		http.Error(w, "enrollment refused: "+err.Error(), http.StatusForbidden)
		return identity{}, false
	}
	return id, true
}

// basicIdentity binds a Basic user's request to the names it may hold: the
// CSR's CN and DNS SANs, every one under one of the user's suffixes, and
// nothing else.
func basicIdentity(u User, csr *x509.CertificateRequest) (identity, error) {
	if len(csr.IPAddresses)+len(csr.URIs)+len(csr.EmailAddresses) > 0 {
		return identity{}, errors.New("only DNS names may be requested")
	}
	cn := strings.ToLower(strings.TrimSpace(csr.Subject.CommonName))
	names := make([]string, 0, len(csr.DNSNames))
	for _, n := range csr.DNSNames {
		names = append(names, strings.ToLower(strings.TrimSpace(n)))
	}
	if cn == "" && len(names) == 0 {
		return identity{}, errors.New("the request names nothing")
	}
	check := names
	if cn != "" {
		check = append([]string{cn}, names...)
	}
	for _, n := range check {
		if !nameAllowed(n, u.AllowedDNSSuffixes) {
			return identity{}, fmt.Errorf("%q is not under an allowed suffix for %s", n, u.Username)
		}
	}
	if cn == "" {
		cn = names[0]
	}
	return identity{method: "basic", actor: u.Username, subject: pkix.Name{CommonName: cn}, dnsNames: names}, nil
}

// nameAllowed reports whether name is a hostname strictly below one of
// suffixes (each starting with "."): ".devices.corp" admits a.devices.corp,
// not devices.corp or evildevices.corp.
func nameAllowed(name string, suffixes []string) bool {
	if name == "" || strings.ContainsAny(name, "* /") {
		return false
	}
	for _, sfx := range suffixes {
		label, ok := strings.CutSuffix(name, sfx)
		if ok && label != "" && !strings.HasPrefix(label, ".") && !strings.HasSuffix(label, ".") && !strings.Contains(label, "..") {
			return true
		}
	}
	return false
}
