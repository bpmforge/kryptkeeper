// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"
)

// W36-02 (D-304, D-305): an external CA is a CA row whose signing is
// delegated to an issuer connector. Every front door (REST, ACME, EST, SCEP,
// CMP, WSTEP) reaches signing through Engine.IssueCertificate, so routing here
// gives a customer's own CA every protocol and the hub's template policy. What
// comes back is verified before anyone sees it: an upstream that changes what
// we asked for is a security event, not a convenience.

// CATypeExternal is the CA.Type of an external CA.
const CATypeExternal = "external"

// externalIssueTimeout bounds one upstream issuance. ca.Service carries no
// context, and commercial CAs poll for minutes (DigiCert's default budget is
// 10 x 3 s); five minutes covers that without pinning a protocol handler forever.
const externalIssueTimeout = 5 * time.Minute

// externalValidityAllowance tolerates upstreams that round validity up to a
// day boundary.
const externalValidityAllowance = 24 * time.Hour

var (
	// ErrExternalCAUnsupportedKey: no supported upstream accepts ML-DSA or
	// hybrid CSRs, and the hub never relabels a request to make it fit.
	ErrExternalCAUnsupportedKey = errors.New("external CAs accept only classical (RSA, ECDSA, Ed25519) certificate requests")
	// ErrExternalCAResponseRejected wraps every reason a returned certificate
	// is refused.
	ErrExternalCAResponseRejected = errors.New("external CA response rejected")
	// ErrExternalCANotConfigured: no ExternalIssuer is attached to the engine.
	ErrExternalCANotConfigured = errors.New("external CA issuance is not configured on this hub")
	// ErrExternalCAUpstream wraps an error from the connector or upstream CA
	// itself (refusal, outage, rate limit), as opposed to a rejected response.
	ErrExternalCAUpstream = errors.New("external CA upstream error")
	// ErrExternalCAInvalid: the external CA definition itself is unusable.
	ErrExternalCAInvalid = errors.New("invalid external CA")
)

// ExternalIssuer forwards a CSR to the connector behind an external CA and
// returns the PEM bundle the upstream sent (leaf first). Implementations
// resolve credentials, enforce tenancy (D-308) and throttling; the engine
// owns policy and response verification.
type ExternalIssuer interface {
	IssueExternal(ctx context.Context, caID, connectorID, csrPEM, templateID string) (string, error)
}

// ExternalRejection is the reason a response was refused. Callers audit it.
type ExternalRejection struct {
	Reason      string
	Fingerprint string
}

func (e *ExternalRejection) Error() string {
	return fmt.Sprintf("%s: %s", ErrExternalCAResponseRejected, e.Reason)
}

func (e *ExternalRejection) Unwrap() error { return ErrExternalCAResponseRejected }

// ExternalRejectionObserver hears every refused upstream response so the
// caller can write the audit record (certificate.issue.upstream_rejected).
type ExternalRejectionObserver func(caID, connectorID string, rej *ExternalRejection)

// SetExternalRejectionObserver attaches the observer. Set once at startup.
func (e *Engine) SetExternalRejectionObserver(fn ExternalRejectionObserver) {
	e.mu.Lock()
	e.onExternalReject = fn
	e.mu.Unlock()
}

// SetExternalIssuer attaches the connector bridge. Set once at startup.
func (e *Engine) SetExternalIssuer(x ExternalIssuer) {
	e.mu.Lock()
	e.external = x
	e.mu.Unlock()
}

// CreateExternalCA records an external CA. trustPEM must hold at least one
// CA certificate; the first becomes the row's displayed certificate.
func (e *Engine) CreateExternalCA(name, connectorID string, trustPEM []byte) (*CA, error) {
	if name == "" || connectorID == "" {
		return nil, fmt.Errorf("%w: name and connector are required", ErrExternalCAInvalid)
	}
	anchors, err := parseCACertificates(trustPEM)
	if err != nil {
		return nil, err
	}
	id := newCAID()
	first := anchors[0]
	c := &CA{
		ID:               id,
		Name:             name,
		Type:             CATypeExternal,
		Certificate:      first,
		CertPEM:          pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: first.Raw}),
		Status:           "active",
		CreatedAt:        time.Now().UTC(),
		KeyStorageType:   "external",
		ConnectorID:      connectorID,
		ExternalTrustPEM: encodeCertificates(anchors),
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.saveCA(c); err != nil {
		return nil, err
	}
	return c, nil
}

func parseCACertificates(raw []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: trust bundle certificate unparseable: %w", ErrExternalCAInvalid, err)
		}
		if !c.IsCA || !c.BasicConstraintsValid {
			return nil, fmt.Errorf("%w: trust bundle certificate %q is not a CA certificate", ErrExternalCAInvalid, c.Subject.String())
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: trust bundle holds no CA certificate", ErrExternalCAInvalid)
	}
	return out, nil
}

func encodeCertificates(certs []*x509.Certificate) []byte {
	var buf bytes.Buffer
	for _, c := range certs {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}) // bytes.Buffer writes cannot fail
	}
	return buf.Bytes()
}

// externalCA returns the CA when caID names an external CA.
func (e *Engine) externalCA(caID string) (*CA, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	c, ok := e.get(caID)
	if !ok || c.Type != CATypeExternal {
		return nil, false
	}
	return c, true
}

func (e *Engine) issueExternal(c *CA, req IssuanceRequest) (*IssuedCertificate, error) {
	if err := e.checkIssuable(c); err != nil {
		return nil, err
	}
	if req.PQCCSR != nil || req.HybridCSR != nil {
		return nil, ErrExternalCAUnsupportedKey
	}
	if req.CSR == nil {
		return nil, ErrInvalidCSR
	}
	if err := req.CSR.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: CSR signature invalid", ErrInvalidCSR)
	}
	if req.IsCA {
		return nil, fmt.Errorf("%w: an external CA issues leaf certificates only", ErrExternalCAInvalid)
	}
	if len(req.PermanentIdentifiers) > 0 {
		return nil, fmt.Errorf("%w: an external CA cannot carry a permanent-identifier SAN", ErrExternalCAInvalid)
	}
	if req.Policy != nil {
		if err := ValidateAgainstTemplate(req, *req.Policy); err != nil {
			return nil, err
		}
	}
	if err := e.checkIssuancePolicy(c.ID, req); err != nil {
		return nil, err
	}
	e.mu.Lock()
	x := e.external
	e.mu.Unlock()
	if x == nil {
		return nil, ErrExternalCANotConfigured
	}
	anchors, err := parseCACertificates(c.ExternalTrustPEM)
	if err != nil {
		return nil, err
	}

	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: req.CSR.Raw}))
	ctx, cancel := context.WithTimeout(context.Background(), externalIssueTimeout)
	defer cancel()
	now := time.Now()
	bundle, err := x.IssueExternal(ctx, c.ID, c.ConnectorID, csrPEM, req.TemplateID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrExternalCAUpstream, err)
	}
	issued, err := VerifyExternalIssuance(req, anchors, []byte(bundle), now)
	var rej *ExternalRejection
	if errors.As(err, &rej) {
		e.mu.Lock()
		obs := e.onExternalReject
		e.mu.Unlock()
		if obs != nil {
			obs(c.ID, c.ConnectorID, rej)
		}
	}
	return issued, err
}

// VerifyExternalIssuance checks an upstream's PEM bundle against the request
// that produced it. issuedAfter is the moment the request was sent. It is
// exported so connector-pinned renewals can apply the same checks.
func VerifyExternalIssuance(req IssuanceRequest, anchors []*x509.Certificate, bundle []byte, issuedAfter time.Time) (*IssuedCertificate, error) {
	certs, err := parseBundle(bundle)
	if err != nil {
		return nil, &ExternalRejection{Reason: err.Error()}
	}
	leaf := certs[0]
	sum := sha256.Sum256(leaf.Raw)
	fp := hex.EncodeToString(sum[:])
	reject := func(format string, a ...any) error {
		return &ExternalRejection{Reason: fmt.Sprintf(format, a...), Fingerprint: fp}
	}

	if req.CSR == nil {
		return nil, ErrInvalidCSR
	}
	csrKey, err := x509.MarshalPKIXPublicKey(req.CSR.PublicKey)
	if err != nil {
		return nil, ErrInvalidCSR
	}
	leafKey, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil || !bytes.Equal(csrKey, leafKey) {
		return nil, reject("certificate public key does not match the request's key")
	}
	if leaf.IsCA {
		return nil, reject("certificate is a CA certificate")
	}
	if leaf.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		return nil, reject("certificate may sign certificates or CRLs")
	}

	wantDNS, wantIP, wantURI := expectedNames(req)
	for _, n := range leaf.DNSNames {
		if !wantDNS[n] {
			return nil, reject("DNS name %q was not requested", n)
		}
	}
	for _, ip := range leaf.IPAddresses {
		if !wantIP[ip.String()] {
			return nil, reject("IP address %s was not requested", ip)
		}
	}
	for _, u := range leaf.URIs {
		if !wantURI[u.String()] {
			return nil, reject("URI %q was not requested", u.String())
		}
	}
	if len(leaf.EmailAddresses) > 0 {
		return nil, reject("email addresses were not requested")
	}
	if req.Subject != nil && leaf.Subject.String() != req.Subject.String() {
		return nil, reject("subject %q differs from the bound identity %q", leaf.Subject.String(), req.Subject.String())
	}
	if err := checkExtKeyUsage(req.ExtKeyUsage, leaf.ExtKeyUsage, len(leaf.UnknownExtKeyUsage) > 0); err != "" {
		return nil, reject("%s", err)
	}

	validity := req.Validity
	if validity <= 0 {
		validity = 365 * 24 * time.Hour
	}
	if leaf.NotAfter.After(issuedAfter.Add(validity + externalValidityAllowance)) {
		return nil, reject("certificate is valid until %s, beyond the policy's %s", leaf.NotAfter.UTC().Format(time.RFC3339), validity)
	}
	if !leaf.NotAfter.After(time.Now()) {
		return nil, reject("certificate is already expired")
	}

	roots := x509.NewCertPool()
	for _, a := range anchors {
		roots.AddCert(a)
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil || len(chains) == 0 {
		return nil, reject("certificate does not chain to this external CA's trusted certificates")
	}

	var chainPEM bytes.Buffer
	for _, c := range chains[0][1:] {
		if bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil {
			continue // relying parties hold the root; serving it only adds bytes
		}
		_ = pem.Encode(&chainPEM, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}) // bytes.Buffer writes cannot fail
	}
	return &IssuedCertificate{
		Certificate:  leaf,
		CertPEM:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}),
		SerialNumber: leaf.SerialNumber,
		Fingerprint:  fp,
		ChainPEM:     chainPEM.Bytes(),
	}, nil
}

func parseBundle(raw []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("returned certificate unparseable: %w", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("response holds no PEM certificate")
	}
	return out, nil
}

// expectedNames mirrors issueLeafCertificate: caller-supplied names win, and
// the CSR's names are used only when the caller gave none and did not ask
// for caller names only.
func expectedNames(req IssuanceRequest) (map[string]bool, map[string]bool, map[string]bool) {
	dns, ips, uris := req.DNSNames, req.IPAddresses, req.URIs
	if !req.CallerNamesOnly {
		if len(dns) == 0 {
			dns = req.CSR.DNSNames
		}
		if len(ips) == 0 {
			ips = req.CSR.IPAddresses
		}
		if len(uris) == 0 {
			uris = req.CSR.URIs
		}
	}
	return toSet(dns, func(s string) string { return s }),
		toSet(ips, func(ip net.IP) string { return ip.String() }),
		toSet(uris, func(u *url.URL) string { return u.String() })
}

func toSet[T any](in []T, key func(T) string) map[string]bool {
	out := make(map[string]bool, len(in))
	for _, v := range in {
		out[key(v)] = true
	}
	return out
}

// highRiskEKUs grant powers beyond TLS. An upstream may add serverAuth or
// clientAuth (public CAs differ on that), but never one of these unless the
// template asked for it.
var highRiskEKUs = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:             "any",
	x509.ExtKeyUsageCodeSigning:     "codeSigning",
	x509.ExtKeyUsageEmailProtection: "emailProtection",
	x509.ExtKeyUsageTimeStamping:    "timeStamping",
	x509.ExtKeyUsageOCSPSigning:     "OCSPSigning",
	x509.ExtKeyUsageIPSECEndSystem:  "ipsecEndSystem",
	x509.ExtKeyUsageIPSECTunnel:     "ipsecTunnel",
	x509.ExtKeyUsageIPSECUser:       "ipsecUser",
}

func checkExtKeyUsage(requested, got []x509.ExtKeyUsage, unknown bool) string {
	asked := map[x509.ExtKeyUsage]bool{}
	for _, u := range requested {
		asked[u] = true
	}
	for _, u := range got {
		if name, risky := highRiskEKUs[u]; risky && !asked[u] {
			return fmt.Sprintf("extended key usage %s was not requested", name)
		}
	}
	if unknown {
		return "certificate carries an unrecognised extended key usage"
	}
	return ""
}
