// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Idempotent issuance (W26-32, US-010 AC4): the same key and template asked
// twice returns the same certificate instead of a second serial. Reuse is
// deliberately narrow -- every condition below must hold, and policy checks
// run before it, so a request that would be refused is never answered with a
// previously issued certificate.

// certReuseMinRemaining is the fraction of a certificate's validity that must
// be left for it to be handed out again; a near-expiry cert is reissued.
const certReuseMinRemainingDenom = 3

// csrSPKIHash is the SHA-256 (hex) of the CSR's SubjectPublicKeyInfo DER, the
// same value spkiHash derives from an issued certificate. Empty for a CSR
// that is not a classical PKCS#10 request (ML-DSA and hybrid are never reused).
func csrSPKIHash(csr *x509.CertificateRequest) string {
	if csr == nil || len(csr.RawSubjectPublicKeyInfo) == 0 {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(csr.RawSubjectPublicKeyInfo))
}

// csrFromPEM parses a classical CSR from PEM, or returns nil.
func csrFromPEM(csrPEM string) *x509.CertificateRequest {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil
	}
	return csr
}

// nameSet is the CN plus the sorted, de-duplicated SAN set of either a CSR or
// a certificate, as comparable strings.
func nameSet(cn string, dns []string, ips []string, emails []string, uris []string) (string, []string) {
	var sans []string
	for _, d := range dns {
		sans = append(sans, "dns:"+strings.ToLower(d))
	}
	for _, i := range ips {
		sans = append(sans, "ip:"+i)
	}
	for _, e := range emails {
		sans = append(sans, "email:"+strings.ToLower(e))
	}
	for _, u := range uris {
		sans = append(sans, "uri:"+u)
	}
	slices.Sort(sans)
	return cn, slices.Compact(sans)
}

func csrNames(csr *x509.CertificateRequest) (string, []string) {
	ips := make([]string, 0, len(csr.IPAddresses))
	for _, ip := range csr.IPAddresses {
		ips = append(ips, ip.String())
	}
	uris := make([]string, 0, len(csr.URIs))
	for _, u := range csr.URIs {
		uris = append(uris, u.String())
	}
	return nameSet(csr.Subject.CommonName, csr.DNSNames, ips, csr.EmailAddresses, uris)
}

func certNames(c *x509.Certificate) (string, []string) {
	ips := make([]string, 0, len(c.IPAddresses))
	for _, ip := range c.IPAddresses {
		ips = append(ips, ip.String())
	}
	uris := make([]string, 0, len(c.URIs))
	for _, u := range c.URIs {
		uris = append(uris, u.String())
	}
	return nameSet(c.Subject.CommonName, c.DNSNames, ips, c.EmailAddresses, uris)
}

// findReusableCertificate returns a stored certificate that this request may
// be answered with, or false. The caller has already passed the CA tenant
// gate for req.CAID, so a certificate from that same CA is in the caller's
// tenant by construction.
func (p *caCertificateProvider) findReusableCertificate(req CertificateIssueRequest, csr *x509.CertificateRequest, templateRevision int, now time.Time) (CertificateItem, bool) {
	spki := csrSPKIHash(csr)
	if spki == "" || req.CAID == "" {
		return CertificateItem{}, false
	}
	p.ensureIndex()
	wantCN, wantSANs := csrNames(csr)

	p.mu.RLock()
	defer p.mu.RUnlock()
	var best *storedCert
	for _, fp := range p.spkiIdx[spki] {
		sc := p.certs[fp]
		if sc == nil || sc.x509 == nil {
			continue
		}
		it := &sc.item
		if it.CAID != req.CAID || it.TemplateID != req.TemplateID || it.TemplateRevision != templateRevision ||
			it.TeamID != req.TeamID || it.SuccessorFP != nil || !isActiveCertificate(it) {
			continue
		}
		nb, na := sc.x509.NotBefore, sc.x509.NotAfter
		total := na.Sub(nb)
		if total <= 0 || !now.Before(na) || na.Sub(now) < total/certReuseMinRemainingDenom {
			continue
		}
		cn, sans := certNames(sc.x509)
		if cn != wantCN || !slices.Equal(sans, wantSANs) {
			continue
		}
		if best == nil || na.After(best.x509.NotAfter) {
			best = sc
		}
	}
	if best == nil {
		return CertificateItem{}, false
	}
	return best.item, true
}

// findPendingApproval returns the open approval for the same CA, template,
// public key and requester, so a repeated POST does not queue a second one.
func findPendingApproval(ctx context.Context, store ApprovalStore, req CertificateIssueRequest, requester string) (ApprovalRequest, bool) {
	if store == nil {
		return ApprovalRequest{}, false
	}
	wantCSR := csrFromPEM(req.CSRPEM)
	wantSPKI := csrSPKIHash(wantCSR)
	const page = 200
	for offset := 0; ; offset += page {
		rows, total, err := store.List(ctx, "pending", page, offset)
		if err != nil {
			return ApprovalRequest{}, false
		}
		for _, a := range rows {
			if a.Kind == approvalKindSSH || a.CAID != req.CAID || a.TemplateID != req.TemplateID || a.Requester != requester {
				continue
			}
			if wantSPKI != "" {
				if csrSPKIHash(csrFromPEM(a.CSRPEM)) == wantSPKI {
					return a, true
				}
			} else if a.CSRPEM == req.CSRPEM {
				return a, true
			}
		}
		if offset+page >= total || len(rows) == 0 {
			return ApprovalRequest{}, false
		}
	}
}
