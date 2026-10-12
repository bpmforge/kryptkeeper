// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"slices"
	"testing"
	"time"

	"kryptkeeper/internal/keystore"
)

func TestEngineRevocationPointers(t *testing.T) {
	engine, rootID := identityRoot(t)
	other, err := engine.CreateRootCA("Second Root", pkix.Name{CommonName: "Second Root"}, keystore.ECDSAP256, 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var asked []string
	engine.SetRevocationPointers(func(caID string) ([]string, []string) {
		asked = append(asked, caID)
		return []string{"http://hub.corp.example:8081/crl/" + caID + ".crl"}, []string{"http://hub.corp.example:8081/ocsp"}
	})
	issue := func(caID string, mod func(*IssuanceRequest)) *x509.Certificate {
		t.Helper()
		req := IssuanceRequest{CSR: identityCSR(t), Validity: 90 * 24 * time.Hour,
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if mod != nil {
			mod(&req)
		}
		issued, err := engine.IssueCertificate(caID, req)
		if err != nil {
			t.Fatal(err)
		}
		return issued.Certificate
	}

	// Each leaf points at its own issuer's CRL.
	for _, id := range []string{rootID, other.ID} {
		c := issue(id, nil)
		if !slices.Equal(c.CRLDistributionPoints, []string{"http://hub.corp.example:8081/crl/" + id + ".crl"}) ||
			!slices.Equal(c.OCSPServer, []string{"http://hub.corp.example:8081/ocsp"}) {
			t.Fatalf("CA %s: CRL %v OCSP %v", id, c.CRLDistributionPoints, c.OCSPServer)
		}
	}
	if !slices.Equal(asked, []string{rootID, other.ID}) {
		t.Fatalf("resolver asked for %v", asked)
	}

	// A caller's own pointers win and the resolver is not consulted.
	asked = nil
	own := issue(rootID, func(r *IssuanceRequest) { r.CRLDistPoints = []string{"http://elsewhere/x.crl"} })
	if !slices.Equal(own.CRLDistributionPoints, []string{"http://elsewhere/x.crl"}) || len(own.OCSPServer) != 0 || len(asked) != 0 {
		t.Fatalf("caller pointers overridden: CRL %v OCSP %v asked %v", own.CRLDistributionPoints, own.OCSPServer, asked)
	}

	ownOCSP := issue(rootID, func(r *IssuanceRequest) { r.OCSPServer = []string{"http://elsewhere/ocsp"} })
	if !slices.Equal(ownOCSP.OCSPServer, []string{"http://elsewhere/ocsp"}) || len(ownOCSP.CRLDistributionPoints) != 0 || len(asked) != 0 {
		t.Fatalf("caller OCSP overridden: CRL %v OCSP %v asked %v", ownOCSP.CRLDistributionPoints, ownOCSP.OCSPServer, asked)
	}

	// Short-lived leaves and CA certificates carry none.
	short := issue(rootID, func(r *IssuanceRequest) { r.Validity = 7 * 24 * time.Hour })
	if len(short.CRLDistributionPoints)+len(short.OCSPServer) != 0 {
		t.Fatalf("7-day leaf got pointers: %v %v", short.CRLDistributionPoints, short.OCSPServer)
	}
	if justOver := issue(rootID, func(r *IssuanceRequest) { r.Validity = 7*24*time.Hour + time.Hour }); len(justOver.CRLDistributionPoints) == 0 {
		t.Fatal("a leaf just over 7 days must get pointers")
	}
	ca := issue(rootID, func(r *IssuanceRequest) { r.IsCA = true; r.KeyUsage = x509.KeyUsageCertSign })
	if len(ca.CRLDistributionPoints)+len(ca.OCSPServer) != 0 {
		t.Fatal("CA certificate got leaf pointers")
	}

	// Without a resolver nothing changes.
	engine.SetRevocationPointers(nil)
	if c := issue(rootID, nil); len(c.CRLDistributionPoints)+len(c.OCSPServer) != 0 {
		t.Fatal("pointers added with no resolver")
	}
}
