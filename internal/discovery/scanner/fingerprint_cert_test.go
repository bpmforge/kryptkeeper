// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
	"unicode/utf16"
)

// bmpString DER-encodes s the way AD CS writes the template-name extension.
func bmpString(t *testing.T, s string) []byte {
	t.Helper()
	u := utf16.Encode([]rune(s))
	b := make([]byte, 0, len(u)*2)
	for _, c := range u {
		b = append(b, byte(c>>8), byte(c))
	}
	der, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagBMPString, Bytes: b})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func templateInfo(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	der, err := asn1.Marshal(struct {
		ID    asn1.ObjectIdentifier
		Major int
		Minor int
	}{oid, 100, 4})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// issueCert builds a leaf with the given subject, signed by a parent with the
// given issuer name, carrying extra extensions.
func issueCert(t *testing.T, subject, issuer pkix.Name, ext []pkix.Extension) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	parent := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: issuer, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: subject, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtraExtensions: ext}
	der, err := x509.CreateCertificate(rand.Reader, leaf, parent, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCertContentSignals(t *testing.T) {
	cases := []struct {
		name     string
		subject  pkix.Name
		issuer   pkix.Name
		tech     string
		signal   string
		platform string
	}{
		{"SQL Server default cert", pkix.Name{CommonName: "SSL_Self_Signed_Fallback"}, pkix.Name{CommonName: "SSL_Self_Signed_Fallback"}, "mssql", SignalCertIssuer, ""},
		{"kubeadm API server", pkix.Name{CommonName: "kube-apiserver"}, pkix.Name{CommonName: "kubernetes"}, "kubernetes-api", SignalCertIssuer, ""},
		{"kube-apiserver subject, foreign issuer", pkix.Name{CommonName: "kube-apiserver"}, pkix.Name{CommonName: "Corp Root"}, "kubernetes-api", SignalCertSubj, ""},
		{"vCenter", pkix.Name{CommonName: "vc01.corp.local", Organization: []string{"VMware"}}, pkix.Name{CommonName: "CA", Organization: []string{"VMware"}}, "vmware-vcenter", SignalCertIssuer, PlatformAppliance},
		{"ESXi is not also vCenter", pkix.Name{CommonName: "esx01", Organization: []string{"VMware, Inc."}, OrganizationalUnit: []string{"VMware ESXi"}}, pkix.Name{CommonName: "esx01", OrganizationalUnit: []string{"VMware ESXi"}}, "vmware-esxi", SignalCertIssuer, PlatformAppliance},
		{"iDRAC", pkix.Name{CommonName: "idrac-ABC1234"}, pkix.Name{CommonName: "Dell Inc. iDRAC Root"}, "idrac", SignalCertIssuer, PlatformAppliance},
		{"iLO", pkix.Name{CommonName: "ilo-host.corp.local", Organization: []string{"Hewlett Packard Enterprise"}}, pkix.Name{CommonName: "Default Issuer (Do not trust)"}, "ilo", SignalCertSubj, PlatformAppliance},
		{"iLO by product name", pkix.Name{CommonName: "x"}, pkix.Name{CommonName: "Integrated Lights-Out Root"}, "ilo", SignalCertIssuer, PlatformAppliance},
		{"MS-Organization-Access names no product", pkix.Name{CommonName: "MS-Organization-Access"}, pkix.Name{CommonName: "MS-Organization-Access"}, "", SignalCertIssuer, PlatformWindows},
		{"WMSvc", pkix.Name{CommonName: "WMSvc-SHA2-WEB01"}, pkix.Name{CommonName: "WMSvc-SHA2-WEB01"}, "", SignalCertIssuer, PlatformWindows},
		{"FortiGate", pkix.Name{CommonName: "FortiGate"}, pkix.Name{CommonName: "FortiGate CA", Organization: []string{"Fortinet"}}, "fortinet", SignalCertIssuer, PlatformAppliance},
		{"Palo Alto", pkix.Name{CommonName: "pa-fw"}, pkix.Name{CommonName: "Palo Alto Networks Inc"}, "paloalto", SignalCertIssuer, PlatformAppliance},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := certEvidence([]*x509.Certificate{issueCert(t, c.subject, c.issuer, nil)})
			if len(ev) != 1 {
				t.Fatalf("a pattern matching issuer and subject is one observation; got %+v", ev)
			}
			e := ev[0]
			if e.Tech != c.tech || e.Signal != c.signal || e.Platform != c.platform || e.Weight != 40 {
				t.Fatalf("got %+v, want tech=%q signal=%s platform=%q weight=40", e, c.tech, c.signal, c.platform)
			}
		})
	}
}

func TestCertContentSignalsDoNotOverreach(t *testing.T) {
	for _, n := range []pkix.Name{
		{CommonName: "Kubernetes Ingress Controller Fake Certificate", Organization: []string{"Acme Co"}},
		{CommonName: "www.example.com"},
		{CommonName: "silo.example.com"}, // contains "ilo" but is not iLO
		{CommonName: "Let's Encrypt R3", Organization: []string{"Let's Encrypt"}},
	} {
		if ev := certEvidence([]*x509.Certificate{issueCert(t, n, pkix.Name{CommonName: "Corp Root"}, nil)}); len(ev) != 0 {
			t.Errorf("%q must not produce evidence: %+v", n.CommonName, ev)
		}
	}
	if certEvidence(nil) != nil {
		t.Error("no chain, no evidence")
	}
}

func TestADCSTemplateExtensions(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 8, 1234, 5678, 1, 2}
	cert := issueCert(t, pkix.Name{CommonName: "web01.corp.local"}, pkix.Name{CommonName: "Corp Issuing CA"}, []pkix.Extension{
		{Id: oidMSCertTemplateInfo, Value: templateInfo(t, oid)},
		{Id: oidMSCertTemplateName, Value: bmpString(t, "WebServer")},
	})
	info := ParseADCS(cert)
	if !info.IssuedByADCS || info.TemplateName != "WebServer" || info.TemplateOID != oid.String() {
		t.Fatalf("ADCSInfo = %+v", info)
	}
	ev := certEvidence([]*x509.Certificate{cert})
	if len(ev) != 2 {
		t.Fatalf("want template info + name rows, got %+v", ev)
	}
	for _, e := range ev {
		if e.Signal != SignalCertExt || e.Weight != 40 {
			t.Errorf("template rows are cert_ext@40: %+v", e)
		}
	}
	if !hasEvidence(ev, "", "template WebServer") || !hasEvidence(ev, "", oid.String()) {
		t.Fatalf("template name and OID must be recorded: %+v", ev)
	}
	// WebServer names no service, so the fingerprint stays unknown.
	if fp := Resolve(ev); fp.Tech != TechUnknown {
		t.Fatalf("WebServer template must not name a tech: %+v", fp)
	}

	dc := certToDiscovered(cert, "web01.corp.local", true)
	if !dc.IssuedByADCS || dc.ADCSTemplate != "WebServer" {
		t.Fatalf("DiscoveredCert not marked issued-by-ADCS: %+v", dc)
	}
}

func TestADCSDomainControllerTemplateNamesLDAPAD(t *testing.T) {
	cert := issueCert(t, pkix.Name{CommonName: "dc01.corp.local"}, pkix.Name{CommonName: "Corp Issuing CA"}, []pkix.Extension{
		{Id: oidMSCertTemplateName, Value: bmpString(t, "DomainControllerAuthentication")},
	})
	fp := Resolve(certEvidence([]*x509.Certificate{cert}))
	if fp.Tech != "ldap-ad" || fp.Platform != PlatformWindows || fp.Confidence != ConfidenceMedium {
		t.Fatalf("fingerprint = %+v", fp)
	}
}

func TestADCSOnlyNameExtensionStillMarksADCS(t *testing.T) {
	cert := issueCert(t, pkix.Name{CommonName: "pc"}, pkix.Name{CommonName: "CA"}, []pkix.Extension{{Id: oidMSCertTemplateName, Value: bmpString(t, "Machine")}})
	if info := ParseADCS(cert); !info.IssuedByADCS || info.TemplateName != "Machine" || info.TemplateOID != "" {
		t.Fatalf("info = %+v", info)
	}
	if fp := Resolve(certEvidence([]*x509.Certificate{cert})); fp.Platform != PlatformWindows {
		t.Fatalf("Machine template should vote windows: %+v", fp)
	}
}

func TestADCSMalformedExtensionsDoNotPanicOrMislead(t *testing.T) {
	bad := [][]byte{nil, {0x30}, {0x1e, 0x03, 0x00, 0x41, 0x00}, {0x04, 0x01, 0x41}, {0xff, 0xff}}
	for _, b := range bad {
		cert := issueCert(t, pkix.Name{CommonName: "x"}, pkix.Name{CommonName: "y"}, []pkix.Extension{
			{Id: oidMSCertTemplateInfo, Value: b}, {Id: oidMSCertTemplateName, Value: b},
		})
		info := ParseADCS(cert)
		if info.TemplateName != "" || info.TemplateOID != "" {
			t.Errorf("malformed %x decoded to %+v", b, info)
		}
	}
}

func TestPlainCertIsNotADCS(t *testing.T) {
	cert := issueCert(t, pkix.Name{CommonName: "plain"}, pkix.Name{CommonName: "plain-ca"}, nil)
	if ParseADCS(cert).IssuedByADCS || certToDiscovered(cert, "plain", true).IssuedByADCS {
		t.Fatal("a certificate without the Microsoft extensions must not be marked ADCS")
	}
}

func TestPrintableAndUTF8TemplateNames(t *testing.T) {
	for _, tag := range []int{asn1.TagUTF8String, asn1.TagPrintableString, asn1.TagIA5String} {
		der, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: tag, Bytes: []byte("WebServer")})
		if got := decodeTemplateName(der); got != "WebServer" {
			t.Errorf("tag %d: got %q", tag, got)
		}
	}
}

// Certificate content costs no connection: it rides on the handshake the scan
// already made, in any tier.
func TestCapturedCertFeedsEndpointFingerprint(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "SSL_Self_Signed_Fallback"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	l := listenLocal(t)
	serveTLS(t, l, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	ep := captureOne(t, portOf(l))
	if ep.Fingerprint == nil || ep.Fingerprint.Tech != "mssql" || ep.Fingerprint.Confidence != ConfidenceMedium {
		t.Fatalf("fingerprint = %+v", ep.Fingerprint)
	}
}
