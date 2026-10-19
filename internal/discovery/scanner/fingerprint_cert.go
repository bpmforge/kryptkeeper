// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"regexp"
	"strings"
	"unicode/utf16"
)

// Microsoft certificate-template extensions. Both are written by AD CS and by
// nothing else in practice, so their presence is the strongest available sign
// that an enterprise Windows CA issued the certificate.
var (
	oidMSCertTemplateInfo = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 7}
	oidMSCertTemplateName = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2}
)

// certTell is one issuer/subject pattern. It is matched against the lower-cased
// CN and organisation fields of the certificate, never the whole encoding.
//
// family groups patterns that describe the same product line: only the first
// match in a family is recorded, so an ESXi cert (which also says VMware) is
// not counted as both ESXi and vCenter.
type certTell struct {
	re       *regexp.Regexp
	family   string
	tech     string
	platform string
}

// The kubernetes pattern is anchored: ingress-nginx's fake certificate also
// says "Kubernetes" and must not be read as an API server.
var certTells = []certTell{
	{regexp.MustCompile(`ssl_self_signed_fallback`), "mssql", "mssql", ""},
	{regexp.MustCompile(`kube-apiserver|^kubernetes \|`), "k8s", "kubernetes-api", ""},
	{regexp.MustCompile(`\besxi\b`), "vmware", "vmware-esxi", PlatformAppliance},
	{regexp.MustCompile(`vmware|vcenter|\bvmca\b`), "vmware", "vmware-vcenter", PlatformAppliance},
	{regexp.MustCompile(`idrac|dell remote access`), "idrac", "idrac", PlatformAppliance},
	{regexp.MustCompile(`integrated lights.out|\bilo\b`), "ilo", "ilo", PlatformAppliance},
	{regexp.MustCompile(`fortinet|fortigate`), "fortinet", "fortinet", PlatformAppliance},
	{regexp.MustCompile(`palo alto`), "paloalto", "paloalto", PlatformAppliance},
	{regexp.MustCompile(`ms-organization-access|wmsvc-sha2`), "mswin", "", PlatformWindows},
}

// nameText flattens the fields the tells look at. The separator lets a pattern
// anchor on a CN that stands alone.
func nameText(n pkix.Name) string {
	return strings.ToLower(n.CommonName + " | " + strings.Join(n.Organization, " ") + " " + strings.Join(n.OrganizationalUnit, " "))
}

// adcsTemplateTells map a certificate template name to what it is used for.
// Only templates whose purpose names a service are listed: WebServer says
// nothing about which web server.
var adcsTemplateTells = map[string]struct{ tech, platform string }{
	"domaincontroller":               {"ldap-ad", PlatformWindows},
	"domaincontrollerauthentication": {"ldap-ad", PlatformWindows},
	"kerberosauthentication":         {"ldap-ad", PlatformWindows},
	"remotedesktopauthentication":    {"rdp", PlatformWindows},
	"machine":                        {"", PlatformWindows},
}

// ADCSInfo is what the Microsoft template extensions reveal about a cert.
type ADCSInfo struct {
	// IssuedByADCS is true when either template extension is present.
	IssuedByADCS bool
	// TemplateName is the certificate template name (e.g. WebServer), if the
	// name extension was present and decodable.
	TemplateName string
	// TemplateOID is the template OID from the template-information extension.
	TemplateOID string
}

// ParseADCS reads the Microsoft template extensions of cert.
func ParseADCS(cert *x509.Certificate) ADCSInfo {
	var info ADCSInfo
	for _, ext := range cert.Extensions {
		switch {
		case ext.Id.Equal(oidMSCertTemplateInfo):
			info.IssuedByADCS = true
			var t struct {
				ID    asn1.ObjectIdentifier
				Major int `asn1:"optional"`
				Minor int `asn1:"optional"`
			}
			if _, err := asn1.Unmarshal(ext.Value, &t); err == nil {
				info.TemplateOID = t.ID.String()
			}
		case ext.Id.Equal(oidMSCertTemplateName):
			info.IssuedByADCS = true
			info.TemplateName = decodeTemplateName(ext.Value)
		}
	}
	return info
}

// decodeTemplateName decodes the template-name extension: a BMPString from
// AD CS, though other string types are accepted for old or foreign encoders.
func decodeTemplateName(der []byte) string {
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(der, &raw); err != nil || raw.Class != asn1.ClassUniversal {
		return ""
	}
	var name string
	switch raw.Tag {
	case asn1.TagBMPString:
		b := raw.Bytes
		if len(b)%2 != 0 {
			return ""
		}
		u := make([]uint16, len(b)/2)
		for i := range u {
			u[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
		}
		name = string(utf16.Decode(u))
	case asn1.TagUTF8String, asn1.TagPrintableString, asn1.TagIA5String:
		name = string(raw.Bytes)
	default:
		return ""
	}
	return redactEvidenceValue(name)
}

// certEvidence derives evidence from the leaf of a served chain. A pattern
// that matches both issuer and subject is one observation, recorded once.
func certEvidence(chain []*x509.Certificate) []Evidence {
	if len(chain) == 0 {
		return nil
	}
	leaf := chain[0]
	var ev []Evidence
	issuer, subject := nameText(leaf.Issuer), nameText(leaf.Subject)
	seenFamily := map[string]bool{}
	for _, t := range certTells {
		if seenFamily[t.family] {
			continue
		}
		signal, field, text := "", "", ""
		switch {
		case t.re.MatchString(issuer):
			signal, field, text = SignalCertIssuer, "issuer", leaf.Issuer.CommonName
		case t.re.MatchString(subject):
			signal, field, text = SignalCertSubj, "subject", leaf.Subject.CommonName
		default:
			continue
		}
		seenFamily[t.family] = true
		if text == "" {
			text = t.re.String()
		}
		e := NewEvidence(signal, field+" CN="+text, t.tech)
		e.Platform = t.platform
		ev = append(ev, e)
	}

	adcs := ParseADCS(leaf)
	if adcs.TemplateOID != "" {
		ev = append(ev, NewEvidence(SignalCertExt, "1.3.6.1.4.1.311.21.7 template "+adcs.TemplateOID, ""))
	}
	if adcs.TemplateName != "" {
		e := NewEvidence(SignalCertExt, "1.3.6.1.4.1.311.20.2 template "+adcs.TemplateName, "")
		if tell, ok := adcsTemplateTells[strings.ToLower(adcs.TemplateName)]; ok {
			e.Tech, e.Platform = tell.tech, tell.platform
		}
		ev = append(ev, e)
	}
	return ev
}
