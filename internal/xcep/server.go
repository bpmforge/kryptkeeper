// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package xcep

import (
	"encoding/asn1"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"kryptkeeper/internal/wstep"
)

// Template represents a certificate template for XCEP policy response.
type Template struct {
	Name          string
	OID           string
	DisplayName   string
	SchemaVersion int
	MinKeySize    int
	KeyUsage      []string
	// ValiditySeconds and RenewalSeconds become certificateValidity; the
	// client starts renewal when less than RenewalSeconds remain. Zero
	// means one year and six weeks, the ADCS defaults.
	ValiditySeconds uint64
	RenewalSeconds  uint64
	AutoEnroll      bool
	Revision        int
	// Enrollee is wstep.EnrolleeMachine or wstep.EnrolleeUser; empty is
	// machine. A caller is offered only templates of its own kind (W20-17).
	Enrollee string
}

// TemplateListFunc returns available templates for XCEP policy responses.
type TemplateListFunc func() ([]Template, error)

// Server implements the MS-XCEP Certificate Enrollment Policy Protocol.
// XCEP uses SOAP over HTTPS with a single GetPolicies operation.
type Server struct {
	templateFunc TemplateListFunc
	policyID     string
	authenticate wstep.AuthWrapper
	audit        wstep.AuditFunc
	caCertDER    []byte
	enrollURL    string
}

// NewServer creates an XCEP server.
func NewServer(templateFunc TemplateListFunc, policyID string) *Server {
	if policyID == "" {
		policyID = "kryptkeeper-default-policy"
	}
	return &Server{templateFunc: templateFunc, policyID: policyID}
}

// WithAuthenticator sets how policy requests are authenticated; it is the
// same Kerberos authenticator WSTEP uses. Without one every request is
// challenged (W20-08).
func (s *Server) WithAuthenticator(a wstep.AuthWrapper) *Server {
	s.authenticate = a
	return s
}

// WithAuditFunc records rejected credentials as "xcep.policy" denials.
func (s *Server) WithAuditFunc(fn wstep.AuditFunc) *Server {
	s.audit = fn
	return s
}

// WithIssuer names the CA every policy is issued by and the WSTEP (CES)
// endpoint that issues it. Windows refuses a policy without an issuer
// (MS-XCEP 3.1.4.1.3.2). An empty enrollURL means the /wstep path on the
// host the client used for XCEP: Kerberos only works by DNS name, and that
// is the name the client already resolved and holds a ticket for.
func (s *Server) WithIssuer(caCertDER []byte, enrollURL string) *Server {
	s.caCertDER = caCertDER
	s.enrollURL = enrollURL
	return s
}

// Handler returns an http.Handler for the XCEP endpoint.
// MS-XCEP uses a single endpoint that receives SOAP POST requests.
func (s *Server) Handler() http.Handler {
	policies := wstep.RequireIdentity(s.authenticate, s.audit, "xcep.policy", s.servePolicies)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		policies.ServeHTTP(w, r)
	})
}

// servePolicies answers GetPolicies. The caller's identity decides whether
// the policies are offered as machine or user templates, matching how WSTEP
// will name the certificate.
func (s *Server) servePolicies(w http.ResponseWriter, r *http.Request, id wstep.Identity) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64*1024))
	if err != nil {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}

	var envelope soapEnvelope
	if err := xml.Unmarshal(body, &envelope); err != nil {
		s.writeSoapFault(w, "s:Client", "Invalid SOAP envelope")
		return
	}

	action := strings.TrimSpace(envelope.Header.Action)
	if !strings.Contains(action, "GetPolicies") {
		s.writeSoapFault(w, "s:Client", fmt.Sprintf("Unknown action: %s", action))
		return
	}
	if len(s.caCertDER) == 0 {
		log.Print("xcep: no issuing CA configured")
		s.writeSoapFault(w, "s:Server", "No issuing CA configured")
		return
	}

	templates, err := s.templateFunc()
	if err != nil {
		log.Printf("xcep: template list error: %v", err)
		s.writeSoapFault(w, "s:Server", "Internal error retrieving policies")
		return
	}

	enrollURL := s.enrollURL
	if enrollURL == "" {
		enrollURL = "https://" + r.Host + "/wstep"
	}
	resp := s.buildGetPoliciesResponse(templates, id, enrollURL, strings.TrimSpace(envelope.Header.MessageID))

	w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := io.WriteString(w, resp); err != nil {
		log.Printf("xcep: writing response: %v", err)
	}
}

type soapEnvelope struct {
	XMLName xml.Name   `xml:"Envelope"`
	Header  soapHeader `xml:"Header"`
}

type soapHeader struct {
	Action    string `xml:"Action"`
	MessageID string `xml:"MessageID"`
}

// Values from MS-XCEP 3.1.4.1.3.x.
const (
	authKerberos = 2

	oidGroupExtension        = 6
	oidGroupEnrollmentObject = 9

	// subjectNameFlags: the CA builds subject and SAN from the directory,
	// which is what the hub does from the authenticated principal; the
	// CSR's names are never used.
	subjectDNSAsCN   = 0x10000000
	subjectDNSInSAN  = 0x08000000
	subjectCNFromDir = 0x40000000

	generalMachineType = 0x00000040

	keySpecKeyExchange = 1

	defaultValiditySeconds = 365 * 24 * 3600
	defaultRenewalSeconds  = 42 * 24 * 3600
)

// buildGetPoliciesResponse renders the GetPoliciesResponse of MS-XCEP
// 3.1.4.1.2.2. Element order and nil-ness follow the schema exactly:
// Windows parses it with a strict WCF serializer and rejects anything else
// with WS_E_INVALID_FORMAT.
func (s *Server) buildGetPoliciesResponse(templates []Template, id wstep.Identity, enrollURL, relatesTo string) string {
	machine := id.IsMachine()
	var b strings.Builder
	b.WriteString(xml.Header)
	b.WriteString(`<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope">`)
	b.WriteString(`<s:Header><a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPoliciesResponse</a:Action>`)
	if relatesTo != "" {
		b.WriteString(`<a:RelatesTo>` + esc(relatesTo) + `</a:RelatesTo>`)
	}
	b.WriteString(`</s:Header>`)
	b.WriteString(`<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema">`)
	b.WriteString(`<GetPoliciesResponse xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">`)

	b.WriteString(`<response>`)
	el(&b, "policyID", s.policyID)
	el(&b, "policyFriendlyName", "Kryptkeeper")
	el(&b, "nextUpdateHours", "8")
	nilEl(&b, "policiesNotChanged")
	var oids []string
	usable := make([]Template, 0, len(templates))
	for _, t := range templates {
		// A template whose OID does not parse cannot be named in the
		// certificate, so autoenrollment could never match it: leave it out.
		// Only templates of the caller's kind: a user is never offered a
		// machine template, nor a machine a user one (W20-17).
		if (t.Enrollee == wstep.EnrolleeUser) == machine {
			continue
		}
		if t.Name != "" && templateExtensionValue(t.OID, 1) != nil {
			usable = append(usable, t)
		}
	}
	// Every policy's template extension points at one shared OID entry,
	// numbered after the policies' own.
	templateExtRef := len(usable) + 1
	if len(usable) == 0 {
		nilEl(&b, "policies")
	} else {
		b.WriteString(`<policies>`)
		for i, t := range usable {
			oids = append(oids, oidXML(t.OID, oidGroupEnrollmentObject, i+1, firstNonEmpty(t.DisplayName, t.Name)))
			s.writePolicy(&b, t, i+1, templateExtRef, machine)
		}
		b.WriteString(`</policies>`)
		oids = append(oids, oidXML(oidCertificateTemplate.String(), oidGroupExtension, templateExtRef, "Certificate Template Information"))
	}
	b.WriteString(`</response>`)

	// Kerberos only. clientAuthentication 8 is WS-Security message-level
	// X.509 signing, which the hub does not implement; a domain machine
	// renews over this same Kerberos URI with a PKCS#7 request signed by
	// its old key (MS-WSTEP 4.1.5.1).
	b.WriteString(`<cAs><cA><uris>`)
	caURI(&b, authKerberos, enrollURL, false)
	b.WriteString(`</uris>`)
	el(&b, "certificate", base64.StdEncoding.EncodeToString(s.caCertDER))
	el(&b, "enrollPermission", "true")
	el(&b, "cAReferenceID", "0")
	b.WriteString(`</cA></cAs>`)

	if len(oids) == 0 {
		nilEl(&b, "oIDs")
	} else {
		b.WriteString(`<oIDs>` + strings.Join(oids, "") + `</oIDs>`)
	}
	b.WriteString(`</GetPoliciesResponse></s:Body></s:Envelope>`)
	return b.String()
}

func (s *Server) writePolicy(b *strings.Builder, t Template, oidRef, templateExtRef int, machine bool) {
	validity, renewal := t.ValiditySeconds, t.RenewalSeconds
	if validity == 0 {
		validity = defaultValiditySeconds
	}
	if renewal == 0 || renewal >= validity {
		renewal = min(defaultRenewalSeconds, validity/2)
	}
	minKey, revision := t.MinKeySize, t.Revision
	if minKey <= 0 {
		minKey = 2048
	}
	if revision <= 0 {
		revision = 1
	}
	subjectFlags, generalFlags := subjectCNFromDir, 0
	if machine {
		subjectFlags, generalFlags = subjectDNSAsCN|subjectDNSInSAN, generalMachineType
	}

	b.WriteString(`<policy>`)
	el(b, "policyOIDReference", strconv.Itoa(oidRef))
	b.WriteString(`<cAs><cAReference>0</cAReference></cAs>`)
	b.WriteString(`<attributes>`)
	el(b, "commonName", t.Name)
	// Schema 2: hashAlgorithmOIDReference must then be nil (3.1.4.1.3.1).
	el(b, "policySchema", "2")
	b.WriteString(`<certificateValidity>`)
	el(b, "validityPeriodSeconds", strconv.FormatUint(validity, 10))
	el(b, "renewalPeriodSeconds", strconv.FormatUint(renewal, 10))
	b.WriteString(`</certificateValidity>`)
	b.WriteString(`<permission>`)
	el(b, "enroll", "true")
	el(b, "autoEnroll", strconv.FormatBool(t.AutoEnroll))
	b.WriteString(`</permission>`)
	b.WriteString(`<privateKeyAttributes>`)
	el(b, "minimalKeyLength", strconv.Itoa(minKey))
	el(b, "keySpec", strconv.Itoa(keySpecKeyExchange))
	nilEl(b, "keyUsageProperty")
	nilEl(b, "permissions")
	nilEl(b, "algorithmOIDReference")
	nilEl(b, "cryptoProviders")
	b.WriteString(`</privateKeyAttributes>`)
	b.WriteString(`<revision>`)
	el(b, "majorRevision", strconv.Itoa(revision))
	el(b, "minorRevision", "0")
	b.WriteString(`</revision>`)
	nilEl(b, "supersededPolicies")
	el(b, "privateKeyFlags", "0")
	el(b, "subjectNameFlags", strconv.FormatUint(uint64(subjectFlags), 10))
	el(b, "enrollmentFlags", "0")
	el(b, "generalFlags", strconv.Itoa(generalFlags))
	nilEl(b, "hashAlgorithmOIDReference")
	nilEl(b, "rARequirements")
	nilEl(b, "keyArchivalAttributes")
	// CertEnroll copies these into its request. The CertificateTemplate
	// extension is what autoenrollment later matches installed
	// certificates on; without it every pulse enrolls again.
	b.WriteString(`<extensions><extension>`)
	el(b, "oIDReference", strconv.Itoa(templateExtRef))
	el(b, "critical", "false")
	el(b, "value", base64.StdEncoding.EncodeToString(templateExtensionValue(t.OID, revision)))
	b.WriteString(`</extension></extensions>`)
	b.WriteString(`</attributes></policy>`)
}

// oidCertificateTemplate is szOID_CERTIFICATE_TEMPLATE.
var oidCertificateTemplate = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 7}

// templateExtensionValue is CertEnroll's CertificateTemplate extension:
// SEQUENCE { templateID, templateMajorVersion, templateMinorVersion }.
// An OID that does not parse yields nil, which leaves the value empty.
func templateExtensionValue(oid string, major int) []byte {
	var id asn1.ObjectIdentifier
	for _, part := range strings.Split(oid, ".") {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return nil
		}
		id = append(id, n)
	}
	der, err := asn1.Marshal(struct {
		TemplateID asn1.ObjectIdentifier
		Major      int64
		Minor      int64
	}{id, int64(major), 0})
	if err != nil {
		return nil
	}
	return der
}

func caURI(b *strings.Builder, auth int, uri string, renewalOnly bool) {
	b.WriteString(`<cAURI>`)
	el(b, "clientAuthentication", strconv.Itoa(auth))
	el(b, "uri", uri)
	el(b, "priority", "1")
	el(b, "renewalOnly", strconv.FormatBool(renewalOnly))
	b.WriteString(`</cAURI>`)
}

func oidXML(value string, group, ref int, name string) string {
	var b strings.Builder
	b.WriteString(`<oID>`)
	el(&b, "value", value)
	el(&b, "group", strconv.Itoa(group))
	el(&b, "oIDReferenceID", strconv.Itoa(ref))
	el(&b, "defaultName", name)
	b.WriteString(`</oID>`)
	return b.String()
}

func el(b *strings.Builder, name, value string) {
	b.WriteString("<" + name + ">" + esc(value) + "</" + name + ">")
}

func nilEl(b *strings.Builder, name string) {
	b.WriteString("<" + name + ` xsi:nil="true"/>`)
}

func esc(s string) string {
	var b strings.Builder
	// A strings.Builder write cannot fail; refuse rather than emit unescaped text.
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		return ""
	}
	return b.String()
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (s *Server) writeSoapFault(w http.ResponseWriter, code string, reason string) {
	fault := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <s:Fault>
      <s:Code><s:Value>%s</s:Value></s:Code>
      <s:Reason><s:Text xml:lang="en">%s</s:Text></s:Reason>
    </s:Fault>
  </s:Body>
</s:Envelope>`, code, esc(reason))
	w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(fault))
}
