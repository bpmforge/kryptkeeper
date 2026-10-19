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
	"kryptkeeper/internal/logging"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/wstep"
)

// Template represents a certificate template for XCEP policy response.
type Template struct {
	Name          string
	OID           string
	DisplayName   string
	SchemaVersion int
	MinKeySize    int
	// AllowedAlgorithms is the template's own allow-list (empty: any); the
	// advertised key size must be one of its RSA entries.
	AllowedAlgorithms []string
	KeyUsage          []string
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
	// EnrollRoles is the template's enroll list; a caller is offered the
	// template only when wstep.EnrollPermitted allows it (B5).
	EnrollRoles []string
}

// TemplateListFunc returns available templates for XCEP policy responses.
type TemplateListFunc func() ([]Template, error)

// KeyPolicyFunc resolves the RSA modulus a template can be enrolled with
// under the hub's issuance policy: the smallest size of at least atLeast bits
// (and within templateAlgos when non-empty) that issuance will accept. ok is
// false, with reason, when none is. An error fails the request closed.
type KeyPolicyFunc func(atLeast int, templateAlgos []string) (bits int, ok bool, reason string, err error)

// KeyPolicyLoader snapshots the issuance policy for one GetPolicies request
// and returns the KeyPolicyFunc that answers every template of that request
// from the snapshot, so the policy store is read once per request, not once
// per template and candidate size.
type KeyPolicyLoader func() (KeyPolicyFunc, error)

// policyAuditWindow bounds xcep.policy success rows to one per principal per
// window: Windows polls every few hours and on every GPO refresh, and a row
// per poll would bury the enrollment trail.
const policyAuditWindow = 15 * time.Minute

// defaultMinRSABits is the minimum a template advertises and enforces when it
// sets none. internal/ca keeps the matching ladder floor (rsaKeyLadder[0]).
const defaultMinRSABits = 2048

// auditSeenMax bounds the dedupe map. An expired entry is already ignored by
// the check, so pruning only reclaims memory: it runs at most once per window,
// or earlier when the map reaches this size. If it is still full of live
// entries a new principal is audited on every poll rather than remembered.
const auditSeenMax = 50000

// Server implements the MS-XCEP Certificate Enrollment Policy Protocol.
// XCEP uses SOAP over HTTPS with a single GetPolicies operation.
type Server struct {
	templateFunc TemplateListFunc
	policyID     string
	authenticate wstep.AuthWrapper
	audit        wstep.AuditFunc
	caCertDER    []byte
	enrollURL    string
	keyPolicy    KeyPolicyLoader
	now          func() time.Time

	auditMu        sync.Mutex
	auditSeen      map[string]time.Time
	auditLastPrune time.Time
}

// NewServer creates an XCEP server.
func NewServer(templateFunc TemplateListFunc, policyID string) *Server {
	if policyID == "" {
		policyID = "kryptkeeper-default-policy"
	}
	return &Server{templateFunc: templateFunc, policyID: policyID, now: time.Now, auditSeen: map[string]time.Time{}}
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

// WithKeyPolicy makes GetPolicies advertise only key sizes the issuance
// policy accepts, so a client generates a key WSTEP will not then refuse.
// Without it the template's own minimum is advertised.
func (s *Server) WithKeyPolicy(fn KeyPolicyLoader) *Server {
	s.keyPolicy = fn
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
		logging.Info("xcep: no issuing CA configured")
		s.writeSoapFault(w, "s:Server", "No issuing CA configured")
		return
	}

	templates, err := s.templateFunc()
	if err != nil {
		logging.Infof("xcep: template list error: %v", err)
		s.writeSoapFault(w, "s:Server", "Internal error retrieving policies")
		return
	}

	templates, err = s.applyKeyPolicy(templates, id)
	if err != nil {
		logging.Warnf("xcep: issuance policy unavailable, refusing to advertise templates: %v", err)
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
		logging.Infof("xcep: writing response: %v", err)
		return
	}
	s.auditServed(r, id, templates)
}

// auditServed records a successful policy fetch, at most once per principal
// per policyAuditWindow.
func (s *Server) auditServed(r *http.Request, id wstep.Identity, templates []Template) {
	if s.audit == nil {
		return
	}
	now := s.now()
	s.auditMu.Lock()
	if last, ok := s.auditSeen[id.Principal]; ok && now.Sub(last) < policyAuditWindow {
		s.auditMu.Unlock()
		return
	}
	if now.Sub(s.auditLastPrune) >= policyAuditWindow || len(s.auditSeen) >= auditSeenMax {
		s.pruneAuditSeen(now)
	}
	if len(s.auditSeen) < auditSeenMax {
		s.auditSeen[id.Principal] = now
	}
	s.auditMu.Unlock()

	machine := id.IsMachine()
	var offered []string
	for _, t := range templates {
		if s.offeredTo(t, id, machine) {
			offered = append(offered, fmt.Sprintf("%s(min_key=%d)", t.Name, max(t.MinKeySize, defaultMinRSABits)))
		}
	}
	wstep.EmitAudit(s.audit, r, wstep.AuditEvent{Action: "xcep.policy", Actor: id.Principal, Outcome: "success",
		Detail: fmt.Sprintf("method=%s offered=[%s]", id.Method, strings.Join(offered, " "))})
}

// pruneAuditSeen drops expired dedupe entries; the caller holds auditMu.
func (s *Server) pruneAuditSeen(now time.Time) {
	s.auditLastPrune = now
	for k, t := range s.auditSeen {
		if now.Sub(t) >= policyAuditWindow {
			delete(s.auditSeen, k)
		}
	}
}

// offeredTo reports whether t is a template the caller may be offered. A
// template whose OID does not parse cannot be named in the certificate, so
// autoenrollment could never match it: it is left out. Only templates of the
// caller's kind are offered (W20-17), and never one the caller may not enroll
// (B5): WSTEP would refuse it and autoenrollment would retry it every pulse.
func (s *Server) offeredTo(t Template, id wstep.Identity, machine bool) bool {
	if (t.Enrollee == wstep.EnrolleeUser) == machine {
		return false
	}
	if !wstep.EnrollPermitted(t.EnrollRoles, id) {
		return false
	}
	return t.Name != "" && templateExtensionValue(t.OID, 1) != nil
}

// applyKeyPolicy raises each offered template's minimum key size to one the
// issuance policy accepts and drops a template no key size satisfies,
// logging why: an offer WSTEP is certain to refuse would only be retried
// every pulse. The template's own minimum is a floor, never lowered.
func (s *Server) applyKeyPolicy(templates []Template, id wstep.Identity) ([]Template, error) {
	if s.keyPolicy == nil {
		return templates, nil
	}
	machine := id.IsMachine()
	out := make([]Template, 0, len(templates))
	var probe KeyPolicyFunc // loaded on the first offered template
	for _, t := range templates {
		if !s.offeredTo(t, id, machine) {
			out = append(out, t)
			continue
		}
		if probe == nil {
			var err error
			if probe, err = s.keyPolicy(); err != nil {
				return nil, err
			}
		}
		bits, ok, reason, err := probe(max(t.MinKeySize, defaultMinRSABits), t.AllowedAlgorithms)
		if err != nil {
			return nil, err
		}
		if !ok {
			// Windows enrolls over XCEP with RSA only; an ECDSA-only policy
			// cannot be advertised in a schema-2 policy, so the template is
			// withheld rather than offered into a certain refusal.
			logging.Warnf("xcep: template %s not offered to %s: no RSA key size is accepted: %s", t.Name, id.Principal, reason)
			continue
		}
		t.MinKeySize = bits
		out = append(out, t)
	}
	return out, nil
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
		if s.offeredTo(t, id, machine) {
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
		minKey = defaultMinRSABits
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
