// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package wstep

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"go.mozilla.org/pkcs7"

	"kryptkeeper/internal/ca"
)

// TemplateLookupFunc looks up an offered template by the WSTEP TokenType.
// The TokenType may carry a template OID (e.g. "1.3.6.1.4.1.311.21.8.12345")
// or a template name. Return (template, true) when it is found.
type TemplateLookupFunc func(tokenType string) (TemplateRef, bool)

// Enrollee types of a template (W20-17). A machine template names the
// computer (DNS name as CN and SAN), a user template the user (CN only);
// each is offered and issued only to its own kind of principal. The empty
// value is machine: every template was a machine template before W20-17.
const (
	EnrolleeMachine = "machine"
	EnrolleeUser    = "user"
)

// Identity is who the certificate is for, established by authentication and
// never by the CSR (W20-08, D-109). Subject and DNSNames are copied verbatim
// into the issued certificate.
type Identity struct {
	// Method is "kerberos" or "certificate".
	Method    string
	Principal string
	Subject   pkix.Name
	DNSNames  []string
	// Predecessor is the hub-issued certificate this request renews, when
	// known: the TLS client certificate, or the old certificate that signed
	// a Kerberos-path renewal request (W20-11). Audit only.
	Predecessor *x509.Certificate
}

// IsMachine reports whether the identity is a computer rather than a user.
// IdentityForPrincipal gives exactly the machine accounts DNS names.
func (id Identity) IsMachine() bool { return len(id.DNSNames) > 0 }

type identityKey struct{}

// WithIdentity returns ctx carrying id. The Kerberos adapter calls it after
// SPNEGO succeeds; tests use it to stand in for a KDC.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

func identityFrom(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(Identity)
	return id, ok
}

// IdentityForPrincipal maps a Kerberos principal to the certificate identity.
// A machine account (NAME$) becomes its host name in the realm's DNS domain,
// which is how AD names domain members; a user becomes a bare CN. The UPN SAN
// a Windows logon certificate carries is W18-08's client-compatibility work.
func IdentityForPrincipal(user, realm string) Identity {
	principal := user + "@" + realm
	if host, ok := strings.CutSuffix(user, "$"); ok {
		fqdn := strings.ToLower(host + "." + realm)
		return Identity{Method: "kerberos", Principal: principal, Subject: pkix.Name{CommonName: fqdn}, DNSNames: []string{fqdn}}
	}
	return Identity{Method: "kerberos", Principal: principal, Subject: pkix.Name{CommonName: user}}
}

// AuthWrapper authenticates a request and, on success, serves inner with an
// Identity in the context (see WithIdentity). It writes its own 401 when the
// caller has not authenticated.
type AuthWrapper func(inner http.Handler) http.Handler

// TemplateRef is a certificate template the hub offers through XCEP.
type TemplateRef struct {
	Name string
	OID  string
	// Enrollee is EnrolleeMachine or EnrolleeUser (empty means machine).
	Enrollee     string
	MajorVersion int
	MinorVersion int
	// Policy is the template's issuance policy (W20-09). When set it is
	// enforced by the CA engine, and a positive MaxValidity becomes the
	// issued validity, so the certificate is what XCEP advertised.
	Policy *ca.TemplatePolicy
}

// TemplateResolveFunc returns the offered template with the given OID.
type TemplateResolveFunc func(oid string) (TemplateRef, bool)

// RevocationChecker reports whether a certificate the hub issued is revoked;
// ca.RevocationStore satisfies it.
type RevocationChecker = ca.RevocationChecker

// AuditEvent is one security-relevant WSTEP or XCEP outcome.
type AuditEvent struct {
	Action   string // "wstep.enroll", "wstep.renew" or "xcep.policy"
	Actor    string // principal or certificate subject; empty when unknown
	Outcome  string // "success" or "denied"
	SourceIP string
	Detail   string
}

// AuditFunc records an AuditEvent; main adapts it to the hub's audit log.
type AuditFunc func(ctx context.Context, ev AuditEvent)

// Server implements the MS-WSTEP Certificate Enrollment Service.
// WSTEP uses WS-Trust RequestSecurityToken over SOAP/HTTPS.
type Server struct {
	caEngine       ca.Service
	caID           string
	templateLookup TemplateLookupFunc // optional; nil = no policy enforcement
	// issuedRecorder writes each issued certificate into the hub's inventory
	// (source "wstep") so WSTEP issuance is reconstructable like every other
	// protocol's.
	issuedRecorder  ca.IssuedCertificateRecorder
	resolveTemplate TemplateResolveFunc
	authenticate    AuthWrapper
	revocation      RevocationChecker
	audit           AuditFunc
	now             func() time.Time
}

// NewServer creates a WSTEP server. Until WithAuthenticator is set every
// enrollment is refused: there is no anonymous mode.
func NewServer(caEngine ca.Service, caID string) *Server {
	return &Server{caEngine: caEngine, caID: caID, now: time.Now}
}

// WithTemplateLookup attaches a template policy lookup function.
// When set, the TokenType from each RST is resolved to a TemplatePolicy
// and enforced during issuance.
func (s *Server) WithTemplateLookup(fn TemplateLookupFunc) *Server {
	s.templateLookup = fn
	return s
}

// WithIssuedRecorder wires an IssuedCertificateRecorder into the server.
func (s *Server) WithIssuedRecorder(r ca.IssuedCertificateRecorder) *Server {
	s.issuedRecorder = r
	return s
}

// WithTemplateResolver lets a request name one of the hub's templates.
// Windows autoenrollment puts the template it is enrolling for in the CSR
// and matches installed certificates to templates by the same extension in
// the certificate; without it every autoenrollment pulse enrolls again.
func (s *Server) WithTemplateResolver(fn TemplateResolveFunc) *Server {
	s.resolveTemplate = fn
	return s
}

// WithAuthenticator sets how enrollment requests are authenticated
// (Kerberos in production, see KerberosFromEnv).
func (s *Server) WithAuthenticator(a AuthWrapper) *Server {
	s.authenticate = a
	return s
}

// WithRenewal enables renewal by a client certificate this CA issued, checked
// against rc for revocation.
func (s *Server) WithRenewal(rc RevocationChecker) *Server {
	s.revocation = rc
	return s
}

// WithAuditFunc records enrollment and renewal outcomes.
func (s *Server) WithAuditFunc(fn AuditFunc) *Server {
	s.audit = fn
	return s
}

func (s *Server) emit(r *http.Request, ev AuditEvent) { emitAudit(s.audit, r, ev) }

func emitAudit(audit AuditFunc, r *http.Request, ev AuditEvent) {
	if audit == nil {
		return
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ev.SourceIP = host
	} else {
		ev.SourceIP = r.RemoteAddr
	}
	audit(r.Context(), ev)
}

// RequireIdentity serves next only for a caller auth has identified. With no
// authenticator every request gets the Negotiate challenge: there is no
// anonymous mode. XCEP shares it so both endpoints audit alike.
func RequireIdentity(auth AuthWrapper, audit AuditFunc, action string, next func(http.ResponseWriter, *http.Request, Identity)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth == nil {
			w.Header().Set("WWW-Authenticate", "Negotiate")
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		rec := &statusRecorder{ResponseWriter: w}
		auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, ok := identityFrom(r.Context())
			if !ok {
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
			next(w, r, id)
		})).ServeHTTP(rec, r)
		// The first Negotiate leg (no Authorization header) is a challenge,
		// not a failure; only a presented credential that was rejected is.
		if rec.status == http.StatusUnauthorized && r.Header.Get("Authorization") != "" {
			emitAudit(audit, r, AuditEvent{Action: action, Outcome: "denied", Detail: "Kerberos authentication failed"})
		}
	})
}

// Handler returns an http.Handler for the WSTEP endpoint.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Renewal: a client certificate from this CA is the credential. A
		// certificate from anywhere else is not a credential here; Windows
		// may offer one unprompted, so it falls through to Kerberos instead
		// of failing the request.
		if s.revocation != nil && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			if handled := s.serveRenewal(w, r); handled {
				return
			}
		}

		RequireIdentity(s.authenticate, s.audit, "wstep.enroll", func(w http.ResponseWriter, r *http.Request, id Identity) {
			s.serveRST(w, r, id, "wstep.enroll")
		}).ServeHTTP(w, r)
	})
}

// serveRenewal handles a request carrying a client certificate. It reports
// false when the certificate is not from this CA, so the caller falls back to
// Kerberos.
func (s *Server) serveRenewal(w http.ResponseWriter, r *http.Request) bool {
	issuer, err := s.caEngine.GetCA(s.caID)
	if err != nil || issuer.Certificate == nil {
		return false
	}
	cert := r.TLS.PeerCertificates[0]
	err = ca.CheckHubClientCertificate(cert, issuer.Certificate, s.caID, s.now(), s.revocation)
	if errors.Is(err, ca.ErrNotIssuedHere) {
		return false
	}
	actor := cert.Subject.String()
	if err != nil {
		var refused *ca.CredentialRefusedError
		if errors.As(err, &refused) && refused.Err != nil {
			log.Printf("wstep: renewal credential for %s: %v", actor, refused.Err)
		}
		s.emit(r, AuditEvent{Action: "wstep.renew", Actor: actor, Outcome: "denied", Detail: err.Error()})
		http.Error(w, "renewal refused: "+err.Error(), http.StatusForbidden)
		return true
	}
	s.serveRST(w, r, Identity{
		Method: "certificate", Principal: actor,
		Subject: cert.Subject, DNSNames: cert.DNSNames, Predecessor: cert,
	}, "wstep.renew")
	return true
}

func (s *Server) serveRST(w http.ResponseWriter, r *http.Request, id Identity, action string) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 128*1024))
	if err != nil {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}

	var envelope rstEnvelope
	if err := xml.Unmarshal(body, &envelope); err != nil {
		s.writeSoapFault(w, "s:Client", "Invalid SOAP envelope")
		return
	}

	soapAction := strings.TrimSpace(envelope.Header.Action)
	if !isWSTEPAction(soapAction) {
		s.writeSoapFault(w, "s:Client", fmt.Sprintf("Unknown action: %s", soapAction))
		return
	}

	csr, signer, err := requestCSR(envelope.Body.RST.BinarySecurityToken)
	if err != nil {
		s.writeSoapFault(w, "s:Client", err.Error())
		return
	}
	if action == "wstep.enroll" {
		if prior := s.renewalPredecessor(signer, id); prior != nil {
			action, id.Predecessor = "wstep.renew", prior
		}
	}

	// The CSR only proves possession of the key: subject and SANs come from
	// the authenticated identity, so a requester cannot name anyone else.
	subject := id.Subject
	issuanceReq := ca.IssuanceRequest{
		CSR:             csr,
		Subject:         &subject,
		DNSNames:        id.DNSNames,
		CallerNamesOnly: true,
		Validity:        365 * 24 * time.Hour,
		// Kerberos already bounds the client's clock to the KDC's default
		// 5-minute skew, so that much backdating covers any caller we
		// authenticated.
		Backdate:    5 * time.Minute,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	templateExt, ref, err := s.templateExtension(csr)
	if err != nil {
		s.writeSoapFault(w, "s:Client", err.Error())
		return
	}
	var tmpl *TemplateRef
	if templateExt != nil {
		issuanceReq.ExtraExtensions = []pkix.Extension{*templateExt}
		tmpl = &ref
	}
	// A template named in the CSR (what Windows sends) wins; TokenType is
	// for clients that name the template there, as our WSTEP connector does.
	tokenType := strings.TrimSpace(envelope.Body.RST.TokenType)
	if tmpl == nil && s.templateLookup != nil && tokenType != "" {
		if t, ok := s.templateLookup(tokenType); ok {
			tmpl = &t
		}
	}
	if tmpl != nil {
		if err := enrolleeMatches(*tmpl, id); err != nil {
			s.emit(r, AuditEvent{Action: action, Actor: id.Principal, Outcome: "denied", Detail: err.Error()})
			s.writeSoapFault(w, "s:Client", err.Error())
			return
		}
	}
	var policy *ca.TemplatePolicy
	if tmpl != nil {
		policy = tmpl.Policy
	}
	if policy != nil {
		issuanceReq.TemplateID = policy.ID
		issuanceReq.Policy = policy
		if policy.MaxValidity > 0 {
			issuanceReq.Validity = policy.MaxValidity
		}
	}
	issued, err := s.caEngine.IssueCertificate(s.caID, issuanceReq)
	if err != nil {
		log.Printf("wstep: issuance for %s failed: %v", id.Principal, err)
		if errors.Is(err, ca.ErrPolicyViolation) {
			// The requester can act on a template policy refusal.
			s.writeSoapFault(w, "s:Client", err.Error())
			return
		}
		s.writeSoapFault(w, "s:Server", "Certificate issuance failed")
		return
	}

	if s.issuedRecorder != nil {
		var err error
		if tr, ok := s.issuedRecorder.(ca.TemplateIssuedCertificateRecorder); ok && issuanceReq.TemplateID != "" {
			err = tr.RecordIssuedCertificateWithTemplate(r.Context(), s.caID, issued.Certificate, issued.CertPEM, "wstep", issuanceReq.TemplateID)
		} else {
			err = s.issuedRecorder.RecordIssuedCertificate(r.Context(), s.caID, issued.Certificate, issued.CertPEM, "wstep")
		}
		if err != nil {
			log.Printf("wstep: issued certificate %s not recorded: %v", issued.Fingerprint, err)
		}
	}
	s.emit(r, AuditEvent{Action: action, Actor: id.Principal, Outcome: "success",
		Detail: auditDetail(id, issued.Certificate)})

	respXML, err := s.buildRSTResponse(issued.Certificate, strings.TrimSpace(envelope.Header.MessageID))
	if err != nil {
		log.Printf("wstep: building response for serial %s failed: %v", issued.Certificate.SerialNumber.Text(16), err)
		s.writeSoapFault(w, "s:Server", "Certificate issued but the response could not be built")
		return
	}

	w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := io.WriteString(w, respXML); err != nil {
		log.Printf("wstep: writing response: %v", err)
	}
}

// oidCertificateTemplate is szOID_CERTIFICATE_TEMPLATE.
var oidCertificateTemplate = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 7}

// certificateTemplateExt is CertEnroll's CertificateTemplate extension:
// SEQUENCE { templateID, templateMajorVersion, templateMinorVersion OPTIONAL }.
type certificateTemplateExt struct {
	TemplateID asn1.ObjectIdentifier
	Major      int64
	Minor      int64 `asn1:"optional"`
}

// templateExtension returns the template extension for the certificate,
// or nil when the CSR names no template. Only the template's identity is
// taken from the request; its version is the hub's, so a client cannot
// claim a newer revision than the policy it was given.
// enrolleeMatches refuses a template of the other kind: a user template
// asked for by a machine, or a machine template by a user. XCEP only offers
// the matching kind, so a mismatch is a client naming a template it was not
// offered.
func enrolleeMatches(t TemplateRef, id Identity) error {
	user := t.Enrollee == EnrolleeUser
	if user == id.IsMachine() {
		kind, caller := "machine", "a user"
		if user {
			kind, caller = "user", "a machine"
		}
		return fmt.Errorf("Certificate template %s is a %s template and cannot be issued to %s", firstNonEmptyName(t.Name, t.OID), kind, caller)
	}
	return nil
}

func firstNonEmptyName(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (s *Server) templateExtension(csr *x509.CertificateRequest) (*pkix.Extension, TemplateRef, error) {
	for _, ext := range csr.Extensions {
		if !ext.Id.Equal(oidCertificateTemplate) {
			continue
		}
		var requested certificateTemplateExt
		if rest, err := asn1.Unmarshal(ext.Value, &requested); err != nil || len(rest) != 0 {
			return nil, TemplateRef{}, errors.New("Invalid certificate template extension")
		}
		if s.resolveTemplate == nil {
			return nil, TemplateRef{}, errors.New("This hub offers no certificate templates")
		}
		ref, ok := s.resolveTemplate(requested.TemplateID.String())
		if !ok {
			return nil, TemplateRef{}, fmt.Errorf("Certificate template %s is not offered by this hub", requested.TemplateID)
		}
		value, err := asn1.Marshal(certificateTemplateExt{TemplateID: requested.TemplateID, Major: int64(max(ref.MajorVersion, 1)), Minor: int64(max(ref.MinorVersion, 0))})
		if err != nil {
			return nil, TemplateRef{}, err
		}
		return &pkix.Extension{Id: oidCertificateTemplate, Value: value}, ref, nil
	}
	return nil, TemplateRef{}, nil
}

// requestCSR decodes the RST's BinarySecurityToken. Windows sends base64
// with line breaks, a bare PKCS#10 for a first enrollment and a PKCS#7
// SignedData wrapping the PKCS#10 for a renewal (MS-WSTEP 4.1.1.1, 4.1.5.1).
// The outer signature by the old key is not checked: the caller's Kerberos
// identity already decides who the certificate is for, and the PKCS#10's
// own signature is verified at issuance.
func requestCSR(token string) (*x509.CertificateRequest, *x509.Certificate, error) {
	token = strings.Join(strings.Fields(token), "")
	if token == "" {
		return nil, nil, errors.New("Missing BinarySecurityToken (CSR)")
	}
	der, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, nil, errors.New("Invalid base64 CSR encoding")
	}
	if csr, err := x509.ParseCertificateRequest(der); err == nil {
		return csr, nil, nil
	}
	p7, err := pkcs7.Parse(der)
	if err != nil {
		return nil, nil, errors.New("Invalid CSR: neither PKCS#10 nor PKCS#7")
	}
	// The old-key signer, when its signature over the request verifies
	// (renewal_signer.go). It labels a renewal in the audit log and never
	// authorizes.
	signer := oldKeySigner(der, p7.Content, p7.Certificates)
	if csr, err := x509.ParseCertificateRequest(p7.Content); err == nil {
		return csr, signer, nil
	}
	// Windows CES clients send a CMC PKIData here (RFC 5272 3.2.1), even
	// for a first enrollment.
	inner, err := cmcCertificationRequest(p7.Content)
	if err != nil {
		log.Printf("wstep: CMC request rejected: %v", err)
		return nil, nil, errors.New("Invalid CSR: PKCS#7 content is neither PKCS#10 nor a supported CMC request")
	}
	csr, err := x509.ParseCertificateRequest(inner)
	if err != nil {
		return nil, nil, errors.New("Invalid CSR: CMC request is not a PKCS#10")
	}
	return csr, signer, nil
}

// renewalPredecessor returns signer when it is a certificate this CA issued
// to the identity Kerberos authenticated: then the request is a renewal
// (MS-WSTEP 4.1.5.1). Anything else -- no signer, a foreign or self-made
// signer, or someone else's certificate -- leaves the request an
// enrollment. This labels the audit row; Kerberos alone authorizes.
func (s *Server) renewalPredecessor(signer *x509.Certificate, id Identity) *x509.Certificate {
	if signer == nil {
		return nil
	}
	issuer, err := s.caEngine.GetCA(s.caID)
	if err != nil || issuer.Certificate == nil || signer.CheckSignatureFrom(issuer.Certificate) != nil {
		return nil
	}
	if !strings.EqualFold(signer.Subject.CommonName, id.Subject.CommonName) {
		return nil
	}
	return signer
}

func auditDetail(id Identity, issued *x509.Certificate) string {
	d := fmt.Sprintf("method=%s serial=%s subject=%q", id.Method, issued.SerialNumber.Text(16), issued.Subject.String())
	if id.Predecessor != nil {
		d += " predecessor=" + id.Predecessor.SerialNumber.Text(16)
	}
	return d
}

// cmcPKIData is RFC 5272's PKIData with the request list kept raw.
type cmcPKIData struct {
	ControlSequence asn1.RawValue
	ReqSequence     []asn1.RawValue
	CMSSequence     asn1.RawValue
	OtherMsgSeq     asn1.RawValue
}

// cmcTaggedCertificationRequest is the [0] arm of TaggedRequest.
type cmcTaggedCertificationRequest struct {
	BodyPartID           int64
	CertificationRequest asn1.RawValue
}

// cmcCertificationRequest returns the single PKCS#10 in a PKIData. Exactly
// one request is accepted: one RST yields one certificate, and anything
// else (CRMF, nested bodies) is refused rather than half-understood.
func cmcCertificationRequest(der []byte) ([]byte, error) {
	var pki cmcPKIData
	if rest, err := asn1.Unmarshal(der, &pki); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("trailing data after PKIData")
	}
	if len(pki.ReqSequence) != 1 {
		return nil, fmt.Errorf("want exactly one request, got %d", len(pki.ReqSequence))
	}
	req := pki.ReqSequence[0]
	if req.Class != asn1.ClassContextSpecific || req.Tag != 0 || !req.IsCompound {
		return nil, fmt.Errorf("unsupported TaggedRequest [%d]; only PKCS#10 is accepted", req.Tag)
	}
	// [0] IMPLICIT: the contents are a SEQUENCE body without its header.
	seq, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: req.Bytes})
	if err != nil {
		return nil, err
	}
	var tcr cmcTaggedCertificationRequest
	if rest, err := asn1.Unmarshal(seq, &tcr); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("trailing data after TaggedCertificationRequest")
	}
	return tcr.CertificationRequest.FullBytes, nil
}

// statusRecorder captures the status the authenticator wrote, so a rejected
// credential can be audited after the fact.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

// SOAP XML structures for WS-Trust RST/RSTR

type rstEnvelope struct {
	XMLName xml.Name  `xml:"Envelope"`
	Header  rstHeader `xml:"Header"`
	Body    rstBody   `xml:"Body"`
}

type rstHeader struct {
	Action    string `xml:"Action"`
	MessageID string `xml:"MessageID"`
}

type rstBody struct {
	RST requestSecurityToken `xml:"RequestSecurityToken"`
}

type requestSecurityToken struct {
	TokenType           string `xml:"TokenType"`
	RequestType         string `xml:"RequestType"`
	BinarySecurityToken string `xml:"BinarySecurityToken"`
}

// buildRSTResponse renders the RSTR collection of MS-WSTEP 4.1.1.2: the
// issued certificate as an X509v3 RequestedSecurityToken, the certificate
// with its chain as a PKCS#7 token (Windows installs the chain from it), a
// disposition and a request ID, and RelatesTo echoing the request's
// MessageID, which WCF clients require to correlate the reply.
func (s *Server) buildRSTResponse(cert *x509.Certificate, relatesTo string) (string, error) {
	bundle := append([]byte(nil), cert.Raw...)
	if chain, err := s.caEngine.GetCAChain(s.caID); err == nil {
		for _, c := range chain {
			if c != nil && c.Certificate != nil {
				bundle = append(bundle, c.Certificate.Raw...)
			}
		}
	}
	p7, err := pkcs7.DegenerateCertificate(bundle)
	if err != nil {
		return "", err
	}
	const (
		wsse   = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
		b64Enc = wsse + "#base64binary"
		x509v3 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
		enroll = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment"
	)
	var b strings.Builder
	b.WriteString(xml.Header)
	b.WriteString(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">`)
	b.WriteString(`<s:Header><a:Action s:mustUnderstand="1">` + enroll + `/RSTRC/wstep</a:Action>`)
	if relatesTo != "" {
		b.WriteString(`<a:RelatesTo>` + xmlEscape(relatesTo) + `</a:RelatesTo>`)
	}
	b.WriteString(`</s:Header><s:Body>`)
	b.WriteString(`<RequestSecurityTokenResponseCollection xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512"><RequestSecurityTokenResponse>`)
	b.WriteString(`<TokenType>` + x509v3 + `</TokenType>`)
	b.WriteString(`<DispositionMessage xml:lang="en-US" xmlns="` + enroll + `">Issued</DispositionMessage>`)
	b.WriteString(`<BinarySecurityToken ValueType="` + wsse + `#PKCS7" EncodingType="` + b64Enc + `" xmlns="` + wsse + `">` + base64.StdEncoding.EncodeToString(p7) + `</BinarySecurityToken>`)
	b.WriteString(`<RequestedSecurityToken><BinarySecurityToken ValueType="` + x509v3 + `" EncodingType="` + b64Enc + `" xmlns="` + wsse + `">` + base64.StdEncoding.EncodeToString(cert.Raw) + `</BinarySecurityToken></RequestedSecurityToken>`)
	b.WriteString(`<RequestID xmlns="` + enroll + `">` + cert.SerialNumber.Text(16) + `</RequestID>`)
	b.WriteString(`</RequestSecurityTokenResponse></RequestSecurityTokenResponseCollection></s:Body></s:Envelope>`)
	return b.String(), nil
}

func xmlEscape(v string) string {
	var b strings.Builder
	// A strings.Builder write cannot fail; refuse rather than emit unescaped text.
	if err := xml.EscapeText(&b, []byte(v)); err != nil {
		return ""
	}
	return b.String()
}

func (s *Server) writeSoapFault(w http.ResponseWriter, code string, reason string) {
	// Real clients only surface WS_E_ENDPOINT_FAULT_RECEIVED; the reason is
	// otherwise invisible to an operator.
	log.Printf("wstep: SOAP fault %s: %s", code, reason)
	fault := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <s:Fault>
      <s:Code><s:Value>%s</s:Value></s:Code>
      <s:Reason><s:Text xml:lang="en">%s</s:Text></s:Reason>
    </s:Fault>
  </s:Body>
</s:Envelope>`, code, xmlEscape(reason))
	w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(fault))
}

// isWSTEPAction returns true for recognized WSTEP/WS-Trust enrollment action URIs.
// Accepts both the MS-WSTEP specific URI and generic WS-Trust RST actions.
func isWSTEPAction(action string) bool {
	return strings.Contains(action, "RequestSecurityToken") ||
		strings.Contains(action, "enrollment/RST/wstep") ||
		strings.Contains(action, "enrollment/RST/renewCertificate")
}
