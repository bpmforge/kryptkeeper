// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package est

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.mozilla.org/pkcs7"
	"kryptkeeper/internal/logging"

	"kryptkeeper/internal/ca"
)

// Server is an EST protocol server per RFC 7030.
type Server struct {
	caEngine ca.Service
	caID     string
	// issuedRecorder writes each issued certificate into the hub's inventory
	// (see ca.IssuedCertificateRecorder). Nil means "not recorded" -- every
	// existing caller and test that builds a Server without
	// WithIssuedRecorder keeps working unchanged.
	issuedRecorder ca.IssuedCertificateRecorder
	enrollGate     EnrollmentGate
	// Authentication (auth.go). Enrollment is refused until at least one
	// credential type is configured (W20-14, D-112).
	users       map[string]User
	clientRoots *x509.CertPool
	revocation  ca.RevocationChecker
	audit       AuditFunc
	now         func() time.Time
	// W26-07: Basic users beyond the users file, and the failed-attempt alert.
	userSource UserSource
	alert      AlertFunc
	failures   failureWindow
	// W26-06: named endpoints bound to templates (labels.go).
	labels    LabelStore
	labelGate func(templateID string) EnrollmentGate
}

// NewServer creates an EST server. Enrollment is refused until a credential
// type is configured (WithBasicUsers, WithClientCertAnchors); cacerts,
// which issues nothing, is always served anonymously (RFC 7030 4.1.1); every
// other route answers 401 without credentials.
func NewServer(caEngine ca.Service, caID string) *Server {
	return &Server{caEngine: caEngine, caID: caID, now: time.Now}
}

// WithIssuedRecorder wires an IssuedCertificateRecorder into the server and
// returns it for chaining. Leaving it unset (nil) is a valid, tested
// configuration: enrollment simply does not record.
func (s *Server) WithIssuedRecorder(r ca.IssuedCertificateRecorder) *Server {
	s.issuedRecorder = r
	return s
}

// EnrollmentGate decides whether this protocol may issue from its configured
// template (W23-43). It is a function value because protocol packages must not
// import internal/bootstrap. An error wrapping ca.ErrEnrollmentDenied is a
// policy denial; any other error is a failure to evaluate, which also blocks
// issuance (fail closed). Nil means no gate is configured.
type EnrollmentGate func(ctx context.Context, actor string) error

// WithEnrollmentGate wires the template enrollment gate and returns the server
// for chaining.
func (s *Server) WithEnrollmentGate(g EnrollmentGate) *Server {
	s.enrollGate = g
	return s
}

// Handler returns an http.Handler for EST endpoints.
// EST endpoints are under /.well-known/est/ per RFC 7030 §3.2.2.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/est/cacerts", s.handleCACerts)
	mux.HandleFunc("/.well-known/est/simpleenroll", s.handleSimpleEnroll)
	mux.HandleFunc("/.well-known/est/simplereenroll", s.handleSimpleReenroll)
	mux.HandleFunc("/.well-known/est/csrattrs", s.handleCSRAttrs)
	mux.HandleFunc("/.well-known/est/", s.handleLabelPath) // exact patterns above win
	return mux
}

// handleCACerts returns the CA certificate chain as a real RFC 7030 §4.1.3
// "certs-only" response: a degenerate PKCS#7 SignedData carrying only
// certificates, no signer. W19-14/UAT W19-05: this previously returned
// concatenated raw base64 DER certs, which is not a PKCS#7 structure at all
// -- neither openssl nor a real EST client (github.com/globalsign/est's
// decodePKCS7CertsOnly calls pkcs7.Parse) can consume it.
func (s *Server) handleCACerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if _, rerr := ca.ResolveCAID(s.caEngine, s.caID); errors.Is(rerr, ca.ErrNoCAConfigured) {
		http.Error(w, rerr.Error(), http.StatusServiceUnavailable)
		return
	}
	chain, err := s.caEngine.GetCAChain(s.activeCAID())
	if err != nil {
		logging.Infof("est cacerts: %v", err)
		http.Error(w, "CA chain unavailable", http.StatusServiceUnavailable)
		return
	}

	var certs []*x509.Certificate
	for _, chainCA := range chain {
		if chainCA.Certificate != nil {
			certs = append(certs, chainCA.Certificate)
		}
	}
	if err := writePKCS7CertsOnly(w, certs); err != nil {
		logging.Infof("est cacerts: %v", err)
		http.Error(w, "CA chain unavailable", http.StatusServiceUnavailable)
	}
}

// writePKCS7CertsOnly writes certs as an RFC 7030 §4.1.3 "certs-only"
// application/pkcs7-mime response (also used by simpleenroll/simplereenroll
// per §4.2.3, which return the same degenerate structure carrying the
// issued certificate). The body must be a single unbroken base64 run: real
// clients decode it with a plain base64.StdEncoding.Decode that has no
// newline tolerance (see github.com/globalsign/est's readAllBase64Response),
// so this must not line-wrap the way some MIME writers do.
func writePKCS7CertsOnly(w http.ResponseWriter, certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return fmt.Errorf("no certificates to encode")
	}
	var der []byte
	for _, c := range certs {
		der = append(der, c.Raw...)
	}
	p7, err := pkcs7.DegenerateCertificate(der)
	if err != nil {
		return fmt.Errorf("pkcs7 degenerate: %w", err)
	}
	w.Header().Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
	w.Header().Set("Content-Transfer-Encoding", "base64")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write([]byte(base64.StdEncoding.EncodeToString(p7)))
	return err
}

// handleSimpleEnroll processes a CSR and returns a signed certificate.
// Per RFC 7030 §4.2, the request is a PKCS#10 CSR.
func (s *Server) handleSimpleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.EnrollmentConfigured() {
		http.Error(w, "EST enrollment is disabled: no authentication is configured", http.StatusForbidden)
		return
	}
	csr, err := s.parseCSRFromRequest(r)
	if err != nil {
		http.Error(w, "invalid CSR: "+err.Error(), http.StatusBadRequest)
		return
	}
	id, ok := s.authenticateEnroll(w, r, csr)
	if !ok {
		return
	}
	s.issue(w, r, csr, id, "est.enroll")
}

// handleSimpleReenroll (RFC 7030 4.2.2) renews for the holder of a
// certificate this CA issued: it must be presented as the TLS client
// certificate and pass the same checks as WSTEP renewal. The new
// certificate keeps its subject and DNS SANs.
func (s *Server) handleSimpleReenroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.TLS == nil {
		http.Error(w, "EST requires TLS", http.StatusForbidden)
		return
	}
	if s.revocation == nil {
		http.Error(w, "re-enrollment is not enabled", http.StatusForbidden)
		return
	}
	if len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "re-enrollment requires the client certificate this hub issued", http.StatusUnauthorized)
		return
	}
	issuer, err := s.caEngine.GetCA(s.activeCAID())
	if err != nil || issuer.Certificate == nil {
		http.Error(w, "CA unavailable", http.StatusServiceUnavailable)
		return
	}
	cert := r.TLS.PeerCertificates[0]
	actor := cert.Subject.String()
	if err := ca.CheckHubClientCertificate(cert, issuer.Certificate, s.activeCAID(), s.now(), s.revocation); err != nil {
		var refused *ca.CredentialRefusedError
		if errors.As(err, &refused) && refused.Err != nil {
			logging.Infof("est simplereenroll: credential for %s: %v", actor, refused.Err)
		}
		s.emit(r, AuditEvent{Action: "est.reenroll", Actor: actor, Outcome: "denied", Detail: err.Error()})
		http.Error(w, "re-enrollment refused: "+err.Error(), http.StatusForbidden)
		return
	}
	csr, err := s.parseCSRFromRequest(r)
	if err != nil {
		http.Error(w, "invalid CSR: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.issue(w, r, csr, identity{method: "certificate", actor: actor, subject: cert.Subject, dnsNames: cert.DNSNames}, "est.reenroll")
}

// issue signs csr's key for id. The subject and SANs come only from the
// authenticated identity, never verbatim from the CSR.
func (s *Server) issue(w http.ResponseWriter, r *http.Request, csr *x509.CertificateRequest, id identity, action string) {
	subject := id.subject
	gate := s.enrollGate
	label := labelFrom(r.Context())
	labelDetail := ""
	if label != nil {
		labelDetail = "label=" + label.Label + " "
		gate = func(context.Context, string) error { return errors.New("no enrollment gate for labels") } // fail closed
		if s.labelGate != nil {
			gate = s.labelGate(label.TemplateID)
		}
	}
	if gate != nil {
		if gerr := gate(r.Context(), id.actor); gerr != nil {
			s.emit(r, AuditEvent{Action: action, Actor: id.actor, Outcome: "denied", Detail: labelDetail + gerr.Error()})
			if errors.Is(gerr, ca.ErrEnrollmentDenied) {
				http.Error(w, "enrollment not permitted for this template", http.StatusForbidden)
				return
			}
			logging.Warnf("est %s: enrollment gate failed: %v", action, gerr)
			http.Error(w, "certificate issuance failed", http.StatusInternalServerError)
			return
		}
	}
	issuerID, rerr := ca.ResolveCAID(s.caEngine, s.caID)
	if rerr != nil {
		logging.Warnf("est %s: %v", action, rerr)
		s.emit(r, AuditEvent{Action: action, Actor: id.actor, Outcome: "failure", Detail: rerr.Error()})
		msg := "CA unavailable"
		if errors.Is(rerr, ca.ErrNoCAConfigured) {
			msg = rerr.Error()
		}
		http.Error(w, msg, http.StatusServiceUnavailable)
		return
	}
	issued, err := s.caEngine.IssueCertificate(issuerID, ca.IssuanceRequest{
		CSR:             csr,
		Subject:         &subject,
		DNSNames:        id.dnsNames,
		CallerNamesOnly: true,
		Validity:        365 * 24 * time.Hour,
		KeyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		logging.Warnf("est %s: issuance failed: %v", action, err)
		if errors.Is(err, ca.ErrCARevoked) {
			s.emit(r, AuditEvent{Action: action, Actor: id.actor, Outcome: "denied", Detail: "ca revoked"})
			http.Error(w, "issuing CA revoked", http.StatusForbidden)
			return
		}
		// W22-14: surface an issuance-policy refusal (policy + rule) to the
		// enrolling client as 403 rather than a generic 500. Only the status
		// and text change; nothing was signed.
		var pv *ca.PolicyViolationError
		if errors.As(err, &pv) {
			s.emit(r, AuditEvent{Action: action, Actor: id.actor, Outcome: "denied", Detail: pv.Error()})
			http.Error(w, pv.Error(), http.StatusForbidden)
			return
		}
		http.Error(w, "certificate issuance failed", http.StatusInternalServerError)
		return
	}

	// Record into the hub's inventory -- the client already has its
	// certificate in issued above, so a recorder failure must never fail the
	// enrollment response; it would hand the client a credential this system
	// then can't undo. Best-effort, logged only (W18-18).
	if s.issuedRecorder != nil {
		var err error
		if tr, ok := s.issuedRecorder.(ca.TemplateIssuedCertificateRecorder); ok && label != nil {
			err = tr.RecordIssuedCertificateWithTemplate(r.Context(), s.activeCAID(), issued.Certificate, issued.CertPEM, "est", label.TemplateID)
		} else {
			err = s.issuedRecorder.RecordIssuedCertificate(r.Context(), s.activeCAID(), issued.Certificate, issued.CertPEM, "est")
		}
		if err != nil {
			logging.Infof("est: issued certificate %s not recorded: %v", issued.Fingerprint, err)
		}
	}
	s.emit(r, AuditEvent{Action: action, Actor: id.actor, Outcome: "success",
		Detail: fmt.Sprintf(labelDetail+"method=%s serial=%s subject=%q", id.method, issued.Certificate.SerialNumber.Text(16), issued.Certificate.Subject.String())})

	// RFC 7030 4.2.3: same degenerate PKCS#7 certs-only structure as
	// cacerts, carrying just the issued certificate (see writePKCS7CertsOnly).
	if err := writePKCS7CertsOnly(w, []*x509.Certificate{issued.Certificate}); err != nil {
		logging.Infof("est %s: %v", action, err)
		http.Error(w, "response encoding failed", http.StatusInternalServerError)
	}
}

// handleCSRAttrs returns the CSR attributes the server requires.
func (s *Server) handleCSRAttrs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Anonymous callers get 401 like every other route but cacerts.
	if r.TLS != nil && !s.EnrollmentConfigured() {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	if _, ok := s.authenticateEnroll(w, r, nil); !ok {
		return
	}

	// Return empty attributes (no mandatory fields beyond subject).
	w.Header().Set("Content-Type", "application/csrattrs")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) parseCSRFromRequest(r *http.Request) (*x509.CertificateRequest, error) {
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	// Try PEM first.
	block, _ := pem.Decode(body)
	if block != nil && block.Type == "CERTIFICATE REQUEST" {
		return x509.ParseCertificateRequest(block.Bytes)
	}

	// Try base64-encoded DER.
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err == nil {
		csr, parseErr := x509.ParseCertificateRequest(der)
		if parseErr == nil {
			return csr, nil
		}
	}

	// Try raw DER.
	return x509.ParseCertificateRequest(body)
}

// activeCAID returns the CA this server issues from: the configured id, else
// the first stored CA resolved at request time so a root created after
// startup (first-run onboarding) becomes the default without a restart. It
// returns "" while no CA exists or the CA list cannot be read; callers that
// issue check ca.ResolveCAID for the specific error.
func (s *Server) activeCAID() string {
	id, _ := ca.ResolveCAID(s.caEngine, s.caID)
	return id
}
