// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package scep

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/smallstep/pkcs7"
	"kryptkeeper/internal/logging"

	"kryptkeeper/internal/ca"
)

// SCEP attribute OIDs (RFC 8894 §8.2, "id-attributes" arc under VeriSign's
// id-pki 2.16.840.1.113733.1.9). challengePassword is not SCEP-specific --
// it is the PKCS#9 attribute (RFC 2985 §5.4.1) carried inside the PKCS#10
// CSR itself, not a CMS signed attribute on the outer pkiMessage.
var (
	oidMessageType       = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	oidPKIStatus         = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 3}
	oidFailInfo          = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 4}
	oidSenderNonce       = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
	oidRecipientNonce    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 6}
	oidTransactionID     = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}
	oidChallengePassword = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}
)

// messageType / pkiStatus / failInfo values (RFC 8894 §3.2, §3.3, §3.3.3).
const (
	msgTypePKCSReq    = "19"
	msgTypeRenewalReq = "17"
	msgTypeCertRep    = "3"

	pkiStatusSuccess = "0"
	pkiStatusFailure = "2"

	failInfoBadMessageCheck = "1"
	failInfoBadRequest      = "2"
)

// errBadSignature marks a pkiMessage whose CMS signature did not verify; the
// CertRep then carries failInfo badMessageCheck instead of badRequest.
var errBadSignature = errors.New("pkiMessage signature verification failed")

// RevocationChecker reports whether a certificate serial issued by the SCEP CA
// is revoked. An error means the status is unknown; renewal treats that as a
// refusal.
type RevocationChecker func(serial *big.Int) (bool, error)

// DecrypterFunc returns the crypto.Decrypter for the SCEP CA's private key,
// resolved lazily on every enrollment rather than cached at startup -- a
// pkcs11-backed CA that cannot support decryption should fail each request
// with a clear error, not a permanently-nil value chosen once at boot.
type DecrypterFunc func() (crypto.Decrypter, error)

// Server is a SCEP protocol server.
// SCEP uses HTTP GET/POST with an "operation" query parameter.
type Server struct {
	caEngine   ca.Service
	caID       string
	challenges ChallengeStore // one-time, name-bound challenges (W20-16)
	decrypter  DecrypterFunc
	// issuedRecorder writes each issued certificate into the hub's inventory
	// (see ca.IssuedCertificateRecorder). Nil means "not recorded" -- every
	// existing caller and test that builds a Server without
	// WithIssuedRecorder keeps working unchanged.
	issuedRecorder ca.IssuedCertificateRecorder
	enrollGate     EnrollmentGate
	revoked        RevocationChecker // nil refuses every renewal (fail closed)
	labels         LabelStore        // named /scep/<label> endpoints (W20-23)
	intune         IntuneBackend
	labelGate      func(templateID string) EnrollmentGate
	withdraw       WithdrawFunc
	audit          AuditFunc
	now            func() time.Time
}

// AuditEvent is one SCEP enrollment outcome. Detail never carries the
// challenge itself.
type AuditEvent struct {
	Action   string // "scep.enroll" or "scep.renew"
	Actor    string // the challenge's bound CN, or empty when unknown
	Outcome  string // "success" or "denied"
	SourceIP string
	Detail   string
}

// AuditFunc records an AuditEvent; main adapts it to the hub's audit log.
type AuditFunc func(ctx context.Context, ev AuditEvent)

// WithRevocationChecker wires the revocation lookup renewal needs to refuse a
// revoked signer certificate. Without it every renewal is refused.
func (s *Server) WithRevocationChecker(fn RevocationChecker) *Server {
	s.revoked = fn
	return s
}

// WithAuditFunc records enrollment outcomes.
func (s *Server) WithAuditFunc(fn AuditFunc) *Server {
	s.audit = fn
	return s
}

func (s *Server) emit(r *http.Request, ev AuditEvent) {
	if s.audit == nil {
		return
	}
	ev.SourceIP = r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ev.SourceIP = host
	}
	s.audit(r.Context(), ev)
}

// NewServer creates a SCEP server. The CA identified by caID must hold an
// RSA key: SCEP's PKIOperation wraps the CSR in a CMS EnvelopedData keyed
// to the CA's public key, and PKCS#1/RSA-OAEP key transport (RFC 8894 §3.1)
// has no EC analogue -- callers select an RSA-capable CA before construction
// (see cmd/kryptkeeper/main.go's SCEP wiring).
//
// Enrollment needs a one-time challenge from challenges (W20-16, D-121): the
// CSR's challengePassword is consumed there and the certificate carries the
// names the challenge was minted for. A nil store refuses every enrollment.
func NewServer(caEngine ca.Service, caID string, challenges ChallengeStore) *Server {
	// pkcs7.ContentEncryptionAlgorithm is a package-level variable, not a
	// per-Server option (the library has no per-call knob) -- setting it
	// once here is safe because main.go constructs exactly one SCEP Server
	// per process, but it does mean a second Server instance in the same
	// process (e.g. two tests running in parallel packages) would race on
	// it if either changed the value; both call sites in this package set
	// the same AES-256-GCM value, so there is nothing to race over in
	// practice. Left at DES-CBC (the library default) it would silently
	// contradict the AES capability GetCACaps advertises below.
	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256GCM

	return &Server{
		caEngine:   caEngine,
		caID:       caID,
		challenges: challenges,
		now:        time.Now,
	}
}

// WithDecrypter wires the SCEP CA's private-key decrypter into the server
// and returns it for chaining. Required for PKIOperation to succeed --
// without it every enrollment fails with a clear "SCEP decryption not
// configured" error rather than a panic.
func (s *Server) WithDecrypter(d DecrypterFunc) *Server {
	s.decrypter = d
	return s
}

// WithIssuedRecorder wires an IssuedCertificateRecorder into the server and
// returns it for chaining. Leaving it unset (nil) is a valid, tested
// configuration: PKIOperation simply does not record.
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

// Handler returns an http.Handler for SCEP endpoints.
// All SCEP operations go through a single endpoint with ?operation= parameter.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /scep/<label> selects a named endpoint; any unknown label answers
		// the same 404 so labels cannot be enumerated.
		if rest, ok := strings.CutPrefix(r.URL.Path, "/scep/"); ok && strings.Trim(rest, "/") != "" {
			name := strings.Trim(rest, "/")
			if s.labels == nil || !ValidLabel(name) {
				http.NotFound(w, r)
				return
			}
			l, err := s.labels.Get(r.Context(), name)
			if errors.Is(err, ErrLabelNotFound) {
				http.NotFound(w, r)
				return
			}
			if err != nil {
				http.Error(w, "SCEP labels unavailable", http.StatusServiceUnavailable)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), ctxLabelKey{}, &l))
		}
		operation := r.URL.Query().Get("operation")
		switch strings.ToLower(operation) {
		case "getcacert":
			s.handleGetCACert(w, r)
		case "getcacaps":
			s.handleGetCACaps(w, r)
		case "pkioperation":
			s.handlePKIOperation(w, r)
		default:
			http.Error(w, "unknown operation", http.StatusBadRequest)
		}
	})
}

// handleGetCACert returns the CA certificate in DER format.
func (s *Server) handleGetCACert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	caObj, err := s.caEngine.GetCA(s.caID)
	if err != nil {
		logging.Infof("scep GetCACert: %v", err)
		http.Error(w, "CA unavailable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.WriteHeader(http.StatusOK)
	w.Write(caObj.Certificate.Raw)
}

// handleGetCACaps returns the capabilities of this SCEP server. Every entry
// here must be true of the implementation below -- POSTPKIOperation and
// SCEPStandard because handlePKIOperation only accepts the RFC 8894 PKCS#7
// exchange (no legacy bare-CSR fallback), SHA-256 because buildCertRep signs
// with SetDigestAlgorithm(OIDDigestAlgorithmSHA256), AES because NewServer
// sets pkcs7.ContentEncryptionAlgorithm to AES-256-GCM, Renewal because
// handlePKIOperation accepts a PKCSReq or RenewalReq signed by a currently
// valid, unrevoked certificate this CA issued (W26-30).
func (s *Server) handleGetCACaps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	caps := []string{
		"SHA-256",
		"AES",
		"POSTPKIOperation",
		"SCEPStandard",
	}
	// A label's certificates are validated by Intune on every request, which
	// the hub-native renewal (no challenge) would bypass, so it is not offered.
	if labelFrom(r.Context()) == nil {
		caps = append(caps, "Renewal")
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(strings.Join(caps, "\n")))
}

// handlePKIOperation processes a SCEP enrollment request: the client's
// self-signed CMS SignedData wraps a CMS EnvelopedData wrapping the PKCS#10
// CSR (RFC 8894 §3.1-3.2). Three outcomes:
//   - the outer message does not even parse as PKCS#7 -- there is no
//     transactionID to echo, so a CertRep would be unattributable; reply
//     HTTP 400 directly.
//   - it parses but fails signature verification, carries the wrong
//     messageType, fails to decrypt, or the challenge password is wrong --
//     reply HTTP 200 with a signed CertRep, pkiStatus FAILURE, failInfo
//     badRequest (RFC 8894's contract: transport-level failure is still a
//     protocol-level FAILURE, not an HTTP error).
//   - everything checks out -- issue through the existing engine path and
//     reply with a signed CertRep, pkiStatus SUCCESS, carrying the issued
//     certificate enveloped to the client's own self-signed cert.
func (s *Server) handlePKIOperation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var msgBytes []byte
	var err error

	if r.Method == http.MethodGet {
		msg := r.URL.Query().Get("message")
		if msg == "" {
			http.Error(w, "missing message parameter", http.StatusBadRequest)
			return
		}
		msgBytes, err = base64.StdEncoding.DecodeString(msg)
		if err != nil {
			http.Error(w, "invalid base64 message", http.StatusBadRequest)
			return
		}
	} else {
		// W19-05: a single r.Body.Read(buf) silently truncated any POST body
		// over the short-read boundary (observed truncating real PKCS#7
		// blobs from sscep/micromdm-scep clients) -- read to completion like
		// est and cmp do. POSTPKIOperation (advertised in GetCACaps) carries
		// the raw binary pkiMessage per RFC 8894 §3.4 -- unlike GET, there is
		// no base64 layer to strip.
		msgBytes, err = io.ReadAll(http.MaxBytesReader(w, r.Body, 64*1024))
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
	}

	outer, err := pkcs7.Parse(msgBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid pkiMessage: %v", err), http.StatusBadRequest)
		return
	}

	txID, senderNonce, ok := transactionAndNonce(outer)
	if !ok {
		http.Error(w, "pkiMessage missing transactionID or senderNonce", http.StatusBadRequest)
		return
	}

	caObj, err := s.caEngine.GetCA(s.caID)
	if err != nil {
		logging.Warnf("scep PKIOperation: CA %s unavailable: %v", s.caID, err)
		http.Error(w, "CA unavailable", http.StatusServiceUnavailable)
		return
	}

	csr, clientCert, msgType, failErr := s.unwrapRequest(outer, txID)
	if failErr != nil {
		logging.Infof("scep PKIOperation: %v", failErr)
		failInfo := failInfoBadRequest
		if errors.Is(failErr, errBadSignature) {
			failInfo = failInfoBadMessageCheck
			if msgType == msgTypeRenewalReq {
				s.emit(r, AuditEvent{Action: "scep.renew", Outcome: "denied", Detail: failErr.Error()})
			}
		}
		s.writeCertRep(w, caObj, txID, senderNonce, pkiStatusFailure, failInfo, nil, nil)
		return
	}

	// An Intune label sends every request, renewals included, through Intune:
	// the hub-native renewal below would skip the challenge check.
	if l := labelFrom(r.Context()); l != nil {
		s.enrollIntune(w, r, caObj, txID, senderNonce, csr, clientCert, l)
		return
	}

	// A signer that is not self-signed is a certificate the client already
	// holds: this is a renewal and ONLY the renewal checks apply. Every
	// refusal inside renew returns; nothing falls through to the challenge
	// path below. A RenewalReq signed by a throwaway self-signed identity has
	// nothing to renew and is refused, never treated as an enrollment.
	if !isSelfSigned(clientCert) {
		s.renew(w, r, caObj, txID, senderNonce, csr, clientCert)
		return
	}
	if msgType == msgTypeRenewalReq {
		s.denyRenewal(w, r, caObj, txID, senderNonce, clientCert, "RenewalReq signed by a self-signed certificate")
		return
	}

	// W23-43: the gate runs before the challenge is claimed, so a denial does
	// not burn a valid one-time challenge. The CSR subject is the only actor
	// known at this point; the gate's verdict does not depend on it.
	if s.enrollGate != nil {
		actor := csr.Subject.CommonName
		if gerr := s.enrollGate(r.Context(), actor); gerr != nil {
			logging.Infof("scep PKIOperation: enrollment gate: %v", gerr)
			s.emit(r, AuditEvent{Action: "scep.enroll", Actor: actor, Outcome: "denied",
				Detail: "template enrollment_permissions: " + gerr.Error()})
			s.writeCertRep(w, caObj, txID, senderNonce, pkiStatusFailure, failInfoBadRequest, nil, nil)
			return
		}
	}

	// The challenge is claimed before issuance, so two requests carrying
	// it cannot both get a certificate; a CA failure after this burns it.
	challenge, err := s.consumeChallenge(r.Context(), csr)
	if err != nil {
		logging.Infof("scep PKIOperation: %v", err)
		s.emit(r, AuditEvent{Action: "scep.enroll", Actor: challenge.CommonName, Outcome: "denied", Detail: err.Error()})
		s.writeCertRep(w, caObj, txID, senderNonce, pkiStatusFailure, failInfoBadRequest, nil, nil)
		return
	}

	// The CSR only proves the key: the names are the challenge's.
	issued, err := s.caEngine.IssueCertificate(s.caID, ca.IssuanceRequest{
		CSR:             csr,
		Subject:         &pkix.Name{CommonName: challenge.CommonName},
		DNSNames:        challenge.DNSNames,
		CallerNamesOnly: true,
		Validity:        365 * 24 * time.Hour,
		KeyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		logging.Warnf("scep PKIOperation: issuance failed: %v", err)
		detail := fmt.Sprintf("challenge %s consumed, issuance failed: %v", challenge.ID, err)
		if errors.Is(err, ca.ErrCARevoked) {
			detail = fmt.Sprintf("challenge %s consumed, ca revoked: %v", challenge.ID, err)
		}
		s.emit(r, AuditEvent{Action: "scep.enroll", Actor: challenge.CommonName, Outcome: "denied", Detail: detail})
		s.writeCertRep(w, caObj, txID, senderNonce, pkiStatusFailure, failInfoBadRequest, nil, nil)
		return
	}
	s.emit(r, AuditEvent{Action: "scep.enroll", Actor: challenge.CommonName, Outcome: "success",
		Detail: fmt.Sprintf("challenge=%s serial=%s subject=%q dns=%s", challenge.ID, issued.Certificate.SerialNumber.Text(16),
			issued.Certificate.Subject.String(), strings.Join(issued.Certificate.DNSNames, ","))})

	// Record into the hub's inventory -- the client already has its
	// certificate in issued above, so a recorder failure must never fail the
	// PKIOperation response; it would hand the client a credential this
	// system then can't undo. Best-effort, logged only (W18-18: previously
	// nothing recorded SCEP issuance at all, matching the gap W18-16 closed
	// for ACME).
	if s.issuedRecorder != nil {
		if err := s.issuedRecorder.RecordIssuedCertificate(r.Context(), s.caID, issued.Certificate, issued.CertPEM, "scep"); err != nil {
			logging.Infof("scep: issued certificate %s not recorded: %v", issued.Fingerprint, err)
		}
	}

	s.writeCertRep(w, caObj, txID, senderNonce, pkiStatusSuccess, "", issued.Certificate, clientCert)
}

// isSelfSigned reports whether cert is a genuine self-signed certificate: the
// subject equals the issuer AND its signature verifies under its own key. A
// certificate that merely claims issuer==subject is not self-signed. The
// signature is checked directly rather than through CheckSignatureFrom, which
// demands CA basic constraints that throwaway SCEP identities do not carry.
func isSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawSubject, cert.RawIssuer) &&
		cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// revocationAdapter lets the optional RevocationChecker satisfy
// ca.RevocationChecker; a nil checker yields nil so the shared check fails closed.
type revocationAdapter struct{ fn RevocationChecker }

func (a revocationAdapter) IsRevoked(serial *big.Int, _ string) (bool, time.Time, int, error) {
	revoked, err := a.fn(serial)
	return revoked, time.Time{}, 0, err
}

// denyRenewal audits a refused renewal and answers a FAILURE CertRep. It is the
// single exit for every renewal refusal.
func (s *Server) denyRenewal(w http.ResponseWriter, r *http.Request, caObj *ca.CA, txID string, nonce []byte, signer *x509.Certificate, reason string) {
	logging.Warnf("scep PKIOperation: renewal refused: %s", reason)
	actor := ""
	if signer != nil {
		actor = signer.Subject.CommonName
	}
	s.emit(r, AuditEvent{Action: "scep.renew", Actor: actor, Outcome: "denied", Detail: reason})
	s.writeCertRep(w, caObj, txID, nonce, pkiStatusFailure, failInfoBadRequest, nil, nil)
}

// renew handles a request signed by a certificate the client already holds
// (RFC 8894 §3.3.1.2). The signer must chain to this CA, be within its
// validity window, and be known unrevoked; no challenge is used or consumed.
// The new certificate takes its names from the signer, which proved them at
// first enrollment, never from the CSR. Every refusal returns through
// denyRenewal; this function never reaches the challenge path.
func (s *Server) renew(w http.ResponseWriter, r *http.Request, caObj *ca.CA, txID string, nonce []byte, csr *x509.CertificateRequest, signer *x509.Certificate) {
	var rev ca.RevocationChecker
	if s.revoked != nil {
		rev = revocationAdapter{fn: s.revoked}
	}
	if err := ca.CheckHubClientCertificate(signer, caObj.Certificate, s.caID, s.now(), rev); err != nil {
		reason := "signer certificate was not issued by this CA"
		var refused *ca.CredentialRefusedError
		if errors.As(err, &refused) {
			reason = refused.Reason
			if refused.Err != nil {
				logging.Infof("scep PKIOperation: renewal check: %v", refused.Err)
			}
		}
		s.denyRenewal(w, r, caObj, txID, nonce, signer, reason)
		return
	}
	if signer.Subject.CommonName == "" && len(signer.DNSNames) == 0 {
		s.denyRenewal(w, r, caObj, txID, nonce, signer, "signer certificate carries no name to renew")
		return
	}

	actor := signer.Subject.CommonName
	if s.enrollGate != nil {
		if gerr := s.enrollGate(r.Context(), actor); gerr != nil {
			s.denyRenewal(w, r, caObj, txID, nonce, signer, "template enrollment_permissions: "+gerr.Error())
			return
		}
	}

	// Same issuance call shape as enrollment; the CSR only proves the key
	// (the same key as the old certificate or a new one -- both allowed).
	issued, err := s.caEngine.IssueCertificate(s.caID, ca.IssuanceRequest{
		CSR:             csr,
		Subject:         &pkix.Name{CommonName: signer.Subject.CommonName},
		DNSNames:        signer.DNSNames,
		CallerNamesOnly: true,
		Validity:        365 * 24 * time.Hour,
		KeyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		reason := fmt.Sprintf("issuance failed: %v", err)
		if errors.Is(err, ca.ErrCARevoked) {
			reason = fmt.Sprintf("ca revoked: %v", err)
		}
		s.denyRenewal(w, r, caObj, txID, nonce, signer, reason)
		return
	}
	s.emit(r, AuditEvent{Action: "scep.renew", Actor: actor, Outcome: "success",
		Detail: fmt.Sprintf("old_serial=%s new_serial=%s subject=%q", signer.SerialNumber.Text(16),
			issued.Certificate.SerialNumber.Text(16), issued.Certificate.Subject.String())})

	if s.issuedRecorder != nil {
		if err := s.issuedRecorder.RecordIssuedCertificate(r.Context(), s.caID, issued.Certificate, issued.CertPEM, "scep"); err != nil {
			logging.Infof("scep: renewed certificate %s not recorded: %v", issued.Fingerprint, err)
		}
	}
	s.writeCertRep(w, caObj, txID, nonce, pkiStatusSuccess, "", issued.Certificate, signer)
}

// unwrapRequest verifies the client's self-signed enrollment envelope and
// decrypts the inner CSR. It returns a non-nil error for any of: wrong
// messageType, unverifiable signature, no single signer, missing decrypter,
// or a CSR that fails to parse/self-verify -- all of which the caller turns
// into a FAILURE CertRep rather than an HTTP error, since the outer message
// parsed fine enough to attribute a transactionID.
func (s *Server) unwrapRequest(outer *pkcs7.PKCS7, txID string) (*x509.CertificateRequest, *x509.Certificate, string, error) {
	var mt asn1.RawValue
	if err := outer.UnmarshalSignedAttribute(oidMessageType, &mt); err != nil {
		return nil, nil, "", fmt.Errorf("txn %s: missing messageType: %w", txID, err)
	}
	msgType := string(mt.Bytes)
	if msgType != msgTypePKCSReq && msgType != msgTypeRenewalReq {
		return nil, nil, msgType, fmt.Errorf("txn %s: unsupported messageType %q (only PKCSReq/19 and RenewalReq/17 are implemented)", txID, msgType)
	}

	// Signature-only verification against the signer certificate embedded in
	// the message: an initial enrollment is signed by a throwaway self-signed
	// identity with no CA to chain to. Whether the signer is acceptable as a
	// renewal credential (chains to this CA, valid, unrevoked) is decided
	// afterwards by renew, never here.
	if err := outer.Verify(); err != nil {
		return nil, nil, msgType, fmt.Errorf("txn %s: %w: %v", txID, errBadSignature, err)
	}

	clientCert := outer.GetOnlySigner()
	if clientCert == nil {
		return nil, nil, msgType, fmt.Errorf("txn %s: pkiMessage must have exactly one signer", txID)
	}

	if s.decrypter == nil {
		return nil, nil, msgType, fmt.Errorf("txn %s: SCEP decryption not configured", txID)
	}
	decrypter, err := s.decrypter()
	if err != nil {
		return nil, nil, msgType, fmt.Errorf("txn %s: resolving CA decrypter: %w", txID, err)
	}

	caObj, err := s.caEngine.GetCA(s.caID)
	if err != nil {
		return nil, nil, msgType, fmt.Errorf("txn %s: CA unavailable: %w", txID, err)
	}

	envelope, err := pkcs7.Parse(outer.Content)
	if err != nil {
		return nil, nil, msgType, fmt.Errorf("txn %s: inner content is not a PKCS#7 envelope: %w", txID, err)
	}
	csrDER, err := envelope.Decrypt(caObj.Certificate, decrypter)
	if err != nil {
		return nil, nil, msgType, fmt.Errorf("txn %s: decrypting envelopedData: %w", txID, err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, msgType, fmt.Errorf("txn %s: invalid CSR: %w", txID, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, msgType, fmt.Errorf("txn %s: invalid CSR signature: %w", txID, err)
	}

	return csr, clientCert, msgType, nil
}

// writeCertRep builds and sends the CertRep pkiMessage. On failure (status
// != SUCCESS) issuedCert/clientCert are nil and the response carries no
// envelopedData -- there is nothing to encrypt and no client cert may even
// be available (a parse failure inside unwrapRequest can precede getting
// one).
func (s *Server) writeCertRep(w http.ResponseWriter, caObj *ca.CA, txID string, recipientNonce []byte, status, failInfo string, issuedCert, clientCert *x509.Certificate) {
	body, err := s.buildCertRep(caObj, txID, recipientNonce, status, failInfo, issuedCert, clientCert)
	if err != nil {
		logging.Warnf("scep: building CertRep failed: %v", err)
		http.Error(w, "internal error building CertRep", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-pki-message")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

// buildCertRep signs a CertRep over the CA's own key. For SUCCESS it
// encrypts a degenerate certs-only PKCS#7 (containing just the issued leaf)
// to the requesting client's self-signed certificate, matching RFC 8894
// §3.3's "SUCCESS -> degenerate SignedData wrapped in EnvelopedData" shape.
func (s *Server) buildCertRep(caObj *ca.CA, txID string, recipientNonce []byte, status, failInfo string, issuedCert, clientCert *x509.Certificate) ([]byte, error) {
	caSigner, err := s.caSignerFor(caObj)
	if err != nil {
		return nil, err
	}

	var content []byte
	if status == pkiStatusSuccess {
		degenerate, err := pkcs7.DegenerateCertificate(issuedCert.Raw)
		if err != nil {
			return nil, fmt.Errorf("building degenerate certs-only message: %w", err)
		}
		content, err = pkcs7.Encrypt(degenerate, []*x509.Certificate{clientCert})
		if err != nil {
			return nil, fmt.Errorf("encrypting CertRep to client cert: %w", err)
		}
	}

	sd, err := pkcs7.NewSignedData(content)
	if err != nil {
		return nil, err
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)

	respNonce := make([]byte, 16)
	if _, err := rand.Read(respNonce); err != nil {
		return nil, fmt.Errorf("generating response senderNonce: %w", err)
	}

	extra := []pkcs7.Attribute{
		{Type: oidMessageType, Value: asn1.RawValue{Tag: 19, Bytes: []byte(msgTypeCertRep)}},
		{Type: oidPKIStatus, Value: asn1.RawValue{Tag: 19, Bytes: []byte(status)}},
		{Type: oidTransactionID, Value: asn1.RawValue{Tag: 19, Bytes: []byte(txID)}},
		{Type: oidSenderNonce, Value: asn1.RawValue{Tag: 4, Bytes: respNonce}},
		{Type: oidRecipientNonce, Value: asn1.RawValue{Tag: 4, Bytes: recipientNonce}},
	}
	if status == pkiStatusFailure {
		extra = append(extra, pkcs7.Attribute{Type: oidFailInfo, Value: asn1.RawValue{Tag: 19, Bytes: []byte(failInfo)}})
	}

	if err := sd.AddSigner(caObj.Certificate, caSigner, pkcs7.SignerInfoConfig{ExtraSignedAttributes: extra}); err != nil {
		return nil, fmt.Errorf("signing CertRep with CA key: %w", err)
	}
	return sd.Finish()
}

// caSignerFor resolves a crypto.Signer for the CA's own key so buildCertRep
// can sign the CertRep response -- separate from s.decrypter (crypto.
// Decrypter), which unwraps the inbound request instead.
func (s *Server) caSignerFor(caObj *ca.CA) (crypto.Signer, error) {
	if s.decrypter == nil {
		return nil, fmt.Errorf("SCEP signer not configured")
	}
	dec, err := s.decrypter()
	if err != nil {
		return nil, err
	}
	signer, ok := dec.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("SCEP CA key backend does not support signing (crypto.Signer)")
	}
	return signer, nil
}

// transactionAndNonce extracts the two attributes every well-formed SCEP
// request must carry, regardless of whether the message later fails
// signature/decrypt/challenge checks -- needed to attribute a FAILURE
// CertRep back to the right transaction.
func transactionAndNonce(p7 *pkcs7.PKCS7) (txID string, nonce []byte, ok bool) {
	var txRaw, nonceRaw asn1.RawValue
	if err := p7.UnmarshalSignedAttribute(oidTransactionID, &txRaw); err != nil {
		return "", nil, false
	}
	if err := p7.UnmarshalSignedAttribute(oidSenderNonce, &nonceRaw); err != nil {
		return "", nil, false
	}
	return string(txRaw.Bytes), nonceRaw.Bytes, true
}

// consumeChallenge claims the one-time challenge in the CSR's PKCS#9
// challengePassword (RFC 2985 §5.4.1). SCEP carries it inside the PKCS#10,
// not as a CMS signed attribute; Go's x509.CertificateRequest.Attributes
// drops it, so challengePasswordFromCSR re-parses the raw attributes. The
// store is looked up by the secret's hash, so no constant-time compare is
// needed here. The returned Challenge names the bound CN even on some
// refusals, for the audit row.
func (s *Server) consumeChallenge(ctx context.Context, csr *x509.CertificateRequest) (Challenge, error) {
	if s.challenges == nil {
		return Challenge{}, errors.New("no challenge store configured")
	}
	secret, ok := challengePasswordFromCSR(csr)
	if !ok || secret == "" {
		return Challenge{}, errors.New("CSR carries no challengePassword")
	}
	c, err := s.challenges.Consume(ctx, secret, s.now())
	if err != nil {
		return Challenge{}, err
	}
	if c.CAID != s.caID {
		return c, fmt.Errorf("challenge %s was minted for CA %s, not this SCEP CA", c.ID, c.CAID)
	}
	return c, nil
}

// tbsCertificateRequestAttrs mirrors crypto/x509's private tbsCertificateRequest
// shape (RFC 2986 CertificationRequestInfo) just far enough to reach the
// raw attributes SET -- Subject/PublicKey are left as opaque RawValues
// since only Attributes is needed here.
type tbsCertificateRequestAttrs struct {
	Raw           asn1.RawContent
	Version       int
	Subject       asn1.RawValue
	PublicKey     asn1.RawValue
	RawAttributes []asn1.RawValue `asn1:"tag:0"`
}

// pkcs10Attribute is RFC 2986 §4.1's Attribute: { type OID, values SET OF AttributeValue }.
type pkcs10Attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

func challengePasswordFromCSR(csr *x509.CertificateRequest) (string, bool) {
	var tbs tbsCertificateRequestAttrs
	if _, err := asn1.Unmarshal(csr.RawTBSCertificateRequest, &tbs); err != nil {
		return "", false
	}
	for _, rawAttr := range tbs.RawAttributes {
		var attr pkcs10Attribute
		if rest, err := asn1.Unmarshal(rawAttr.FullBytes, &attr); err != nil || len(rest) != 0 || len(attr.Values) == 0 {
			continue
		}
		if !attr.Type.Equal(oidChallengePassword) {
			continue
		}
		return string(attr.Values[0].Bytes), true
	}
	return "", false
}
