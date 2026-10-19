// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package cmp

import (
	"context"
	"crypto/hmac"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"kryptkeeper/internal/logging"
	"net"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/ca"
)

// CMP message types per RFC 4210 §5.1.
const (
	PKIBodyIR       = 0  // Initialization Request
	PKIBodyIP       = 1  // Initialization Response
	PKIBodyCR       = 2  // Certification Request
	PKIBodyCP       = 3  // Certification Response
	PKIBodyKUR      = 7  // Key Update Request
	PKIBodyKUP      = 8  // Key Update Response
	PKIBodyRR       = 11 // Revocation Request
	PKIBodyRP       = 12 // Revocation Response
	PKIBodyPKIConf  = 19 // Confirmation
	PKIBodyGenM     = 21 // General message (unsupported)
	PKIBodyError    = 23 // Error
	PKIBodyCertConf = 24 // Certificate confirm
	PKIBodyPollReq  = 25 // Polling request
	PKIBodyPollRep  = 26 // Polling response
)

// AuditEvent is one CMP outcome. Action is cmp.ir|cr|kur|rr|poll|reject;
// Actor is the request's senderKID; Outcome is success, denied, failure or
// pending_approval.
type AuditEvent struct {
	Action   string
	Actor    string
	Outcome  string
	SourceIP string
	Detail   string
}

// AuditFunc records an AuditEvent; main adapts it to the hub's audit log.
type AuditFunc func(ctx context.Context, ev AuditEvent)

// AlertFunc raises a security alert (kind "cmp.replay"); main adapts it.
type AlertFunc func(ctx context.Context, kind string, detail map[string]string)

// Server implements the Certificate Management Protocol per RFC 4210.
type Server struct {
	caEngine  ca.Service
	caID      string
	secret    []byte // RFC 4210 §5.1.3.1 shared secret (KRYPTKEEPER_CMP_SECRET)
	reference []byte // senderKID identifying the secret (KRYPTKEEPER_CMP_REFERENCE)
	// issuedRecorder writes each issued certificate into the hub's inventory
	// (see ca.IssuedCertificateRecorder). Nil means "not recorded" -- every
	// existing caller and test that builds a Server without
	// WithIssuedRecorder keeps working unchanged. handleCertRequest is the
	// single issuance path shared by IR, CR and key-update (KUR routes here
	// via handleKeyUpdate), so recording there covers all three.
	issuedRecorder ca.IssuedCertificateRecorder
	// replay rejects a reused transactionID+senderNonce (SUP-A04-2). Per
	// process and in memory; see replay.go for the window and its limits.
	replay *replayCache
	// allowedDNSSuffixes, when set, binds this client's secret to those
	// zones: names the certTemplate asks for are issued only if they match
	// (CallerNamesOnly semantics). Empty keeps the old "any name" behaviour.
	allowedDNSSuffixes []string

	// credentials, when set, supplies per-client PBM secrets and trust
	// anchors (W26-09). The env secret above stays valid beside it.
	credentials CredentialStore

	audit    AuditFunc
	alert    AlertFunc
	revoker  Revoker
	approver Approver
	pending  *pendingStore
	pollTTL  time.Duration
	now      func() time.Time
}

// NewServer creates a CMP server. secret is the RFC 4210 §5.1.3.1
// PasswordBasedMac shared secret and reference is the senderKID a client
// names it by (openssl's -secret/-ref); both are required for a message to
// be accepted (W19-16 — previously nothing checked message protection at
// all). See cmd/kryptkeeper/main.go for how these are sourced from env.
func NewServer(caEngine ca.Service, caID, secret, reference string) *Server {
	return &Server{
		caEngine:  caEngine,
		caID:      caID,
		secret:    []byte(secret),
		reference: []byte(reference),
		replay:    newReplayCache(replayMaxEntries, replayWindow),
		pending:   newPendingStore(),
		pollTTL:   defaultPollTTL,
		now:       time.Now,
	}
}

// WithAuditFunc wires the audit sink. Nil (the default) records nothing.
func (s *Server) WithAuditFunc(f AuditFunc) *Server {
	s.audit = f
	return s
}

// WithAlertFunc wires the alert sink for replayed transactions.
func (s *Server) WithAlertFunc(f AlertFunc) *Server {
	s.alert = f
	return s
}

// WithRevoker enables rr. Without it rr answers badRequest.
func (s *Server) WithRevoker(r Revoker) *Server {
	s.revoker = r
	return s
}

// WithApprover enables deferred issuance: when the approver says approval is
// needed, ir/cr/kur answer status waiting and the client polls.
func (s *Server) WithApprover(a Approver) *Server {
	s.approver = a
	return s
}

// WithPollTTL sets how long a waiting transaction stays pollable.
func (s *Server) WithPollTTL(d time.Duration) *Server {
	if d > 0 {
		s.pollTTL = d
	}
	return s
}

func (s *Server) emit(ctx context.Context, r *http.Request, msg *parsedMessage, action, outcome, detail string) {
	if s.audit == nil {
		return
	}
	s.audit(ctx, AuditEvent{Action: action, Actor: string(msg.Header.SenderKID), Outcome: outcome, SourceIP: sourceIP(r), Detail: detail})
}

func sourceIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// WithAllowedDNSSuffixes limits the names an authenticated client may obtain
// (SUP-A04-2): there is one shared secret and one reference, so the binding
// is per server, not per client. Suffix syntax is that of ca.NamePolicy.
func (s *Server) WithAllowedDNSSuffixes(suffixes []string) *Server {
	s.allowedDNSSuffixes = nil
	for _, sfx := range suffixes {
		if sfx = strings.TrimSpace(sfx); sfx != "" {
			s.allowedDNSSuffixes = append(s.allowedDNSSuffixes, sfx)
		}
	}
	return s
}

// WithIssuedRecorder wires an IssuedCertificateRecorder into the server and
// returns it for chaining. Leaving it unset (nil) is a valid, tested
// configuration: certificate requests simply are not recorded.
func (s *Server) WithIssuedRecorder(r ca.IssuedCertificateRecorder) *Server {
	s.issuedRecorder = r
	return s
}

// Handler returns an http.Handler for CMP over HTTP (RFC 6712).
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 128*1024))
		if err != nil {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}

		msg, err := parsePKIMessage(body)
		if err != nil {
			logging.Infof("cmp: parse error: %v", err)
			http.Error(w, "invalid CMP message", http.StatusBadRequest)
			return
		}

		// RFC 4210 §5.1.3: every request must carry valid message protection
		// before any body-specific processing happens. This is the gate
		// W19-16 added — previously nothing here checked protection at all,
		// so any anonymous POST that satisfied CSR extraction was issued a
		// certificate with zero authentication.
		cred := s.credFor(r.Context(), msg.Header)
		msg.cred = cred
		if len(cred.secret) == 0 && s.credentials != nil {
			// Credentials-only mode and an unknown or revoked reference: there
			// is no secret to verify against, and an empty one must never
			// authenticate. Same answer as any MAC failure.
			logging.Infof("cmp: rejecting request: no active credential for the senderKID")
			s.writeError(w, cred, msg.Header, "badMessageCheck: MAC mismatch")
			return
		}
		if protErr := verifyPBMProtection(&msg.Header, msg.Protection, msg.BodyRaw.FullBytes, cred.secret); protErr != nil {
			logging.Infof("cmp: rejecting unprotected/invalid request: %v", protErr)
			s.writeError(w, cred, msg.Header, protErr.Error())
			return
		}

		// The MAC proves knowledge of the secret; the senderKID must also name
		// the configured reference, so a key identifier is not decorative.
		// Same answer as a MAC failure so the two are not distinguishable.
		if len(cred.reference) > 0 && !hmac.Equal(msg.Header.SenderKID, cred.reference) {
			logging.Infof("cmp: rejecting request: senderKID does not match the configured reference")
			s.writeError(w, cred, msg.Header, "badMessageCheck: MAC mismatch")
			return
		}
		// Only authenticated messages are recorded, so unauthenticated junk
		// cannot fill the cache.
		if !s.replay.firstUse(msg.Header.TransactionID, msg.Header.SenderNonce) {
			logging.Infof("cmp: rejecting request: transactionID/senderNonce missing or already used")
			s.emit(r.Context(), r, msg, "cmp.reject", "denied", "replayed transaction")
			if s.alert != nil {
				s.alert(r.Context(), "cmp.replay", map[string]string{
					"transaction_id": hex.EncodeToString(msg.Header.TransactionID),
					"source_ip":      sourceIP(r),
				})
			}
			s.writeErrorFail(w, msg.cred, msg.Header, "badRequest: transactionID and senderNonce must be present and not reused", failBadRequest)
			return
		}

		switch msg.BodyType {
		case PKIBodyIR, PKIBodyCR:
			s.handleCertRequest(w, r, msg, msg.BodyType)
		case PKIBodyKUR:
			s.handleCertRequest(w, r, msg, PKIBodyKUR)
		case PKIBodyCertConf:
			s.handleCertConf(w, r, msg)
		case PKIBodyRR:
			s.handleRevoke(w, r, msg)
		case PKIBodyPollReq:
			s.handlePollReq(w, r, msg)
		default:
			// genm (21) and anything else.
			text := fmt.Sprintf("unsupported CMP body type: %d", msg.BodyType)
			s.emit(r.Context(), r, msg, "cmp.reject", "denied", text)
			s.writeErrorFail(w, msg.cred, msg.Header, text, failBadRequest)
		}
	})
}

func (s *Server) handleCertRequest(w http.ResponseWriter, r *http.Request, msg *parsedMessage, reqBodyType int) {
	action := certAction(reqBodyType)

	reqs, err := parseCertReqMessages(msg.BodyBytes)
	if err != nil {
		logging.Infof("cmp: CertReqMessages rejected: %v", err)
		s.emit(r.Context(), r, msg, action, "denied", "malformed request")
		s.writeError(w, msg.cred, msg.Header, err.Error())
		return
	}
	// A real CMP client sends one CertReqMsg per ir/cr/kur; issuing exactly
	// that one keeps the response shape (single CertResponse) simple and
	// matches what openssl cmp expects back.
	req := reqs[0]

	issuanceReq, refusal := s.buildIssuanceRequest(req.CSR, msg.cred.suffixes)
	if refusal != "" {
		s.emit(r.Context(), r, msg, action, "denied", refusal)
		s.writeError(w, msg.cred, msg.Header, refusal)
		return
	}

	if s.approver != nil {
		needs, err := s.approver.Needs(r.Context())
		if err != nil {
			logging.Warnf("cmp: approval check failed: %v", err)
			s.emit(r.Context(), r, msg, action, "failure", "approval check failed")
			s.writeErrorFail(w, msg.cred, msg.Header, "approval check failed", failSystemFailure)
			return
		}
		if needs {
			s.deferIssuance(w, r, msg, reqBodyType, req)
			return
		}
	}
	s.issue(w, r, msg.cred, msg.Header, string(msg.Header.SenderKID), reqBodyType, req, issuanceReq)
}

func certAction(reqBodyType int) string {
	switch reqBodyType {
	case PKIBodyIR:
		return "cmp.ir"
	case PKIBodyKUR:
		return "cmp.kur"
	default:
		return "cmp.cr"
	}
}

// buildIssuanceRequest applies the key-strength and DNS-suffix checks and
// returns the CA request, or a client-safe refusal text.
func (s *Server) buildIssuanceRequest(csr *x509.CertificateRequest, suffixes []string) (ca.IssuanceRequest, string) {
	if err := ca.CheckPublicKeyStrength(csr.PublicKey); err != nil {
		logging.Infof("cmp: weak key rejected: %v", err)
		return ca.IssuanceRequest{}, "key too weak: " + err.Error()
	}

	issuanceReq := ca.IssuanceRequest{
		CSR:         csr,
		Validity:    365 * 24 * time.Hour,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if len(suffixes) > 0 {
		if reason := nameBindingViolation(csr, suffixes); reason != "" {
			logging.Warnf("cmp: names refused by the DNS suffix binding: %s", reason)
			return ca.IssuanceRequest{}, "requested name is not permitted for this client"
		}
		// Only the names just checked are signed.
		issuanceReq.DNSNames = csr.DNSNames
		issuanceReq.CallerNamesOnly = true
	}
	return issuanceReq, ""
}

// issue signs the certificate and answers with the protected ip/cp/kup. It is
// the single issuance path: immediate ir/cr/kur and an approved pollReq both
// end here, so recording and auditing cover both.
func (s *Server) issue(w http.ResponseWriter, r *http.Request, cred credCtx, hdr parsedHeader, actor string, reqBodyType int, req crmfRequest, issuanceReq ca.IssuanceRequest) {
	action := certAction(reqBodyType)
	audit := func(outcome, detail string) {
		if s.audit != nil {
			s.audit(r.Context(), AuditEvent{Action: action, Actor: actor, Outcome: outcome, SourceIP: sourceIP(r), Detail: detail})
		}
	}

	issuerID, rerr := ca.ResolveCAID(s.caEngine, s.caID)
	if rerr != nil {
		logging.Warnf("cmp: %v", rerr)
		audit("failure", rerr.Error())
		msg := "certificate issuance failed"
		if errors.Is(rerr, ca.ErrNoCAConfigured) {
			msg = rerr.Error()
		}
		s.writeError(w, cred, hdr, msg)
		return
	}
	issued, err := s.caEngine.IssueCertificate(issuerID, issuanceReq)
	if err != nil {
		logging.Warnf("cmp: issuance failed: %v", err)
		if errors.Is(err, ca.ErrCARevoked) {
			audit("denied", "issuing CA revoked")
			s.writeError(w, cred, hdr, "issuing CA revoked")
			return
		}
		audit("failure", "certificate issuance failed")
		s.writeError(w, cred, hdr, "certificate issuance failed")
		return
	}

	// Record into the hub's inventory -- the client already has its
	// certificate in issued above, so a recorder failure must never fail the
	// PKIMessage response; it would hand the client a credential this system
	// then can't undo. Best-effort, logged only (W18-18: previously nothing
	// recorded CMP issuance at all, matching the gap W18-16 closed for ACME).
	// This path is shared by IR, CR and KUR (and an approved pollReq), so all
	// record here.
	if s.issuedRecorder != nil {
		if err := s.issuedRecorder.RecordIssuedCertificate(r.Context(), s.activeCAID(), issued.Certificate, issued.CertPEM, "cmp"); err != nil {
			logging.Infof("cmp: issued certificate %s not recorded: %v", issued.Fingerprint, err)
		}
	}

	pkiMsg, err := buildCertResponse(issued.Certificate, req.CertReqID, responseBodyType(reqBodyType), hdr, cred.secret, cred.reference)
	if err != nil {
		logging.Warnf("cmp: build PKIMessage failed: %v", err)
		audit("failure", "certificate response encoding failed")
		s.writeError(w, cred, hdr, "certificate response encoding failed")
		return
	}

	audit("success", "serial="+issued.Certificate.SerialNumber.Text(16))
	s.write(w, pkiMsg)
}

// nameBindingViolation returns why csr's names fall outside the configured
// DNS suffixes, or "". The CN is checked too: it is not a SAN but relying
// parties still read it.
func nameBindingViolation(csr *x509.CertificateRequest, suffixes []string) string {
	for _, d := range csr.DNSNames {
		if !ca.DNSNameMatchesSuffixes(d, suffixes) {
			return fmt.Sprintf("DNS name %q", d)
		}
	}
	if len(csr.IPAddresses) > 0 || len(csr.URIs) > 0 {
		return "IP or URI SAN (only DNS names can match a DNS suffix)"
	}
	if cn := strings.TrimSpace(csr.Subject.CommonName); cn != "" && !ca.DNSNameMatchesSuffixes(cn, suffixes) {
		return fmt.Sprintf("subject CN %q", cn)
	}
	return ""
}

// handleCertConf answers a client's certConf (body type 24, sent after ir/cr
// unless -disable_confirm) with a protected pkiconf (body type 19) per
// RFC 4210 §5.3.20 -- openssl cmp waits for this before considering the
// enrollment transaction complete. A CertStatus whose statusInfo is neither
// accepted (0) nor grantedWithMods (1) means the client refused the
// certificate: that is audited (cmp.reject) but not acted on (no auto-revoke),
// and pkiconf is still returned.
func (s *Server) handleCertConf(w http.ResponseWriter, r *http.Request, msg *parsedMessage) {
	var statuses []struct {
		CertHash   []byte
		CertReqID  int
		StatusInfo pkiStatusInfo `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(msg.BodyBytes, &statuses); err != nil {
		logging.Infof("cmp: certConf not parsed (still confirming): %v", err)
	}
	for _, st := range statuses {
		if st.StatusInfo.Status != 0 && st.StatusInfo.Status != 1 {
			s.emit(r.Context(), r, msg, "cmp.reject", "denied", fmt.Sprintf("client rejected certificate certReqId=%d", st.CertReqID))
		}
	}

	pkiMsg, err := buildPKIConf(msg.Header, msg.cred.secret, msg.cred.reference)
	if err != nil {
		logging.Warnf("cmp: build pkiconf failed: %v", err)
		s.writeError(w, msg.cred, msg.Header, "pkiconf encoding failed")
		return
	}
	s.write(w, pkiMsg)
}

func (s *Server) writeError(w http.ResponseWriter, cred credCtx, hdr parsedHeader, statusText string) {
	s.writeErrorFail(w, cred, hdr, statusText, failBadMessageCheck)
}

// writeErrorFail answers with a protected error carrying PKIFailureInfo bit
// failBit.
func (s *Server) writeErrorFail(w http.ResponseWriter, cred credCtx, hdr parsedHeader, statusText string, failBit int) {
	pkiMsg, err := buildErrorResponseFail(hdr, statusText, failBit, cred.secret, cred.reference)
	if err != nil {
		logging.Warnf("cmp: build error response failed: %v", err)
		http.Error(w, "invalid CMP message", http.StatusBadRequest)
		return
	}
	s.write(w, pkiMsg)
}

func (s *Server) write(w http.ResponseWriter, pkiMsg []byte) {
	w.Header().Set("Content-Type", "application/pkixcmp")
	w.WriteHeader(http.StatusOK)
	w.Write(pkiMsg)
}

// responseBodyType maps a request body type to its RFC 4210 §5.1 response
// counterpart: ir->ip, kur->kup, cr (and anything else routed here)->cp.
// W19-05: a real openssl `cmp -cmd kur` request was previously answered with
// cp (a Certification Response) instead of kup, which openssl's CMP client
// rejects as a transfer-error mismatch (expected KUP, got CP).
func responseBodyType(reqBodyType int) int {
	switch reqBodyType {
	case PKIBodyIR:
		return PKIBodyIP
	case PKIBodyKUR:
		return PKIBodyKUP
	default:
		return PKIBodyCP
	}
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
