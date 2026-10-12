// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package cmp

import (
	"crypto/hmac"
	"crypto/x509"
	"fmt"
	"io"
	"log"
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
	PKIBodyError    = 23 // Error
	PKIBodyCertConf = 24 // Certificate confirm
)

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
	}
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
			log.Printf("cmp: parse error: %v", err)
			http.Error(w, "invalid CMP message", http.StatusBadRequest)
			return
		}

		// RFC 4210 §5.1.3: every request must carry valid message protection
		// before any body-specific processing happens. This is the gate
		// W19-16 added — previously nothing here checked protection at all,
		// so any anonymous POST that satisfied CSR extraction was issued a
		// certificate with zero authentication.
		if protErr := verifyPBMProtection(&msg.Header, msg.Protection, msg.BodyRaw.FullBytes, s.secret); protErr != nil {
			log.Printf("cmp: rejecting unprotected/invalid request: %v", protErr)
			s.writeError(w, msg.Header, protErr.Error())
			return
		}

		// The MAC proves knowledge of the secret; the senderKID must also name
		// the configured reference, so a key identifier is not decorative.
		// Same answer as a MAC failure so the two are not distinguishable.
		if len(s.reference) > 0 && !hmac.Equal(msg.Header.SenderKID, s.reference) {
			log.Printf("cmp: rejecting request: senderKID does not match the configured reference")
			s.writeError(w, msg.Header, "badMessageCheck: MAC mismatch")
			return
		}
		// Only authenticated messages are recorded, so unauthenticated junk
		// cannot fill the cache.
		if !s.replay.firstUse(msg.Header.TransactionID, msg.Header.SenderNonce) {
			log.Printf("cmp: rejecting request: transactionID/senderNonce missing or already used")
			s.writeError(w, msg.Header, "badRequest: transactionID and senderNonce must be present and not reused")
			return
		}

		switch msg.BodyType {
		case PKIBodyIR, PKIBodyCR:
			s.handleCertRequest(w, r, msg, msg.BodyType)
		case PKIBodyKUR:
			s.handleCertRequest(w, r, msg, PKIBodyKUR)
		case PKIBodyCertConf:
			s.handleCertConf(w, msg)
		default:
			s.writeError(w, msg.Header, fmt.Sprintf("unsupported CMP body type: %d", msg.BodyType))
		}
	})
}

func (s *Server) handleCertRequest(w http.ResponseWriter, r *http.Request, msg *parsedMessage, reqBodyType int) {
	respBodyType := responseBodyType(reqBodyType)

	reqs, err := parseCertReqMessages(msg.BodyBytes)
	if err != nil {
		log.Printf("cmp: CertReqMessages rejected: %v", err)
		s.writeError(w, msg.Header, err.Error())
		return
	}
	// A real CMP client sends one CertReqMsg per ir/cr/kur; issuing exactly
	// that one keeps the response shape (single CertResponse) simple and
	// matches what openssl cmp expects back.
	csr := reqs[0].CSR

	if err := ca.CheckPublicKeyStrength(csr.PublicKey); err != nil {
		log.Printf("cmp: weak key rejected: %v", err)
		s.writeError(w, msg.Header, "key too weak: "+err.Error())
		return
	}

	issuanceReq := ca.IssuanceRequest{
		CSR:         csr,
		Validity:    365 * 24 * time.Hour,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if len(s.allowedDNSSuffixes) > 0 {
		if reason := s.nameBindingViolation(csr); reason != "" {
			log.Printf("cmp: names refused by the DNS suffix binding: %s", reason)
			s.writeError(w, msg.Header, "requested name is not permitted for this client")
			return
		}
		// Only the names just checked are signed.
		issuanceReq.DNSNames = csr.DNSNames
		issuanceReq.CallerNamesOnly = true
	}
	issued, err := s.caEngine.IssueCertificate(s.caID, issuanceReq)
	if err != nil {
		log.Printf("cmp: issuance failed: %v", err)
		s.writeError(w, msg.Header, "certificate issuance failed")
		return
	}

	// Record into the hub's inventory -- the client already has its
	// certificate in issued above, so a recorder failure must never fail the
	// PKIMessage response; it would hand the client a credential this system
	// then can't undo. Best-effort, logged only (W18-18: previously nothing
	// recorded CMP issuance at all, matching the gap W18-16 closed for ACME).
	// This path is shared by IR, CR and KUR (handleKeyUpdate delegates here),
	// so all three record here.
	if s.issuedRecorder != nil {
		if err := s.issuedRecorder.RecordIssuedCertificate(r.Context(), s.caID, issued.Certificate, issued.CertPEM, "cmp"); err != nil {
			log.Printf("cmp: issued certificate %s not recorded: %v", issued.Fingerprint, err)
		}
	}

	pkiMsg, err := buildCertResponse(issued.Certificate, respBodyType, msg.Header, s.secret, s.reference)
	if err != nil {
		log.Printf("cmp: build PKIMessage failed: %v", err)
		s.writeError(w, msg.Header, "certificate response encoding failed")
		return
	}

	s.write(w, pkiMsg)
}

// nameBindingViolation returns why csr's names fall outside the configured
// DNS suffixes, or "". The CN is checked too: it is not a SAN but relying
// parties still read it.
func (s *Server) nameBindingViolation(csr *x509.CertificateRequest) string {
	for _, d := range csr.DNSNames {
		if !ca.DNSNameMatchesSuffixes(d, s.allowedDNSSuffixes) {
			return fmt.Sprintf("DNS name %q", d)
		}
	}
	if len(csr.IPAddresses) > 0 || len(csr.URIs) > 0 {
		return "IP or URI SAN (only DNS names can match a DNS suffix)"
	}
	if cn := strings.TrimSpace(csr.Subject.CommonName); cn != "" && !ca.DNSNameMatchesSuffixes(cn, s.allowedDNSSuffixes) {
		return fmt.Sprintf("subject CN %q", cn)
	}
	return ""
}

// handleCertConf answers a client's certConf (body type 24, sent after ir/cr
// unless -disable_confirm) with a protected pkiconf (body type 19) per
// RFC 4210 §5.3.20 -- openssl cmp waits for this before considering the
// enrollment transaction complete.
func (s *Server) handleCertConf(w http.ResponseWriter, msg *parsedMessage) {
	pkiMsg, err := buildPKIConf(msg.Header, s.secret, s.reference)
	if err != nil {
		log.Printf("cmp: build pkiconf failed: %v", err)
		s.writeError(w, msg.Header, "pkiconf encoding failed")
		return
	}
	s.write(w, pkiMsg)
}

func (s *Server) writeError(w http.ResponseWriter, hdr parsedHeader, statusText string) {
	pkiMsg, err := buildErrorResponse(hdr, statusText, s.secret, s.reference)
	if err != nil {
		log.Printf("cmp: build error response failed: %v", err)
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
