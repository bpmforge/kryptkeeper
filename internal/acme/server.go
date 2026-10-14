// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/metrics"
)

// Server is an ACME protocol server per RFC 8555.
type Server struct {
	baseURL   string
	caEngine  ca.Service
	caID      string // default CA for ACME issuance
	nonces    *NonceService
	store     Store
	eabConfig eabConfig // W4-04: External Account Binding posture (APP_ACME_EAB_*)
	// lookupTXT resolves dns-01 records; nil is the system resolver.
	lookupTXT func(name string) ([]string, error)
	// http01Dial is the test-only dial override; nil uses the guarded dialer.
	http01Dial http01Dial
	// revoked tracks ACME-level certificate revocation (RFC 8555 §7.6),
	// keyed by certFingerprint. Server-local like NonceService: it answers
	// the alreadyRevoked idempotency check without a revStore round-trip and
	// needs no CA resolution (fingerprint alone identifies the cert). W1-09/
	// G-45 stopped here; W1-14/G-91 forwards each revocation to revStore
	// (below) too, since this map alone never reached OCSP/CRL.
	revoked map[string]revocationRecord
	// revStore is the downstream ca.RevocationStore that OCSP
	// (internal/ocsp) and CRL (internal/crl) actually query. Nil-safe: a nil
	// revStore (e.g. NewServer, or tests that don't need OCSP/CRL parity)
	// leaves revocation ACME-protocol-local, matching pre-W1-14 behavior.
	revStore ca.RevocationStore
	// issuedRecorder writes each finalized certificate into the hub's
	// inventory (see IssuedCertificateRecorder). Nil means "not recorded" —
	// the pre-W18-16 behavior, and every existing test that builds a Server
	// without WithIssuedRecorder keeps working unchanged.
	issuedRecorder IssuedCertificateRecorder
	// ocspInvalidator tells a live OCSP responder that a just-revoked
	// serial's cached "good" response is stale (W19-01: internal/ocsp.Responder
	// caches per-serial for its full validity window and had no invalidation
	// hook wired anywhere, so a real client's revoke never showed up in OCSP
	// until the cache aged out). Nil means "not wired" -- handleRevokeCert
	// still updates revStore and the ACME-local map exactly as before.
	ocspInvalidator ca.RevocationCacheInvalidator
	mu              sync.Mutex // guards multi-step state transitions (challenge, finalize, key-change)
}

// IssuedCertificateRecorder persists a certificate issued through this ACME
// server into the hub's certificate inventory. W18-18 promoted the
// definition to internal/ca (see ca.IssuedCertificateRecorder) so EST, SCEP
// and CMP share it too; this alias keeps every existing acme caller and test
// working unchanged.
type IssuedCertificateRecorder = ca.IssuedCertificateRecorder

// revocationRecord is the ACME-level revocation state for one certificate.
type revocationRecord struct {
	RevokedAt  time.Time
	ReasonCode int
}

// NewServer creates an ACME server backed by an in-memory store. Revocation
// stays ACME-protocol-local (no revStore); use NewServerWithStore to wire
// one in.
func NewServer(baseURL string, caEngine ca.Service, caID string) *Server {
	return NewServerWithStore(baseURL, caEngine, caID, NewMemStore(), nil)
}

// NewServerWithStore creates an ACME server backed by the provided Store.
// EAB posture (APP_ACME_EAB_REQUIRED, APP_ACME_EAB_KEYS_JSON) is read from the
// environment; a malformed config is logged and treated as EAB-disabled
// rather than failing construction (matches the store-fallback convention
// used elsewhere in main.go). revStore may be nil, in which case
// handleRevokeCert only records revocation in the server-local s.revoked map
// (W1-14/G-91).
func NewServerWithStore(baseURL string, caEngine ca.Service, caID string, store Store, revStore ca.RevocationStore) *Server {
	cfg, err := eabConfigFromEnv()
	if err != nil {
		log.Printf("warning: ACME EAB config invalid (%v) — EAB disabled", err)
		cfg = eabConfig{}
	} else if err := seedEABKeys(store, cfg.seedKeys); err != nil {
		log.Printf("warning: ACME EAB key seeding failed (%v)", err)
	}
	return &Server{
		baseURL:   strings.TrimRight(baseURL, "/"),
		caEngine:  caEngine,
		caID:      caID,
		nonces:    NewNonceService(10000),
		store:     store,
		eabConfig: cfg,
		revoked:   make(map[string]revocationRecord),
		revStore:  revStore,
	}
}

// WithIssuedRecorder wires an IssuedCertificateRecorder into the server and
// returns it for chaining. Leaving it unset (nil) is a valid, tested
// configuration: finalize simply does not record.
func (s *Server) WithIssuedRecorder(r IssuedCertificateRecorder) *Server {
	s.issuedRecorder = r
	return s
}

// WithOCSPCacheInvalidator wires a RevocationCacheInvalidator into the
// server and returns it for chaining. Leaving it unset (nil) is a valid,
// tested configuration: handleRevokeCert still revokes via revStore exactly
// as before, it just can't clear a live OCSP responder's cache for the
// serial it just revoked.
func (s *Server) WithOCSPCacheInvalidator(inv ca.RevocationCacheInvalidator) *Server {
	s.ocspInvalidator = inv
	return s
}

// Handler returns an http.Handler for all ACME endpoints.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/acme/directory", s.handleDirectory)
	mux.HandleFunc("/acme/new-nonce", s.handleNewNonce)
	mux.HandleFunc("/acme/new-account", s.handleNewAccount)
	mux.HandleFunc("/acme/new-order", s.handleNewOrder)
	mux.HandleFunc("/acme/order/", s.handleOrder)
	mux.HandleFunc("/acme/authz/", s.handleAuthz)
	mux.HandleFunc("/acme/challenge/", s.handleChallenge)
	mux.HandleFunc("/acme/finalize/", s.handleFinalize)
	mux.HandleFunc("/acme/cert/", s.handleCertificate)
	mux.HandleFunc("/acme/renewalInfo/", s.handleRenewalInfo)
	mux.HandleFunc("/acme/revoke-cert", s.handleRevokeCert)
	mux.HandleFunc("/acme/key-change", s.handleKeyChange)
	return mux
}

func (s *Server) handleDirectory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	dir := Directory{
		NewNonce:    s.baseURL + "/acme/new-nonce",
		NewAccount:  s.baseURL + "/acme/new-account",
		NewOrder:    s.baseURL + "/acme/new-order",
		RevokeCert:  s.baseURL + "/acme/revoke-cert",
		KeyChange:   s.baseURL + "/acme/key-change",
		RenewalInfo: s.baseURL + "/acme/renewalInfo",
	}

	nonce, _ := s.nonces.New()
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dir)
}

func (s *Server) handleNewNonce(w http.ResponseWriter, r *http.Request) {
	nonce, err := s.nonces.New()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Cache-Control", "no-store")

	switch r.Method {
	case http.MethodHead:
		w.WriteHeader(http.StatusOK)
	case http.MethodGet:
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeACMEError(w, http.StatusMethodNotAllowed, "urn:ietf:params:acme:error:malformed", "method not allowed")
		return
	}

	vjws, ok := s.verifyOuterJWS(w, r, true, 8*1024)
	if !ok {
		return
	}

	var req struct {
		Contact                []string                `json:"contact"`
		TermsOfServiceAgreed   bool                    `json:"termsOfServiceAgreed"`
		ExternalAccountBinding *ExternalAccountBinding `json:"externalAccountBinding"`
	}
	if err := json.Unmarshal(vjws.Payload, &req); err != nil {
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "invalid request body")
		return
	}

	// requireJWK=true above guarantees vjws.JWK is set.
	thumbprint, err := jwkThumbprint(vjws.JWK)
	if err != nil {
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "invalid account key: "+err.Error())
		return
	}

	eabKID := ""
	if req.ExternalAccountBinding != nil {
		if err := verifyExternalAccountBinding(s.store, req.ExternalAccountBinding, s.baseURL+"/acme/new-account", thumbprint); err != nil {
			s.writeACMEError(w, http.StatusUnauthorized, "urn:ietf:params:acme:error:unauthorized", "invalid externalAccountBinding: "+err.Error())
			return
		}
		var hdr eabProtectedHeader
		if raw, decErr := base64.RawURLEncoding.DecodeString(req.ExternalAccountBinding.Protected); decErr == nil {
			_ = json.Unmarshal(raw, &hdr) // corrupt header degrades kid to empty; EAB already verified above
		}
		eabKID = hdr.KID
	} else if s.eabConfig.required {
		s.writeACMEError(w, http.StatusUnauthorized, "urn:ietf:params:acme:error:externalAccountRequired", "this server requires an externalAccountBinding")
		return
	}

	acct := &Account{
		ID:            generateID("acct"),
		Key:           vjws.PublicKey,
		KeyThumbprint: thumbprint,
		Contact:       req.Contact,
		Status:        "valid",
		CreatedAt:     time.Now().UTC(),
	}
	s.store.SaveAccount(acct)
	if eabKID != "" {
		if err := s.store.BindAccountEAB(acct.ID, eabKID); err != nil {
			log.Printf("acme: record eab binding for account %s failed: %v", acct.ID, err)
		}
	}

	nonce, _ := s.nonces.New()
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Location", s.baseURL+"/acme/account/"+acct.ID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(acct)
}

// verifyOuterJWS reads the request body, parses it as an outer ACME JWS
// (RFC 8555 §6.2), and verifies it against this exact request's URL. On any
// failure it writes the appropriate ACME problem response itself and
// returns ok=false; callers should return immediately in that case.
// requireJWK is true only for new-account.
func (s *Server) verifyOuterJWS(w http.ResponseWriter, r *http.Request, requireJWK bool, maxBody int64) (*verifiedJWS, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "invalid request body")
		return nil, false
	}
	jws, err := parseJWS(body)
	if err != nil {
		s.writeJWSError(w, err)
		return nil, false
	}
	vjws, err := verifyJWS(jws, s.baseURL+r.URL.Path, requireJWK, s.resolveAccountKey, s.nonces.Consume)
	if err != nil {
		s.writeJWSError(w, err)
		return nil, false
	}
	return vjws, true
}

// resolveAccountKey resolves a kid (an account URL) to that account's
// verified public key, for verifyJWS's kid-authenticated requests.
//
// Locked on s.mu: handleKeyChange (RFC 8555 §7.3.5) is the first handler to
// mutate an existing account's Key/KeyThumbprint post-creation, which makes
// this read race with that mutation unless both sides share a lock.
func (s *Server) resolveAccountKey(kid string) (crypto.PublicKey, error) {
	id, ok := accountIDFromKID(kid, s.baseURL)
	if !ok {
		return nil, errAccountNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	acct, ok := s.store.LoadAccount(id)
	if !ok || acct.Key == nil || acct.Status != "valid" {
		return nil, errAccountNotFound
	}
	return acct.Key, nil
}

// writeJWSError maps a jws.go verification error to an RFC 8555 §6.7
// problem response.
func (s *Server) writeJWSError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errJWSBadNonce):
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:badNonce", err.Error())
	case errors.Is(err, errAccountNotFound):
		s.writeACMEError(w, http.StatusUnauthorized, "urn:ietf:params:acme:error:accountDoesNotExist", err.Error())
	case errors.Is(err, errJWSBadSignature), errors.Is(err, errJWSUnsupportedAlg):
		s.writeACMEError(w, http.StatusUnauthorized, "urn:ietf:params:acme:error:unauthorized", err.Error())
	default:
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", err.Error())
	}
}

// keyAuthorization computes the RFC 8555 §8.1 KeyAuthorization
// (token+"."+accountThumbprint) for the account bound to accountID.
//
// Locked on s.mu for the same reason as resolveAccountKey above: handleKeyChange
// can mutate acct.KeyThumbprint concurrently with this read.
func (s *Server) keyAuthorization(accountID, token string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	acct, ok := s.store.LoadAccount(accountID)
	if !ok || acct.KeyThumbprint == "" {
		return "", errAccountNotFound
	}
	return token + "." + acct.KeyThumbprint, nil
}

func (s *Server) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeACMEError(w, http.StatusMethodNotAllowed, "urn:ietf:params:acme:error:malformed", "method not allowed")
		return
	}

	vjws, ok := s.verifyOuterJWS(w, r, false, 8*1024)
	if !ok {
		return
	}
	accountID, _ := accountIDFromKID(vjws.KID, s.baseURL)

	var req struct {
		Identifiers []Identifier `json:"identifiers"`
	}
	if err := json.Unmarshal(vjws.Payload, &req); err != nil {
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "invalid request body")
		return
	}
	if len(req.Identifiers) == 0 {
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "at least one identifier required")
		return
	}

	// Validate every identifier before creating any state. Only "dns" is
	// supported: an "ip" order validated over http-01 must never be able to
	// authorise DNS names (OWASP-A04-001).
	type vetted struct {
		ident    Identifier
		base     string
		wildcard bool
	}
	idents := make([]vetted, 0, len(req.Identifiers))
	seen := make(map[string]bool, len(req.Identifiers))
	for _, ident := range req.Identifiers {
		if ident.Type != "dns" {
			s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:unsupportedIdentifier", fmt.Sprintf("identifier type %q is not supported; only dns", ident.Type))
			return
		}
		value, base, wildcard, err := normalizeDNSIdentifier(ident.Value)
		if err != nil {
			s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:rejectedIdentifier", err.Error())
			return
		}
		if seen[value] {
			continue
		}
		seen[value] = true
		idents = append(idents, vetted{Identifier{Type: "dns", Value: value}, base, wildcard})
	}

	now := time.Now().UTC()
	authzURLs := make([]string, 0, len(idents))
	orderIdents := make([]Identifier, 0, len(idents))

	for _, v := range idents {
		orderIdents = append(orderIdents, v.ident)
		// RFC 8555 §7.1.3: a wildcard's authorization names the base domain
		// and is flagged wildcard.
		authz := &Authorization{
			ID:         generateID("authz"),
			AccountID:  accountID,
			Identifier: Identifier{Type: "dns", Value: v.base},
			Wildcard:   v.wildcard,
			Status:     "pending",
			Expires:    now.Add(7 * 24 * time.Hour),
		}
		// Both challenge types for one authz share the same token.
		token := generateToken()
		// RFC 8555 §8.3: http-01 must not validate a wildcard.
		if !v.wildcard {
			authz.Challenges = append(authz.Challenges, Challenge{Type: "http-01", URL: s.baseURL + "/acme/challenge/" + authz.ID + "/http-01", Token: token, Status: "pending"})
		}
		authz.Challenges = append(authz.Challenges, Challenge{Type: "dns-01", URL: s.baseURL + "/acme/challenge/" + authz.ID + "/dns-01", Token: token, Status: "pending"})

		s.store.SaveAuthz(authz)
		authzURLs = append(authzURLs, s.baseURL+"/acme/authz/"+authz.ID)
	}

	order := &Order{
		ID:             generateID("order"),
		AccountID:      accountID,
		Status:         "pending",
		Identifiers:    orderIdents,
		Authorizations: authzURLs,
		Expires:        now.Add(7 * 24 * time.Hour),
		CreatedAt:      now,
	}
	order.Finalize = s.baseURL + "/acme/finalize/" + order.ID
	s.store.SaveOrder(order)
	metrics.ACMEOrdersCreated.Inc()

	nonce, _ := s.nonces.New()
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Location", s.baseURL+"/acme/order/"+order.ID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(order)
}

func (s *Server) handleOrder(w http.ResponseWriter, r *http.Request) {
	orderID := strings.TrimPrefix(r.URL.Path, "/acme/order/")

	// G-74: LoadOrder hands back the same *Order the background validation
	// goroutines and handleFinalize mutate directly (Store does not copy on
	// read or write). Take a snapshot while s.mu is held, matching every
	// writer's locking, rather than reading fields off the live pointer
	// after the lock is released -- concurrent GET /order/{id} polling
	// during validation/finalization is normal ACME client behavior, not an
	// edge case. Order has no nested slice-of-mutable-struct fields (unlike
	// Authorization.Challenges), so a shallow copy is sufficient.
	s.mu.Lock()
	order, ok := s.store.LoadOrder(orderID)
	if !ok {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	snapshot := *order
	s.mu.Unlock()

	nonce, _ := s.nonces.New()
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snapshot)
}

func (s *Server) handleAuthz(w http.ResponseWriter, r *http.Request) {
	authzID := strings.TrimPrefix(r.URL.Path, "/acme/authz/")

	// G-74: same reasoning as handleOrder above, but a shallow copy of
	// Authorization is NOT enough on its own -- Challenges is a slice of
	// Challenge VALUES, and handleChallenge/validateHTTP01/validateDNS01
	// mutate a challenge in place via a pointer into that slice
	// (&authz.Challenges[i]). A shallow struct copy would still share the
	// slice's backing array with the live authorization, so the Challenges
	// elements are copied into a fresh backing array too, while s.mu is
	// held, before anything is read outside the lock.
	s.mu.Lock()
	authz, ok := s.store.LoadAuthz(authzID)
	if !ok {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	snapshot := *authz
	snapshot.Challenges = append([]Challenge(nil), authz.Challenges...)
	s.mu.Unlock()

	nonce, _ := s.nonces.New()
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snapshot)
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeACMEError(w, http.StatusMethodNotAllowed, "urn:ietf:params:acme:error:malformed", "method not allowed")
		return
	}

	parts := strings.TrimPrefix(r.URL.Path, "/acme/challenge/")
	segments := strings.SplitN(parts, "/", 2)
	if len(segments) != 2 {
		http.NotFound(w, r)
		return
	}
	authzID := segments[0]
	challengeType := segments[1]

	vjws, ok := s.verifyOuterJWS(w, r, false, 8*1024)
	if !ok {
		return
	}
	accountID, _ := accountIDFromKID(vjws.KID, s.baseURL)

	s.mu.Lock()

	authz, ok := s.store.LoadAuthz(authzID)
	if !ok {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	if authz.AccountID != accountID {
		s.mu.Unlock()
		s.writeACMEError(w, http.StatusUnauthorized, "urn:ietf:params:acme:error:unauthorized", "authorization does not belong to this account")
		return
	}

	var found *Challenge
	for i := range authz.Challenges {
		if authz.Challenges[i].Type == challengeType {
			found = &authz.Challenges[i]
			break
		}
	}
	if found == nil {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}

	if found.Status == "valid" {
		// G-74: snapshot before unlocking. Only Status=="valid" gates
		// re-spawning a validation goroutine below -- "processing" does
		// not -- so a concurrent double-POST while a validation is already
		// in flight can leave a second validateHTTP01/validateDNS01
		// goroutine running against this same *Challenge. If that goroutine
		// writes found.Status again after this branch's lock is released,
		// encoding the live pointer here would race with it.
		validSnapshot := *found
		s.mu.Unlock()
		nonce, _ := s.nonces.New()
		w.Header().Set("Replay-Nonce", nonce)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Link", fmt.Sprintf(`<%s/acme/authz/%s>;rel="up"`, s.baseURL, authzID))
		json.NewEncoder(w).Encode(validSnapshot)
		return
	}

	identifier := authz.Identifier.Value
	token := found.Token

	switch challengeType {
	case "http-01":
		found.Status = "processing"
	case "dns-01":
		found.Status = "processing"
	default:
		// Encoding the live `found` pointer unlocked is safe here specifically
		// because no validation goroutine is ever spawned for an unknown
		// challenge type (unlike the http-01/dns-01 cases above) -- nothing
		// else can write to this *Challenge after this point.
		found.Status = "invalid"
		authz.Status = "invalid"
		s.store.SaveAuthz(authz)
		s.mu.Unlock()
		nonce, _ := s.nonces.New()
		w.Header().Set("Replay-Nonce", nonce)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Link", fmt.Sprintf(`<%s/acme/authz/%s>;rel="up"`, s.baseURL, authzID))
		json.NewEncoder(w).Encode(found)
		return
	}

	snapshot := *found
	challengeRef := found
	authzRef := authz
	s.store.SaveAuthz(authz)
	s.mu.Unlock()

	if challengeType == "dns-01" {
		go s.validateDNS01(identifier, token, challengeRef, authzRef)
	} else {
		go s.validateHTTP01(identifier, token, challengeRef, authzRef)
	}

	nonce, _ := s.nonces.New()
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Content-Type", "application/json")
	// RFC 8555 SS7.5.1: the response to answering a challenge must let the
	// client find the authorization it belongs to. python-acme's ClientV2
	// (certbot, and anything built on it) hard-requires this: answer_challenge
	// reads resp.links['up'] and raises ClientError("\"up\" Link header
	// missing") if absent -- found live, the first real ACME client to ever
	// exercise this endpoint failed HTTP-01 on exactly this (W19-01).
	w.Header().Set("Link", fmt.Sprintf(`<%s/acme/authz/%s>;rel="up"`, s.baseURL, authzID))
	json.NewEncoder(w).Encode(snapshot)
}

func (s *Server) handleFinalize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeACMEError(w, http.StatusMethodNotAllowed, "urn:ietf:params:acme:error:malformed", "method not allowed")
		return
	}

	orderID := strings.TrimPrefix(r.URL.Path, "/acme/finalize/")

	vjws, ok := s.verifyOuterJWS(w, r, false, 64*1024)
	if !ok {
		return
	}
	accountID, _ := accountIDFromKID(vjws.KID, s.baseURL)

	var req struct {
		CSR string `json:"csr"` // base64url-encoded DER CSR
	}
	if err := json.Unmarshal(vjws.Payload, &req); err != nil {
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "invalid request body")
		return
	}

	s.mu.Lock()
	order, ok := s.store.LoadOrder(orderID)
	if !ok {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	if order.AccountID != accountID {
		s.mu.Unlock()
		s.writeACMEError(w, http.StatusUnauthorized, "urn:ietf:params:acme:error:unauthorized", "order does not belong to this account")
		return
	}
	if order.Status != "ready" {
		s.mu.Unlock()
		s.writeACMEError(w, http.StatusForbidden, "urn:ietf:params:acme:error:orderNotReady", "order is not ready for finalization")
		return
	}
	order.Status = "processing"
	s.store.SaveOrder(order)
	s.mu.Unlock()

	// RFC 8555 §7.4: a CSR that fails here invalidates the order.
	rejectCSR := func(detail string) {
		s.mu.Lock()
		order.Status = "invalid"
		s.store.SaveOrder(order)
		s.mu.Unlock()
		metrics.ACMEOrdersInvalid.Inc()
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:badCSR", detail)
	}

	csrDER, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		rejectCSR("invalid CSR encoding")
		return
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		rejectCSR("invalid CSR")
		return
	}

	acctKey, _ := s.resolveAccountKey(vjws.KID)
	dnsNames := sortedIdentifierValues(order.Identifiers)
	if err := checkFinalizeCSR(csr, dnsNames, acctKey); err != nil {
		log.Printf("acme finalize: order %q CSR rejected: %v", orderID, err)
		rejectCSR(err.Error())
		return
	}

	// The certificate carries exactly the validated identifiers; nothing is
	// inherited from the CSR (OWASP-A04-001).
	issued, err := s.caEngine.IssueCertificate(s.caID, ca.IssuanceRequest{
		CSR:             csr,
		Validity:        90 * 24 * time.Hour,
		DNSNames:        dnsNames,
		Subject:         &pkix.Name{CommonName: dnsNames[0]},
		CallerNamesOnly: true,
		KeyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		log.Printf("acme finalize issuance failed: %v", err)
		s.mu.Lock()
		order.Status = "invalid"
		s.store.SaveOrder(order)
		s.mu.Unlock()
		metrics.ACMEOrdersInvalid.Inc()
		s.writeACMEError(w, http.StatusInternalServerError, "urn:ietf:params:acme:error:serverInternal", "certificate issuance failed")
		return
	}

	// RFC 8555 SS7.4.2 doesn't strictly require intermediate certificates in
	// the download response, but every real client's parser was written
	// against Let's Encrypt, which always sends leaf+issuer -- found live,
	// certbot hard-fails with "less than 2 certificates in chain" on a
	// leaf-only response (W19-01). Append the issuing CA's own certificate
	// so /acme/cert/{id} returns an actual chain; best-effort (GetCA failing
	// still ships the leaf certificate the client is entitled to rather than
	// failing an already-successful issuance).
	chainPEM := issued.CertPEM
	if issuerCA, caErr := s.caEngine.GetCA(s.caID); caErr == nil && len(issuerCA.CertPEM) > 0 {
		chainPEM = append(append([]byte(nil), issued.CertPEM...), issuerCA.CertPEM...)
	} else if caErr != nil {
		log.Printf("acme finalize: issuer CA chain unavailable for %s, serving leaf-only cert: %v", s.caID, caErr)
	}

	certID := generateID("cert")
	s.mu.Lock()
	order.Status = "valid"
	order.Certificate = s.baseURL + "/acme/cert/" + certID
	s.store.SaveOrder(order)
	s.store.SaveCert(certID, chainPEM)
	snapshot := *order
	s.mu.Unlock()
	metrics.ACMEOrdersFinalized.Inc()

	// Record into the hub's inventory outside s.mu -- the client already has
	// its certificate at this point (SaveCert above), so a recorder failure
	// must never fail the order; it would hand the client a credential this
	// system then can't undo. Best-effort, logged only (W18-16: previously
	// nothing recorded these at all, matching the comment this replaces in
	// handleRevokeCert's on-demand fallback).
	if s.issuedRecorder != nil {
		if err := s.issuedRecorder.RecordIssuedCertificate(r.Context(), s.caID, issued.Certificate, chainPEM, "acme"); err != nil {
			log.Printf("acme: issued certificate %s not recorded: %v", issued.Fingerprint, err)
		}
	}

	nonce, _ := s.nonces.New()
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snapshot)
}

func (s *Server) handleCertificate(w http.ResponseWriter, r *http.Request) {
	certID := strings.TrimPrefix(r.URL.Path, "/acme/cert/")

	certPEM, ok := s.store.LoadCert(certID)
	if !ok {
		http.NotFound(w, r)
		return
	}

	// RFC 8555 SS6.5.1: every ACME response, this one included, must carry a
	// Replay-Nonce for the client's next POST -- found live, certbot's
	// python-acme raised MissingNonce on exactly this response the first
	// time a real client ever downloaded a certificate from this endpoint
	// (W19-01).
	nonce, _ := s.nonces.New()
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.Write(certPEM)
}

// handleRevokeCert implements RFC 8555 §7.6. Unlike every other
// authenticated endpoint (kid-only) or new-account (jwk-only), revoke-cert
// accepts EITHER an account key (kid, authorized if the account owns the
// order the certificate was issued from) or the certificate's own key (jwk,
// authorized by the outer signature itself proving possession).
func (s *Server) handleRevokeCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeACMEError(w, http.StatusMethodNotAllowed, "urn:ietf:params:acme:error:malformed", "method not allowed")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8*1024))
	if err != nil {
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "invalid request body")
		return
	}
	jws, err := parseJWS(body)
	if err != nil {
		s.writeJWSError(w, err)
		return
	}

	// Peek the protected header to learn which authorization mode this
	// request is using before delegating the actual signature check to
	// verifyJWS -- requireJWK there only picks which of jwk/kid is
	// mandatory, so passing the mode that's actually present lets either
	// succeed on its own terms.
	hasJWK, err := jwsHeaderHasJWK(jws)
	if err != nil {
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "invalid protected header")
		return
	}
	vjws, err := verifyJWS(jws, s.baseURL+r.URL.Path, hasJWK, s.resolveAccountKey, s.nonces.Consume)
	if err != nil {
		s.writeJWSError(w, err)
		return
	}

	var req struct {
		Certificate string `json:"certificate"`
		Reason      *int   `json:"reason"`
	}
	if err := json.Unmarshal(vjws.Payload, &req); err != nil {
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "invalid request body")
		return
	}
	if req.Reason != nil && !validRevocationReason(*req.Reason) {
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:badRevocationReason", "unsupported revocation reason code")
		return
	}

	certDER, err := base64.RawURLEncoding.DecodeString(req.Certificate)
	if err != nil {
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "invalid certificate encoding")
		return
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "invalid certificate")
		return
	}

	// Possession of a key (cert-key) or an account (account-key) answers who
	// may ask for a revocation, not whether this server has any relationship
	// to the certificate at all -- RFC 8555 §7.6: "a server SHOULD NOT allow
	// revocation of certificates it did not issue." Resolve the certificate
	// against this server's own orders FIRST; an unrecognized certificate is
	// rejected before either authorization mode is even considered, so a
	// self-signed cert plus its own throwaway key can't be "revoked" into
	// s.revoked for free.
	fingerprint := certFingerprint(cert)
	issuerAccountID, issuedByUs := s.findIssuedCertificate(fingerprint)
	if !issuedByUs {
		s.writeACMEError(w, http.StatusUnauthorized, "urn:ietf:params:acme:error:unauthorized", "certificate was not issued by this server")
		return
	}

	if vjws.JWK != nil {
		// Cert-key authorized: the outer signature already proved possession
		// of the private key for vjws.PublicKey; RFC 8555 §7.6 requires that
		// to be the certificate's own key.
		if !publicKeysEqual(vjws.PublicKey, cert.PublicKey) {
			s.writeACMEError(w, http.StatusUnauthorized, "urn:ietf:params:acme:error:unauthorized", "jwk does not match certificate public key")
			return
		}
	} else {
		accountID, _ := accountIDFromKID(vjws.KID, s.baseURL)
		if accountID != issuerAccountID {
			s.writeACMEError(w, http.StatusUnauthorized, "urn:ietf:params:acme:error:unauthorized", "account is not authorized to revoke this certificate")
			return
		}
	}

	reason := 0
	if req.Reason != nil {
		reason = *req.Reason
	}

	// Resolve the issuing CA before recording anything: a failure here is a
	// server error the client can retry, and it must not have been recorded
	// as revoked (a retry would then be refused as alreadyRevoked) nor be
	// attributed to a CA that did not issue the certificate (SEMGREP-014).
	var issuingCAID string
	if s.revStore != nil {
		id, err := s.resolveIssuingCAID(cert)
		if err != nil {
			log.Printf("acme revoke-cert: cannot determine the issuing CA for serial=%s: %v", cert.SerialNumber, err)
			s.writeACMEError(w, http.StatusInternalServerError, "urn:ietf:params:acme:error:serverInternal", "unable to determine the issuing CA; retry later")
			return
		}
		issuingCAID = id
	}

	s.mu.Lock()
	if _, already := s.revoked[fingerprint]; already {
		s.mu.Unlock()
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:alreadyRevoked", "certificate has already been revoked")
		return
	}
	revokedAt := time.Now().UTC()
	s.revoked[fingerprint] = revocationRecord{RevokedAt: revokedAt, ReasonCode: reason}
	s.mu.Unlock()

	// Forward to the downstream ca.RevocationStore (OCSP/CRL's actual source
	// of truth) outside s.mu -- this is a best-effort side effect, not part
	// of revoke-cert's request/response contract (W1-14/G-91 acceptance #4),
	// so a failure here is logged, never turned into an error response.
	if s.revStore != nil {
		if caID := issuingCAID; caID != "" {
			// ACME-issued certificates are never written to the certificates
			// table at issuance (unlike bootstrap.caCertificateProvider's
			// writeCertToDB for the dashboard/API path), so a DB-backed
			// RevocationStore has no row to UPDATE yet. Pass along the
			// parsed certificate's own metadata so it can create one on
			// demand instead of silently discarding the revocation
			// (W1-15/G-92); MemRevocationStore ignores it.
			meta := ca.CertMeta{
				FingerprintSHA256: fmt.Sprintf("%x", sha256.Sum256(cert.Raw)),
				CommonName:        cert.Subject.CommonName,
				SubjectDN:         cert.Subject.String(),
				// W18-14: DNS-only here silently dropped IP/URI/email SANs
				// from the on-demand row a DB-backed RevocationStore
				// creates, and from every certificate later renewed from
				// that row.
				SubjectAltNames:    ca.SubjectAltNameStrings(cert),
				IssuerDN:           cert.Issuer.String(),
				IssuerCN:           cert.Issuer.CommonName,
				NotBefore:          cert.NotBefore,
				NotAfter:           cert.NotAfter,
				PublicKeyAlgorithm: ca.StoredPublicKeyAlgorithm(cert),
				KeySizeBits:        ca.PublicKeyBits(cert.PublicKey),
				SignatureAlgorithm: cert.SignatureAlgorithm.String(),
				ExtendedKeyUsage:   extKeyUsageNames(cert.ExtKeyUsage),
				KeyUsage:           keyUsageNames(cert.KeyUsage),
				Source:             "acme",
				CertPEM:            pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
			}
			if err := s.revStore.Revoke(cert.SerialNumber, caID, reason, revokedAt, meta); err != nil {
				log.Printf("acme revoke-cert: ca.RevocationStore.Revoke failed (caID=%s serial=%s): %v", caID, cert.SerialNumber, err)
			} else if s.ocspInvalidator != nil {
				// Without this, OCSP keeps answering "good" for this serial
				// until its cached response's validity window (24h default)
				// ages out on its own -- found live, W19-01.
				s.ocspInvalidator.InvalidateCache(cert.SerialNumber)
			}
		}
	}

	nonce, _ := s.nonces.New()
	w.Header().Set("Replay-Nonce", nonce)
	w.WriteHeader(http.StatusOK)
}

// resolveIssuingCAID identifies which CA actually issued cert, by matching
// its RFC 5280 §4.2.1.1 AuthorityKeyId against each CA's SubjectKeyId --
// engine.issueLeafCertificate always sets AuthorityKeyId from the issuing
// CA's own SubjectKeyId. A certificate without an AuthorityKeyId is matched
// by verifying its signature against each CA instead. It never falls back to
// s.caID: guessing would record the revocation against a CA that never issued
// the certificate, so that CA's CRL/OCSP would not show it (W1-14/G-91
// acceptance #3, SEMGREP-014). A CA list that cannot be read, or a
// certificate no CA claims, is an error.
func (s *Server) resolveIssuingCAID(cert *x509.Certificate) (string, error) {
	cas, err := s.caEngine.ListCAs()
	if err != nil {
		return "", fmt.Errorf("list CAs: %w", err)
	}
	for _, c := range cas {
		if c.Certificate == nil {
			continue
		}
		if len(cert.AuthorityKeyId) > 0 {
			if bytes.Equal(c.Certificate.SubjectKeyId, cert.AuthorityKeyId) {
				return c.ID, nil
			}
		} else if cert.CheckSignatureFrom(c.Certificate) == nil {
			return c.ID, nil
		}
	}
	return "", errIssuingCANotFound
}

var errIssuingCANotFound = errors.New("certificate matches no CA known to this server")

// handleKeyChange implements RFC 8555 §7.3.5 account key rollover. The outer
// JWS is a standard kid-authenticated request from the account's CURRENT
// key; its payload is itself a JWS (the "inner JWS"), signed by the
// PROPOSED new key to prove possession of it. The nine server-verification
// steps below follow the RFC's list in order.
func (s *Server) handleKeyChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeACMEError(w, http.StatusMethodNotAllowed, "urn:ietf:params:acme:error:malformed", "method not allowed")
		return
	}

	reqURL := s.baseURL + r.URL.Path

	// Step 1: POST belongs to a currently active account (kid-authenticated,
	// resolveAccountKey requires Status=="valid").
	vjws, ok := s.verifyOuterJWS(w, r, false, 8*1024)
	if !ok {
		return
	}
	accountID, _ := accountIDFromKID(vjws.KID, s.baseURL)

	// Step 2: payload of the outer JWS is a well-formed JWS object.
	innerJWS, err := parseJWS(vjws.Payload)
	if err != nil {
		s.writeJWSError(w, err)
		return
	}
	innerHdrJSON, err := base64.RawURLEncoding.DecodeString(innerJWS.Protected)
	if err != nil {
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "invalid inner jws protected header")
		return
	}
	var innerHdr jwsProtectedHeader
	if err := json.Unmarshal(innerHdrJSON, &innerHdr); err != nil {
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "invalid inner jws protected header")
		return
	}

	// Step 3: inner protected header has a jwk field (and, since this server
	// only accepts kid for every other authenticated request, must not also
	// carry a kid or a nonce -- the inner JWS MUST omit nonce per §7.3.5).
	switch {
	case innerHdr.JWK == nil:
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "inner jws must contain jwk")
		return
	case innerHdr.KID != "":
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "inner jws must not contain kid")
		return
	case innerHdr.Nonce != "":
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "inner jws must not contain a nonce")
		return
	case innerHdr.URL != reqURL:
		// Step 6: url parameters of inner and outer JWS are the same.
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "inner jws url does not match outer jws url")
		return
	}

	newPub, err := innerHdr.JWK.publicKey()
	if err != nil {
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "invalid new key: "+err.Error())
		return
	}
	innerSig, err := base64.RawURLEncoding.DecodeString(innerJWS.Signature)
	if err != nil {
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "invalid inner jws signature encoding")
		return
	}
	innerSigningInput := []byte(innerJWS.Protected + "." + innerJWS.Payload)
	// Step 4: inner JWS verifies using the key in its jwk field.
	if err := verifyJWSSignature(innerHdr.Alg, newPub, innerSigningInput, innerSig); err != nil {
		s.writeJWSError(w, err)
		return
	}

	var innerPayload []byte
	if innerJWS.Payload != "" {
		innerPayload, err = base64.RawURLEncoding.DecodeString(innerJWS.Payload)
		if err != nil {
			s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "invalid inner jws payload")
			return
		}
	}
	// Step 5: payload of the inner JWS is a well-formed keyChange object.
	var kc struct {
		Account string     `json:"account"`
		OldKey  JSONWebKey `json:"oldKey"`
	}
	if err := json.Unmarshal(innerPayload, &kc); err != nil {
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "invalid keyChange payload")
		return
	}
	// Step 7: account field of the keyChange object names the account
	// matching the old key (the outer JWS's kid).
	if kc.Account != vjws.KID {
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "keyChange account does not match the requesting account")
		return
	}
	oldThumb, err := jwkThumbprint(&kc.OldKey)
	if err != nil {
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "invalid oldKey: "+err.Error())
		return
	}
	newThumb, err := jwkThumbprint(innerHdr.JWK)
	if err != nil {
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "invalid new key: "+err.Error())
		return
	}

	s.mu.Lock()
	acct, ok := s.store.LoadAccount(accountID)
	if !ok {
		s.mu.Unlock()
		s.writeACMEError(w, http.StatusUnauthorized, "urn:ietf:params:acme:error:accountDoesNotExist", "account does not exist")
		return
	}
	// Step 8: oldKey field of the keyChange object is the account's current key.
	if oldThumb != acct.KeyThumbprint {
		s.mu.Unlock()
		s.writeACMEError(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "keyChange oldKey does not match the account's current key")
		return
	}
	// Step 9: no other account already uses the proposed new key.
	for _, other := range s.store.ListAccounts() {
		if other.ID != accountID && other.KeyThumbprint == newThumb {
			s.mu.Unlock()
			w.Header().Set("Location", s.baseURL+"/acme/account/"+other.ID)
			s.writeACMEError(w, http.StatusConflict, "urn:ietf:params:acme:error:malformed", "an account already exists with this key")
			return
		}
	}
	acct.Key = newPub
	acct.KeyThumbprint = newThumb
	s.store.SaveAccount(acct)
	s.mu.Unlock()

	nonce, _ := s.nonces.New()
	w.Header().Set("Replay-Nonce", nonce)
	w.WriteHeader(http.StatusOK)
}

// jwsHeaderHasJWK reports whether jws's protected header carries an inline
// jwk (cert-key authorized) rather than a kid (account-key authorized) --
// revoke-cert is the one endpoint besides new-account that accepts either,
// so the caller must peek before choosing which verifyJWS mode applies.
func jwsHeaderHasJWK(jws *JWS) (bool, error) {
	hdrJSON, err := base64.RawURLEncoding.DecodeString(jws.Protected)
	if err != nil {
		return false, err
	}
	var hdr jwsProtectedHeader
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		return false, err
	}
	return hdr.JWK != nil, nil
}

// publicKeysEqual reports whether a and b are the same public key,
// regardless of concrete type -- crypto/{rsa,ecdsa,ed25519} public keys all
// implement Equal(crypto.PublicKey) bool (Go 1.15+).
func publicKeysEqual(a, b crypto.PublicKey) bool {
	ae, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return false
	}
	return ae.Equal(b)
}

// validRevocationReason reports whether reason is one of the CRLReason
// values RFC 8555 §7.6 permits in a revoke-cert request (RFC 5280 §5.3.1's
// list, excluding 7, which is unassigned).
func validRevocationReason(reason int) bool {
	switch reason {
	case 0, 1, 2, 3, 4, 5, 6, 8, 9, 10:
		return true
	default:
		return false
	}
}

// certFingerprint is a stable identity key for a parsed certificate, used to
// track ACME revocation state and to match a submitted certificate against
// one this server issued.
func certFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// extKeyUsageNames renders x509.ExtKeyUsage values as the string names
// bootstrap.caCertificateProvider's own ekuStrings uses, for CertMeta
// (W1-15/G-92) so an ACME-issued certificates row reads the same way as one
// written by writeCertToDB. An unrecognized value renders as its numeric
// form rather than being dropped silently.
func extKeyUsageNames(ekus []x509.ExtKeyUsage) []string {
	names := make([]string, 0, len(ekus))
	for _, e := range ekus {
		switch e {
		case x509.ExtKeyUsageServerAuth:
			names = append(names, "serverAuth")
		case x509.ExtKeyUsageClientAuth:
			names = append(names, "clientAuth")
		case x509.ExtKeyUsageCodeSigning:
			names = append(names, "codeSigning")
		case x509.ExtKeyUsageEmailProtection:
			names = append(names, "emailProtection")
		case x509.ExtKeyUsageTimeStamping:
			names = append(names, "timeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			names = append(names, "ocspSigning")
		default:
			names = append(names, fmt.Sprintf("%d", e))
		}
	}
	return names
}

// keyUsageNames renders an x509.KeyUsage bitmask as string names, for
// CertMeta (W1-15/G-92).
func keyUsageNames(ku x509.KeyUsage) []string {
	bits := []struct {
		flag x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digitalSignature"},
		{x509.KeyUsageContentCommitment, "contentCommitment"},
		{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
		{x509.KeyUsageDataEncipherment, "dataEncipherment"},
		{x509.KeyUsageKeyAgreement, "keyAgreement"},
		{x509.KeyUsageCertSign, "certSign"},
		{x509.KeyUsageCRLSign, "crlSign"},
		{x509.KeyUsageEncipherOnly, "encipherOnly"},
		{x509.KeyUsageDecipherOnly, "decipherOnly"},
	}
	var names []string
	for _, b := range bits {
		if ku&b.flag != 0 {
			names = append(names, b.name)
		}
	}
	return names
}

// findIssuedCertificate reports whether wantFingerprint matches a
// certificate this server actually issued (i.e. it is attached to some
// order's Certificate URL), and if so, which account's order it came from.
// RFC 8555 §7.6: a server should not treat revocation of a certificate it
// has no relationship to as authorized by anyone, cert-key or account-key
// alike -- so handleRevokeCert requires this lookup to succeed before
// either authorization mode is considered.
func (s *Server) findIssuedCertificate(wantFingerprint string) (accountID string, ok bool) {
	for _, order := range s.store.ListOrders() {
		if order.Certificate == "" {
			continue
		}
		parts := strings.Split(order.Certificate, "/acme/cert/")
		if len(parts) < 2 {
			continue
		}
		pemBytes, loaded := s.store.LoadCert(parts[len(parts)-1])
		if !loaded {
			continue
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			continue
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if certFingerprint(leaf) == wantFingerprint {
			return order.AccountID, true
		}
	}
	return "", false
}

// validateHTTP01 performs RFC 8555 §8.3 HTTP-01 challenge validation
// asynchronously. It fetches the well-known URL and checks that the
// response body is EXACTLY the KeyAuthorization (token+"."+the requesting
// account's JWK thumbprint, captured at account creation — jws.go), closing
// the account-key gap this used to leave as token-prefix matching (G-44).
func (s *Server) validateHTTP01(identifier, token string, ch *Challenge, authz *Authorization) {
	// identifier is a validated DNS name (newOrder), so this is always port 80.
	url := fmt.Sprintf("http://%s/.well-known/acme-challenge/%s", identifier, token)

	s.mu.Lock()
	dial := s.http01Dial
	s.mu.Unlock()
	resp, err := newHTTP01Client(dial).Get(url)

	now := time.Now().UTC()

	expectedKeyAuth, kaErr := s.keyAuthorization(authz.AccountID, token)

	s.mu.Lock()
	defer s.mu.Unlock()

	if kaErr != nil {
		log.Printf("acme http-01 validation failed for %q: %v", identifier, kaErr)
		ch.Status = "invalid"
		authz.Status = "invalid"
		s.store.SaveAuthz(authz)
		return
	}

	if err != nil {
		log.Printf("acme http-01 validation fetch failed for %q: %v", identifier, err)
		ch.Status = "invalid"
		authz.Status = "invalid"
		s.store.SaveAuthz(authz)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	keyAuth := strings.TrimSpace(string(body))

	if resp.StatusCode != http.StatusOK || keyAuth != expectedKeyAuth {
		// The body is attacker-controlled and the fetch is unauthenticated,
		// so it is never logged.
		log.Printf("acme http-01 validation failed for %q: status=%d body_len=%d", identifier, resp.StatusCode, len(body))
		ch.Status = "invalid"
		authz.Status = "invalid"
		s.store.SaveAuthz(authz)
		return
	}

	ch.Status = "valid"
	ch.Validated = &now
	authz.Status = "valid"
	s.store.SaveAuthz(authz)
	s.updateOrderStatus()
}

func (s *Server) updateOrderStatus() {
	for _, order := range s.store.ListOrders() {
		if order.Status != "pending" {
			continue
		}
		allValid := true
		for _, authzURL := range order.Authorizations {
			authzID := authzURL[strings.LastIndex(authzURL, "/")+1:]
			if authz, ok := s.store.LoadAuthz(authzID); ok {
				if authz.Status != "valid" {
					allValid = false
					break
				}
			} else {
				allValid = false
				break
			}
		}
		if allValid {
			order.Status = "ready"
			s.store.SaveOrder(order)
		}
	}
}

func (s *Server) writeACMEError(w http.ResponseWriter, status int, errType string, detail string) {
	nonce, _ := s.nonces.New()
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(Problem{
		Type:   errType,
		Detail: detail,
		Status: status,
	})
}

func generateID(prefix string) string {
	b := make([]byte, 12)
	rand.Read(b)
	return prefix + "-" + base64.RawURLEncoding.EncodeToString(b)
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// SetTXTResolver replaces the resolver dns-01 validation uses, so a test
// can serve its own zone. Production servers never call it.
func (s *Server) SetTXTResolver(lookup func(name string) ([]string, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lookupTXT = lookup
}

// validateDNS01 performs RFC 8555 §8.4 DNS-01 challenge validation
// asynchronously. It resolves TXT records at _acme-challenge.<identifier>
// and checks that at least one record equals base64url(SHA-256(
// KeyAuthorization)), where KeyAuthorization is token+"."+the requesting
// account's JWK thumbprint (jws.go) — closing the same account-key gap as
// validateHTTP01 above (G-44).
func (s *Server) validateDNS01(identifier, token string, ch *Challenge, authz *Authorization) {
	dnsName := "_acme-challenge." + identifier
	lookup := s.lookupTXT
	if lookup == nil {
		lookup = net.LookupTXT
	}
	txts, err := lookup(dnsName)

	now := time.Now().UTC()

	expectedKeyAuth, kaErr := s.keyAuthorization(authz.AccountID, token)

	s.mu.Lock()
	defer s.mu.Unlock()

	if kaErr != nil {
		log.Printf("acme dns-01 validation failed for %q: %v", dnsName, kaErr)
		ch.Status = "invalid"
		authz.Status = "invalid"
		s.store.SaveAuthz(authz)
		return
	}

	if err != nil {
		log.Printf("acme dns-01 validation lookup failed for %q: %v", dnsName, err)
		ch.Status = "invalid"
		authz.Status = "invalid"
		s.store.SaveAuthz(authz)
		return
	}

	digest := sha256.Sum256([]byte(expectedKeyAuth))
	expectedDigest := base64.RawURLEncoding.EncodeToString(digest[:])

	for _, txt := range txts {
		if strings.TrimSpace(txt) == expectedDigest {
			ch.Status = "valid"
			ch.Validated = &now
			authz.Status = "valid"
			s.store.SaveAuthz(authz)
			s.updateOrderStatus()
			return
		}
	}

	log.Printf("acme dns-01 validation failed for %s: no TXT record matching expected digest", dnsName)
	ch.Status = "invalid"
	authz.Status = "invalid"
	s.store.SaveAuthz(authz)
}

// handleRenewalInfo implements the ACME ARI (Renewal Information) endpoint.
// Draft spec: draft-ietf-acme-ari
// GET /acme/renewalInfo/{certID}
// certID = base64url(issuerKeyHash) + "." + base64url(serialNumber)
func (s *Server) handleRenewalInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	certID := strings.TrimPrefix(r.URL.Path, "/acme/renewalInfo/")
	if certID == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// The certID is <issuerKeyHashB64url>.<certSerialB64url>.
	// We use it to look up the certificate and compute a per-cert renewal window.
	// If the cert is not found, we return a default window to avoid fingerprinting.
	window := computeARIWindow(certID, s.store)

	nonce, _ := s.nonces.New()
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Content-Type", "application/json")
	// ARI recommends Retry-After with the start of the window.
	w.Header().Set("Retry-After", window.SuggestedWindow.Start)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(window)
}

// computeARIWindow returns a suggested renewal window for the given certID.
// The window is calculated as: start = notAfter - (validity * 1/3), end = notAfter - 7 days.
// This spreads renewals to prevent thundering-herd at expiry (critical at 47-day lifetimes).
func computeARIWindow(certID string, store Store) RenewalInfoResponse {
	now := time.Now().UTC()

	// Try to find the cert in store by parsing the certID.
	// certID format: base64url(issuerKeyHash).base64url(serial)
	parts := strings.SplitN(certID, ".", 2)
	if len(parts) == 2 {
		serialB64 := parts[1]
		serialBytes, err := base64.RawURLEncoding.DecodeString(serialB64)
		if err == nil && len(serialBytes) > 0 {
			serialHex := fmt.Sprintf("%X", serialBytes)
			if cert := findCertBySerial(store, serialHex); cert != nil {
				return ariWindowFromCert(cert, now)
			}
		}
	}

	// Default window: renew in the next 24h starting 1 hour from now.
	return RenewalInfoResponse{
		SuggestedWindow: RenewalWindow{
			Start: now.Add(time.Hour).Format(time.RFC3339),
			End:   now.Add(25 * time.Hour).Format(time.RFC3339),
		},
	}
}

func ariWindowFromCert(cert *x509.Certificate, now time.Time) RenewalInfoResponse {
	validity := cert.NotAfter.Sub(cert.NotBefore)
	// Start renewing at 1/3 of lifetime remaining before expiry.
	windowStart := cert.NotAfter.Add(-validity / 3)
	// End the renewal window 7 days before expiry (hard deadline).
	windowEnd := cert.NotAfter.Add(-7 * 24 * time.Hour)

	if windowEnd.Before(windowStart) {
		windowEnd = windowStart.Add(24 * time.Hour)
	}

	// If the window has already passed, set a near-future window.
	if windowEnd.Before(now) {
		windowStart = now.Add(time.Hour)
		windowEnd = now.Add(25 * time.Hour)
	}

	return RenewalInfoResponse{
		SuggestedWindow: RenewalWindow{
			Start: windowStart.UTC().Format(time.RFC3339),
			End:   windowEnd.UTC().Format(time.RFC3339),
		},
	}
}

// findCertBySerial searches the store for a certificate matching the given serial number (hex).
// Each Order holds a Certificate URL of the form "<baseURL>/acme/cert/<certID>".
// We extract the certID suffix and look up the PEM via LoadCert.
func findCertBySerial(store Store, serialHex string) *x509.Certificate {
	orders := store.ListOrders()
	for _, order := range orders {
		if order.Certificate == "" {
			continue
		}
		// Extract the certID from the certificate URL.
		parts := strings.Split(order.Certificate, "/acme/cert/")
		if len(parts) < 2 {
			continue
		}
		certID := parts[len(parts)-1]
		pemBytes, ok := store.LoadCert(certID)
		if !ok || len(pemBytes) == 0 {
			continue
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			continue
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if fmt.Sprintf("%X", leaf.SerialNumber.Bytes()) == serialHex {
			return leaf
		}
	}
	return nil
}
