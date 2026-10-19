// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Rate-limited ACME stub CA for the W27-34 storm test.
//
// TEST-ONLY. It implements the RFC 8555 subset golang.org/x/crypto/acme needs
// to register, order, finalize and download, and it deliberately does NOT
// verify JWS signatures or nonces: the storm test measures the hub's
// scheduling and rate-limit behaviour, not the CA's request authentication.
// Never point a production client at this.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type stubConfig struct {
	Limit   int           // new orders per Window
	Window  time.Duration // sliding window
	Service time.Duration // issuance time per order, paid at finalize
	Idle    time.Duration // an order untouched this long stops counting as in flight
	// Grace separates a request that was already on the wire when a 429 went out
	// (concurrency, unavoidable) from one sent well after it (a client that
	// ignored Retry-After): only the latter is a late violation.
	Grace time.Duration
	Now   func() time.Time
}

type stubOrder struct {
	id       string
	names    []string
	touched  time.Time
	inFlight bool
	certPEM  []byte
	done     bool // finalized
}

type stubStats struct {
	Orders          int   `json:"orders"`
	LimitHits       int   `json:"limit_hits"`
	Violations      int   `json:"violations"`
	LateViolations  int   `json:"late_violations"`
	PeakInFlight    int   `json:"peak_in_flight"`
	FinalizedUnique int   `json:"finalized_unique"`
	Duplicates      int   `json:"duplicates"`
	FirstOrderUnix  int64 `json:"first_order_unix"`
	LastFinalizeAt  int64 `json:"last_finalize_unix"`
}

type stubCA struct {
	cfg     stubConfig
	root    *x509.Certificate
	key     *ecdsa.PrivateKey
	rootPEM []byte

	mu           sync.Mutex
	recent       []time.Time // accepted newOrder times inside the window
	blockedUntil time.Time
	blockedAt    time.Time
	orders       map[string]*stubOrder
	nextID       int
	inFlight     int
	finalized    map[string]int
	st           stubStats
}

func newStubCA(cfg stubConfig) (*stubCA, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Grace == 0 {
		cfg.Grace = time.Second
	}
	if cfg.Idle == 0 {
		cfg.Idle = 60 * time.Second
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "KK Storm Stub Root (TEST ONLY)"},
		NotBefore:             cfg.Now().Add(-time.Hour),
		NotAfter:              cfg.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &stubCA{
		cfg: cfg, root: root, key: key,
		rootPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		orders:    map[string]*stubOrder{},
		finalized: map[string]int{},
	}, nil
}

// RootPEM is the stub root, which the hub must trust (SSL_CERT_FILE).
func (s *stubCA) RootPEM() []byte { return s.rootPEM }

// signServerCert issues a serverAuth leaf for the fixture's own TLS listeners.
func (s *stubCA) signServerCert(names []string) (tlsCertPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    s.cfg.Now().Add(-time.Hour),
		NotAfter:     s.cfg.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.root, &key.PublicKey, s.key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	return n.Add(n, big.NewInt(1))
}

// admit applies the sliding-window limit to a newOrder arriving now. ok=false
// carries the wait until a slot frees. A request arriving while a previous 429's
// Retry-After is still running is a violation: the client ignored it.
func (s *stubCA) admit(now time.Time) (ok bool, wait time.Duration) {
	cut := now.Add(-s.cfg.Window)
	i := 0
	for i < len(s.recent) && !s.recent[i].After(cut) {
		i++
	}
	s.recent = s.recent[i:]

	if now.Before(s.blockedUntil) {
		s.st.Violations++
		if now.Sub(s.blockedAt) > s.cfg.Grace {
			s.st.LateViolations++
			log.Printf("late violation: newOrder %s after the 429 at %s, %s of Retry-After left",
				now.Sub(s.blockedAt).Round(time.Millisecond), s.blockedAt.Format(time.RFC3339Nano), s.blockedUntil.Sub(now).Round(time.Millisecond))
		}
		s.st.LimitHits++
		return false, s.blockedUntil.Sub(now)
	}
	if len(s.recent) >= s.cfg.Limit {
		wait = s.recent[0].Add(s.cfg.Window).Sub(now)
		s.blockedUntil, s.blockedAt = now.Add(wait), now
		s.st.LimitHits++
		return false, wait
	}
	s.recent = append(s.recent, now)
	return true, 0
}

func (s *stubCA) reapLocked(now time.Time) {
	for _, o := range s.orders {
		if o.inFlight && now.Sub(o.touched) > s.cfg.Idle {
			o.inFlight = false
			s.inFlight--
		}
	}
}

func (s *stubCA) leave(o *stubOrder) {
	if o.inFlight {
		o.inFlight = false
		s.inFlight--
	}
}

// Stats is a snapshot for GET /stats.
func (s *stubCA) Stats() stubStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapLocked(s.cfg.Now())
	out := s.st
	out.FinalizedUnique = len(s.finalized)
	for _, n := range s.finalized {
		if n > 1 {
			out.Duplicates++
		}
	}
	return out
}

func (s *stubCA) base(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

func (s *stubCA) Handler() http.Handler {
	mux := http.NewServeMux()
	nonce := func(w http.ResponseWriter) {
		b := make([]byte, 12)
		_, _ = rand.Read(b)
		w.Header().Set("Replay-Nonce", base64.RawURLEncoding.EncodeToString(b))
		w.Header().Set("Cache-Control", "no-store")
	}
	writeJSON := func(w http.ResponseWriter, code int, v any) {
		nonce(w)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		b := s.base(r)
		writeJSON(w, http.StatusOK, map[string]any{
			"newNonce": b + "/nonce", "newAccount": b + "/acct", "newOrder": b + "/order",
			"revokeCert": b + "/revoke", "keyChange": b + "/keychange",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		nonce(w)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.Stats())
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })

	mux.HandleFunc("/acct", func(w http.ResponseWriter, r *http.Request) {
		drainBody(r)
		s.mu.Lock()
		s.nextID++
		id := s.nextID
		s.mu.Unlock()
		w.Header().Set("Location", s.base(r)+"/acct/"+strconv.Itoa(id))
		writeJSON(w, http.StatusCreated, map[string]any{"status": "valid"})
	})

	mux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		payload, err := readJWS(r)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "malformed", err.Error(), 0)
			return
		}
		var req struct {
			Identifiers []struct{ Type, Value string } `json:"identifiers"`
		}
		if err := json.Unmarshal(payload, &req); err != nil || len(req.Identifiers) == 0 {
			writeProblem(w, http.StatusBadRequest, "malformed", "identifiers required", 0)
			return
		}
		now := s.cfg.Now()
		s.mu.Lock()
		s.reapLocked(now)
		ok, wait := s.admit(now)
		if !ok {
			s.mu.Unlock()
			nonce(w)
			writeProblem(w, http.StatusTooManyRequests, "rateLimited", "too many new orders", wait)
			return
		}
		s.nextID++
		o := &stubOrder{id: "o" + strconv.Itoa(s.nextID), touched: now, inFlight: true}
		for _, id := range req.Identifiers {
			o.names = append(o.names, id.Value)
		}
		sort.Strings(o.names)
		s.orders[o.id] = o
		s.inFlight++
		if s.inFlight > s.st.PeakInFlight {
			s.st.PeakInFlight = s.inFlight
		}
		s.st.Orders++
		if s.st.FirstOrderUnix == 0 {
			s.st.FirstOrderUnix = now.Unix()
		}
		s.mu.Unlock()

		b := s.base(r)
		w.Header().Set("Location", b+"/order/"+o.id)
		writeJSON(w, http.StatusCreated, s.orderBody(b, o))
	})

	mux.HandleFunc("/order/", func(w http.ResponseWriter, r *http.Request) {
		o := s.lookup(strings.TrimPrefix(r.URL.Path, "/order/"))
		if o == nil {
			writeProblem(w, http.StatusNotFound, "malformed", "no such order", 0)
			return
		}
		drainBody(r)
		b := s.base(r)
		w.Header().Set("Location", b+"/order/"+o.id)
		writeJSON(w, http.StatusOK, s.orderBody(b, o))
	})

	mux.HandleFunc("/authz/", func(w http.ResponseWriter, r *http.Request) {
		o := s.lookup(strings.TrimPrefix(r.URL.Path, "/authz/"))
		if o == nil {
			writeProblem(w, http.StatusNotFound, "malformed", "no such authorization", 0)
			return
		}
		drainBody(r)
		w.Header().Set("Location", s.base(r)+r.URL.Path)
		// Already valid, so the connector skips challenges (connector_acme.go).
		writeJSON(w, http.StatusOK, map[string]any{
			"status":     "valid",
			"identifier": map[string]string{"type": "dns", "value": o.names[0]},
			"challenges": []any{},
		})
	})

	mux.HandleFunc("/finalize/", func(w http.ResponseWriter, r *http.Request) {
		o := s.lookup(strings.TrimPrefix(r.URL.Path, "/finalize/"))
		if o == nil {
			writeProblem(w, http.StatusNotFound, "malformed", "no such order", 0)
			return
		}
		payload, err := readJWS(r)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "malformed", err.Error(), 0)
			return
		}
		var req struct {
			CSR string `json:"csr"`
		}
		csrDER, derr := base64.RawURLEncoding.DecodeString("")
		if json.Unmarshal(payload, &req) == nil {
			csrDER, derr = base64.RawURLEncoding.DecodeString(req.CSR)
		}
		if derr != nil {
			writeProblem(w, http.StatusBadRequest, "badCSR", "csr is not base64url", 0)
			return
		}
		time.Sleep(s.cfg.Service)
		chain, err := s.issue(csrDER)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "badCSR", err.Error(), 0)
			return
		}
		now := s.cfg.Now()
		s.mu.Lock()
		o.certPEM, o.done, o.touched = chain, true, now
		s.finalized[o.names[0]]++
		s.st.LastFinalizeAt = now.Unix()
		s.mu.Unlock()

		b := s.base(r)
		w.Header().Set("Location", b+"/order/"+o.id)
		writeJSON(w, http.StatusOK, s.orderBody(b, o))
	})

	mux.HandleFunc("/cert/", func(w http.ResponseWriter, r *http.Request) {
		o := s.lookup(strings.TrimPrefix(r.URL.Path, "/cert/"))
		if o == nil || !o.done {
			writeProblem(w, http.StatusNotFound, "malformed", "no such certificate", 0)
			return
		}
		drainBody(r)
		s.mu.Lock()
		s.leave(o)
		chain := o.certPEM
		s.mu.Unlock()
		nonce(w)
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(chain)
	})
	return mux
}

func (s *stubCA) lookup(id string) *stubOrder {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.orders[id]
	if o != nil {
		o.touched = s.cfg.Now()
	}
	return o
}

func (s *stubCA) orderBody(base string, o *stubOrder) map[string]any {
	s.mu.Lock()
	done := o.done
	s.mu.Unlock()
	ids := make([]map[string]string, 0, len(o.names))
	for _, n := range o.names {
		ids = append(ids, map[string]string{"type": "dns", "value": n})
	}
	body := map[string]any{
		"status": "ready", "identifiers": ids,
		"authorizations": []string{base + "/authz/" + o.id},
		"finalize":       base + "/finalize/" + o.id,
	}
	if done {
		body["status"] = "valid"
		body["certificate"] = base + "/cert/" + o.id
	}
	return body
}

// issue signs the CSR's public key for the CSR's names, 90 days.
func (s *stubCA) issue(csrDER []byte) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("csr unparseable: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("csr signature invalid: %w", err)
	}
	names := csr.DNSNames
	if len(names) == 0 && csr.Subject.CommonName != "" {
		names = []string{csr.Subject.CommonName}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("csr carries no names")
	}
	now := s.cfg.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.root, csr.PublicKey.(crypto.PublicKey), s.key)
	if err != nil {
		return nil, err
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return append(out, s.rootPEM...), nil
}

// readJWS returns the decoded payload of a flattened JWS body (empty for
// POST-as-GET). Signatures are not verified; see the file header.
func readJWS(r *http.Request) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var env struct{ Payload string }
	if len(raw) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("body is not a JWS: %w", err)
	}
	return base64.RawURLEncoding.DecodeString(env.Payload)
}

func writeProblem(w http.ResponseWriter, code int, typ, detail string, retryAfter time.Duration) {
	if retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(retryAfter.Seconds()))))
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"type": "urn:ietf:params:acme:error:" + typ, "detail": detail})
}

// drainBody discards a POST-as-GET body; the stub does not authenticate requests.
func drainBody(r *http.Request) { _, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20)) }
