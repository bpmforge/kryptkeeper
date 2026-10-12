// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ocsp

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	goocsp "golang.org/x/crypto/ocsp"

	// Register the CertID hash algorithms a client may name (RFC 6960 §4.1.1).
	_ "crypto/sha1"   //nolint:gosec // SHA-1 CertIDs are what most clients send
	_ "crypto/sha256" // SHA-256/384/512 (sha512 registers 384/512)
	_ "crypto/sha512"
)

// ErrUnknownIssuer is what an IssuerLookupFunc returns when no CA this
// responder serves matches the request's issuer hashes. The responder answers
// it with the RFC 6960 "unauthorized" status (§2.3: the server is not
// authoritative for the requested certificate); any other lookup or status
// error is a "tryLater". Neither is ever a signed "good".
var ErrUnknownIssuer = errors.New("ocsp: issuer is not served by this responder")

// errSigning marks a failure to sign a response: internalError, not tryLater.
var errSigning = errors.New("ocsp: signing failed")

// CertStatusFunc looks up a certificate's revocation status by serial number and issuer.
// Returns: revoked (bool), revokedAt (time), reasonCode (int), error.
type CertStatusFunc func(serial *big.Int, issuer *x509.Certificate) (revoked bool, revokedAt time.Time, reason int, err error)

// IssuerLookupFunc resolves an issuer certificate by key hash.
type IssuerLookupFunc func(keyHash []byte) (*x509.Certificate, crypto.Signer, error)

// Responder is an OCSP responder that handles GET and POST requests.
type Responder struct {
	statusFunc CertStatusFunc
	issuerFunc IssuerLookupFunc
	validity   time.Duration // thisUpdate → nextUpdate window
	mu         sync.RWMutex
	cache      map[string]cachedResponse // keyed by hash alg | issuer name hash | issuer key hash | serial
	cacheSize  int
}

type cachedResponse struct {
	serial    string
	body      []byte
	expiresAt time.Time
}

// NewResponder creates an OCSP responder.
func NewResponder(statusFunc CertStatusFunc, issuerFunc IssuerLookupFunc, validity time.Duration, cacheSize int) *Responder {
	if validity == 0 {
		validity = 24 * time.Hour
	}
	if cacheSize <= 0 {
		cacheSize = 10000
	}
	return &Responder{
		statusFunc: statusFunc,
		issuerFunc: issuerFunc,
		validity:   validity,
		cache:      make(map[string]cachedResponse),
		cacheSize:  cacheSize,
	}
}

// Handler returns an http.Handler for OCSP requests (GET and POST per RFC 5019).
func (r *Responder) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var reqBytes []byte
		var err error

		switch req.Method {
		case http.MethodPost:
			reqBytes, err = io.ReadAll(http.MaxBytesReader(w, req.Body, 8*1024))
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write(goocsp.MalformedRequestErrorResponse)
				return
			}
		case http.MethodGet:
			// RFC 5019 §2.1: GET with base64url path suffix: /ocsp/<base64url(DER)>
			// Trim the path prefix and any leading slash so we get just the encoded DER.
			encoded := strings.TrimPrefix(req.URL.Path, "/")
			if idx := strings.LastIndex(encoded, "/"); idx >= 0 {
				encoded = encoded[idx+1:]
			}
			if encoded == "" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write(goocsp.MalformedRequestErrorResponse)
				return
			}
			reqBytes, err = base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				// Try URL-safe base64 (some clients omit padding).
				reqBytes, err = base64.RawURLEncoding.DecodeString(encoded)
			}
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write(goocsp.MalformedRequestErrorResponse)
				return
			}
		default:
			w.Header().Set("Allow", "GET, POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		ocspReq, err := goocsp.ParseRequest(reqBytes)
		if err != nil {
			log.Printf("ocsp: malformed request: %v", err)
			w.Header().Set("Content-Type", "application/ocsp-response")
			w.WriteHeader(http.StatusOK)
			w.Write(goocsp.MalformedRequestErrorResponse)
			return
		}

		respBytes, err := r.respond(ocspReq)
		if err != nil {
			// Error responses are unsigned and carry no status for the
			// certificate, so a client cannot mistake them for "good".
			errResp := goocsp.TryLaterErrorResponse
			switch {
			case errors.Is(err, ErrUnknownIssuer):
				errResp = goocsp.UnauthorizedErrorResponse
			case errors.Is(err, errSigning):
				errResp = goocsp.InternalErrorErrorResponse
			}
			log.Printf("ocsp: no signed response (serial %s): %v", ocspReq.SerialNumber, err)
			w.Header().Set("Content-Type", "application/ocsp-response")
			w.WriteHeader(http.StatusOK)
			w.Write(errResp)
			return
		}

		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d, public", int(r.validity.Seconds())))
		w.WriteHeader(http.StatusOK)
		w.Write(respBytes)
	})
}

func (r *Responder) respond(req *goocsp.Request) ([]byte, error) {
	// The serial alone is not an identity: two CAs may issue the same one.
	cacheKey := fmt.Sprintf("%d|%x|%x|%s", req.HashAlgorithm, req.IssuerNameHash, req.IssuerKeyHash, req.SerialNumber)

	// Check cache.
	r.mu.RLock()
	if cached, ok := r.cache[cacheKey]; ok && time.Now().Before(cached.expiresAt) {
		r.mu.RUnlock()
		return cached.body, nil
	}
	r.mu.RUnlock()

	// Look up issuer by key hash.
	issuerCert, signer, err := r.issuerFunc(req.IssuerKeyHash)
	if err != nil {
		return nil, fmt.Errorf("issuer lookup: %w", err)
	}
	// Do not trust the lookup to have matched: the CertID names an issuer by
	// both hashes, and signing for any other CA than the one named would
	// vouch for a certificate this responder knows nothing about.
	if !issuerMatchesRequest(issuerCert, req) {
		return nil, fmt.Errorf("%w: CertID hashes do not match the resolved issuer", ErrUnknownIssuer)
	}

	// Look up certificate status.
	revoked, revokedAt, reason, err := r.statusFunc(req.SerialNumber, issuerCert)
	if err != nil {
		return nil, fmt.Errorf("status lookup: %w", err)
	}

	now := time.Now().UTC()
	template := goocsp.Response{
		SerialNumber: req.SerialNumber,
		ThisUpdate:   now,
		NextUpdate:   now.Add(r.validity),
		Certificate:  issuerCert,
		IssuerHash:   req.HashAlgorithm, // echo the client's CertID hash
	}

	if revoked {
		template.Status = goocsp.Revoked
		template.RevokedAt = revokedAt
		template.RevocationReason = reason
	} else {
		template.Status = goocsp.Good
	}

	respBytes, err := goocsp.CreateResponse(issuerCert, issuerCert, template, signer)
	if err != nil {
		return nil, fmt.Errorf("%w: create OCSP response: %v", errSigning, err)
	}

	// Cache the response.
	r.mu.Lock()
	if len(r.cache) >= r.cacheSize {
		// Simple eviction: clear all when full. Production would use LRU.
		r.cache = make(map[string]cachedResponse)
	}
	r.cache[cacheKey] = cachedResponse{
		serial:    req.SerialNumber.String(),
		body:      respBytes,
		expiresAt: now.Add(r.validity),
	}
	r.mu.Unlock()

	return respBytes, nil
}

// InvalidateCache removes a cached response for the given serial number.
// Call this when a certificate is revoked to ensure the next OCSP query
// returns the updated status.
// The cache is keyed per issuer as well, and this must work from the serial
// alone (ca.RevocationCacheInvalidator), so every issuer's entry for it goes.
func (r *Responder) InvalidateCache(serial *big.Int) {
	want := serial.String()
	r.mu.Lock()
	for k, c := range r.cache {
		if c.serial == want {
			delete(r.cache, k)
		}
	}
	r.mu.Unlock()
}

// issuerMatchesRequest checks req's issuerNameHash and issuerKeyHash against
// issuer, hashing with the algorithm the request names (RFC 6960 §4.1.1).
func issuerMatchesRequest(issuer *x509.Certificate, req *goocsp.Request) bool {
	if issuer == nil || !req.HashAlgorithm.Available() {
		return false
	}
	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		return false
	}
	nameHash := req.HashAlgorithm.New()
	nameHash.Write(issuer.RawSubject)
	keyHash := req.HashAlgorithm.New()
	keyHash.Write(spki.PublicKey.Bytes)
	return bytes.Equal(nameHash.Sum(nil), req.IssuerNameHash) && bytes.Equal(keyHash.Sum(nil), req.IssuerKeyHash)
}
