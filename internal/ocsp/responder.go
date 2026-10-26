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
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/revsign"

	goocsp "golang.org/x/crypto/ocsp"

	// Register the CertID hash algorithms a client may name (RFC 6960 §4.1.1).
	_ "crypto/sha1"   //nolint:gosec // SHA-1 CertIDs are what most clients send
	_ "crypto/sha256" // SHA-256/384/512 (sha512 registers 384/512)
	_ "crypto/sha512"

	"kryptkeeper/internal/logging"
)

// ErrUnknownIssuer is what an IssuerLookupFunc returns when no CA this
// responder serves matches the request's issuer hashes. The responder answers
// it with the RFC 6960 "unauthorized" status (§2.3: the server is not
// authoritative for the requested certificate); any other lookup or status
// error is a "tryLater". Neither is ever a signed "good".
var ErrUnknownIssuer = errors.New("ocsp: issuer is not served by this responder")

// ErrExternalIssuer is what an IssuerLookupFunc returns when the issuer is an
// external CA: its OCSP is the upstream's, so the hub answers 404 rather than
// a signed or "unauthorized" response (W36-02).
var ErrExternalIssuer = errors.New("external_ca")

// errSigning marks a failure to sign a response: internalError, not tryLater.
var errSigning = errors.New("ocsp: signing failed")

// CertStatusFunc looks up a certificate's revocation status by serial number and issuer.
// Returns: revoked (bool), revokedAt (time), reasonCode (int), error.
type CertStatusFunc func(serial *big.Int, issuer *x509.Certificate) (revoked bool, revokedAt time.Time, reason int, err error)

// IssuerLookupFunc resolves an issuer certificate by key hash.
type IssuerLookupFunc func(keyHash []byte) (*x509.Certificate, crypto.Signer, error)

// IssuerStatusFunc reports whether the issuer itself (or an ancestor) is
// revoked. A revoked issuer makes every certificate under it read revoked.
type IssuerStatusFunc func(issuer *x509.Certificate) (revoked bool, at time.Time, reason int, err error)

// Responder is an OCSP responder that handles GET and POST requests.
type Responder struct {
	statusFunc   CertStatusFunc
	issuerStatus IssuerStatusFunc // optional (W23-35)
	issuerFunc   IssuerLookupFunc
	retiredFunc  IssuerLookupFunc // optional (W23-19)
	validity     time.Duration    // thisUpdate → nextUpdate window
	mu           sync.RWMutex
	cache        map[string]cachedResponse // keyed by hash alg | issuer name hash | issuer key hash | serial
	cacheSize    int
	lastStamp    string        // last revocation version stamp seen (W23-26)
	maxAge       time.Duration // Cache-Control max-age ceiling (W23-51)
}

// WithIssuerStatus installs the issuer-revoked check consulted before the
// per-certificate lookup.
func (r *Responder) WithIssuerStatus(fn IssuerStatusFunc) *Responder {
	r.issuerStatus = fn
	return r
}

// WithRetiredIssuers installs a second lookup for CA certificates a key
// rotation retired (W23-19). It is consulted only when the live lookup answers
// ErrUnknownIssuer, must resolve only while the retired key still exists, and
// returns the OLD certificate with the OLD signer so the response verifies
// against the issuer the CertID names. After the key is destroyed it returns
// ErrUnknownIssuer and the request is answered "unauthorized" (RFC 6960 2.3).
func (r *Responder) WithRetiredIssuers(fn IssuerLookupFunc) *Responder {
	r.retiredFunc = fn
	return r
}

// DefaultMaxAge is the default Cache-Control max-age on OCSP responses (US-047).
const DefaultMaxAge = 4 * time.Hour

// WithMaxAge sets the Cache-Control max-age. d < 0 is ignored (default kept).
// d == 0 means clients must not cache: the header becomes "no-cache, no-store".
func (r *Responder) WithMaxAge(d time.Duration) *Responder {
	if d >= 0 {
		r.maxAge = d
	}
	return r
}

// MaxAgeFromEnv reads KRYPTKEEPER_OCSP_MAX_AGE: a Go duration ("4h", "0s") or
// a bare integer of seconds ("14400"). Unset -> DefaultMaxAge; invalid or
// negative -> DefaultMaxAge, logged.
func MaxAgeFromEnv() time.Duration {
	const key = "KRYPTKEEPER_OCSP_MAX_AGE"
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return DefaultMaxAge
	}
	var d time.Duration
	if n, err := strconv.Atoi(raw); err == nil {
		d = time.Duration(n) * time.Second
	} else if pd, perr := time.ParseDuration(raw); perr == nil {
		d = pd
	} else {
		logging.Infof("ocsp: invalid %s %q, using default %s", key, raw, DefaultMaxAge)
		return DefaultMaxAge
	}
	if d < 0 {
		logging.Infof("ocsp: negative %s %q, using default %s", key, raw, DefaultMaxAge)
		return DefaultMaxAge
	}
	return d
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
		maxAge:     DefaultMaxAge,
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
			// RFC 6960 A.1 / RFC 5019 §2.1: GET {url}/{url-encoding of base64(DER)}.
			// Standard base64 contains '/', which clients send either
			// percent-encoded (%2F, e.g. nginx) or raw. Splitting the decoded
			// path on its last '/' truncated both, so take everything after
			// the /ocsp/ mount from the escaped path, then unescape once.
			encoded := ocspGETPayload(req.URL.EscapedPath())
			if unescaped, uerr := url.PathUnescape(encoded); uerr == nil {
				encoded = unescaped
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
			logging.Infof("ocsp: malformed request: %v", err)
			w.Header().Set("Content-Type", "application/ocsp-response")
			w.WriteHeader(http.StatusOK)
			w.Write(goocsp.MalformedRequestErrorResponse)
			return
		}

		respBytes, nextUpdate, err := r.respond(ocspReq)
		if errors.Is(err, ErrExternalIssuer) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"external_ca","message":"this CA is operated by an external issuer; use its own CRL and OCSP"}`))
			return
		}
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
			logging.Infof("ocsp: no signed response (serial %s): %v", ocspReq.SerialNumber, err)
			w.Header().Set("Content-Type", "application/ocsp-response")
			w.WriteHeader(http.StatusOK)
			w.Write(errResp)
			return
		}

		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Header().Set("Cache-Control", r.cacheControl(nextUpdate))
		w.WriteHeader(http.StatusOK)
		w.Write(respBytes)
	})
}

// cacheControl is the max-age ceiling clamped to the response's remaining
// validity (RFC 5019 section 6.2): a cached response late in its life must not
// tell proxies to keep it past its NextUpdate.
func (r *Responder) cacheControl(nextUpdate time.Time) string {
	if r.maxAge == 0 {
		return "no-cache, no-store"
	}
	age := r.maxAge
	if remaining := time.Until(nextUpdate); remaining < age {
		age = remaining
	}
	if age < 0 {
		age = 0
	}
	return fmt.Sprintf("max-age=%d, public", int(age.Seconds()))
}

// InvalidateAll empties the response cache. Called on CA key rotation: a
// cached response is signed by the previous key and keyed by issuer hashes the
// rotated CA no longer has.
func (r *Responder) InvalidateAll() {
	r.mu.Lock()
	r.cache = make(map[string]cachedResponse)
	r.mu.Unlock()
}

func (r *Responder) respond(req *goocsp.Request) (body []byte, nextUpdate time.Time, err error) {
	// The serial alone is not an identity: two CAs may issue the same one.
	cacheKey := fmt.Sprintf("%d|%x|%x|%s", req.HashAlgorithm, req.IssuerNameHash, req.IssuerKeyHash, req.SerialNumber)

	// Check cache.
	r.mu.RLock()
	if cached, ok := r.cache[cacheKey]; ok && time.Now().Before(cached.expiresAt) {
		r.mu.RUnlock()
		return cached.body, cached.expiresAt, nil
	}
	r.mu.RUnlock()

	// Look up issuer by key hash.
	issuerCert, signer, err := r.issuerFunc(req.IssuerKeyHash)
	retired := false
	if errors.Is(err, ErrUnknownIssuer) && r.retiredFunc != nil {
		issuerCert, signer, err = r.retiredFunc(req.IssuerKeyHash)
		retired = err == nil
	}
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("issuer lookup: %w", err)
	}
	// Do not trust the lookup to have matched: the CertID names an issuer by
	// both hashes, and signing for any other CA than the one named would
	// vouch for a certificate this responder knows nothing about.
	if !issuerMatchesRequest(issuerCert, req) {
		return nil, time.Time{}, fmt.Errorf("%w: CertID hashes do not match the resolved issuer", ErrUnknownIssuer)
	}

	// A revoked issuer revokes everything under it, whatever the store says.
	var revoked bool
	var revokedAt time.Time
	var reason int
	if r.issuerStatus != nil {
		revoked, revokedAt, reason, err = r.issuerStatus(issuerCert)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("issuer status lookup: %w", err)
		}
	}
	if !revoked {
		revoked, revokedAt, reason, err = r.statusFunc(req.SerialNumber, issuerCert)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("status lookup: %w", err)
		}
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

	respBytes, err := createResponse(issuerCert, signer, template)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("%w: create OCSP response: %v", errSigning, err)
	}

	// A response signed by a retired key is never cached: the cache would keep
	// serving it after the key is destroyed, when the answer is "unauthorized".
	if retired {
		return respBytes, template.NextUpdate, nil
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

	return respBytes, template.NextUpdate, nil
}

// SyncVersion drops all cached responses when stamp differs from the last
// stamp seen and returns true. The first call only records the stamp (false).
// W23-26: replicas share one DB, so a revoke on another replica shows up as a
// changed stamp here.
func (r *Responder) SyncVersion(stamp string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.lastStamp == "" {
		r.lastStamp = stamp
		return false
	}
	if stamp == r.lastStamp {
		return false
	}
	r.lastStamp = stamp
	r.cache = make(map[string]cachedResponse)
	return true
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
	if issuer == nil {
		return false
	}
	nameHash, keyHash, err := certIDHashes(req.HashAlgorithm, issuer)
	if err != nil {
		return false
	}
	return bytes.Equal(nameHash, req.IssuerNameHash) && bytes.Equal(keyHash, req.IssuerKeyHash)
}

// certIDHashes computes the RFC 6960 CertID issuerNameHash and issuerKeyHash.
func certIDHashes(h crypto.Hash, issuer *x509.Certificate) (nameHash, keyHash []byte, err error) {
	if !h.Available() {
		return nil, nil, fmt.Errorf("CertID hash %d unavailable", h)
	}
	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, nil, err
	}
	n := h.New()
	n.Write(issuer.RawSubject)
	k := h.New()
	k.Write(spki.PublicKey.Bytes)
	return n.Sum(nil), k.Sum(nil), nil
}

// ocspGETPayload returns the encoded request from an escaped GET path: the
// remainder after the first "/ocsp/" segment, or the last segment when the
// responder is mounted elsewhere.
func ocspGETPayload(escapedPath string) string {
	if _, after, ok := strings.Cut(escapedPath, "/ocsp/"); ok {
		return after
	}
	p := strings.TrimPrefix(escapedPath, "/")
	if idx := strings.LastIndex(p, "/"); idx >= 0 {
		return p[idx+1:]
	}
	return p
}

// createResponse signs the status answer. ML-DSA issuers cannot go through
// golang.org/x/crypto/ocsp (RSA/ECDSA only), so they use the hand-rolled
// encoder in internal/ca (W31-05).
func createResponse(issuer *x509.Certificate, signer crypto.Signer, t goocsp.Response) ([]byte, error) {
	if !revsign.IsMLDSAIssuer(issuer) {
		return goocsp.CreateResponse(issuer, issuer, t, signer)
	}
	nameHash, keyHash, err := certIDHashes(t.IssuerHash, issuer)
	if err != nil {
		return nil, err
	}
	return revsign.CreateOCSPResponseMLDSA(issuer, signer, revsign.OCSPResponseInput{
		SerialNumber:   t.SerialNumber,
		HashAlgorithm:  t.IssuerHash,
		IssuerNameHash: nameHash,
		IssuerKeyHash:  keyHash,
		Revoked:        t.Status == goocsp.Revoked,
		RevokedAt:      t.RevokedAt,
		Reason:         t.RevocationReason,
		ThisUpdate:     t.ThisUpdate,
		NextUpdate:     t.NextUpdate,
	})
}
