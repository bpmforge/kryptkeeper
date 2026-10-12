// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package crl

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// RevokedCert represents a single revoked certificate entry for CRL generation.
type RevokedCert struct {
	SerialNumber *big.Int
	RevokedAt    time.Time
	ReasonCode   int
}

// RevokedCertsFunc returns the list of revoked certificates for a given CA.
type RevokedCertsFunc func(caID string) ([]RevokedCert, error)

// CALookupFunc resolves a CA certificate and signer by CA ID.
type CALookupFunc func(caID string) (*x509.Certificate, crypto.Signer, error)

// GeneratedCRL holds a generated CRL in both DER and PEM formats.
type GeneratedCRL struct {
	CAAID      string
	DER        []byte
	PEM        []byte
	Number     *big.Int
	ThisUpdate time.Time
	NextUpdate time.Time
}

// Generator produces CRLs for Certificate Authorities.
type Generator struct {
	revokedFunc RevokedCertsFunc
	caFunc      CALookupFunc
	validity    time.Duration // thisUpdate → nextUpdate
	mu          sync.RWMutex
	crls        map[string]*GeneratedCRL // keyed by CA ID
	crlNumbers  map[string]*big.Int      // monotonic CRL number per CA
}

// NewGenerator creates a CRL generator.
func NewGenerator(revokedFunc RevokedCertsFunc, caFunc CALookupFunc, validity time.Duration) *Generator {
	if validity == 0 {
		validity = 24 * time.Hour
	}
	return &Generator{
		revokedFunc: revokedFunc,
		caFunc:      caFunc,
		validity:    validity,
		crls:        make(map[string]*GeneratedCRL),
		crlNumbers:  make(map[string]*big.Int),
	}
}

// Generate creates a new CRL for the given CA ID.
func (g *Generator) Generate(caID string) (*GeneratedCRL, error) {
	caCert, signer, err := g.caFunc(caID)
	if err != nil {
		return nil, fmt.Errorf("ca lookup: %w", err)
	}

	revokedCerts, err := g.revokedFunc(caID)
	if err != nil {
		return nil, fmt.Errorf("revoked certs lookup: %w", err)
	}

	revokedEntries := make([]pkix.RevokedCertificate, 0, len(revokedCerts))
	for _, rc := range revokedCerts {
		revokedEntries = append(revokedEntries, pkix.RevokedCertificate{
			SerialNumber:   rc.SerialNumber,
			RevocationTime: rc.RevokedAt,
		})
	}

	g.mu.Lock()
	crlNumber, ok := g.crlNumbers[caID]
	if !ok {
		crlNumber = big.NewInt(0)
	}
	crlNumber = new(big.Int).Add(crlNumber, big.NewInt(1))
	g.crlNumbers[caID] = crlNumber
	g.mu.Unlock()

	now := time.Now().UTC()
	template := &x509.RevocationList{
		Number:                    crlNumber,
		ThisUpdate:                now,
		NextUpdate:                now.Add(g.validity),
		RevokedCertificateEntries: toRevocationEntries(revokedCerts),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, template, caCert, signer)
	if err != nil {
		return nil, fmt.Errorf("create CRL: %w", err)
	}

	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})

	generated := &GeneratedCRL{
		CAAID:      caID,
		DER:        crlDER,
		PEM:        crlPEM,
		Number:     crlNumber,
		ThisUpdate: now,
		NextUpdate: now.Add(g.validity),
	}

	g.mu.Lock()
	g.crls[caID] = generated
	g.mu.Unlock()

	return generated, nil
}

// GetCRL returns the most recently generated CRL for a CA, or nil.
func (g *Generator) GetCRL(caID string) *GeneratedCRL {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.crls[caID]
}

// InvalidateCache implements ca.RevocationCacheInvalidator, the same seam
// internal/ocsp.Responder uses, so cmd/kryptkeeper/main.go can wire this
// Generator into the very revoke call sites that already invalidate OCSP's
// cache -- one revoke now drops both.
//
// The interface only carries the revoked serial, not its owning CA (it was
// designed for OCSP's per-serial cache), so this generator cannot be told
// directly which cached CRL to drop. It instead re-queries revokedFunc for
// every CA it currently has a cached CRL for -- by the time a caller invokes
// this, the revocation is already persisted in the store (Revoke happens
// before InvalidateCache at every call site) -- and evicts only the CA(s)
// whose CURRENT revoked list actually contains the serial. An unrelated CA's
// revokedFunc will not return the serial, so its cache is left untouched.
// This is bounded work (one query per already-cached CA, on a revoke event,
// not per request) -- the same "poll, not unbounded" posture used elsewhere
// in bootstrap for per-tick reads.
func (g *Generator) InvalidateCache(serial *big.Int) {
	if serial == nil {
		return
	}
	g.mu.RLock()
	caIDs := make([]string, 0, len(g.crls))
	for caID := range g.crls {
		caIDs = append(caIDs, caID)
	}
	g.mu.RUnlock()

	for _, caID := range caIDs {
		revoked, err := g.revokedFunc(caID)
		if err != nil {
			// Fail closed on the side of staleness, not by evicting a cache
			// we can't confirm belongs to this serial -- the entry will
			// still self-correct at its NextUpdate.
			continue
		}
		for _, rc := range revoked {
			if rc.SerialNumber != nil && rc.SerialNumber.Cmp(serial) == 0 {
				g.mu.Lock()
				delete(g.crls, caID)
				g.mu.Unlock()
				break
			}
		}
	}
}

// Handler returns an HTTP handler that serves CRLs at /crl/{ca-id}.crl.
// This is a public endpoint — no authentication required.
func (g *Generator) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Extract CA ID from path: /crl/{ca-id}.crl
		path := r.URL.Path
		if len(path) < 6 || path[:5] != "/crl/" || path[len(path)-4:] != ".crl" {
			http.NotFound(w, r)
			return
		}
		caID := path[5 : len(path)-4]
		if caID == "" {
			http.NotFound(w, r)
			return
		}

		// W19-29: restores the cache W19-01 had to strip. Regenerating on
		// EVERY request was correct at the time -- nothing ever evicted a
		// stale cache entry on revoke -- but made this endpoint's cost
		// O(revocations) per fetch. Freshness is now owned by two
		// independent triggers instead: InvalidateCache (wired at the same
		// revoke call sites OCSP's cache invalidation uses, see its doc
		// comment) drops an entry the instant its CA's revocation list
		// changes, and the NextUpdate check below is the backstop -- a CRL
		// is NEVER served past its own NextUpdate, cache-hit or not,
		// regardless of whether an invalidation call was ever wired at all.
		now := time.Now().UTC()
		cached := g.GetCRL(caID)
		target := cached
		if target == nil || !now.Before(target.NextUpdate) {
			generated, err := g.Generate(caID)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			target = generated
		}

		// Serve DER format by default (standard CRL distribution format).
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d, public", int(g.validity.Seconds()/2)))
		w.WriteHeader(http.StatusOK)
		w.Write(target.DER)
	})
}

func toRevocationEntries(certs []RevokedCert) []x509.RevocationListEntry {
	entries := make([]x509.RevocationListEntry, 0, len(certs))
	for _, rc := range certs {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   rc.SerialNumber,
			RevocationTime: rc.RevokedAt,
			ReasonCode:     rc.ReasonCode,
		})
	}
	return entries
}
