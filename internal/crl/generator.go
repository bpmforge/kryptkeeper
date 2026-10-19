// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package crl

import (
	"context"
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

	"kryptkeeper/internal/revsign"
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
	IsDelta    bool     // true for a delta CRL (W23-49)
	BaseNumber *big.Int // delta only: the base CRL number in the Delta CRL Indicator
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
	crlNumbers  map[string]*big.Int      // in-memory fallback counter, used only when allocator == nil
	allocator   NumberAllocator          // DB-backed numbers (nil: in-memory fallback)
	lastStamp   string                   // last revocation version stamp seen (W23-26)

	// Shard CRL state (W23-50). shardN == 0 means sharding is off.
	shardN    int
	shardBase string
	shards    map[string][]*GeneratedCRL // keyed by CA ID, index = shard

	// Delta CRL state (W23-49). deltaValidity == 0 means delta mode is off.
	deltaValidity time.Duration
	publicBase    string
	bases         map[string]baseInfo      // latest full CRL per CA
	deltas        map[string]*GeneratedCRL // latest delta per CA
	sink          func(Event)
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
		shards:      make(map[string][]*GeneratedCRL),
		bases:       make(map[string]baseInfo),
		deltas:      make(map[string]*GeneratedCRL),
	}
}

// Generate creates a new CRL for the given CA ID.
func (g *Generator) Generate(caID string) (*GeneratedCRL, error) {
	gen, err := g.generate(caID)
	if err != nil {
		g.emit(Event{Action: ActionGenerate, CAID: caID, Detail: err.Error(), Failure: true})
		return nil, err
	}
	g.emit(Event{Action: ActionGenerate, CAID: caID,
		Detail: fmt.Sprintf("number=%s bytes=%d", gen.Number, len(gen.DER))})
	return gen, nil
}

func (g *Generator) generate(caID string) (*GeneratedCRL, error) {
	caCert, signer, err := g.caFunc(caID)
	if err != nil {
		return nil, fmt.Errorf("ca lookup: %w", err)
	}

	// Captured BEFORE listing: a revocation landing between the listing and
	// the signing is then newer than this base and shows up in the next delta.
	now := time.Now().UTC()
	revokedCerts, err := g.revokedFunc(caID)
	if err != nil {
		return nil, fmt.Errorf("revoked certs lookup: %w", err)
	}
	revokedCerts = withoutSerial(revokedCerts, caCert.SerialNumber)

	crlNumber, err := g.nextNumber(caID)
	if err != nil {
		return nil, err
	}
	template := &x509.RevocationList{
		Number:                    crlNumber,
		ThisUpdate:                now,
		NextUpdate:                now.Add(g.validity),
		RevokedCertificateEntries: toRevocationEntries(revokedCerts),
	}
	if g.deltaValidity > 0 && g.publicBase != "" {
		template.ExtraExtensions = []pkix.Extension{freshestCRLExtension(g.deltaURL(caID))}
	}

	crlDER, err := revsign.CreateRevocationList(rand.Reader, template, caCert, signer)
	if err != nil {
		return nil, fmt.Errorf("create CRL: %w", err)
	}

	generated := &GeneratedCRL{
		CAAID:      caID,
		DER:        crlDER,
		PEM:        pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER}),
		Number:     crlNumber,
		ThisUpdate: now,
		NextUpdate: now.Add(g.validity),
	}

	g.mu.Lock()
	// Never let a slower, older generation overwrite a newer one.
	if cur := g.crls[caID]; cur == nil || cur.Number.Cmp(crlNumber) < 0 {
		g.crls[caID] = generated
		g.bases[caID] = baseInfo{Number: crlNumber, ThisUpdate: now}
	}
	g.mu.Unlock()

	return generated, nil
}

// nextNumber takes the next CRL number for scope; base and delta CRLs of a CA
// share one monotonic sequence. With an allocator the sequence lives in the DB
// (monotonic across restarts and replicas, RFC 5280 5.2.3). A DB failure fails
// the generation: falling back to the in-memory counter would hand out numbers
// that can go backwards.
func (g *Generator) nextNumber(scope string) (*big.Int, error) {
	if g.allocator != nil {
		return g.allocator.Next(context.Background(), scope)
	}
	// In-memory path: only for a Generator with no database configured.
	g.mu.Lock()
	defer g.mu.Unlock()
	n, ok := g.crlNumbers[scope]
	if !ok {
		n = big.NewInt(0)
	}
	n = new(big.Int).Add(n, big.NewInt(1))
	g.crlNumbers[scope] = n
	return n, nil
}

// GetCRL returns the most recently generated CRL for a CA, or nil.
func (g *Generator) GetCRL(caID string) *GeneratedCRL {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.crls[caID]
}

// SyncVersion drops every cached CRL when stamp differs from the last stamp
// seen and returns true. The first call only records the stamp (false).
// crlNumbers is kept so CRL numbers stay monotonic across the reset. W23-26:
// replicas share one DB, so a revoke on another replica shows up as a changed
// stamp here.
func (g *Generator) SyncVersion(stamp string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.lastStamp == "" {
		g.lastStamp = stamp
		return false
	}
	if stamp == g.lastStamp {
		return false
	}
	g.lastStamp = stamp
	if g.deltaValidity > 0 {
		// Delta mode: the full CRL ages to its NextUpdate, the delta follows
		// the revocations (W23-49).
		g.deltas = make(map[string]*GeneratedCRL)
		return true
	}
	g.crls = make(map[string]*GeneratedCRL)
	g.shards = make(map[string][]*GeneratedCRL)
	return true
}

// InvalidateCA drops every cached CRL (full, base and delta) for caID so the
// next request is signed by the CA's current key. Called on CA key rotation;
// the CRL number sequence is kept so numbers stay monotonic across the swap.
func (g *Generator) InvalidateCA(caID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.crls, caID)
	delete(g.bases, caID)
	delete(g.deltas, caID)
}

// InvalidateAll drops every cached CRL (full, base, delta and shards) so the
// next request is regenerated. Called when a CA is revoked: the parent's CRL
// gains an entry and children's cached lists are stale. CRL numbers are kept.
func (g *Generator) InvalidateAll() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.crls = make(map[string]*GeneratedCRL)
	g.shards = make(map[string][]*GeneratedCRL)
	g.bases = make(map[string]baseInfo)
	g.deltas = make(map[string]*GeneratedCRL)
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
	caIDs := make([]string, 0, len(g.crls)+len(g.shards))
	for caID := range g.crls {
		caIDs = append(caIDs, caID)
	}
	for caID := range g.shards {
		if _, dup := g.crls[caID]; !dup {
			caIDs = append(caIDs, caID)
		}
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
				if g.deltaValidity > 0 {
					delete(g.deltas, caID)
				} else {
					delete(g.crls, caID)
					delete(g.shards, caID)
				}
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

		req, ok := parseCRLRequest(r.URL.Path)
		if !ok {
			http.NotFound(w, r)
			return
		}
		caID := req.CAID
		if req.Shard >= 0 {
			g.serveShard(w, r, caID, req.Shard)
			return
		}
		if req.Delta {
			g.serveDelta(w, r, caID)
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
			if target != nil {
				g.emitStale(caID, target)
			}
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

// withoutSerial drops the CA's own certificate serial: a revoked root keeps a
// self-keyed timestamp record (W23-34) that must not appear in its own CRL.
func withoutSerial(certs []RevokedCert, own *big.Int) []RevokedCert {
	if own == nil {
		return certs
	}
	out := make([]RevokedCert, 0, len(certs))
	for _, c := range certs {
		if c.SerialNumber != nil && c.SerialNumber.Cmp(own) == 0 {
			continue
		}
		out = append(out, c)
	}
	return out
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

func (g *Generator) serveShard(w http.ResponseWriter, r *http.Request, caID string, i int) {
	if g.shardN <= 1 || i >= g.shardN {
		http.NotFound(w, r)
		return
	}
	target := g.GetShard(caID, i)
	if target == nil {
		set, err := g.GenerateAllShards(caID)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		target = set[i]
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d, public", int(g.validity.Seconds()/2)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(target.DER)
}
