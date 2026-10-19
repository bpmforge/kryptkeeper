// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package crl

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"kryptkeeper/internal/revsign"
)

// Event actions (W23-49).
const (
	ActionGenerate      = "crl.generate"
	ActionDeltaGenerate = "crl.delta_generate"
	ActionStale         = "crl.stale"
)

// Event is an audit/alert notification from the generator.
type Event struct {
	Action, CAID, Detail string
	Failure              bool
}

type baseInfo struct {
	Number     *big.Int
	ThisUpdate time.Time
}

var (
	oidDeltaCRLIndicator = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidFreshestCRL       = asn1.ObjectIdentifier{2, 5, 29, 46}
)

// deltaOverlap makes a delta also repeat revocations just before the base's
// ThisUpdate; duplicates of base entries are harmless.
const deltaOverlap = 5 * time.Second

// WithEventSink sets the callback for generation and staleness events. It is
// called after the generator's locks are released. Call before serving.
func (g *Generator) WithEventSink(fn func(Event)) *Generator {
	g.sink = fn
	return g
}

// WithDelta enables delta CRLs. publicBase "" means no Freshest CRL pointer is
// put into the base CRL. Call before serving.
func (g *Generator) WithDelta(deltaValidity time.Duration, publicBase string) *Generator {
	if deltaValidity > 0 {
		g.deltaValidity = deltaValidity
		g.publicBase = strings.TrimRight(publicBase, "/")
	}
	return g
}

func (g *Generator) emit(ev Event) {
	if g.sink != nil {
		g.sink(ev)
	}
}

func (g *Generator) emitStale(caID string, c *GeneratedCRL) {
	kind := "full"
	if c.IsDelta {
		kind = "delta"
	}
	g.emit(Event{Action: ActionStale, CAID: caID, Failure: true,
		Detail: fmt.Sprintf("kind=%s number=%s nextUpdate=%s", kind, c.Number, c.NextUpdate.Format(time.RFC3339))})
}

func (g *Generator) deltaURL(caID string) string {
	return g.publicBase + "/crl/" + url.PathEscape(caID) + "/delta.crl"
}

// GenerateDelta signs a delta CRL relative to the CA's latest full CRL,
// generating that base first when there is none or it has expired.
func (g *Generator) GenerateDelta(caID string) (*GeneratedCRL, error) {
	d, err := g.generateDelta(caID)
	if err != nil {
		g.emit(Event{Action: ActionDeltaGenerate, CAID: caID, Detail: err.Error(), Failure: true})
		return nil, err
	}
	g.emit(Event{Action: ActionDeltaGenerate, CAID: caID,
		Detail: fmt.Sprintf("base=%s entries=%d bytes=%d", d.BaseNumber, d.entries, len(d.DER))})
	return d.GeneratedCRL, nil
}

type deltaResult struct {
	*GeneratedCRL
	entries int
}

func (g *Generator) generateDelta(caID string) (*deltaResult, error) {
	if g.deltaValidity <= 0 {
		return nil, fmt.Errorf("delta CRLs are not enabled")
	}
	g.mu.RLock()
	base, haveBase := g.bases[caID]
	cached := g.crls[caID]
	g.mu.RUnlock()
	if !haveBase || cached == nil || !time.Now().Before(cached.NextUpdate) {
		if _, err := g.Generate(caID); err != nil {
			return nil, err
		}
		g.mu.RLock()
		base = g.bases[caID]
		g.mu.RUnlock()
	}

	caCert, signer, err := g.caFunc(caID)
	if err != nil {
		return nil, fmt.Errorf("ca lookup: %w", err)
	}
	revoked, err := g.revokedFunc(caID)
	if err != nil {
		return nil, fmt.Errorf("revoked certs lookup: %w", err)
	}
	revoked = withoutSerial(revoked, caCert.SerialNumber)
	cutoff := base.ThisUpdate.Add(-deltaOverlap)
	var recent []RevokedCert
	for _, rc := range revoked {
		if rc.RevokedAt.After(cutoff) {
			recent = append(recent, rc)
		}
	}

	number, err := g.nextNumber(caID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	indicator, err := deltaIndicatorExtension(base.Number)
	if err != nil {
		return nil, err
	}
	template := &x509.RevocationList{
		Number:                    number,
		ThisUpdate:                now,
		NextUpdate:                now.Add(g.deltaValidity),
		RevokedCertificateEntries: toRevocationEntries(recent),
		ExtraExtensions:           []pkix.Extension{indicator},
	}
	der, err := revsign.CreateRevocationList(rand.Reader, template, caCert, signer)
	if err != nil {
		return nil, fmt.Errorf("create delta CRL: %w", err)
	}
	out := &GeneratedCRL{
		CAAID:      caID,
		IsDelta:    true,
		BaseNumber: base.Number,
		DER:        der,
		PEM:        pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}),
		Number:     number,
		ThisUpdate: now,
		NextUpdate: template.NextUpdate,
	}
	g.mu.Lock()
	if cur := g.deltas[caID]; cur == nil || cur.Number.Cmp(number) < 0 {
		g.deltas[caID] = out
	}
	g.mu.Unlock()
	return &deltaResult{GeneratedCRL: out, entries: len(recent)}, nil
}

// GetDelta returns the most recently generated delta CRL for a CA, or nil.
func (g *Generator) GetDelta(caID string) *GeneratedCRL {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.deltas[caID]
}

func (g *Generator) serveDelta(w http.ResponseWriter, r *http.Request, caID string) {
	if g.deltaValidity <= 0 {
		http.NotFound(w, r)
		return
	}
	target := g.GetDelta(caID)
	if target == nil || !time.Now().Before(target.NextUpdate) {
		if target != nil {
			g.emitStale(caID, target)
		}
		d, err := g.GenerateDelta(caID)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		target = d
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d, public", int(g.deltaValidity.Seconds()/2)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(target.DER)
}

// parseCRLPath maps "/crl/{ca}.crl" to (ca,false) and "/crl/{ca}/delta.crl"
// to (ca,true). The CA id may not be empty or contain a slash or "..".
func parseCRLPath(p string) (caID string, delta, ok bool) {
	rest, found := strings.CutPrefix(p, "/crl/")
	if !found {
		return "", false, false
	}
	if id, isDelta := strings.CutSuffix(rest, "/delta.crl"); isDelta {
		caID, delta = id, true
	} else if id, isFull := strings.CutSuffix(rest, ".crl"); isFull {
		caID = id
	} else {
		return "", false, false
	}
	if !validCAID(caID) {
		return "", false, false
	}
	return caID, delta, true
}

// validCAID: not empty, no slash or backslash, no "..".
func validCAID(caID string) bool {
	return caID != "" && !strings.ContainsAny(caID, "/\\") && !strings.Contains(caID, "..")
}

// deltaIndicatorExtension is the critical Delta CRL Indicator (RFC 5280
// 5.2.4): the base CRL number as an INTEGER.
func deltaIndicatorExtension(base *big.Int) (pkix.Extension, error) {
	v, err := asn1.Marshal(base)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshal delta indicator: %w", err)
	}
	return pkix.Extension{Id: oidDeltaCRLIndicator, Critical: true, Value: v}, nil
}

// freshestCRLExtension is the non-critical Freshest CRL pointer (RFC 5280
// 5.2.6), CRLDistributionPoints-encoded with a single URI.
func freshestCRLExtension(uri string) pkix.Extension {
	u := tlv(0x86, []byte(uri)) // uniformResourceIdentifier [6]
	full := tlv(0xA0, u)        // fullName [0]
	dpName := tlv(0xA0, full)   // distributionPoint [0]
	dp := tlv(0x30, dpName)     // DistributionPoint
	return pkix.Extension{Id: oidFreshestCRL, Value: tlv(0x30, dp)}
}

func tlv(tag byte, val []byte) []byte {
	n := len(val)
	out := []byte{tag}
	switch {
	case n < 128:
		out = append(out, byte(n))
	case n < 256:
		out = append(out, 0x81, byte(n))
	case n < 65536:
		out = append(out, 0x82, byte(n>>8), byte(n))
	default:
		out = append(out, 0x83, byte(n>>16), byte(n>>8), byte(n))
	}
	return append(out, val...)
}
