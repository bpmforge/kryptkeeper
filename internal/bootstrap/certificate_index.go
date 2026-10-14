// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// maxCertificatePageSize is the HTTP list contract's page cap. It is a
// property of the paged API only: internal callers that need the whole
// inventory use ForEachCertificate and are never subject to it (H2).
const maxCertificatePageSize = 100

// forEachChunk bounds how many order positions are scanned under one read
// lock. The lock is released between chunks so a full-inventory pass never
// stalls writers for the duration of the pass, and fn may call back into the
// provider without risking a recursive-RLock deadlock.
const forEachChunk = 1024

// certFilter is the shared predicate behind ListCertificates and
// ForEachCertificate, so a page and a full pass can never disagree on what
// a query matches.
type certFilter struct {
	caID, templateID, teamID, status, origin, managementState string
	qLower                                                    string
}

func newCertFilter(q CertificateListQuery) certFilter {
	return certFilter{
		caID: q.CAID, templateID: q.TemplateID, teamID: q.TeamID, status: q.Status,
		origin: q.Origin, managementState: q.ManagementState,
		qLower: strings.ToLower(q.Q),
	}
}

// matchesAll reports a filter that selects the whole inventory, which lets
// a page be served from the order index without scanning.
func (f certFilter) matchesAll() bool {
	return f.caID == "" && f.templateID == "" && f.teamID == "" && f.origin == "" && f.managementState == "" &&
		f.qLower == "" && f.status != "active" && f.status != "revoked"
}

func (f certFilter) matches(item *CertificateItem) bool {
	if f.caID != "" && item.CAID != f.caID {
		return false
	}
	if f.templateID != "" && item.TemplateID != f.templateID {
		return false
	}
	if f.teamID != "" && item.TeamID != f.teamID {
		return false
	}
	switch f.status {
	case "active":
		if item.RevokedAt != nil {
			return false
		}
	case "revoked":
		if item.RevokedAt == nil {
			return false
		}
	}
	if f.qLower != "" && !strings.Contains(strings.ToLower(item.CommonName), f.qLower) {
		return false
	}
	if f.origin != "" && item.Origin != f.origin {
		return false
	}
	if f.managementState != "" && item.ManagementState != f.managementState {
		return false
	}
	return true
}

// certOrderBefore is the total list order: newest first, fingerprint as the
// tiebreak (S-62).
func certOrderBefore(a, b *storedCert) bool {
	if a.item.CreatedAt != b.item.CreatedAt {
		return a.item.CreatedAt > b.item.CreatedAt
	}
	return a.item.FingerprintSHA256 < b.item.FingerprintSHA256
}

func countsAsActive(item *CertificateItem) bool {
	return item.RenewalStatus == string(RenewalStatusActive) && item.CAID != ""
}

func (p *caCertificateProvider) adjustActiveLocked(item *CertificateItem, delta int) {
	if !countsAsActive(item) {
		return
	}
	if p.activeByCA == nil {
		p.activeByCA = make(map[string]int)
	}
	p.activeByCA[item.CAID] += delta
	if p.activeByCA[item.CAID] <= 0 {
		delete(p.activeByCA, item.CAID)
	}
}

// putUnindexedLocked stores a cert without touching the derived indexes; the
// caller must follow with rebuildIndexLocked. Used by the startup load,
// where per-row index maintenance would be quadratic.
func (p *caCertificateProvider) putUnindexedLocked(fp string, sc *storedCert) {
	sc.item.KeyAlgorithmDisplay = keyAlgorithmDisplay(sc.x509)
	p.certs[fp] = sc
}

// rebuildIndexLocked recomputes every derived index from p.certs.
func (p *caCertificateProvider) rebuildIndexLocked() {
	p.order = make([]*storedCert, 0, len(p.certs))
	p.spkiIdx = make(map[string][]string)
	p.activeByCA = make(map[string]int)
	for _, sc := range p.certs {
		p.order = append(p.order, sc)
		sc.spki = ""
		if sc.x509 != nil {
			sc.spki = spkiHash(sc.x509)
			p.spkiIdx[sc.spki] = append(p.spkiIdx[sc.spki], sc.item.FingerprintSHA256)
		}
		p.adjustActiveLocked(&sc.item, 1)
	}
	slices.SortFunc(p.order, func(a, b *storedCert) int {
		switch {
		case certOrderBefore(a, b):
			return -1
		case certOrderBefore(b, a):
			return 1
		}
		return 0
	})
}

// ensureIndex rebuilds the derived indexes if p.certs was populated without
// them (a direct map write, as the package's own tests do). Production writes
// all go through addLocked, so this is a length comparison in practice.
func (p *caCertificateProvider) ensureIndex() {
	p.mu.RLock()
	stale := len(p.order) != len(p.certs)
	p.mu.RUnlock()
	if !stale {
		return
	}
	p.mu.Lock()
	if len(p.order) != len(p.certs) {
		p.rebuildIndexLocked()
	}
	p.mu.Unlock()
}

func (p *caCertificateProvider) orderPosLocked(sc *storedCert) int {
	return sort.Search(len(p.order), func(i int) bool { return !certOrderBefore(p.order[i], sc) })
}

// addLocked inserts sc under fp, keeping the order, key-reuse and per-CA
// count indexes in step. Key-reuse FLAGGING is separate (flagKeyReuse) so it
// only happens once the cert is durably recorded.
func (p *caCertificateProvider) addLocked(fp string, sc *storedCert) {
	if _, exists := p.certs[fp]; exists {
		p.removeLocked(fp)
	}
	if sc.x509 != nil {
		sc.spki = spkiHash(sc.x509)
	}
	sc.item.KeyAlgorithmDisplay = keyAlgorithmDisplay(sc.x509)
	p.certs[fp] = sc
	pos := p.orderPosLocked(sc)
	p.order = slices.Insert(p.order, pos, sc)
	if sc.spki != "" {
		if p.spkiIdx == nil {
			p.spkiIdx = make(map[string][]string)
		}
		p.spkiIdx[sc.spki] = append(p.spkiIdx[sc.spki], fp)
	}
	p.adjustActiveLocked(&sc.item, 1)
}

// removeLocked is the rollback path for a cert that could not be persisted.
func (p *caCertificateProvider) removeLocked(fp string) {
	sc, ok := p.certs[fp]
	if !ok {
		return
	}
	delete(p.certs, fp)
	pos := p.orderPosLocked(sc)
	if pos < len(p.order) && p.order[pos] == sc {
		p.order = slices.Delete(p.order, pos, pos+1)
	}
	if sc.spki != "" {
		holders := slices.DeleteFunc(p.spkiIdx[sc.spki], func(h string) bool { return h == fp })
		if len(holders) == 0 {
			delete(p.spkiIdx, sc.spki)
		} else {
			p.spkiIdx[sc.spki] = holders
		}
	}
	p.adjustActiveLocked(&sc.item, -1)
}

// setRenewalStatusLocked is the only place RenewalStatus changes after
// insertion, so the per-CA active count stays exact.
func (p *caCertificateProvider) setRenewalStatusLocked(sc *storedCert, status string) {
	p.adjustActiveLocked(&sc.item, -1)
	sc.item.RenewalStatus = status
	p.adjustActiveLocked(&sc.item, 1)
}

// flagKeyReuse marks every holder of fp's public key KEY_REUSE once a second
// holder exists. O(holders of that key), not O(inventory) (M1). Flags are
// additive and idempotent, exactly as the full scan it replaces.
func (p *caCertificateProvider) flagKeyReuse(fp string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	sc := p.certs[fp]
	if sc == nil || sc.spki == "" {
		return
	}
	p.markKeyReuseLocked(p.spkiIdx[sc.spki])
}

// flagAllKeyReuseLocked is the startup pass over the whole index.
func (p *caCertificateProvider) flagAllKeyReuseLocked() {
	for _, holders := range p.spkiIdx {
		p.markKeyReuseLocked(holders)
	}
}

func (p *caCertificateProvider) markKeyReuseLocked(holders []string) {
	if len(holders) < 2 {
		return
	}
	for _, hfp := range holders {
		stored := p.certs[hfp]
		if stored == nil || slices.Contains(stored.item.RiskFlags, "KEY_REUSE") {
			continue
		}
		stored.item.RiskFlags = append(stored.item.RiskFlags, "KEY_REUSE")
		stored.item.RiskScore += 20
		if stored.item.RiskScore > 100 {
			stored.item.RiskScore = 100
		}
		stored.item.Grade = computeGrade(stored.item.RiskScore)
	}
}

// ActiveCertCountsByCA reports active certificates per CA from the in-memory
// inventory, maintained incrementally on issue, renew, revoke and estate
// updates. It replaces a per-issuance GROUP BY over the certificates table.
func (p *caCertificateProvider) ActiveCertCountsByCA(_ context.Context) (map[string]int, error) {
	if p.hydrateErr != nil {
		return nil, p.hydrateErr
	}
	p.ensureIndex()
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[string]int, len(p.activeByCA))
	for k, v := range p.activeByCA {
		out[k] = v
	}
	return out, nil
}

// CertCountsByTemplate reports how many certificates (any status) were issued
// from each template id, for the templates list. Certificates with no template
// are not counted.
func (p *caCertificateProvider) CertCountsByTemplate(_ context.Context) (map[string]int, error) {
	if p.hydrateErr != nil {
		return nil, p.hydrateErr
	}
	p.ensureIndex()
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[string]int)
	for _, sc := range p.order {
		if sc.item.TemplateID != "" {
			out[sc.item.TemplateID]++
		}
	}
	return out, nil
}

// ForEachCertificate visits every certificate matching query, newest first,
// with no page cap (H2). Limit and Offset are ignored. The pass proceeds in
// chunks keyed by a (created_at, fingerprint) cursor and holds no lock while
// fn runs: fn may call back into the provider, and a certificate written
// mid-pass that sorts before the cursor is not visited.
func (p *caCertificateProvider) ForEachCertificate(ctx context.Context, query CertificateListQuery, fn func(CertificateItem) error) error {
	if p.hydrateErr != nil {
		return fmt.Errorf("certificate inventory unavailable: failed to load from database: %w", p.hydrateErr)
	}
	p.ensureIndex()
	f := newCertFilter(query)
	buf := make([]CertificateItem, 0, forEachChunk)
	var cursor *storedCert
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		buf = buf[:0]
		p.mu.RLock()
		start := 0
		if cursor != nil {
			// First position strictly after the cursor in list order.
			start = sort.Search(len(p.order), func(i int) bool { return certOrderBefore(cursor, p.order[i]) })
		}
		end := min(start+forEachChunk, len(p.order))
		for _, sc := range p.order[start:end] {
			if f.matches(&sc.item) {
				buf = append(buf, sc.item)
			}
		}
		done := end >= len(p.order)
		if end > start {
			cursor = p.order[end-1]
		}
		p.mu.RUnlock()

		for _, item := range buf {
			if err := fn(item); err != nil {
				return err
			}
		}
		if done {
			return nil
		}
	}
}
