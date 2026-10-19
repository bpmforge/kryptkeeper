// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"kryptkeeper/internal/logging"
	"slices"
	"sync"
	"time"

	"kryptkeeper/internal/discovery/scanner"
)

// hubCASource returns every CA certificate this hub owns (roots and
// intermediates, any status: a retired CA's certificates are still ours).
type hubCASource func(ctx context.Context) ([]*x509.Certificate, error)

// hubCASetter is implemented by discovery providers that classify scanned
// chains; it follows the winRMScanSetter wiring pattern.
type hubCASetter interface {
	SetHubCASource(hubCASource)
}

// hubCAsFromProvider reads every CA's certificate through the CA provider,
// paging so a large hierarchy is not truncated at the default page size.
func hubCAsFromProvider(p CAProvider) hubCASource {
	return func(ctx context.Context) ([]*x509.Certificate, error) {
		var out []*x509.Certificate
		const page = 100
		for offset := 0; ; offset += page {
			res, err := p.ListCAs(ctx, CAListQuery{Limit: page, Offset: offset})
			if err != nil {
				return nil, err
			}
			for _, item := range res.Items {
				out = append(out, parseCACertsPEM(item.CertificatePEM)...)
			}
			if offset+page >= res.Total || len(res.Items) == 0 {
				return out, nil
			}
		}
	}
}

func parseCACertsPEM(s string) []*x509.Certificate {
	var out []*x509.Certificate
	rest := []byte(s)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			out = append(out, c)
		}
	}
}

// discoveryTrust holds what a discovery store needs to classify the chains it
// persists. The zero value is usable: with no hub source it judges against the
// system roots only. systemRoots is a field so tests inject a pool instead of
// depending on the machine's real roots.
type discoveryTrust struct {
	mu          sync.RWMutex
	hubCAs      hubCASource
	authorized  authorizedIssuerSource
	systemRoots func() (*x509.CertPool, error)

	sysOnce sync.Once
	sys     *x509.CertPool
	sysErr  error
}

// authorizedIssuerSource returns the issuers a stored tenant has declared.
type authorizedIssuerSource func(ctx context.Context, tenant string) ([]AuthorizedIssuer, error)

func (t *discoveryTrust) SetAuthorizedSource(fn authorizedIssuerSource) {
	t.mu.Lock()
	t.authorized = fn
	t.mu.Unlock()
}

// dbAuthorizedSource reads a tenant's authorized issuers from db. The schema is
// ensured on first use so a database the migrations have not reached still
// answers (an empty list), rather than leaving every issuer class unjudged.
func dbAuthorizedSource(db *sql.DB, ph func(int) string) authorizedIssuerSource {
	store := &dbAuthorizedIssuerStore{db: db, ph: ph}
	var once sync.Once
	var ensureErr error
	return func(ctx context.Context, tenant string) ([]AuthorizedIssuer, error) {
		once.Do(func() { ensureErr = store.EnsureSchema(ctx) })
		if ensureErr != nil {
			return nil, ensureErr
		}
		return store.List(ctx, &tenant)
	}
}

func (t *discoveryTrust) SetHubCASource(fn hubCASource) {
	t.mu.Lock()
	t.hubCAs = fn
	t.mu.Unlock()
}

// system loads the platform roots once. On darwin/windows Go verifies against
// the platform verifier whenever Roots is the system pool (it still honours
// CurrentTime, but applies the OS's own policy); Linux uses Go's verifier.
func (t *discoveryTrust) system() (*x509.CertPool, error) {
	t.sysOnce.Do(func() {
		load := t.systemRoots
		if load == nil {
			load = x509.SystemCertPool
		}
		t.sys, t.sysErr = load()
	})
	return t.sys, t.sysErr
}

// classify stamps every TLS-served endpoint in results with its trust verdict
// (scanner.ApplyTrust). It runs before any DB transaction opens so the CA
// provider read never sits behind a write lock. When a verdict cannot be
// reached honestly (system roots unreadable, hub CAs unreadable) the chain is
// left unclassified -- stored as unknown -- rather than judged against an
// incomplete anchor set, which would mislabel a managed or public cert as
// someone else's private one. Chain CA marking still happens either way.
func (t *discoveryTrust) classify(ctx context.Context, results []scanner.DiscoveredEndpoint) {
	if !anyCerts(results) {
		return
	}
	anchors, ok := t.anchors(ctx)
	now := time.Now()
	for i := range results {
		if !ok {
			markChainCAs(&results[i])
			continue
		}
		scanner.ApplyTrust(&results[i], anchors, now)
		scanner.ApplyIssuerClass(&results[i], anchors, now)
	}
}

func (t *discoveryTrust) anchors(ctx context.Context) (scanner.TrustAnchors, bool) {
	tenant := discoveryStampTenant(ctx)
	sys, err := t.system()
	if err != nil || sys == nil {
		logging.Warnf("discovery: system roots unavailable, leaving served chains unclassified: %v", err)
		return scanner.TrustAnchors{}, false
	}
	t.mu.RLock()
	src, authSrc := t.hubCAs, t.authorized
	t.mu.RUnlock()
	var hub []*x509.Certificate
	if src != nil {
		if hub, err = src(ctx); err != nil {
			logging.Warnf("discovery: hub CAs unavailable, leaving served chains unclassified: %v", err)
			return scanner.TrustAnchors{}, false
		}
	}
	a := scanner.TrustAnchors{System: sys, Hub: hub, IssuerClassKnown: true}
	if authSrc != nil {
		list, err := authSrc(ctx, tenant)
		if err != nil {
			// trust_class does not depend on the declared issuers, so the chain
			// is still judged; only issuer_class is left unset (and keeps its
			// previous value in the database) rather than guessed.
			logging.Warnf("discovery: authorized issuers unavailable, leaving issuer class unjudged: %v", err)
			a.IssuerClassKnown = false
		} else {
			a.Authorized, a.IssuerRules = authorizedIssuerAnchors(list)
		}
	}
	return a, true
}

// anyCerts reports whether any result carries a certificate: served chains get
// a trust verdict, every other source (SSH files, stores) an issuer class.
func anyCerts(results []scanner.DiscoveredEndpoint) bool {
	for _, ep := range results {
		if len(ep.Certs) > 0 {
			return true
		}
	}
	return false
}

func anyServed(results []scanner.DiscoveredEndpoint) bool {
	for _, ep := range results {
		if len(ep.Certs) > 0 && ep.Certs[0].Served {
			return true
		}
	}
	return false
}

func markChainCAs(ep *scanner.DiscoveredEndpoint) {
	if len(ep.Certs) == 0 || !ep.Certs[0].Served {
		return
	}
	for i := 1; i < len(ep.Certs); i++ {
		ep.Certs[i].ChainCA = true
	}
}

// TrustClassCounts is a per-class tally of discovery-found leaf certificates.
type TrustClassCounts struct {
	Managed      int `json:"managed"`
	Public       int `json:"public"`
	PrivateOther int `json:"private_other"`
	SelfSigned   int `json:"self_signed"`
	Unknown      int `json:"unknown"`
}

// add tallies n certs of class; empty or out-of-vocabulary counts as unknown.
func (c *TrustClassCounts) add(class string, n int) {
	switch class {
	case scanner.TrustManaged:
		c.Managed += n
	case scanner.TrustPublic:
		c.Public += n
	case scanner.TrustPrivateOther:
		c.PrivateOther += n
	case scanner.TrustSelfSigned:
		c.SelfSigned += n
	default:
		c.Unknown += n
	}
}

// trustClassPredicate is the SQL condition selecting rows of one class from
// the certificates table aliased alias. A hub-managed row never carries a
// discovery verdict (discovery does not write managed rows), so it counts as
// managed; every other class excludes them. class is interpolated, so it is
// re-checked to be a member of the closed vocabulary.
func trustClassPredicate(class, alias, activeCond, notCA string) string {
	if !scanner.IsTrustClass(class) {
		return "1 = 0"
	}
	col := alias + ".trust_class"
	var match string
	switch class {
	case scanner.TrustManaged:
		match = "(" + col + " = 'managed' OR " + alias + ".management_state = 'managed')"
	case scanner.TrustUnknown:
		match = "(" + alias + ".management_state <> 'managed' AND (" + col + " IS NULL OR " + col + " = '' OR " + col + " = 'unknown'))"
	default:
		match = "(" + alias + ".management_state <> 'managed' AND " + col + " = '" + class + "')"
	}
	return activeCond + " AND " + notCA + " AND " + match
}

func (s *sqliteDiscoveryStore) SetHubCASource(fn hubCASource)   { s.trust.SetHubCASource(fn) }
func (s *postgresDiscoveryStore) SetHubCASource(fn hubCASource) { s.trust.SetHubCASource(fn) }

// SetHubCASource installs the hub CA reader on the DB provider's store.
func (p *dbDiscoveryProvider) SetHubCASource(fn hubCASource) {
	if s, ok := p.store.(hubCASetter); ok {
		s.SetHubCASource(fn)
	}
}

// SetHubCASource remembers the reader and hands it to the DB provider
// whenever that provider is (lazily) constructed.
func (c *configuredDiscoveryProvider) SetHubCASource(fn hubCASource) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hubCAs = fn
	if s, ok := c.dbProvider.(hubCASetter); ok && c.dbProvider != nil {
		s.SetHubCASource(fn)
	}
}

// effectiveTrustClass is the class a certificate presents through the API.
// Discovery never writes managed rows (see discoveredCertConflictUpdate*), so a
// hub-managed cert has no stored verdict and is managed by definition; a
// discovery-found cert that was never classified (scanned before trust
// classification existed, or from a non-TLS source) reads as unknown. Other
// certificates are not classified at all.
func effectiveTrustClass(item CertificateItem) string {
	switch {
	case item.TrustClass != "":
		return item.TrustClass
	case item.ManagementState == "managed":
		return scanner.TrustManaged
	case isDiscoverySource(item.Source):
		return scanner.TrustUnknown
	default:
		return ""
	}
}

// effectiveTrustClassSQL is effectiveTrustClass as a SQL expression over a
// certificates row aliased c (LEFT JOINed, so possibly all-NULL): a hub-managed
// cert is managed by definition, otherwise the stored verdict, and a cert that
// was never classified reads as unknown. Used wherever the class of a
// certificate seen on the network is reported, so every view agrees.
const effectiveTrustClassSQL = `(CASE WHEN COALESCE(c.management_state, '') = 'managed' THEN 'managed' WHEN COALESCE(c.trust_class, '') = '' THEN 'unknown' ELSE c.trust_class END)`

// Inventory classes are the headline view of a certificate estate (W34-00
// design 1.3): one bucket per certificate, derived from management_state and
// issuer_class, never stored. Two axes stay in the data (management_state,
// issuer_class) so reports lose nothing; this is the label the UI shows.
const (
	InventoryManaged            = "managed"
	InventoryOursUnmanaged      = "ours_unmanaged"
	InventoryAuthorizedExternal = "authorized_external"
	InventoryUnknownIssuer      = "unknown_issuer"
	InventorySelfSigned         = "self_signed"
)

// InventoryClasses is the closed vocabulary, worst (least trusted) first: the
// order an endpoint presenting several certificates is summarised in.
var InventoryClasses = []string{InventoryUnknownIssuer, InventorySelfSigned, InventoryOursUnmanaged, InventoryAuthorizedExternal, InventoryManaged}

// IsInventoryClass reports membership of the closed vocabulary.
func IsInventoryClass(s string) bool { return slices.Contains(InventoryClasses, s) }

// InventoryClassCounts tallies distinct leaf certificates per inventory class.
type InventoryClassCounts struct {
	Managed            int `json:"managed"`
	OursUnmanaged      int `json:"ours_unmanaged"`
	AuthorizedExternal int `json:"authorized_external"`
	UnknownIssuer      int `json:"unknown_issuer"`
	SelfSigned         int `json:"self_signed"`
}

func (c *InventoryClassCounts) add(class string, n int) {
	switch class {
	case InventoryManaged:
		c.Managed += n
	case InventoryOursUnmanaged:
		c.OursUnmanaged += n
	case InventoryAuthorizedExternal:
		c.AuthorizedExternal += n
	case InventorySelfSigned:
		c.SelfSigned += n
	default:
		c.UnknownIssuer += n
	}
}

// effectiveIssuerClassSQL is the issuer class of a certificates row aliased c.
// A row scanned before issuer_class existed has none, so it is derived from
// the trust verdict it does have; a hub-managed row is the hub's by definition.
const effectiveIssuerClassSQL = `COALESCE(NULLIF(c.issuer_class, ''), CASE
    WHEN COALESCE(c.management_state, '') = 'managed' OR c.trust_class = 'managed' THEN 'hub'
    WHEN c.trust_class = 'self_signed' THEN 'self_signed'
    WHEN c.trust_class = 'public' THEN 'public'
    WHEN c.trust_class = 'private_other' THEN 'private_unknown'
    ELSE 'unknown' END)`

// inventoryClassSQL is the inventory class of a certificates row aliased c.
// A certificate is "managed" only when the hub renews it; one the hub issued
// but nobody renews is ours_unmanaged.
const inventoryClassSQL = `(CASE
    WHEN COALESCE(c.management_state, '') = 'managed' THEN 'managed'
    WHEN ` + effectiveIssuerClassSQL + ` = 'self_signed' THEN 'self_signed'
    WHEN ` + effectiveIssuerClassSQL + ` = 'hub' THEN 'ours_unmanaged'
    WHEN ` + effectiveIssuerClassSQL + ` = 'authorized' THEN 'authorized_external'
    ELSE 'unknown_issuer' END)`

// inventoryClassPredicate selects rows of one class; class is interpolated, so
// it is re-checked against the closed vocabulary.
func inventoryClassPredicate(class, activeCond, notCA string) string {
	if !IsInventoryClass(class) {
		return "1 = 0"
	}
	return activeCond + " AND " + notCA + " AND " + inventoryClassSQL + " = '" + class + "'"
}

func loadInventoryClassCounts(ctx context.Context, db *sql.DB, activeCond, notCA string, args ...any) (InventoryClassCounts, error) {
	rows, err := db.QueryContext(ctx, `
SELECT `+inventoryClassSQL+` AS class, COUNT(DISTINCT ce.certificate_fingerprint)
FROM certificate_endpoints ce
LEFT JOIN certificates c ON ce.certificate_fingerprint = c.fingerprint_sha256
WHERE `+activeCond+` AND `+notCA+`
GROUP BY `+inventoryClassSQL, args...)
	if err != nil {
		return InventoryClassCounts{}, err
	}
	defer rows.Close()
	var out InventoryClassCounts
	for rows.Next() {
		var class string
		var n int
		if err := rows.Scan(&class, &n); err != nil {
			return InventoryClassCounts{}, err
		}
		out.add(class, n)
	}
	return out, rows.Err()
}

// setInventoryClasses summarises each endpoint's leaf certificates as the
// least-trusted class among them.
func setInventoryClasses(endpoints []DiscoveryEndpoint) {
	for i := range endpoints {
		best := -1
		for _, mc := range endpoints[i].MappedCerts {
			if mc.ChainCA || mc.InventoryClass == "" {
				continue
			}
			if rank := slices.Index(InventoryClasses, mc.InventoryClass); rank >= 0 && (best < 0 || rank < best) {
				best = rank
			}
		}
		if best >= 0 {
			endpoints[i].InventoryClass = InventoryClasses[best]
		}
	}
}

// issuerReclassifyChunk bounds how many stored certificates are re-judged per
// query batch when a declared issuer changes.
const issuerReclassifyMax = 20000

// reclassifyIssuers re-derives issuer_class for the discovery-found
// certificates seen on a tenant's endpoints, from the stored leaf alone: the
// served chain is not kept, so an spki_sha256 rule (which needs the issuer
// certificate) is only re-evaluated by the next scan.
func (t *discoveryTrust) reclassifyIssuers(ctx context.Context, db *sql.DB, ph func(int) string, tenant string) error {
	anchors, ok := t.anchors(withDiscoveryTenant(ctx, tenant))
	if !ok || !anchors.IssuerClassKnown {
		return nil
	}
	rows, err := db.QueryContext(ctx, `
SELECT DISTINCT c.fingerprint_sha256, COALESCE(c.raw_cert_b64, ''), COALESCE(c.trust_class, ''), COALESCE(c.issuer_class, '')
FROM certificates c
JOIN certificate_endpoints ce ON ce.certificate_fingerprint = c.fingerprint_sha256
JOIN endpoints e ON e.id = ce.endpoint_id
WHERE e.tenant = `+ph(1)+` AND COALESCE(c.management_state, '') <> 'managed' LIMIT `+fmt.Sprint(issuerReclassifyMax), tenant)
	if err != nil {
		return err
	}
	type stored struct{ fp, raw, trust, issuer string }
	var all []stored
	for rows.Next() {
		var s stored
		if err := rows.Scan(&s.fp, &s.raw, &s.trust, &s.issuer); err != nil {
			rows.Close()
			return err
		}
		all = append(all, s)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	now := time.Now()
	for _, s := range all {
		der, err := base64.StdEncoding.DecodeString(s.raw)
		if err != nil || len(der) == 0 {
			continue
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		trust := s.trust
		if trust == scanner.TrustUnknown {
			trust = ""
		}
		next := scanner.ClassifyIssuer([]*x509.Certificate{leaf}, trust, anchors, now)
		// A hub or self-signed verdict from the full chain is never weakened
		// by a leaf-only re-judgement.
		if next == s.issuer || s.issuer == scanner.IssuerHub || s.issuer == scanner.IssuerSelfSigned {
			continue
		}
		if _, err := db.ExecContext(ctx, `UPDATE certificates SET issuer_class = `+ph(1)+` WHERE fingerprint_sha256 = `+ph(2), next, s.fp); err != nil {
			return err
		}
	}
	return nil
}

func (s *sqliteDiscoveryStore) ReclassifyIssuers(ctx context.Context, tenant string) error {
	return s.trust.reclassifyIssuers(ctx, s.db, sqlitePlaceholder, tenant)
}

func (s *postgresDiscoveryStore) ReclassifyIssuers(ctx context.Context, tenant string) error {
	return s.trust.reclassifyIssuers(ctx, s.db, postgresPlaceholder, tenant)
}

// ReclassifyIssuers re-derives issuer classes on the DB provider's store.
func (p *dbDiscoveryProvider) ReclassifyIssuers(ctx context.Context, tenant string) error {
	if s, ok := p.store.(issuerReclassifier); ok {
		return s.ReclassifyIssuers(ctx, tenant)
	}
	return nil
}

// ReclassifyIssuers delegates to whichever provider is active.
func (c *configuredDiscoveryProvider) ReclassifyIssuers(ctx context.Context, tenant string) error {
	if r, ok := c.current(ctx).(issuerReclassifier); ok {
		return r.ReclassifyIssuers(ctx, tenant)
	}
	return nil
}
