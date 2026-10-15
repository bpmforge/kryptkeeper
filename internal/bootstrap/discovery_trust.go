// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"log"
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
	systemRoots func() (*x509.CertPool, error)

	sysOnce sync.Once
	sys     *x509.CertPool
	sysErr  error
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
	if !anyServed(results) {
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
	}
}

func (t *discoveryTrust) anchors(ctx context.Context) (scanner.TrustAnchors, bool) {
	sys, err := t.system()
	if err != nil || sys == nil {
		log.Printf("discovery: system roots unavailable, leaving served chains unclassified: %v", err)
		return scanner.TrustAnchors{}, false
	}
	t.mu.RLock()
	src := t.hubCAs
	t.mu.RUnlock()
	var hub []*x509.Certificate
	if src != nil {
		if hub, err = src(ctx); err != nil {
			log.Printf("discovery: hub CAs unavailable, leaving served chains unclassified: %v", err)
			return scanner.TrustAnchors{}, false
		}
	}
	return scanner.TrustAnchors{System: sys, Hub: hub}, true
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
