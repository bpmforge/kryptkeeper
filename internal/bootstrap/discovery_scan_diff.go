// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"kryptkeeper/internal/logging"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/discovery/scanner"
)

// W24-06: after each persisted scan, diff every endpoint against its previous
// active leaf and emit CERTIFICATE_REPLACED / CERTIFICATE_DISAPPEARED /
// KEY_DOWNGRADE through the notification provider. The diff never changes what
// the scan persists and never fails it.

const (
	ScanDiffCertificateReplaced    = "CERTIFICATE_REPLACED"
	ScanDiffCertificateDisappeared = "CERTIFICATE_DISAPPEARED"
	ScanDiffKeyDowngrade           = "KEY_DOWNGRADE"

	scanDiffMissesEnv     = "KRYPTKEEPER_DISCOVERY_DISAPPEAR_MISSES"
	scanDiffDefaultMisses = 2
)

// ScanDiffEvent is one change observed between two scans of an endpoint.
type ScanDiffEvent struct {
	Kind, Host                             string
	Port                                   int
	OldFingerprint, NewFingerprint, Detail string
	At                                     time.Time
}

// scanDiffLeaf is the prior or current active LEAF (is_ca = false) of an endpoint.
type scanDiffLeaf struct {
	Fingerprint, Algorithm string
	Bits                   int
}

// ScanDiffNotifier delivers a diff event.
type ScanDiffNotifier interface {
	Notify(ctx context.Context, ev ScanDiffEvent) error
}

// scanDiffNotifierSetter is implemented by discovery providers that diff scans;
// it follows the hubCASetter wiring pattern.
type scanDiffNotifierSetter interface {
	SetScanDiffNotifier(ScanDiffNotifier)
}

// scanDiffEngine holds the in-memory miss counters. They are not durable (no
// migration in W24-06): a hub restart resets them, so DISAPPEARED can fire one
// scan late, and HA replicas count separately.
type scanDiffEngine struct {
	threshold int
	notifier  ScanDiffNotifier

	mu        sync.Mutex
	misses    map[string]int
	announced map[string]bool
}

func newScanDiffEngine(missThreshold int) *scanDiffEngine {
	if missThreshold <= 0 {
		missThreshold = scanDiffDefaultMisses
	}
	return &scanDiffEngine{threshold: missThreshold, misses: map[string]int{}, announced: map[string]bool{}}
}

// scanDiffMissThresholdFromEnv reads the consecutive-miss count after which an
// endpoint that stopped answering is reported gone (default 2, minimum 1).
func scanDiffMissThresholdFromEnv() int {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(scanDiffMissesEnv)))
	if err != nil || n < 1 {
		return scanDiffDefaultMisses
	}
	return n
}

// scanDiffApplies: only endpoints that present a single served leaf. Port-0
// sources (mesh, k8s) have no host:port identity, and ssh/winrm inventories
// list many files or store entries per host, so "the leaf" is not defined.
func scanDiffApplies(ep scanner.DiscoveredEndpoint) bool {
	return ep.Port != 0 && ep.Protocol != "ssh" && ep.Protocol != "winrm-https"
}

func scanDiffKey(ep scanner.DiscoveredEndpoint) string { return fmt.Sprintf("%s:%d", ep.Host, ep.Port) }

// scanDiffCurrentLeaf is the first served non-CA cert, with key facts derived
// from the raw DER the same way discoveredCertRow does.
func scanDiffCurrentLeaf(ep scanner.DiscoveredEndpoint) (scanDiffLeaf, bool) {
	for _, c := range ep.Certs {
		if c.IsCA || c.ChainCA || c.Fingerprint == "" {
			continue
		}
		leaf := scanDiffLeaf{Fingerprint: c.Fingerprint, Algorithm: c.PublicKeyAlgorithm}
		if parsed, err := x509.ParseCertificate(c.Raw); err == nil {
			leaf.Algorithm = ca.StoredPublicKeyAlgorithm(parsed)
			leaf.Bits = ca.PublicKeyBits(parsed.PublicKey)
		}
		if alg, ok := normalizeDiscoveredKeyAlgorithm(leaf.Algorithm); ok {
			leaf.Algorithm = alg
		}
		return leaf, true
	}
	return scanDiffLeaf{}, false
}

// scanDiffTier ranks key strength; 0 means unknown, which never counts as a
// downgrade either way.
func scanDiffTier(l scanDiffLeaf) int {
	switch l.Algorithm {
	case "RSA":
		switch {
		case l.Bits <= 0:
			return 0
		case l.Bits < 3072:
			return 1
		default:
			return 2
		}
	case "ECDSA", "Ed25519":
		return 2
	case "ML-DSA":
		return 3
	}
	return 0
}

func scanDiffIsDowngrade(prior, cur scanDiffLeaf) bool {
	if prior.Algorithm == cur.Algorithm && cur.Bits > 0 && cur.Bits < prior.Bits {
		return true
	}
	pt, ct := scanDiffTier(prior), scanDiffTier(cur)
	return pt > 0 && ct > 0 && ct < pt
}

func shortFP(fp string) string {
	if len(fp) > 12 {
		return fp[:12]
	}
	return fp
}

func (l scanDiffLeaf) String() string {
	if l.Bits > 0 {
		return fmt.Sprintf("%s %d", l.Algorithm, l.Bits)
	}
	return l.Algorithm
}

// diff is pure apart from the miss counters. prior is the previous active leaf
// per "host:port" (absent = never seen), cur this scan's endpoints.
func (e *scanDiffEngine) diff(prior map[string]scanDiffLeaf, cur []scanner.DiscoveredEndpoint, now time.Time) []ScanDiffEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	var events []ScanDiffEvent
	for _, ep := range cur {
		if !scanDiffApplies(ep) {
			continue
		}
		key := scanDiffKey(ep)
		pl, hadPrior := prior[key]
		if endpointNeverReached(ep) {
			// Only an endpoint with a recorded leaf can disappear; one that
			// never answered emits nothing and is not counted.
			if !hadPrior {
				continue
			}
			e.misses[key]++
			if e.misses[key] >= e.threshold && !e.announced[key] {
				e.announced[key] = true
				events = append(events, ScanDiffEvent{Kind: ScanDiffCertificateDisappeared, Host: ep.Host, Port: ep.Port,
					OldFingerprint: pl.Fingerprint, At: now,
					Detail: fmt.Sprintf("no answer for %d consecutive scans (miss counter is in memory: a hub restart can delay this by one scan)", e.misses[key])})
			}
			continue
		}
		delete(e.misses, key)
		delete(e.announced, key)
		cl, ok := scanDiffCurrentLeaf(ep)
		if !hadPrior || !ok {
			continue
		}
		if cl.Fingerprint != pl.Fingerprint {
			events = append(events, ScanDiffEvent{Kind: ScanDiffCertificateReplaced, Host: ep.Host, Port: ep.Port,
				OldFingerprint: pl.Fingerprint, NewFingerprint: cl.Fingerprint, At: now,
				Detail: fmt.Sprintf("leaf %s -> %s", shortFP(pl.Fingerprint), shortFP(cl.Fingerprint))})
		}
		if scanDiffIsDowngrade(pl, cl) {
			events = append(events, ScanDiffEvent{Kind: ScanDiffKeyDowngrade, Host: ep.Host, Port: ep.Port,
				OldFingerprint: pl.Fingerprint, NewFingerprint: cl.Fingerprint, At: now,
				Detail: fmt.Sprintf("%s -> %s", pl, cl)})
		}
	}
	return events
}

// afterCommit computes and delivers the events of a scan that has committed.
// Nil-safe: a store with no diff engine is a no-op. Delivery failures are
// logged, never returned.
func (e *scanDiffEngine) afterCommit(ctx context.Context, prior map[string]scanDiffLeaf, cur []scanner.DiscoveredEndpoint) {
	if e == nil {
		return
	}
	events := e.diff(prior, cur, time.Now().UTC())
	if e.notifier == nil {
		return
	}
	for _, ev := range events {
		if err := e.notifier.Notify(ctx, ev); err != nil {
			logging.Infof("scan diff: delivering %s for %s:%d: %v", ev.Kind, ev.Host, ev.Port, err)
		}
	}
}

// ---- prior snapshot ----

const (
	scanDiffPriorSQLite = `
SELECT ce.certificate_fingerprint, c.public_key_algorithm, COALESCE(c.key_size_bits, 0)
FROM endpoints e
JOIN certificate_endpoints ce ON ce.endpoint_id = e.id AND ce.currently_active = 1
JOIN certificates c ON c.fingerprint_sha256 = ce.certificate_fingerprint
WHERE e.ip_address = ? AND e.port = ? AND e.sni_name = ? AND COALESCE(c.is_ca, 0) = 0
LIMIT 1`
	scanDiffPriorPostgres = `
SELECT ce.certificate_fingerprint, c.public_key_algorithm, COALESCE(c.key_size_bits, 0)
FROM endpoints e
JOIN certificate_endpoints ce ON ce.endpoint_id = e.id AND ce.currently_active = true
JOIN certificates c ON c.fingerprint_sha256 = ce.certificate_fingerprint
WHERE e.ip_address = $1 AND e.port = $2 AND e.sni_name = $3 AND NOT COALESCE(c.is_ca, FALSE)
LIMIT 1`
)

// loadScanDiffPrior reads each endpoint's current leaf before the upsert runs.
// Any error is logged and the diff skipped for this scan (nil map: every
// endpoint then reads as a first scan, which emits nothing).
func loadScanDiffPrior(ctx context.Context, db *sql.DB, query string, cur []scanner.DiscoveredEndpoint) map[string]scanDiffLeaf {
	prior := map[string]scanDiffLeaf{}
	for _, ep := range cur {
		if !scanDiffApplies(ep) {
			continue
		}
		key := scanDiffKey(ep)
		if _, done := prior[key]; done {
			continue
		}
		var l scanDiffLeaf
		err := db.QueryRowContext(ctx, query, ep.Host, ep.Port, ep.Host).Scan(&l.Fingerprint, &l.Algorithm, &l.Bits)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			logging.Infof("scan diff: reading prior state of %s: %v (diff skipped for this scan)", key, err)
			return nil
		default:
			prior[key] = l
		}
	}
	return prior
}

func (s *sqliteDiscoveryStore) loadScanDiffPrior(ctx context.Context, cur []scanner.DiscoveredEndpoint) map[string]scanDiffLeaf {
	return loadScanDiffPrior(ctx, s.db, scanDiffPriorSQLite, cur)
}

func (s *postgresDiscoveryStore) loadScanDiffPrior(ctx context.Context, cur []scanner.DiscoveredEndpoint) map[string]scanDiffLeaf {
	return loadScanDiffPrior(ctx, s.db, scanDiffPriorPostgres, cur)
}

func (s *sqliteDiscoveryStore) SetScanDiffNotifier(n ScanDiffNotifier) {
	s.diff = newScanDiffEngine(scanDiffMissThresholdFromEnv())
	s.diff.notifier = n
}

func (s *postgresDiscoveryStore) SetScanDiffNotifier(n ScanDiffNotifier) {
	s.diff = newScanDiffEngine(scanDiffMissThresholdFromEnv())
	s.diff.notifier = n
}

// SetScanDiffNotifier installs the notifier on the DB provider's store.
func (p *dbDiscoveryProvider) SetScanDiffNotifier(n ScanDiffNotifier) {
	if s, ok := p.store.(scanDiffNotifierSetter); ok {
		s.SetScanDiffNotifier(n)
	}
}

// SetScanDiffNotifier remembers the notifier and hands it to the DB provider
// whenever that provider is (lazily) constructed.
func (c *configuredDiscoveryProvider) SetScanDiffNotifier(n ScanDiffNotifier) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.scanDiffNotifier = n
	if s, ok := c.dbProvider.(scanDiffNotifierSetter); ok && c.dbProvider != nil {
		s.SetScanDiffNotifier(n)
	}
}

// ---- delivery ----

// providerScanDiffNotifier audits every event and fans it out through the
// notification provider. Rules are threshold-days rules with no event-type
// field (UC-I01 event routing is W30-xx), so every enabled rule's channel and
// target receives every event until that lands.
type providerScanDiffNotifier struct {
	p        NotificationProvider
	a        AuditProvider
	warnOnce sync.Once
}

func newProviderScanDiffNotifier(p NotificationProvider, a AuditProvider) ScanDiffNotifier {
	return &providerScanDiffNotifier{p: p, a: a}
}

func (n *providerScanDiffNotifier) Notify(ctx context.Context, ev ScanDiffEvent) error {
	hostPort := fmt.Sprintf("%s:%d", ev.Host, ev.Port)
	if n.a != nil {
		if err := n.a.AppendEntry(ctx, AuditEntry{
			Action: "discovery.scan_diff." + strings.ToLower(ev.Kind), ActorType: "system", ActorID: "discovery",
			ResourceType: "endpoint", ResourceID: hostPort, Outcome: AuditOutcomeSuccess, ChangeSummary: ev.Detail,
		}); err != nil {
			logging.Infof("scan diff: audit %s %s: %v", ev.Kind, hostPort, err)
		}
	}
	if n.p == nil {
		return nil
	}
	rules, err := n.p.ListRules(ctx)
	if err != nil {
		return fmt.Errorf("list notification rules: %w", err)
	}
	if !n.p.Delivers() {
		n.warnOnce.Do(func() {
			logging.Infof("scan diff: notification provider %q only records; scan-diff events reach no channel", n.p.Name())
		})
	}
	msg := fmt.Sprintf("[%s] %s - %s", ev.Kind, hostPort, ev.Detail)
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if _, err := n.p.TestDelivery(ctx, r.Channel, r.Target, msg); err != nil {
			logging.Warnf("scan diff: rule %s delivery of %s %s failed: %v", r.ID, ev.Kind, hostPort, err)
		}
	}
	return nil
}
