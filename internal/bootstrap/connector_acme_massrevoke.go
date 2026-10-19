// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	goocsp "golang.org/x/crypto/ocsp"
	"kryptkeeper/internal/logging"

	"kryptkeeper/internal/connectors"
)

// W26-29: react to a CA-initiated mass revocation. Every
// acmeMassRevokeInterval the monitor re-checks each ACME-renewed certificate
// for a revocation signal (an ARI window pulled forward to "now", or an OCSP
// "revoked" answer), alerts once per connector, audits each affected
// certificate and forces its renewal on the next scheduler scan.

const (
	// acmeMassRevokeInterval must stay <= 5m (board acceptance #1).
	acmeMassRevokeInterval = 2 * time.Minute

	massRevokeImminent    = 5 * time.Minute
	massRevokePullForward = 24 * time.Hour
	massRevokeMaxDetail   = 200

	massRevokeEvent = "acme.upstream.massrevoke"
	massRevokeActor = "acme-massrevoke-monitor"
)

type massRevokeSignal struct {
	ConnectorID, Fingerprint, Source /* "ari"|"ocsp" */, Detail string
}

// --- forced-due set (lives on the W26-27 plan cache) ----------------------

// forceDue makes the scheduler's ARI hook report the certificate as due until
// clearForced is called (when it gets a successor).
func (p *ariPlanCache) forceDue(connectorID, fp, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.forced == nil {
		p.forced = map[string]string{}
	}
	p.forced[connectorID+"|"+fp] = reason
}

func (p *ariPlanCache) forcedDue(connectorID, fp string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	reason, ok := p.forced[connectorID+"|"+fp]
	return reason, ok
}

func (p *ariPlanCache) clearForced(connectorID, fp string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.forced, connectorID+"|"+fp)
}

// --- detector -------------------------------------------------------------

// checkMassRevocation looks for a revocation signal for one certificate and
// returns the CA-advised wait until the next check (the ARI Retry-After clamped like the W26-27 refresh, or the
// default when the CA gave no ARI answer).
func checkMassRevocation(ctx context.Context, c *acmeIssuerConnector, cert CertificateItem, certPEM, chainPEM string, now time.Time) (*massRevokeSignal, time.Duration, error) {
	wait := ariDefaultRetryAfter
	var ariErr error
	key := cert.RenewalConnectorID + "|" + cert.FingerprintSHA256
	w, err := c.fetchARI(ctx, certPEM)
	switch {
	case errors.Is(err, errARIUnsupported):
	case err != nil:
		ariErr = err
	default:
		wait = clampDuration(w.RetryAfter, ariMinRefresh, ariDefaultRetryAfter)
		old, cached := ariPlans.get(key)
		ariPlans.put(key, w, now)
		imminent := !w.End.After(now.Add(massRevokeImminent))
		pulled := cached && old.window.End.After(now.Add(massRevokePullForward))
		if imminent && (pulled || w.ExplanationURL != "") {
			return &massRevokeSignal{
				ConnectorID: cert.RenewalConnectorID, Fingerprint: cert.FingerprintSHA256, Source: "ari",
				Detail: truncateDetail(fmt.Sprintf("window_end=%s explanation_url=%s", w.End.UTC().Format(time.RFC3339), w.ExplanationURL)),
			}, wait, nil
		}
	}

	revoked, odetail, oerr := c.ocspRevoked(ctx, certPEM, chainPEM, now)
	if revoked {
		return &massRevokeSignal{
			ConnectorID: cert.RenewalConnectorID, Fingerprint: cert.FingerprintSHA256, Source: "ocsp",
			Detail: truncateDetail(odetail),
		}, wait, nil
	}
	if ariErr != nil {
		return nil, max(wait, ariMinRefresh), ariErr
	}
	if oerr != nil {
		return nil, max(wait, ariMinRefresh), oerr
	}
	return nil, wait, nil
}

func truncateDetail(s string) string {
	if len(s) > massRevokeMaxDetail {
		return s[:massRevokeMaxDetail]
	}
	return s
}

func pemCerts(bundle string) []*x509.Certificate {
	var out []*x509.Certificate
	rest := []byte(bundle)
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

// ocspRevoked asks the leaf's OCSP responder. No responder, no issuer in the
// chain, or a non-revoked answer all yield (false, "", nil) or a plain error.
func (c *acmeIssuerConnector) ocspRevoked(ctx context.Context, certPEM, chainPEM string, now time.Time) (bool, string, error) {
	leaf, err := parseLeafPEM(certPEM)
	if err != nil || len(leaf.OCSPServer) == 0 {
		return false, "", nil
	}
	var issuer *x509.Certificate
	for _, cand := range pemCerts(chainPEM) {
		if cand.Equal(leaf) {
			continue
		}
		if leaf.CheckSignatureFrom(cand) == nil {
			issuer = cand
			break
		}
	}
	if issuer == nil {
		return false, "", nil
	}
	reqDER, err := goocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return false, "", fmt.Errorf("acme ocsp request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, leaf.OCSPServer[0], bytes.NewReader(reqDER))
	if err != nil {
		return false, "", fmt.Errorf("acme ocsp request: %w", err)
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	resp, err := c.httpClient(15 * time.Second).Do(req)
	if err != nil {
		return false, "", fmt.Errorf("acme ocsp fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("acme ocsp fetch: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, ariMaxResponseBytes))
	if err != nil {
		return false, "", fmt.Errorf("acme ocsp read: %w", err)
	}
	parsed, err := goocsp.ParseResponseForCert(body, leaf, issuer)
	if err != nil {
		return false, "", fmt.Errorf("acme ocsp parse: %w", err)
	}
	if parsed.Status != goocsp.Revoked {
		return false, "", nil
	}
	return true, fmt.Sprintf("ocsp=revoked revoked_at=%s reason=%d checked=%s",
		parsed.RevokedAt.UTC().Format(time.RFC3339), parsed.RevocationReason, now.UTC().Format(time.RFC3339)), nil
}

// --- monitor --------------------------------------------------------------

// massRevokeScanner is the slice of *RenewalScheduler the monitor needs.
type massRevokeScanner interface {
	RequestScan()
	// noTargetCount reports how many of certs have no armed managed target
	// (the scheduler can only remind about those, not renew them).
	noTargetCount(ctx context.Context, certs []CertificateItem) int
}

type ACMEMassRevokeMonitor struct {
	registryFn func(context.Context) (*connectors.Registry, error)
	certs      CertificateProvider
	audit      AuditProvider
	sched      massRevokeScanner
	now        func() time.Time

	mu    sync.Mutex
	latch map[string]bool // connector|fp|source
	// seen holds per-cert pacing and the cached PEM, so an idle tick makes
	// no CA request and no certificate download.
	seen map[string]*massRevokeCert
}

type massRevokeCert struct {
	nextCheck time.Time
	pem       string // leaf then chain; empty until first download
}

func newACMEMassRevokeMonitor(registryFn func(context.Context) (*connectors.Registry, error), certs CertificateProvider, audit AuditProvider, sched massRevokeScanner) *ACMEMassRevokeMonitor {
	return &ACMEMassRevokeMonitor{
		registryFn: registryFn, certs: certs, audit: audit, sched: sched,
		now: time.Now, latch: map[string]bool{}, seen: map[string]*massRevokeCert{},
	}
}

func (m *ACMEMassRevokeMonitor) clearLatch(connectorID, fp string) {
	prefix := connectorID + "|" + fp + "|"
	m.mu.Lock()
	delete(m.seen, connectorID+"|"+fp)
	for k := range m.latch {
		if strings.HasPrefix(k, prefix) {
			delete(m.latch, k)
		}
	}
	m.mu.Unlock()
	ariPlans.clearForced(connectorID, fp)
}

// Tick runs one detection pass and returns the newly affected certificates.
func (m *ACMEMassRevokeMonitor) Tick(ctx context.Context) (affected []massRevokeSignal) {
	if m.registryFn == nil || m.certs == nil {
		return nil
	}
	reg, err := m.registryFn(ctx)
	if err != nil || reg == nil {
		return nil
	}
	list, err := listAllCertificates(ctx, m.certs, CertificateListQuery{})
	if err != nil {
		logging.Warnf("acme massrevoke: list certs failed: %v", err)
		return nil
	}
	now := m.now().UTC()

	byConn := map[string][]CertificateItem{}
	for _, cert := range list.Items {
		if cert.RenewalConnectorID == "" {
			continue
		}
		if cert.SuccessorFP != nil || cert.RevokedAt != nil {
			m.clearLatch(cert.RenewalConnectorID, cert.FingerprintSHA256)
			continue
		}
		// W26-28 gate: a rate-limited connector gets no CA traffic from us either.
		if _, backedOff := acmeConnectorBackedOff(cert.RenewalConnectorID); backedOff {
			continue
		}
		certKey := cert.RenewalConnectorID + "|" + cert.FingerprintSHA256
		m.mu.Lock()
		st := m.seen[certKey]
		if st == nil {
			st = &massRevokeCert{}
			m.seen[certKey] = st
		}
		due := !now.Before(st.nextCheck)
		pemText := st.pem
		m.mu.Unlock()
		if !due {
			continue // CA said "not before nextCheck": no I/O at all
		}
		conn, err := reg.Get(cert.RenewalConnectorID)
		if err != nil || conn.Type() != "acme" {
			continue
		}
		ac, ok := conn.(*acmeIssuerConnector)
		if !ok {
			continue
		}
		if pemText == "" {
			dl, err := m.certs.DownloadCertificate(ctx, cert.FingerprintSHA256, "pem", true)
			if err != nil {
				logging.Warnf("acme massrevoke: download %s failed: %v", cert.FingerprintSHA256, err)
				continue
			}
			pemText = string(dl.Body)
		}
		sig, wait, err := checkMassRevocation(ctx, ac, cert, pemText, pemText, now)
		if err != nil {
			logging.Warnf("acme massrevoke: check %s failed: %v", cert.FingerprintSHA256, err)
		}
		m.mu.Lock()
		st.pem, st.nextCheck = pemText, now.Add(wait)
		m.mu.Unlock()
		if sig == nil {
			continue
		}
		latchKey := sig.ConnectorID + "|" + sig.Fingerprint + "|" + sig.Source
		m.mu.Lock()
		seen := m.latch[latchKey]
		m.latch[latchKey] = true
		m.mu.Unlock()
		if seen {
			continue
		}
		ariPlans.forceDue(sig.ConnectorID, sig.Fingerprint, "mass_revocation:"+sig.Source)
		m.appendAudit(ctx, *sig, now)
		affected = append(affected, *sig)
		byConn[sig.ConnectorID] = append(byConn[sig.ConnectorID], cert)
	}
	if len(affected) == 0 {
		return nil
	}
	ids := make([]string, 0, len(byConn))
	for id := range byConn {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		noTarget := len(byConn[id])
		if m.sched != nil {
			noTarget = m.sched.noTargetCount(ctx, byConn[id])
		}
		acmeAlert(massRevokeEvent, id, fmt.Sprintf("%d certificate(s) affected, no_target=%d", len(byConn[id]), noTarget))
	}
	if m.sched != nil {
		m.sched.RequestScan()
	}
	return affected
}

func (m *ACMEMassRevokeMonitor) appendAudit(ctx context.Context, sig massRevokeSignal, now time.Time) {
	if m.audit == nil {
		return
	}
	err := m.audit.AppendEntry(ctx, AuditEntry{
		Timestamp:     now.Format(time.RFC3339),
		Action:        massRevokeEvent,
		ActorType:     "system",
		ActorID:       massRevokeActor,
		ResourceType:  "certificate",
		ResourceID:    sig.Fingerprint,
		Outcome:       AuditOutcomeSuccess,
		ChangeSummary: fmt.Sprintf("source=%s connector=%s %s", sig.Source, sig.ConnectorID, sig.Detail),
	})
	if err != nil {
		logging.Warnf("acme massrevoke: audit append failed: %v", err)
	}
}

// StartACMEMassRevokeMonitor runs the monitor until ctx ends or stop is
// called. sched may be nil (no forced scan, no target accounting).
func StartACMEMassRevokeMonitor(ctx context.Context, registryFn func(context.Context) (*connectors.Registry, error), certs CertificateProvider, audit AuditProvider, sched *RenewalScheduler) (stop func()) {
	var sc massRevokeScanner
	if sched != nil {
		sc = sched
	}
	m := newACMEMassRevokeMonitor(registryFn, certs, audit, sc)
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(acmeMassRevokeInterval)
		defer ticker.Stop()
		for {
			tctx, tcancel := context.WithTimeout(ctx, 90*time.Second)
			m.Tick(tctx)
			tcancel()
			select {
			case <-ticker.C:
			case <-ctx.Done():
				return
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { cancel(); <-done }) }
}

// --- scheduler hooks (kept here so renewal_scheduler.go edits stay tiny) ---

// RequestScan asks the scheduler for an immediate scan; it never blocks and is
// a no-op on a nil scheduler or one without a scan channel.
func (s *RenewalScheduler) RequestScan() {
	if s == nil || s.scanNow == nil {
		return
	}
	select {
	case s.scanNow <- struct{}{}:
	default:
	}
}

func (s *RenewalScheduler) noTargetCount(ctx context.Context, certs []CertificateItem) int {
	if s == nil || s.renewalExecutor == nil || s.targetStore == nil {
		return len(certs)
	}
	targets, err := s.targetStore.List(ctx)
	if err != nil {
		return len(certs)
	}
	// Since W27-02 the sweep renews only onto bound targets, so a cert
	// "has a target" when a binding names it and an auto-renew target.
	if s.bindingStore == nil {
		return len(certs)
	}
	binds, err := s.bindingStore.ListAll(ctx)
	if err != nil {
		return len(certs)
	}
	auto := map[string]bool{}
	for _, t := range autoRenewTargetsByHost(targets) {
		auto[t.ID] = true
	}
	bound := map[string]bool{}
	for _, b := range binds {
		if auto[b.TargetID] {
			bound[b.CertFingerprint], bound[b.ServedFingerprint] = true, true
		}
	}
	n := 0
	for _, c := range certs {
		if !bound[c.FingerprintSHA256] {
			n++
		}
	}
	return n
}
