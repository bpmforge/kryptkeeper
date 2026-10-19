// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"
	"kryptkeeper/internal/logging"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/notifications/delivery"
)

// W22-31 (FR-R10): accepted-risk exception expiry.
//
// Reopening is structural, not scheduled: IsActive is computed from expires_at
// on every read (fail-closed), and a re-issued certificate has a new
// fingerprint that no exception names. What a lapse still lacks is a human
// signal, so this scanner warns the owner once, 14 days ahead, and audits the
// lapse once. It never mutates or deletes an exception row: the evidence pack
// and the audit history need the lapsed ones.

const haLockExceptionExpiry = "exception-expiry-scanner"

const exceptionWarnWindow = 14 * 24 * time.Hour

const (
	exceptionEventExpiring = "expiring"
	exceptionEventExpired  = "expired"
)

// findingExceptionLifecycleStore is optional so the existing
// FindingExceptionStore interface (and any test fake) stays untouched.
type findingExceptionLifecycleStore interface {
	EnsureLifecycleSchema(ctx context.Context) error
	ListAll(ctx context.Context) ([]FindingException, error)
	// ClaimEvent is true only for the first claim of (exceptionID, kind).
	ClaimEvent(ctx context.Context, exceptionID, kind string, at time.Time) (bool, error)
}

// ExceptionExpiryScanner warns before, and audits at, exception expiry.
type ExceptionExpiryScanner struct {
	store          findingExceptionLifecycleStore // nil => tick is a no-op
	tenants        findingExceptionTenantStore    // optional: tenant for the audit row
	certs          CertificateProvider
	audit          AuditProvider
	channel        delivery.Channel // nil => warnings are logged only
	fallbackTarget string
	pollInterval   time.Duration

	// nil when unavailable (soft-fail) — single-replica behavior.
	haCoordinator *HACoordinator

	schemaReady bool // ticks never overlap, so no lock
	stop        chan struct{}
	once        sync.Once
}

// NewExceptionExpiryScannerFromEnv builds the scanner
// (KRYPTKEEPER_EXCEPTION_EXPIRY_SWEEP_MINUTES, default 60). A store without
// the lifecycle surface yields a scanner whose tick does nothing.
func NewExceptionExpiryScannerFromEnv(store FindingExceptionStore, certs CertificateProvider, audit AuditProvider, ch delivery.Channel, fallbackTarget string) *ExceptionExpiryScanner {
	minutes := 60
	if raw := strings.TrimSpace(os.Getenv("KRYPTKEEPER_EXCEPTION_EXPIRY_SWEEP_MINUTES")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			minutes = n
		}
	}
	s := &ExceptionExpiryScanner{
		certs: certs, audit: audit, channel: ch, fallbackTarget: fallbackTarget,
		pollInterval:  time.Duration(minutes) * time.Minute,
		haCoordinator: newHACoordinatorFromEnvLogged(),
		stop:          make(chan struct{}),
	}
	if ls, ok := store.(findingExceptionLifecycleStore); ok {
		s.store = ls
	} else {
		logging.Info("exception expiry scanner: store has no lifecycle support, scanner disabled")
	}
	s.tenants, _ = store.(findingExceptionTenantStore)
	return s
}

func (s *ExceptionExpiryScanner) Start() {
	go func() {
		ticker := time.NewTicker(s.pollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-ticker.C:
				s.tick(context.Background(), time.Now())
			}
		}
	}()
}

func (s *ExceptionExpiryScanner) Stop() { s.once.Do(func() { close(s.stop) }) }

func (s *ExceptionExpiryScanner) tick(ctx context.Context, now time.Time) {
	if s.store == nil {
		return
	}
	// HA gate: only the lease holder scans; ClaimEvent is the second guard.
	if s.haCoordinator != nil {
		ok, err := s.haCoordinator.TryAcquire(ctx, haLockExceptionExpiry, 2*s.pollInterval)
		if err != nil {
			logging.Warnf("exception expiry scanner: ha lock check failed, skipping this tick: %v", err)
			return
		}
		if !ok {
			return
		}
	}
	if !s.schemaReady {
		if err := s.store.EnsureLifecycleSchema(ctx); err != nil {
			logging.Warnf("exception expiry scanner: schema unavailable: %v", err)
			return
		}
		s.schemaReady = true
	}
	all, err := s.store.ListAll(ctx)
	if err != nil {
		logging.Warnf("exception expiry scanner: list failed: %v", err)
		return
	}
	var stamps map[string]string
	if s.tenants != nil {
		if stamps, err = s.tenants.TenantsByID(ctx); err != nil {
			logging.Warnf("exception expiry scanner: tenant stamps unavailable, audit rows use the default tenant: %v", err)
		}
	}
	for _, e := range all {
		expires, perr := time.Parse(time.RFC3339, e.ExpiresAt)
		if perr != nil {
			continue
		}
		if e.IsActive(now) {
			if expires.Sub(now) <= exceptionWarnWindow {
				s.warn(ctx, e, expires, now)
			}
			continue
		}
		s.recordLapse(ctx, e, stamps[e.ID], now)
	}
}

// warn claims the "expiring" event first, so a failed send is never repeated
// on the next sweep: one warning per exception, however the delivery fares.
func (s *ExceptionExpiryScanner) warn(ctx context.Context, e FindingException, expires, now time.Time) {
	first, err := s.store.ClaimEvent(ctx, e.ID, exceptionEventExpiring, now)
	if err != nil {
		logging.Warnf("exception expiry scanner: claim expiring %s failed: %v", e.ID, err)
		return
	}
	if !first {
		return
	}
	var ownerEmail, ownerTeam string
	if e.TargetType == FindingExceptionTargetCertificate && s.certs != nil {
		if c, found, gerr := s.certs.GetCertificate(ctx, e.TargetID); gerr == nil && found {
			ownerEmail, ownerTeam = c.OwnerEmail, c.OwnerTeam
		}
	}
	days := int(expires.Sub(now).Hours()/24 + 0.999)
	subject := "exception.expiring: " + e.FindingCode + " on " + e.TargetID
	msg := fmt.Sprintf("The accepted-risk exception for %s on %s %s expires in %d day(s) (%s). Owner team: %s. Justification: %s. After expiry the finding counts again.",
		e.FindingCode, e.TargetType, e.TargetID, days, e.ExpiresAt, valueOrUnowned(ownerTeam), e.JustificationCode)
	if s.channel == nil {
		logging.Infof("exception expiry scanner: %s: %s", subject, msg)
		return
	}
	target := s.fallbackTarget
	if s.channel.Name() == "email" && ownerEmail != "" {
		target = ownerEmail
	}
	if target == "" {
		logging.Infof("exception expiry scanner: no owner email or fallback target for %s: %s", e.ID, subject)
		return
	}
	ev := delivery.Event{
		ID: "exception-expiring-" + e.ID, Channel: s.channel.Name(), Target: target,
		Subject: subject, Message: msg, Priority: "medium", CreatedAt: now,
	}
	if err := s.channel.Send(ctx, ev); err != nil {
		logging.Warnf("exception expiry scanner: notify failed for %s: %v", e.ID, err)
	}
}

func valueOrUnowned(v string) string {
	if v == "" {
		return "unowned"
	}
	return v
}

func (s *ExceptionExpiryScanner) recordLapse(ctx context.Context, e FindingException, tenant string, now time.Time) {
	first, err := s.store.ClaimEvent(ctx, e.ID, exceptionEventExpired, now)
	if err != nil {
		logging.Warnf("exception expiry scanner: claim expired %s failed: %v", e.ID, err)
		return
	}
	if !first || s.audit == nil {
		return
	}
	if tenant == "" {
		tenant = DefaultTenant
	}
	if err := s.audit.AppendEntry(ctx, AuditEntry{
		Timestamp: now.UTC().Format(time.RFC3339), Action: "exception.expire", ActorType: "system", ActorID: "exception-expiry-scanner",
		ResourceType: "exception", ResourceID: e.ID, Outcome: AuditOutcomeSuccess, Tenant: tenant,
		ChangeSummary: exceptionSummary(e.TargetType, e.TargetID, e.FindingCode),
	}); err != nil {
		logging.Warnf("exception expiry scanner: audit append failed for %s: %v", e.ID, err)
	}
}

// NewFindingExceptionStoreFromEnv is newFindingExceptionStoreFromEnv for
// cmd/kryptkeeper; nil when the database cannot be opened (the scanner then
// stays off rather than the process failing).
func NewFindingExceptionStoreFromEnv() FindingExceptionStore {
	store, err := newFindingExceptionStoreFromEnv()
	if err != nil {
		logging.Warnf("exception expiry scanner: store unavailable: %v", err)
		return nil
	}
	return store
}
