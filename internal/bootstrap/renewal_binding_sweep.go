// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"fmt"
	"time"

	"kryptkeeper/internal/logging"
)

// W27-02: the binding-driven half of the renewal sweep. The scan loop in
// renewal_scheduler.go asks this file which bound targets a certificate owes
// a renewal to and runs the existing tenant / stamp / history checks on each.

// WithBindingStore arms binding-driven auto-renew. Without it the sweep
// executes nothing: a missing store must never fall back to guessing targets
// from CN/SAN == host.
func (s *RenewalScheduler) WithBindingStore(b CertTargetBindingStore) *RenewalScheduler {
	s.bindingStore = b
	return s
}

// prepareBindingSweep builds the tick's binding index, running the one-time
// backfill first. It returns nil when the sweep cannot execute this tick.
// targets must come from a successful List: a failed read must neither mark
// the backfill done nor renew anything.
func (s *RenewalScheduler) prepareBindingSweep(ctx context.Context, eligible []ManagedTarget, certs []CertificateItem, now time.Time) *bindingSweepIndex {
	if s.renewalExecutor == nil {
		return nil
	}
	if s.bindingStore == nil {
		if s.unboundNotes.should("no-binding-store", now) {
			logging.Warnf("renewal scheduler: certificate-target binding store unavailable; not auto-renewing any target (reminders only)")
		}
		return nil
	}
	done, err := s.bindingStore.BackfillDone(ctx)
	if err != nil {
		logging.Infof("renewal scheduler: binding backfill state unreadable, not auto-renewing this tick: %v", err)
		return nil
	}
	if !done {
		n, err := backfillBindings(ctx, s.bindingStore, certs, eligible, now)
		if err != nil {
			logging.Warnf("renewal scheduler: binding backfill failed after %d binding(s), will retry next tick: %v", n, err)
			return nil
		}
		if err := s.bindingStore.MarkBackfillDone(ctx); err != nil {
			logging.Warnf("renewal scheduler: marking binding backfill done failed, will retry next tick: %v", err)
			return nil
		}
		logging.Infof("renewal scheduler: migrated %d CN/SAN host match(es) to explicit certificate-target bindings", n)
	}
	binds, err := s.bindingStore.ListAll(ctx)
	if err != nil {
		logging.Warnf("renewal scheduler: listing bindings failed, not auto-renewing this tick: %v", err)
		return nil
	}
	return newBindingSweepIndex(binds, eligible)
}

// boundSweepResult is what one certificate's bound targets did this tick.
type boundSweepResult struct {
	owed, renewed, pending, gaveUp int
	finalFailure                   bool
}

// allRenewed reports that cert owed at least one renewal and delivered all of
// them, so no expiry reminder is needed.
func (r boundSweepResult) allRenewed() bool { return r.owed > 0 && r.renewed == r.owed }

// sweepBoundTargets renews cert onto every target currently serving it that an
// operator bound, and records each success so the binding follows the new
// fingerprint. A certificate with no binding is never executed; a host match
// without one is logged so the operator can fix it.
func (s *RenewalScheduler) sweepBoundTargets(ctx context.Context, idx *bindingSweepIndex, cert CertificateItem, now time.Time, pol retryPolicy) boundSweepResult {
	var res boundSweepResult
	binds := idx.byServed[cert.FingerprintSHA256]
	if len(binds) == 0 && !idx.bound[cert.FingerprintSHA256] {
		for _, t := range idx.hostMatches(cert) {
			s.unboundNotes.log(cert, t, now)
		}
		return res
	}
	for _, b := range binds {
		target, ok := idx.autoByID[b.TargetID]
		if !ok {
			continue // deleted, opted out, or no longer eligible; autoRenewSkipReason already logged why
		}
		res.owed++
		st, serr := s.installState(ctx, cert, target.ID)
		switch {
		case !targetMayReceiveCert(ctx, target, cert):
			// The target's tenant cannot see the certificate's CA: never move
			// its key across that boundary.
			logging.Warnf("renewal scheduler: refusing to bind cert %s (CN %q, CA %s) to target %s (%q, tenant %q): tenant mismatch",
				cert.FingerprintSHA256, cert.CommonName, cert.CAID, target.ID, target.Name, target.Tenant)
			s.emitRenewalAudit(ctx, cert, "certificate.renew_execute_denied", AuditOutcomeDenied,
				fmt.Sprintf("target_id=%s tenant mismatch between target and certificate CA", target.ID))
		case !s.stampStillValid(ctx, cert, target):
			// Notify-only for this target this tick; the reminder still goes out.
		case serr != nil:
			// Fail closed: with no readable history a retry could mint a fresh
			// certificate every tick.
			logging.Infof("renewal scheduler: audit history for %s unreadable, not attempting auto-renew on target %s: %v", cert.FingerprintSHA256, target.ID, serr)
		default:
			out := s.tryAutoRenew(ctx, cert, target, now, st, pol)
			if out.pending {
				res.pending++
			}
			if out.gaveUp {
				res.gaveUp++
			}
			res.finalFailure = res.finalFailure || out.finalFailure
			if out.renewed {
				res.renewed++
				if err := s.bindingStore.SetServed(ctx, target.ID, b.CertFingerprint, out.newFingerprint); err != nil {
					// The target already serves the new certificate; failing to
					// record it means the next tick renews again.
					logging.Warnf("renewal scheduler: ERROR recording %s as served on target %s (binding %s) failed: %v", out.newFingerprint, target.ID, b.CertFingerprint, err)
				}
			}
		}
	}
	return res
}

// WithRenewalRunner arms the sweep with any renewalRunner (test seam: a
// recording fake in place of the SSH-installing engine).
func (s *RenewalScheduler) WithRenewalRunner(r renewalRunner) *RenewalScheduler {
	s.renewalExecutor = r
	return s
}
