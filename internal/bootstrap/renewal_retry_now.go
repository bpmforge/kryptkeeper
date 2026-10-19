// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"kryptkeeper/internal/logging"
)

// W27-19: configurable failed-install backoff and the operator retry-now
// signal. Kept out of renewal_scheduler.go, which other lanes also edit.

const (
	defaultRetryBase = 5 * time.Minute
	defaultRetryCap  = 6 * time.Hour
)

// renewalRetryRequestedAction is the audit marker an operator retry-now
// appends (as actor renewal-scheduler, so installState sees it): failures
// older than it no longer count and the next tick attempts immediately.
const renewalRetryRequestedAction = "certificate.renew_retry_requested"

// renewalScanKick wakes Start's loop for an immediate scan. It is
// package-level because the HTTP handler is registered without the scheduler
// instance; a full buffer means a scan is already pending.
var renewalScanKick = make(chan struct{}, 1)

func kickRenewalScan() {
	select {
	case renewalScanKick <- struct{}{}:
	default:
	}
}

// installBackoff is base * 2^(failures-1) clamped to retryCap. It takes no
// clock so tests drive it with plain durations; the early-return loop cannot
// overflow however many failures are passed.
func installBackoff(base, retryCap time.Duration, failures int) time.Duration {
	if base <= 0 {
		base = defaultRetryBase
	}
	if retryCap <= 0 {
		retryCap = defaultRetryCap
	}
	if retryCap < base {
		retryCap = base
	}
	if failures < 1 {
		failures = 1
	}
	d := base
	for i := 1; i < failures; i++ {
		if d >= retryCap-d {
			return retryCap
		}
		d *= 2
	}
	return d
}

// resolveRetryBackoff reads the per-tick backoff shape: config-store override,
// else the env-derived bootstrap value, else the package default.
func (s *RenewalScheduler) resolveRetryBackoff(ctx context.Context) (base, retryCap time.Duration) {
	base, retryCap = s.retryBase, s.retryCap
	if base <= 0 {
		base = defaultRetryBase
	}
	if retryCap <= 0 {
		retryCap = defaultRetryCap
	}
	if v := s.resolveConfigInt(ctx, "renewal_policy.retry_base_minutes", 0); v > 0 {
		base = time.Duration(v) * time.Minute
	}
	if v := s.resolveConfigInt(ctx, "renewal_policy.retry_cap_hours", 0); v > 0 {
		retryCap = time.Duration(v) * time.Hour
	}
	return base, retryCap
}

type renewalRetryRequest struct {
	Fingerprint string `json:"fingerprint"`
}

const renewalRetryAuditAction = "certificate.renew_retry"

// renewalRetryHandler serves POST /api/v1/renewal/retry: re-queue a failed
// scheduled renewal now. The route sits under /api/v1/renewal/**, which
// authz_write_gate maps to certificate.renew for every write method.
func renewalRetryHandler(auth *Authenticator, certificateProvider CertificateProvider, auditProvider AuditProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", renewalRetryAuditAction, "certificate", "renewal-retry", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		audit := func(fp string, outcome AuditOutcome) {
			emitAuditEvent(r, auditProvider, pd.ID, renewalRetryAuditAction, "certificate", fp, outcome)
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRenewalExecuteBodyBytes))
		var req renewalRetryRequest
		if err != nil {
			audit("", AuditOutcomeFailure)
			writeBadRequestJSON(w, "invalid request body")
			return
		}
		if err := json.Unmarshal(raw, &req); err != nil || req.Fingerprint == "" {
			audit(req.Fingerprint, AuditOutcomeFailure)
			writeBadRequestJSON(w, "fingerprint is required")
			return
		}
		fp := req.Fingerprint

		if _, err := authorizeCertificateResourceAccess(r.Context(), certificateProvider, pd, fp); err != nil {
			switch {
			case errors.Is(err, errCertificateNotFound):
				audit(fp, AuditOutcomeFailure)
				writeNotFound(w, "certificate not found")
			case errors.Is(err, errCertificateForbidden), errors.Is(err, errCertificateTeamScopeForbidden), errors.Is(err, errCertificateTenantForbidden):
				audit(fp, AuditOutcomeDenied)
				writeForbidden(w, "forbidden")
			default:
				audit(fp, AuditOutcomeFailure)
				logging.Warnf("renewal retry: certificate unavailable: %v", err)
				writeServiceUnavailable(w, "certificate unavailable")
			}
			return
		}

		queue := currentRenewalFailureStore()
		rec, ok, err := queue.Get(r.Context(), failureKindExecute, fp)
		if err != nil {
			audit(fp, AuditOutcomeFailure)
			logging.Warnf("renewal retry: failure queue unavailable: %v", err)
			writeServiceUnavailable(w, "renewal failure queue unavailable")
			return
		}
		if !ok {
			audit(fp, AuditOutcomeFailure)
			writeNotFound(w, "no failed renewal is queued for this certificate")
			return
		}

		// Actor renewal-scheduler: installState filters on it, so a row under
		// the operator's id would be invisible and the retry a no-op.
		if auditProvider == nil {
			audit(fp, AuditOutcomeFailure)
			writeServiceUnavailable(w, "audit log unavailable")
			return
		}
		if err := auditProvider.AppendEntry(r.Context(), AuditEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339), Action: renewalRetryRequestedAction,
			ActorType: "system", ActorID: "renewal-scheduler", ResourceType: "certificate", ResourceID: fp,
			Outcome: AuditOutcomeSuccess, ChangeSummary: "requested_by=" + pd.ID,
		}); err != nil {
			audit(fp, AuditOutcomeFailure)
			logging.Warnf("renewal retry: recording reset marker failed: %v", err)
			writeServiceUnavailable(w, "could not record the retry request")
			return
		}
		rec.NextAttemptAt = time.Now().UTC()
		if err := queue.Upsert(r.Context(), rec); err != nil {
			// The marker already makes the next tick attempt; only the
			// operator-visible mirror is stale.
			logging.Warnf("renewal retry: updating failure queue for %s failed: %v", fp, err)
		}
		audit(fp, AuditOutcomeSuccess)
		kickRenewalScan()
		writeJSONStatus(w, http.StatusAccepted, map[string]any{"data": map[string]string{"fingerprint": fp, "status": "queued"}})
	}
}
