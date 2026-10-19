// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"kryptkeeper/internal/logging"
	"net/http"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/agentinstall"
	"kryptkeeper/internal/connectors"
)

const maxRenewalExecuteBodyBytes = 64 * 1024

const (
	// renewalExecuteBudget bounds one execution. It must exceed the longest
	// dns-01 propagation wait (an ACME connector allows up to
	// maxDNSPropagationTimeout) plus the CA's order time and the install
	// verify-retry window (~135s, k8s push), or the connection is cut and
	// the caller gets an empty reply instead of the outcome. A delivery
	// plugin may also declare a verify propagation window (W27-37, CDN
	// rollouts take minutes); cutting it short would roll back a correct
	// push, so the budget covers the largest window a manifest may declare.
	renewalExecuteBudget = maxDNSPropagationTimeout + maxPluginVerifyWindow + 5*time.Minute
	// renewalResponseWindow is the write window left for the response once
	// the executor returns, however long that took.
	renewalResponseWindow = 30 * time.Second
)

// renewalRunner is the executor seam, so tests can substitute a slow one.
type renewalRunner interface {
	ExecuteRenewal(ctx context.Context, fingerprint string, target ManagedTarget, profile RenewalInstallProfile) (RenewalExecuteResult, error)
}

// renewalExecuteRequest is the wire shape of POST /api/v1/renewal/execute.
// It lives on its own route rather than under /api/v1/certificates/{fp}/
// because that mux pattern's suffix router is owned by
// handlers_certificates.go, which two parked review branches (S-36/S-37)
// are already editing.
type renewalExecuteRequest struct {
	Fingerprint string `json:"fingerprint"`
	TargetID    string `json:"target_id"`
	// Install overrides the target's stored install profile. Only a pki-admin
	// may send it: the profile chooses where key material is written and
	// which unit is reloaded, so any other caller gets the stored one (RC1-A-03).
	Install RenewalInstallProfile `json:"install"`
	// JITSudoPassword (W34-17) is a sudo password for this run only: held in
	// memory, zeroized when the run ends, never stored, logged or audited.
	JITSudoPassword string `json:"jit_sudo_password,omitempty"`
}

func isRateLimited(err error) bool {
	_, limited := rateLimitWait(err)
	return limited
}

// rateLimitWait reports a connector rate limit and how long to wait: the
// W27-33 throttle's errors and raw ACME 429s (connectors.RetryAfterOf) or the
// ACME connector's own W26-28 gate refusing before it sends.
func rateLimitWait(err error) (time.Duration, bool) {
	if d, ok := connectors.RetryAfterOf(err); ok {
		return d, true
	}
	var rl *acmeRateLimitError
	if errors.As(err, &rl) {
		return max(time.Until(rl.RetryAt), time.Second), true
	}
	return 0, false
}

// retryAfterSeconds renders a wait as whole seconds, rounded up and at least 1,
// as the Retry-After header requires.
func retryAfterSeconds(d time.Duration) string {
	secs := int((d + time.Second - 1) / time.Second)
	if secs < 1 {
		secs = 1
	}
	return strconv.Itoa(secs)
}

// profileFromTarget is the install profile configured on the target.
func profileFromTarget(t ManagedTarget) RenewalInstallProfile {
	return RenewalInstallProfile{
		ServerType:     t.InstallServerType,
		CertPath:       t.InstallCertPath,
		KeyPath:        t.InstallKeyPath,
		ReloadMethod:   t.InstallReloadMethod,
		VerifyHostPort: t.VerifyHostPort,
	}
}

// installProfileForCaller picks the profile an on-demand renewal installs
// with: the target's stored one, unless a pki-admin supplied an override.
// ok=false means a non-admin tried to override it.
func installProfileForCaller(pd AuthPrincipal, target ManagedTarget, supplied RenewalInstallProfile) (profile RenewalInstallProfile, ok bool) {
	if supplied == (RenewalInstallProfile{}) {
		return profileFromTarget(target), true
	}
	if !isAdminRole(pd.Role) {
		return RenewalInstallProfile{}, false
	}
	return supplied, true
}

// RegisterRenewalExecuteHandler mounts the hub-side renewal execution
// endpoint (W5-13). Authorization mirrors the renew endpoint: the caller
// must be able to access the certificate, and the target must be visible to
// the caller's tenant.
func RegisterRenewalExecuteHandler(mux *http.ServeMux, auth *Authenticator, certificateProvider CertificateProvider, targetStore ManagedTargetStore, credentialStore OutboundCredentialStore, auditProvider AuditProvider) {
	registerRenewalExecuteHandler(mux, auth, certificateProvider, targetStore, credentialStore, auditProvider, nil)
}

// registerRenewalExecuteHandler is RegisterRenewalExecuteHandler with the
// delivery plugin manager for install_mode "plugin" targets (W20-20).
func registerRenewalExecuteHandler(mux *http.ServeMux, auth *Authenticator, certificateProvider CertificateProvider, targetStore ManagedTargetStore, credentialStore OutboundCredentialStore, auditProvider AuditProvider, plugins *DeliveryPluginManager) {
	executor := NewRenewalExecutor(certificateProvider, credentialStore).WithEnvConnectorRegistry(certificateProvider).WithPluginDeliverer(plugins, auditProvider)
	if targetStore != nil {
		executor = executor.WithTargetBlocker(targetStateBlocker{targetStore})
	}
	registerRenewalExecuteHandlerWithRunner(mux, auth, certificateProvider, targetStore, credentialStore, auditProvider, executor, renewalExecuteBudget)
}

func registerRenewalExecuteHandlerWithRunner(mux *http.ServeMux, auth *Authenticator, certificateProvider CertificateProvider, targetStore ManagedTargetStore, credentialStore OutboundCredentialStore, auditProvider AuditProvider, executor renewalRunner, budget time.Duration) {
	mux.HandleFunc("/api/v1/renewal/retry", renewalRetryHandler(auth, certificateProvider, auditProvider))
	mux.HandleFunc("/api/v1/renewal/execute", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "certificate.renew_execute", "certificate", "renewal-execute", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}

		body := http.MaxBytesReader(w, r.Body, maxRenewalExecuteBodyBytes)
		defer body.Close()
		raw, err := io.ReadAll(body)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_execute", "certificate", "renewal-execute", AuditOutcomeFailure)
			writeBadRequestJSON(w, "invalid request body")
			return
		}
		var req renewalExecuteRequest
		err = json.Unmarshal(raw, &req)
		zeroize(raw) // the body may carry the one-off sudo password
		jit := newJITSudo(req.JITSudoPassword)
		req.JITSudoPassword = ""
		defer jit.zero()
		if len(jit.text()) > maxJITSudoPasswordLen {
			emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_execute", "certificate", req.Fingerprint, AuditOutcomeFailure)
			writeBadRequestJSON(w, "jit_sudo_password is too long")
			return
		}
		if jit.text() == "" {
			jit = nil
		}
		if err != nil || req.Fingerprint == "" || req.TargetID == "" {
			emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_execute", "certificate", req.Fingerprint, AuditOutcomeFailure)
			writeBadRequestJSON(w, "fingerprint and target_id are required")
			return
		}

		if _, err := authorizeCertificateResourceAccess(r.Context(), certificateProvider, pd, req.Fingerprint); err != nil {
			switch {
			case errors.Is(err, errCertificateNotFound):
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_execute", "certificate", req.Fingerprint, AuditOutcomeFailure)
				writeNotFound(w, "certificate not found")
			case errors.Is(err, errCertificateForbidden), errors.Is(err, errCertificateTeamScopeForbidden), errors.Is(err, errCertificateTenantForbidden):
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_execute", "certificate", req.Fingerprint, AuditOutcomeDenied)
				writeForbidden(w, "forbidden")
			default:
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_execute", "certificate", req.Fingerprint, AuditOutcomeFailure)
				logging.Warnf("renewal execute: certificate unavailable: %v", err)
				writeServiceUnavailable(w, "certificate unavailable")
			}
			return
		}

		target, err := targetStore.Get(r.Context(), req.TargetID)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_execute", "certificate", req.Fingerprint, AuditOutcomeFailure)
			writeNotFound(w, "target not found")
			return
		}
		if !targetVisibleToTenant(pd, target) {
			emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_execute", "certificate", req.Fingerprint, AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}
		profile, ok := installProfileForCaller(pd, target, req.Install)
		if !ok {
			emitAuditEventDetail(r, auditProvider, pd.ID, "certificate.renew_execute", "certificate", req.Fingerprint, AuditOutcomeDenied,
				"install profile override needs pki-admin")
			writeForbidden(w, "an install profile override needs the pki-admin role; the target's stored profile is used otherwise")
			return
		}
		// newOutboundCredentialStoreFromEnv fails closed (nil) without a
		// passphrase; surface that as a config problem, not a panic.
		if credentialStore == nil {
			emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_execute", "certificate", req.Fingerprint, AuditOutcomeFailure)
			writeServiceUnavailable(w, "outbound credential store not configured (set APP_CREDENTIAL_STORE_PASSPHRASE or KRYPTKEEPER_KEYSTORE_PASSPHRASE)")
			return
		}

		// W19-17 finding: a renewal runs well past server.go's global 15s
		// WriteTimeout, which is NOT reset by writes after the request read
		// -- the connection is silently closed mid-handler, surfacing as
		// "curl: (52) Empty reply from server" even though the renewal
		// itself may succeed server-side. server.go's timeouts are outside
		// this endpoint's write_scope, so a per-connection override is the
		// fix (the seam handlers_sse.go uses). SetWriteDeadline's error is
		// ignored exactly as there: a ResponseWriter without deadline
		// support (httptest.ResponseRecorder) keeps the default.
		//
		// The window is the whole execution budget plus a response margin,
		// not a fixed 180s: a dns-01 order alone may wait minutes for TXT
		// propagation (the 180s here was shorter than that wait, so a slow
		// failure or success was dropped). The executor's context is
		// bounded by the same budget, and the deadline is re-armed after it
		// returns, so an error is always written as JSON.
		rc := http.NewResponseController(w)
		_ = rc.SetWriteDeadline(time.Now().Add(budget + renewalResponseWindow)) // unsupported ResponseWriter (tests) keeps server.go's default
		_ = rc.SetReadDeadline(time.Now().Add(budget + renewalResponseWindow))  // unsupported ResponseWriter (tests) keeps server.go's default
		execCtx, cancelExec := context.WithTimeout(withJITSudo(r.Context(), jit), budget)
		defer cancelExec()

		publishOperationEvent(pd.Tenant, EventKindRenew, req.Fingerprint, "queued", nil, "")
		publishOperationEvent(pd.Tenant, EventKindRenew, req.Fingerprint, "running", nil, "")
		result, err := executor.ExecuteRenewal(execCtx, req.Fingerprint, target, profile)
		_ = rc.SetWriteDeadline(time.Now().Add(renewalResponseWindow)) // re-arm so the outcome is written even after a long run; unsupported writers ignore it
		if err != nil {
			if errors.Is(err, errApprovalRequired) {
				publishOperationEvent(pd.Tenant, EventKindRenew, req.Fingerprint, "queued", nil, "pending approval")
			} else {
				publishOperationEvent(pd.Tenant, EventKindRenew, req.Fingerprint, "failed", nil, "renewal failed")
			}
			switch {
			case errors.Is(err, errApprovalRequired):
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_execute", "certificate", req.Fingerprint, AuditOutcomePendingApproval)
				writeJSONStatus(w, http.StatusAccepted, map[string]string{
					"status":  "pending_approval",
					"message": "renewal requires approval; execute again after it is granted",
				})
			case errors.Is(err, errCertificateNotFound):
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_execute", "certificate", req.Fingerprint, AuditOutcomeFailure)
				writeNotFound(w, "certificate not found")
			case errors.Is(err, errCertificateConflict):
				successor := successorFingerprintOf(r.Context(), certificateProvider, req.Fingerprint)
				emitAuditEventDetail(r, auditProvider, pd.ID, "certificate.renew_execute", "certificate", req.Fingerprint, AuditOutcomeFailure,
					conflictAuditDetail(successor))
				writeRenewalConflict(w, successor)
			case isRateLimited(err):
				wait, _ := rateLimitWait(err)
				emitAuditEventDetail(r, auditProvider, pd.ID, "certificate.renew_execute", "certificate", req.Fingerprint, AuditOutcomeFailure,
					"rate_limited retry_after="+retryAfterSeconds(wait))
				w.Header().Set("Retry-After", retryAfterSeconds(wait))
				writeTooManyRequests(w, "the issuing connector is rate limited; retry after the interval in Retry-After")
			case errors.Is(err, errRenewalTargetNotSSH),
				errors.Is(err, errRenewalKeyModeMismatch),
				errors.Is(err, errRenewalNoCredential),
				errors.Is(err, errRenewalBadCredential),
				errors.Is(err, errRenewalInstallProfile),
				errors.Is(err, errCertificateInvalid):
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_execute", "certificate", req.Fingerprint, AuditOutcomeFailure)
				writeBadRequestJSON(w, err.Error())
			default:
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_execute", "certificate", req.Fingerprint, AuditOutcomeFailure)
				logging.Warnf("renewal execute failed: %v", err)
				writeServiceUnavailable(w, "renewal execution failed")
			}
			return
		}

		// Renewed. The install outcome (including failure) rides in the body:
		// the successor cert exists either way and the caller must see both
		// facts — the S-50 lesson applied to this surface.
		// The install outcome is an open set (one per agentinstall.Outcome*),
		// so it rides in the change summary; the audit outcome stays inside
		// the closed AuditOutcome vocabulary.
		outcome, summary := AuditOutcomeSuccess, ""
		if result.InstallOutcome != agentinstall.OutcomeInstalledVerified && result.InstallOutcome != agentinstall.OutcomeInstalled {
			outcome = AuditOutcomePartial
			summary = "renewed; install_outcome=" + nonEmpty(result.InstallOutcome, "failed")
		}
		if jit != nil {
			summary = strings.TrimSpace(summary + " privilege_source=jit")
		}
		publishOperationEvent(pd.Tenant, EventKindRenew, req.Fingerprint, "completed", nil, nonEmpty(summary, "renewed"))
		emitAuditEventDetail(r, auditProvider, pd.ID, "certificate.renew_execute", "certificate", req.Fingerprint, outcome, summary)
		// W27-02: the target now serves the successor; move its binding along so
		// the sweep renews the successor, not the certificate it replaced.
		if outcome == AuditOutcomeSuccess && result.NewFingerprint != "" && activeCertTargetBindingStore != nil {
			if err := activeCertTargetBindingStore.AdvanceServed(r.Context(), target.ID, req.Fingerprint, result.NewFingerprint); err != nil {
				logging.Warnf("renewal execute: recording %s as served on target %s failed: %v", result.NewFingerprint, target.ID, err)
			}
		}
		writeJSONStatus(w, http.StatusOK, struct {
			Data RenewalExecuteResult `json:"data"`
		}{Data: result})
	})
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func writeBadRequestJSON(w http.ResponseWriter, msg string) {
	writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "bad_request", "message": msg})
}

func writeJSONStatus(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		logging.Warnf("failed to encode renewal-execute response: %v", err)
	}
}

// successorFingerprintOf returns the successor already minted for fingerprint
// ("" when unknown). A renewal that halted or rolled back leaves a successor
// no node kept; the operator needs its fingerprint to roll THAT one out, since
// the hub deliberately never re-mints or reuses key material implicitly.
func successorFingerprintOf(ctx context.Context, certs CertificateProvider, fingerprint string) string {
	detail, ok, err := certs.GetCertificate(ctx, fingerprint)
	if err != nil || !ok || detail.SuccessorFP == nil {
		return ""
	}
	return strings.TrimSpace(*detail.SuccessorFP)
}

func conflictAuditDetail(successor string) string {
	return "conflict: certificate already has a successor; successor_fingerprint=" + successor
}

func writeRenewalConflict(w http.ResponseWriter, successor string) {
	body := map[string]string{
		"error":   "conflict",
		"message": "certificate already has a successor; roll out the successor instead of renewing again",
	}
	if successor != "" {
		body["successor_fingerprint"] = successor
	}
	writeJSONStatus(w, http.StatusConflict, body)
}
