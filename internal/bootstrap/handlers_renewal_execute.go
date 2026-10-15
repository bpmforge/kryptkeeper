// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"time"

	"kryptkeeper/internal/agentinstall"
)

const maxRenewalExecuteBodyBytes = 64 * 1024

const (
	// renewalExecuteBudget bounds one execution. It must exceed the longest
	// dns-01 propagation wait (an ACME connector allows up to
	// maxDNSPropagationTimeout) plus the CA's order time and the install
	// verify-retry window (~135s, k8s push), or the connection is cut and
	// the caller gets an empty reply instead of the outcome.
	renewalExecuteBudget = maxDNSPropagationTimeout + 5*time.Minute
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
	registerRenewalExecuteHandlerWithRunner(mux, auth, certificateProvider, targetStore, credentialStore, auditProvider, executor, renewalExecuteBudget)
}

func registerRenewalExecuteHandlerWithRunner(mux *http.ServeMux, auth *Authenticator, certificateProvider CertificateProvider, targetStore ManagedTargetStore, credentialStore OutboundCredentialStore, auditProvider AuditProvider, executor renewalRunner, budget time.Duration) {
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
		if err := json.Unmarshal(raw, &req); err != nil || req.Fingerprint == "" || req.TargetID == "" {
			emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_execute", "certificate", req.Fingerprint, AuditOutcomeFailure)
			writeBadRequestJSON(w, "fingerprint and target_id are required")
			return
		}

		if _, err := authorizeCertificateResourceAccess(r.Context(), certificateProvider, pd, req.Fingerprint); err != nil {
			switch {
			case errors.Is(err, errCertificateNotFound):
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_execute", "certificate", req.Fingerprint, AuditOutcomeFailure)
				writeNotFound(w, "certificate not found")
			case errors.Is(err, errCertificateForbidden):
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_execute", "certificate", req.Fingerprint, AuditOutcomeDenied)
				writeForbidden(w, "forbidden")
			default:
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_execute", "certificate", req.Fingerprint, AuditOutcomeFailure)
				log.Printf("renewal execute: certificate unavailable: %v", err)
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
		execCtx, cancelExec := context.WithTimeout(r.Context(), budget)
		defer cancelExec()

		result, err := executor.ExecuteRenewal(execCtx, req.Fingerprint, target, profile)
		_ = rc.SetWriteDeadline(time.Now().Add(renewalResponseWindow)) // re-arm so the outcome is written even after a long run; unsupported writers ignore it
		if err != nil {
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
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_execute", "certificate", req.Fingerprint, AuditOutcomeFailure)
				writeJSONStatus(w, http.StatusConflict, map[string]string{
					"error":   "conflict",
					"message": "certificate already has a successor",
				})
			case errors.Is(err, errRenewalTargetNotSSH),
				errors.Is(err, errRenewalNoCredential),
				errors.Is(err, errRenewalBadCredential),
				errors.Is(err, errRenewalInstallProfile),
				errors.Is(err, errCertificateInvalid):
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_execute", "certificate", req.Fingerprint, AuditOutcomeFailure)
				writeBadRequestJSON(w, err.Error())
			default:
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_execute", "certificate", req.Fingerprint, AuditOutcomeFailure)
				log.Printf("renewal execute failed: %v", err)
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
		emitAuditEventDetail(r, auditProvider, pd.ID, "certificate.renew_execute", "certificate", req.Fingerprint, outcome, summary)
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
		log.Printf("failed to encode renewal-execute response: %v", err)
	}
}
