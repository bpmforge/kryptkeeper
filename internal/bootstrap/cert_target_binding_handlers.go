// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
)

// W27-02: /api/v1/targets/{id}/bindings. A binding is the operator's
// authorization for the hub to renew one certificate onto one target and push
// its private key there, so creating one needs certificate.renew on top of the
// discovery.manage the /targets/** write gate asks for.

var fingerprintHexRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

const bindingAuditAction = "target.update"

type bindingEnvelope struct {
	Data any `json:"data"`
}

// RegisterCertTargetBindingHandlers mounts the binding routes and makes store
// reachable to the target-delete and manual-renewal paths. Any dependency may
// be nil (DB unavailable): the routes then answer 503, auditing the refusal.
func RegisterCertTargetBindingHandlers(mux *http.ServeMux, auth *Authenticator, targets ManagedTargetStore, certs CertificateProvider, bindings CertTargetBindingStore, auditProvider AuditProvider) {
	setActiveCertTargetBindingStore(bindings)

	// resolveTarget authenticates the caller and loads a tenant-visible target;
	// every refusal is audited and answered here.
	resolveTarget := func(w http.ResponseWriter, r *http.Request, action string) (AuthPrincipal, ManagedTarget, bool) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return AuthPrincipal{}, ManagedTarget{}, false
		}
		id := r.PathValue("id")
		if targets == nil || bindings == nil {
			emitAuditEvent(r, auditProvider, pd.ID, action, "target", id, AuditOutcomeFailure)
			writeServiceUnavailable(w, "certificate binding store unavailable")
			return pd, ManagedTarget{}, false
		}
		target, err := targets.Get(r.Context(), id)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, action, "target", id, AuditOutcomeFailure)
			writeNotFound(w, "target not found")
			return pd, ManagedTarget{}, false
		}
		if !targetVisibleToTenant(pd, target) {
			emitAuditEvent(r, auditProvider, pd.ID, action, "target", id, AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return pd, ManagedTarget{}, false
		}
		return pd, target, true
	}

	mux.HandleFunc("/api/v1/targets/{id}/bindings", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			pd, target, ok := resolveTarget(w, r, "target.get")
			if !ok {
				return
			}
			items, err := bindings.ListByTarget(r.Context(), target.ID)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.get", "target", target.ID, AuditOutcomeFailure)
				writeServiceUnavailable(w, "list failed")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "target.get", "target", target.ID, AuditOutcomeSuccess)
			writeJSONData(w, items)

		case http.MethodPost:
			pd, target, ok := resolveTarget(w, r, bindingAuditAction)
			if !ok {
				return
			}
			createBinding(w, r, auth, certs, bindings, auditProvider, pd, target)

		default:
			writeMethodNotAllowed(w, "GET, POST")
		}
	})

	mux.HandleFunc("/api/v1/targets/{id}/bindings/{fingerprint}", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			writeMethodNotAllowed(w, http.MethodDelete)
			return
		}
		pd, target, ok := resolveTarget(w, r, bindingAuditAction)
		if !ok {
			return
		}
		fp := strings.ToLower(strings.TrimSpace(r.PathValue("fingerprint")))
		if !fingerprintHexRE.MatchString(fp) {
			emitAuditEventDetail(r, auditProvider, pd.ID, bindingAuditAction, "target", target.ID, AuditOutcomeFailure, "binding.delete malformed fingerprint")
			writeBadRequest(w, "fingerprint must be a 64-character SHA-256 hex string")
			return
		}
		detail := "binding.delete cert=" + fp
		if err := bindings.Delete(r.Context(), target.ID, fp); err != nil {
			emitAuditEventDetail(r, auditProvider, pd.ID, bindingAuditAction, "target", target.ID, AuditOutcomeFailure, detail)
			if errors.Is(err, errBindingNotFound) {
				writeNotFound(w, "binding not found")
				return
			}
			writeServiceUnavailable(w, "delete failed")
			return
		}
		emitAuditEventDetail(r, auditProvider, pd.ID, bindingAuditAction, "target", target.ID, AuditOutcomeSuccess, detail)
		w.WriteHeader(http.StatusNoContent)
	})
}

func createBinding(w http.ResponseWriter, r *http.Request, auth *Authenticator, certs CertificateProvider, bindings CertTargetBindingStore, auditProvider AuditProvider, pd AuthPrincipal, target ManagedTarget) {
	audit := func(outcome AuditOutcome, fp string) {
		detail := "binding.create"
		if fp != "" {
			detail += " cert=" + fp
		}
		emitAuditEventDetail(r, auditProvider, pd.ID, bindingAuditAction, "target", target.ID, outcome, detail)
	}

	var req struct {
		CertFingerprint string `json:"cert_fingerprint"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4*1024)).Decode(&req); err != nil {
		audit(AuditOutcomeFailure, "")
		writeBadRequest(w, "invalid request body")
		return
	}
	fp := strings.ToLower(strings.TrimSpace(req.CertFingerprint))
	if !fingerprintHexRE.MatchString(fp) {
		audit(AuditOutcomeFailure, "")
		writeBadRequest(w, "cert_fingerprint must be a 64-character SHA-256 hex string")
		return
	}

	// A binding authorizes key egress to the target: the same bar as arming it.
	perms, admin := principalPermissions(pd, auth.roleStore)
	if !admin && !perms["certificate.renew"] {
		audit(AuditOutcomeDenied, fp)
		writeForbidden(w, "binding a certificate to a target needs certificate.renew")
		return
	}

	if certs == nil {
		audit(AuditOutcomeFailure, fp)
		writeServiceUnavailable(w, "certificate provider unavailable")
		return
	}
	item, err := authorizeCertificateResourceAccess(r.Context(), certs, pd, fp)
	if err != nil {
		switch {
		case errors.Is(err, errCertificateNotFound):
			audit(AuditOutcomeFailure, fp)
			writeNotFound(w, "certificate not found")
		case errors.Is(err, errCertificateForbidden), errors.Is(err, errCertificateTeamScopeForbidden), errors.Is(err, errCertificateTenantForbidden):
			audit(AuditOutcomeDenied, fp)
			writeForbidden(w, "forbidden")
		default:
			audit(AuditOutcomeFailure, fp)
			logging.Warnf("binding create: certificate unavailable: %v", err)
			writeServiceUnavailable(w, "certificate unavailable")
		}
		return
	}
	// Never let a target in one tenant hold a key from another tenant's CA.
	if !targetMayReceiveCert(r.Context(), target, CertificateItem{CAID: item.CAID}) {
		audit(AuditOutcomeDenied, fp)
		writeForbidden(w, "the target's tenant cannot use this certificate's CA")
		return
	}

	created, err := bindings.Create(r.Context(), CertTargetBinding{
		CertFingerprint: fp, TargetID: target.ID, Tenant: target.Tenant,
		Source: bindingSourceOperator, CreatedBy: pd.ID,
	})
	switch {
	case errors.Is(err, errBindingExists):
		audit(AuditOutcomeFailure, fp)
		writeConflict(w, "certificate is already bound to this target")
	case err != nil:
		audit(AuditOutcomeFailure, fp)
		logging.Warnf("binding create failed: %v", err)
		writeServiceUnavailable(w, "create failed")
	default:
		audit(AuditOutcomeSuccess, fp)
		writeJSONStatus(w, http.StatusCreated, bindingEnvelope{Data: created})
	}
}
