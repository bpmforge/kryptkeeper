// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"
)

// W17-07: the W16-04 cluster-atomic rollout, wired to real targets.
//
// RunRolloutGroup had zero non-test callers. Multi-node clusters where
// several nodes serve the SAME certificate are a top operator complaint
// incumbents leave manual: renew node-by-node and the cluster serves a
// split identity until the last node lands. This flips the group
// canary → verify → fleet, with all-or-nothing rollback.

type rolloutRequest struct {
	Fingerprint string                `json:"fingerprint"`
	Group       string                `json:"group"`
	Nodes       []rolloutNodeSpec     `json:"nodes"`
	Window      MaintenanceWindow     `json:"window"`
	Install     RenewalInstallProfile `json:"install"`
}

type rolloutNodeSpec struct {
	TargetID string `json:"target_id"`
	IsCanary bool   `json:"is_canary"`
}

const maxRolloutNodes = 200

// registerRolloutHandler mounts the coordinated rollout endpoint.
// newRolloutExecutor builds the executor the rollout drives. A package
// var so tests can inject a verifier instead of standing up real TLS
// listeners — the same seam renewal_executor_test.go already uses.
var newRolloutExecutor = func(certs CertificateProvider, creds OutboundCredentialStore) *RenewalExecutor {
	return NewRenewalExecutor(certs, creds).WithEnvConnectorRegistry(certs)
}

func registerRolloutHandler(mux *http.ServeMux, auth *Authenticator, certificateProvider CertificateProvider, targetStore ManagedTargetStore, credentialStore OutboundCredentialStore, auditProvider AuditProvider, plugins *DeliveryPluginManager) {
	executor := newRolloutExecutor(certificateProvider, credentialStore).WithPluginDeliverer(plugins, auditProvider)

	mux.HandleFunc("/api/v1/renewal/rollout", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "certificate.renew_rollout", "certificate", "rollout", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}

		var req rolloutRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRenewalExecuteBodyBytes)).Decode(&req); err != nil ||
			req.Fingerprint == "" || len(req.Nodes) == 0 {
			emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_rollout", "certificate", req.Fingerprint, AuditOutcomeFailure)
			writeBadRequestJSON(w, "fingerprint and at least one node are required")
			return
		}
		if len(req.Nodes) > maxRolloutNodes {
			writeBadRequestJSON(w, fmt.Sprintf("a rollout group is limited to %d nodes", maxRolloutNodes))
			return
		}

		if _, err := authorizeCertificateResourceAccess(r.Context(), certificateProvider, pd, req.Fingerprint); err != nil {
			switch {
			case errors.Is(err, errCertificateNotFound):
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_rollout", "certificate", req.Fingerprint, AuditOutcomeFailure)
				writeNotFound(w, "certificate not found")
			case errors.Is(err, errCertificateForbidden):
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_rollout", "certificate", req.Fingerprint, AuditOutcomeDenied)
				writeForbidden(w, "forbidden")
			default:
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_rollout", "certificate", req.Fingerprint, AuditOutcomeFailure)
				writeServiceUnavailable(w, "certificate unavailable")
			}
			return
		}
		if credentialStore == nil {
			emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_rollout", "certificate", req.Fingerprint, AuditOutcomeFailure)
			writeServiceUnavailable(w, "outbound credential store not configured (set APP_CREDENTIAL_STORE_PASSPHRASE or KRYPTKEEPER_KEYSTORE_PASSPHRASE)")
			return
		}

		// Resolve and authorize EVERY node BEFORE touching any of them.
		// A rollout is cluster-atomic; discovering an invisible target
		// halfway through would leave the cluster split across a tenant
		// boundary — a security defect, not a partial failure.
		targets := make(map[string]ManagedTarget, len(req.Nodes))
		profiles := make(map[string]RenewalInstallProfile, len(req.Nodes))
		nodes := make([]RolloutNode, 0, len(req.Nodes))
		for _, spec := range req.Nodes {
			target, err := targetStore.Get(r.Context(), spec.TargetID)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_rollout", "certificate", req.Fingerprint, AuditOutcomeFailure)
				writeNotFound(w, "target not found: "+spec.TargetID)
				return
			}
			if !targetVisibleToTenant(pd, target) {
				emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_rollout", "certificate", req.Fingerprint, AuditOutcomeDenied)
				writeForbidden(w, "forbidden")
				return
			}
			profile, ok := installProfileForCaller(pd, target, req.Install)
			if !ok {
				emitAuditEventDetail(r, auditProvider, pd.ID, "certificate.renew_rollout", "certificate", req.Fingerprint, AuditOutcomeDenied,
					"install profile override needs pki-admin")
				writeForbidden(w, "an install profile override needs the pki-admin role; each target's stored profile is used otherwise")
				return
			}
			targets[spec.TargetID] = target
			profiles[spec.TargetID] = profile
			nodes = append(nodes, RolloutNode{ID: spec.TargetID, IsCanary: spec.IsCanary})
		}

		// ONE renewal for the WHOLE group. Renewing per node would give
		// each node a different certificate — the precise opposite of
		// what a cluster serving one identity needs.
		material, err := executor.renewPushMaterial(r.Context(), req.Fingerprint)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_rollout", "certificate", req.Fingerprint, AuditOutcomeFailure)
			log.Printf("rollout: renew: %v", err)
			writeServiceUnavailable(w, "renewal failed: "+err.Error())
			return
		}
		defer zeroize(material.KeyPEM)

		install := func(ctx context.Context, node RolloutNode) (bool, string) {
			res, perr := executor.pushMaterialToTarget(ctx, targets[node.ID], profiles[node.ID],
				material.ChainPEM, material.KeyPEM, material.LeafFingerprint)
			if perr != nil {
				return false, perr.Error()
			}
			if !res.Verified {
				detail := res.Detail
				if detail == "" {
					detail = res.Outcome
				}
				return false, detail
			}
			return true, res.Outcome
		}

		// Reverting a node that ALREADY SUCCEEDED would mean re-installing
		// the predecessor certificate — and its private key, which we
		// deliberately do not retain (the key-boundary law; retention is
		// the opt-in W15-03 escrow, off by default). So this reports the
		// limitation instead of returning nil and letting the engine
		// record a rollback that never happened. RunRolloutGroup marks
		// such nodes rollback_failed, which tells the operator exactly
		// which nodes are on the new certificate and need attention.
		// Nodes whose VERIFY failed are already reverted by the pusher's
		// own restore inside pushMaterialToTarget.
		rollback := func(_ context.Context, node RolloutNode) error {
			return fmt.Errorf("node %s installed successfully and cannot be auto-reverted: "+
				"restoring the predecessor certificate requires its private key, which is not retained", node.ID)
		}

		result := RunRolloutGroup(r.Context(), RolloutGroup{Name: req.Group, Nodes: nodes, Window: req.Window},
			install, rollback, time.Now().UTC())

		outcome := AuditOutcomeSuccess
		if result.Halted {
			outcome = AuditOutcomeFailure
		}
		emitAuditEventDetail(r, auditProvider, pd.ID, "certificate.renew_rollout", "certificate", req.Fingerprint, outcome,
			fmt.Sprintf(`{"group":%q,"nodes":%d,"deferred":%t,"halted":%t,"halt_reason":%q}`,
				req.Group, len(nodes), result.Deferred, result.Halted, result.HaltReason))

		if err := json.NewEncoder(w).Encode(struct {
			Data RolloutResult `json:"data"`
		}{Data: result}); err != nil {
			log.Printf("failed to encode rollout result: %v", err)
		}
	})
}
