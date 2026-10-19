// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"kryptkeeper/internal/logging"
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
			emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_rollout", "certificate", req.Fingerprint, AuditOutcomeFailure)
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

		// Staged (two-phase) rollout needs every node to be an ssh-mode
		// nginx/apache/haproxy host; a mixed group stays sequential rather
		// than half-staging.
		stageable := true
		for _, spec := range req.Nodes {
			p := profiles[spec.TargetID]
			if targets[spec.TargetID].InstallMode != "ssh" || (p.ServerType != "nginx" && p.ServerType != "apache" && p.ServerType != "haproxy") {
				stageable = false
				break
			}
		}
		mode := RolloutModeSequential
		if stageable {
			mode = RolloutModeStaged
		}
		group := RolloutGroup{Name: req.Group, Nodes: nodes, Window: req.Window}

		respond := func(result RolloutResult) {
			if err := json.NewEncoder(w).Encode(struct {
				Data RolloutResult `json:"data"`
			}{Data: result}); err != nil {
				logging.Warnf("failed to encode rollout result: %v", err)
			}
		}

		// The window is checked BEFORE renewing: an out-of-window request
		// must not issue a certificate or dial any node.
		if now := time.Now().UTC(); !req.Window.allows(now) {
			emitAuditEventDetail(r, auditProvider, pd.ID, "certificate.renew_rollout", "certificate", req.Fingerprint, AuditOutcomeSuccess,
				fmt.Sprintf(`{"group":%q,"nodes":%d,"deferred":true,"halted":false,"mode":%q}`, req.Group, len(nodes), mode))
			respond(deferredResult(group, mode))
			return
		}

		// The rollout runs inside this request, well past server.go's 15s
		// WriteTimeout once a plugin node waits out its verify propagation
		// window (W27-37, up to 30 min per node). Extend the deadline the
		// way renewal/execute does, sized to the group, and re-arm it
		// before the response is written.
		rc := http.NewResponseController(w)
		rolloutBudget := renewalExecuteBudget + time.Duration(len(nodes))*(maxPluginVerifyWindow+2*time.Minute)
		_ = rc.SetWriteDeadline(time.Now().Add(rolloutBudget + renewalResponseWindow)) // unsupported ResponseWriter (tests) keeps server.go's default
		_ = rc.SetReadDeadline(time.Now().Add(rolloutBudget + renewalResponseWindow))  // unsupported ResponseWriter (tests) keeps server.go's default

		// ONE renewal for the WHOLE group. Renewing per node would give
		// each node a different certificate — the precise opposite of
		// what a cluster serving one identity needs.
		material, err := executor.renewPushMaterial(r.Context(), req.Fingerprint)
		if errors.Is(err, errCertificateConflict) {
			successor := successorFingerprintOf(r.Context(), certificateProvider, req.Fingerprint)
			emitAuditEventDetail(r, auditProvider, pd.ID, "certificate.renew_rollout", "certificate", req.Fingerprint, AuditOutcomeFailure,
				conflictAuditDetail(successor))
			writeRenewalConflict(w, successor)
			return
		}
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "certificate.renew_rollout", "certificate", req.Fingerprint, AuditOutcomeFailure)
			logging.Infof("rollout: renew: %v", err)
			writeServiceUnavailable(w, "renewal failed: "+err.Error())
			return
		}
		defer zeroize(material.KeyPEM)

		var result RolloutResult
		if stageable {
			adapter := &sshStagedRollout{
				e: executor, targets: targets, profiles: profiles,
				chainPEM: material.ChainPEM, keyPEM: material.KeyPEM, leafFP: material.LeafFingerprint,
				conns: map[string]*stagedConn{},
			}
			defer adapter.closeAll()
			result = RunStagedRolloutGroup(r.Context(), group, adapter.ops(), time.Now().UTC())
		} else {
			result = runSequentialRollout(r.Context(), executor, group, targets, profiles, material)
		}
		result.NewFingerprint = material.LeafFingerprint
		_ = rc.SetWriteDeadline(time.Now().Add(renewalResponseWindow)) // re-arm so the outcome is written after a long run

		outcome := AuditOutcomeSuccess
		if result.Halted {
			outcome = AuditOutcomeFailure
		}
		emitAuditEventDetail(r, auditProvider, pd.ID, "certificate.renew_rollout", "certificate", req.Fingerprint, outcome,
			fmt.Sprintf(`{"group":%q,"nodes":%d,"deferred":%t,"halted":%t,"halt_reason":%q,"mode":%q}`,
				req.Group, len(nodes), result.Deferred, result.Halted, result.HaltReason, result.Mode))
		// One row per node so each node's fate is reconstructable from the log.
		for _, n := range result.NodeResults {
			detail, _ := json.Marshal(struct {
				Group   string `json:"group"`
				NodeID  string `json:"node_id"`
				Outcome string `json:"outcome"`
				Canary  bool   `json:"canary"`
			}{req.Group, n.NodeID, n.Outcome, n.IsCanary})
			emitAuditEventDetail(r, auditProvider, pd.ID, "certificate.renew_rollout", "certificate", req.Fingerprint,
				nodeAuditOutcome(n.Outcome), string(detail))
		}

		respond(result)
	})
}

func nodeAuditOutcome(outcome string) AuditOutcome {
	switch outcome {
	case "installed":
		return AuditOutcomeSuccess
	case "skipped":
		return AuditOutcomeSkipped
	default:
		return AuditOutcomeFailure
	}
}

// runSequentialRollout is the pre-W27-15 path for groups that cannot be staged
// (non-ssh or mixed): install node by node. Reverting a node that ALREADY
// SUCCEEDED would mean re-installing the predecessor certificate and its
// private key, which is deliberately not retained (the key-boundary law;
// retention is the opt-in W15-03 escrow, off by default), so such nodes are
// reported rollback_failed, telling the operator exactly which nodes are on
// the new certificate. Nodes whose VERIFY failed are already reverted by the
// pusher's own restore inside pushMaterialToTarget.
func runSequentialRollout(ctx context.Context, executor *RenewalExecutor, group RolloutGroup, targets map[string]ManagedTarget, profiles map[string]RenewalInstallProfile, material renewedPushMaterial) RolloutResult {
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
	rollback := func(_ context.Context, node RolloutNode) error {
		return fmt.Errorf("node %s installed successfully and cannot be auto-reverted: "+
			"restoring the predecessor certificate requires its private key, which is not retained", node.ID)
	}
	return RunRolloutGroup(ctx, group, install, rollback, time.Now().UTC())
}
