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
	"strings"
	"time"

	"kryptkeeper/internal/keystore"
)

// W17-12: BYOK export — wrap an escrow-recovered CA key and import it
// into a customer-controlled cloud KMS.
//
// This moves OUR OWN root across a custody boundary into the customer's
// HSM. No new custody is taken on, but the plaintext root does exist
// transiently in memory to be wrapped, which is why every step below is
// dual-control gated and audited, and why the material is zeroized on
// every exit path including the error paths.

// errUnsupportedBYOKProvider is returned for a destination this build
// cannot wrap for. Named so tests can assert the ordering of the gates.
var errUnsupportedBYOKProvider = errors.New("byok: unsupported destination")

// byokAuditSink forwards BYOK steps into the append-only trail.
type byokAuditSink struct {
	r        *http.Request
	provider AuditProvider
	actor    string
}

func (s byokAuditSink) Record(ev keystore.BYOKEvent) {
	emitAuditEventDetail(s.r, s.provider, s.actor, ev.Step, "key", ev.KeyID, AuditOutcome(ev.Outcome),
		fmt.Sprintf(`{"provider":%q}`, ev.Provider))
}

// newBYOKTarget is a package var so tests inject a KMS stand-in; CI must
// never need cloud credentials to exercise this path.
var newBYOKTarget = func(ctx context.Context, provider, region, keyID string) (keystore.KMSImportTarget, error) {
	return keystore.NewKMSImportTarget(ctx, provider, region, keyID)
}

func registerBYOKHandlers(mux *http.ServeMux, auth *Authenticator, auditProvider AuditProvider) {
	dualControl := NewKeyDualControlFromEnv(NewPendingActionStoreFromEnv())
	// POST /api/v1/keys/byok/export
	mux.HandleFunc("/api/v1/keys/byok/export", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "byok.export", "key", "-", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		// Exporting a CA root is at least as consequential as approving an
		// issuance, so it takes the approver capability, not plain admin.
		if !canApproveActions(pd.Role) {
			emitAuditEvent(r, auditProvider, pd.ID, "byok.export", "key", "-", AuditOutcomeDenied)
			writeForbidden(w, "approver role required to export key material to an external KMS")
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}

		var req struct {
			Bundle               json.RawMessage `json:"bundle"`
			CustodianAPassphrase string          `json:"custodian_a_passphrase"`
			CustodianBPassphrase string          `json:"custodian_b_passphrase"`
			Provider             string          `json:"provider"`
			Region               string          `json:"region"`
			KeyID                string          `json:"key_id"`
			ApprovedActionID     string          `json:"approved_action_id"`
		}
		err = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024*1024)).Decode(&req)
		if rejectOversizeBody(w, err) {
			return
		}
		if err != nil ||
			len(req.Bundle) == 0 || strings.TrimSpace(req.KeyID) == "" {
			writeBadRequest(w, "bundle, key_id and both custodian passphrases are required")
			return
		}
		// The grant binds the destination KMS key AND the bundle, so an
		// approval to export one root to one KMS cannot be repointed.
		_, bundleSHA := bundleDigest(req.Bundle)
		if !dualControl.gate(w, r, auth, auditProvider, pd, egressGate{
			actionType: keyActionBYOKExport, keyID: req.KeyID, bundleSHA256: bundleSHA,
			approvedID: req.ApprovedActionID, auditAction: "byok.export",
			message: "dual control is on - after approval, retry with approved_action_id",
		}) {
			return
		}

		// Resolve the destination BEFORE recovering anything: an unknown
		// or unimplemented provider must fail while the key is still
		// sealed, not after it has been materialized.
		target, err := newBYOKTarget(r.Context(), req.Provider, req.Region, req.KeyID)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "byok.export", "key", req.KeyID, AuditOutcomeFailure)
			writeBadRequest(w, err.Error())
			return
		}

		material, err := keystore.RecoverEscrowedKeyMaterial(req.Bundle,
			[]byte(req.CustodianAPassphrase), []byte(req.CustodianBPassphrase))
		if err != nil {
			// Covers a failed dual-control check and a wrong custodian
			// secret alike; neither reveals which secret was wrong.
			emitAuditEvent(r, auditProvider, pd.ID, "byok.export", "key", req.KeyID, AuditOutcomeDenied)
			writeForbidden(w, err.Error())
			return
		}
		// ExportEscrowedKeyToKMS zeroizes `material` on EVERY exit path.
		if err := keystore.ExportEscrowedKeyToKMS(r.Context(), target,
			byokAuditSink{r: r, provider: auditProvider, actor: pd.ID},
			material, []byte(req.CustodianAPassphrase), []byte(req.CustodianBPassphrase), time.Now()); err != nil {
			writeServiceUnavailable(w, err.Error())
			return
		}

		writeJSONData(w, map[string]any{
			"provider": target.Provider(),
			"key_id":   target.KeyID(),
			"imported": true,
		})
	})
}
