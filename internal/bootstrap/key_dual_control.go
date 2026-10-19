// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"kryptkeeper/internal/logging"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// W9-10 (D-088/FR-P50/NFR-P2): dual control for destructive key ops.
// Unless KRYPTKEEPER_KEY_DUAL_CONTROL=false (D-122: on by default), delete/
// rotate and every private-key egress (export, whole-store backup, escrow and
// its recovery, leaf escrow and its recovery, BYOK export) stop executing
// directly and route through the pending-actions approval queue: one admin
// proposes, a different human approves, and only then does the op run (or,
// for egress, may the proposer redeem a one-time grant).

const (
	keyActionDelete = "key_delete"
	keyActionRotate = "key_rotate"
	keyActionExport = "key_export"

	// W23-22: un-schedule a provider-side key deletion. Executes on approval
	// (it is not a grant): there is no secret to redeem, only a recovery.
	keyActionCancelDelete = "key_cancel_delete"

	// FG-2 / A2A7-001: the other private-key egress routes.
	keyActionBackup            = "key_backup"
	keyActionEscrow            = "key_escrow"
	keyActionEscrowRecover     = "key_escrow_recover"
	keyActionLeafEscrow        = "key_leaf_escrow"
	keyActionLeafEscrowRecover = "key_leaf_escrow_recover"
	keyActionBYOKExport        = "key_byok_export"

	// W23-03: trust-anchor import/removal. KeyID carries the certificate
	// fingerprint (import) or the CA id (removal), not a keystore key.
	keyActionCAImport            = "key_ca_import"
	keyActionCARotate            = "key_ca_rotate" // W23-15: grant to re-key / cross-sign a CA
	keyActionCATrustAnchorRemove = "key_ca_trust_anchor_remove"

	// backupScope is the key_id of a whole-keystore backup grant.
	backupScope = "all-keys"

	// grantTTL bounds how long an approved egress grant is redeemable. It
	// also bounds the residual of the in-memory redeemed-set being lost on
	// restart (spec decision 4).
	grantTTL = 10 * time.Minute
)

// grantActions are the actions whose approval only GRANTS: the operation
// itself runs at its own endpoint when the proposer redeems the grant, so
// key bytes and passphrases never rest in the queue.
var grantActions = map[string]bool{
	keyActionExport: true, keyActionBackup: true, keyActionEscrow: true,
	keyActionEscrowRecover: true, keyActionLeafEscrow: true,
	keyActionLeafEscrowRecover: true, keyActionBYOKExport: true,
	keyActionCAImport: true, keyActionCATrustAnchorRemove: true,
	keyActionCARotate: true,
}

// isKeyAction reports whether an action type belongs to this guard.
func isKeyAction(t string) bool {
	return t == keyActionDelete || t == keyActionRotate || t == keyActionCancelDelete || grantActions[t]
}

// keyActionParams is the params_json payload for all key actions.
type keyActionParams struct {
	KeyID string `json:"key_id"`
	// OwnerTenant is shown to the approver so they can see whose key it is.
	OwnerTenant string `json:"owner_tenant,omitempty"`
	// BundleSHA256 binds a recover/BYOK grant to the exact escrow bundle the
	// approver saw, so an approval for one bundle cannot unseal another.
	BundleSHA256 string `json:"bundle_sha256,omitempty"`

	// RC1-B-02: a grant is bound to the credential that proposed it, not to
	// the free-text principal id (which any admin can mint a key under).
	// Redemption must come from the same canonical human, the same auth type
	// and, for API keys, the same key.
	ProposerHuman    string   `json:"proposer_human,omitempty"`
	ProposerAuthType AuthType `json:"proposer_auth_type,omitempty"`
	ProposerKid      string   `json:"proposer_kid,omitempty"`
}

// KeyDualControl gates destructive key operations behind the approval
// queue. Constructor-injected; nil-safe (a nil guard is "disabled").
type KeyDualControl struct {
	enabled bool
	store   PendingActionStore

	mu       sync.Mutex
	redeemed map[string]bool // approved grants already redeemed
}

// NewKeyDualControlFromEnv resolves the on/off switch from
// KRYPTKEEPER_KEY_DUAL_CONTROL. D-122: ON unless explicitly "false".
func NewKeyDualControlFromEnv(store PendingActionStore) *KeyDualControl {
	return &KeyDualControl{
		enabled:  keyDualControlEnabledFromEnv(),
		store:    store,
		redeemed: map[string]bool{},
	}
}

func keyDualControlEnabledFromEnv() bool {
	return !strings.EqualFold(strings.TrimSpace(os.Getenv("KRYPTKEEPER_KEY_DUAL_CONTROL")), "false")
}

// WarnIfKeyDualControlDisabled logs, at startup, that an operator has turned
// the guard off. Called once from the hub's wiring.
func WarnIfKeyDualControlDisabled() {
	if !keyDualControlEnabledFromEnv() {
		logging.Warnf("KRYPTKEEPER_KEY_DUAL_CONTROL=false - key delete/rotate/export, backup, escrow, recovery and BYOK export run on ONE admin's say-so; private key material can leave the hub without a second approver. Remove the setting to restore dual control (D-122).")
	}
}

// Enabled reports whether key ops require a second approver. It does not
// depend on the queue being reachable: with the guard on and no queue the
// handlers fail closed (503) rather than silently exporting.
func (d *KeyDualControl) Enabled() bool {
	return d != nil && d.enabled
}

// Propose files a delete/rotate on the approval queue and returns it. The
// propose ENDPOINT's allow-list is untouched: key actions can only be
// filed here, by an authenticated admin hitting the keys API. Egress grants
// go through ProposeGrant, which binds them to the proposing credential.
func (d *KeyDualControl) Propose(ctx context.Context, actionType, keyID, principal string) (PendingAction, error) {
	if grantActions[actionType] {
		return PendingAction{}, fmt.Errorf("dual control: %q is a grant and must be proposed with ProposeGrant", actionType)
	}
	return d.propose(ctx, actionType, keyID, principal, "", keyActionParams{KeyID: keyID})
}

// ProposeGrant files an egress grant bound to pd's canonical human, auth
// type and key id (RC1-B-02), plus an optional bundle digest.
func (d *KeyDualControl) ProposeGrant(ctx context.Context, auth *Authenticator, actionType, keyID, bundleSHA256 string, pd AuthPrincipal) (PendingAction, error) {
	if !grantActions[actionType] {
		return PendingAction{}, fmt.Errorf("dual control: %q is not a grant action", actionType)
	}
	return d.propose(ctx, actionType, keyID, pd.ID, pd.Tenant, keyActionParams{
		KeyID: keyID, BundleSHA256: bundleSHA256,
		ProposerHuman: auth.canonicalHuman(pd), ProposerAuthType: pd.AuthType, ProposerKid: pd.Kid,
	})
}

func (d *KeyDualControl) propose(ctx context.Context, actionType, keyID, principal, proposerTenant string, p keyActionParams) (PendingAction, error) {
	if d == nil || d.store == nil {
		return PendingAction{}, fmt.Errorf("dual control: approval queue unavailable")
	}
	if !isKeyAction(actionType) {
		return PendingAction{}, fmt.Errorf("dual control: %q is not a key action", actionType)
	}
	if keyID == "" || principal == "" {
		return PendingAction{}, fmt.Errorf("dual control: key id and principal are required")
	}
	// The grant belongs to the tenant that owns the key, not the proposer's:
	// otherwise a foreign-tenant approver sees (and can approve) it while the
	// owner's approvers never do. Unattributable keys stay with the proposer.
	tenant := ""
	rationale := fmt.Sprintf("dual-control %s of key %s", strings.TrimPrefix(actionType, "key_"), keyID)
	if multiTenancyEnabled() {
		tenant = proposerTenant
		if owner, ok := keyOwnerTenant(ctx, activeTenantStore, keyID); ok {
			tenant = owner
		}
		if tenant != "" {
			p.OwnerTenant = tenant
			rationale += fmt.Sprintf(" (owning tenant: %s)", tenant)
		}
	}
	params, err := json.Marshal(p)
	if err != nil {
		return PendingAction{}, fmt.Errorf("dual control: params marshal: %w", err)
	}
	return d.store.Create(ctx, PendingAction{
		ActionType: actionType,
		Params:     params,
		ProposedBy: principal,
		Rationale:  rationale,
		Status:     "pending",
		Tenant:     tenant,
	})
}

// AuthorizeGrant validates and redeems an approved grant of actionType: the
// action must be approved for THIS key (and bundle), proposed by THIS
// credential (same canonical human, auth type and key id, so a reused
// free-text principal id does not suffice), approved by a DIFFERENT human,
// younger than the grant TTL, and not redeemed before.
func (d *KeyDualControl) AuthorizeGrant(ctx context.Context, auth *Authenticator, actionType, keyID, bundleSHA256 string, pd AuthPrincipal, actionID string) error {
	return d.authorize(ctx, auth, actionType, keyID, bundleSHA256, pd, actionID)
}

func (d *KeyDualControl) authorize(ctx context.Context, auth *Authenticator, actionType, keyID, bundleSHA256 string, pd AuthPrincipal, actionID string) error {
	if d == nil || d.store == nil {
		return fmt.Errorf("dual control: approval queue unavailable")
	}
	if actionID == "" {
		return fmt.Errorf("dual control: approved_action_id is required for this operation")
	}
	action, found, err := d.store.Get(ctx, actionID)
	if err != nil {
		return fmt.Errorf("dual control: load action: %w", err)
	}
	if !found || action.ActionType != actionType {
		return fmt.Errorf("dual control: %s is not a %s approval", actionID, strings.TrimPrefix(actionType, "key_"))
	}
	if action.Status != "approved" {
		return fmt.Errorf("dual control: action %s is %s, not approved", actionID, action.Status)
	}
	var p keyActionParams
	if err := json.Unmarshal(action.Params, &p); err != nil || p.KeyID != keyID || p.BundleSHA256 != bundleSHA256 {
		return fmt.Errorf("dual control: action %s does not approve this %s of %s", actionID, strings.TrimPrefix(actionType, "key_"), keyID)
	}
	if err := grantTenantStillOwnsKey(ctx, action, p); err != nil {
		return err
	}
	if action.ProposedBy != pd.ID || !grantBoundTo(auth, p, pd) {
		// Generic on purpose: do not reveal which binding failed.
		return fmt.Errorf("dual control: grant %s belongs to a different principal", actionID)
	}
	if auth.sameHuman(pd, action.ApprovedBy) {
		return fmt.Errorf("dual control: grant %s was approved by the same person redeeming it", actionID)
	}
	decidedAt, err := time.Parse(time.RFC3339, action.DecidedAt)
	if err != nil {
		return fmt.Errorf("dual control: grant %s has no valid decision time", actionID)
	}
	if time.Since(decidedAt) > grantTTL {
		return fmt.Errorf("dual control: grant %s expired (older than %s)", actionID, grantTTL)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.redeemed[actionID] {
		return fmt.Errorf("dual control: grant %s was already redeemed - grants are single-use", actionID)
	}
	d.redeemed[actionID] = true
	return nil
}

// grantTenantStillOwnsKey re-resolves the key's owning tenant at redemption.
// The grant is stamped with the owner at proposal time; if the key's CA has
// been remapped to another tenant since, or its owner can no longer be
// resolved, the approval was given for a different tenant's key and must not
// release it (deny by default).
func grantTenantStillOwnsKey(ctx context.Context, action PendingAction, p keyActionParams) error {
	if !multiTenancyEnabled() {
		return nil
	}
	norm := func(t string) string {
		if t == "" {
			return DefaultTenant
		}
		return t
	}
	owner, ok := keyOwnerTenant(ctx, activeTenantStore, p.KeyID)
	if !ok {
		if p.OwnerTenant != "" {
			return fmt.Errorf("dual control: grant %s cannot be redeemed: key ownership is no longer resolvable", action.ID)
		}
		return nil // never attributable to a tenant: the grant stayed with its proposer
	}
	if norm(owner) != norm(action.Tenant) {
		return fmt.Errorf("dual control: grant %s was approved for a different tenant than the one that now owns the key", action.ID)
	}
	return nil
}

// grantBoundTo reports whether pd is the credential the grant was proposed
// with. A grant without a binding (queued before RC1-B-02) is never
// redeemable: fail closed.
func grantBoundTo(auth *Authenticator, p keyActionParams, pd AuthPrincipal) bool {
	return p.ProposerHuman != "" &&
		p.ProposerHuman == auth.canonicalHuman(pd) &&
		p.ProposerAuthType == pd.AuthType &&
		p.ProposerKid == pd.Kid
}

// egressGate is one private-key egress route's dual-control check.
type egressGate struct {
	actionType   string
	keyID        string
	bundleSHA256 string
	approvedID   string // approved_action_id from the request, if any
	auditAction  string
	message      string
}

// gate returns true when the egress may proceed now (dual control off, or a
// valid grant redeemed). Otherwise it has already written the response: 202
// with the proposed action id, 403 for a bad grant, or 503 when the queue is
// down: fail closed, never an unguarded export.
func (d *KeyDualControl) gate(w http.ResponseWriter, r *http.Request, auth *Authenticator, audit AuditProvider, pd AuthPrincipal, g egressGate) bool {
	// Ownership is enforced even when dual control is off: egress of a key the
	// caller's tenant does not own is a cross-tenant export either way.
	if !keyVisibleToTenant(r.Context(), activeTenantStore, pd, g.keyID) {
		emitAuditEvent(r, audit, pd.ID, g.auditAction, "key", g.keyID, AuditOutcomeDenied)
		writeForbidden(w, "key is not owned by the caller's tenant")
		return false
	}
	if !d.Enabled() {
		return true
	}
	if g.approvedID == "" {
		action, err := d.ProposeGrant(r.Context(), auth, g.actionType, g.keyID, g.bundleSHA256, pd)
		if err != nil {
			emitAuditEvent(r, audit, pd.ID, g.auditAction, "key", g.keyID, AuditOutcomeFailure)
			writeServiceUnavailable(w, "dual-control proposal failed")
			return false
		}
		emitAuditEventDetail(r, audit, pd.ID, g.auditAction, "key", g.keyID, AuditOutcomeProposed,
			fmt.Sprintf(`{"action_id":%q}`, action.ID))
		writeDualControlProposed(w, action.ID, g.message)
		return false
	}
	if err := d.AuthorizeGrant(r.Context(), auth, g.actionType, g.keyID, g.bundleSHA256, pd, g.approvedID); err != nil {
		emitAuditEventDetail(r, audit, pd.ID, g.auditAction, "key", g.keyID, AuditOutcomeDenied,
			fmt.Sprintf(`{"action_id":%q,"reason":%q}`, g.approvedID, err.Error()))
		writeForbidden(w, err.Error())
		return false
	}
	return true
}

// writeDualControlProposed writes the 202 every guarded route answers with.
func writeDualControlProposed(w http.ResponseWriter, actionID, message string) {
	body, _ := json.Marshal(map[string]any{"data": map[string]string{ // static map: cannot fail
		"status": "proposed", "action_id": actionID, "message": message,
	}})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write(body)
}

// bundleDigest returns the key id an escrow bundle declares in clear (it is
// AAD-bound to the ciphertext, so it cannot be altered without breaking
// recovery) and the sha256 of the whole bundle.
func bundleDigest(bundle []byte) (keyID, digest string) {
	sum := sha256.Sum256(bundle)
	var b struct {
		KeyID string `json:"key_id"`
	}
	_ = json.Unmarshal(bundle, &b) // an unparseable bundle fails recovery anyway; the digest still binds it
	keyID = b.KeyID
	if keyID == "" {
		keyID = "unknown"
	}
	return keyID, hex.EncodeToString(sum[:])
}

// executeKeyAction runs an APPROVED key action. Called by the approve
// path of the pending-actions handler for key_* action types.
func executeKeyAction(ctx context.Context, keys keystore.Store, action PendingAction) (json.RawMessage, error) {
	if keys == nil {
		return nil, fmt.Errorf("key action %s: no keystore configured", action.ActionType)
	}
	var p keyActionParams
	if err := json.Unmarshal(action.Params, &p); err != nil || p.KeyID == "" {
		return nil, fmt.Errorf("key action %s: invalid params", action.ActionType)
	}

	switch action.ActionType {
	case keyActionDelete:
		// Same rule as the propose path, re-checked here: a CA may have been
		// issued onto this key between proposal and approval.
		if activeCAStore != nil {
			if caID, found, err := ca.KeyInUseByCA(activeCAStore, p.KeyID); err == nil && found {
				return nil, fmt.Errorf("key %s backs CA %s; refusing to delete", p.KeyID, caID)
			}
		}
		if err := keys.Delete(p.KeyID); err != nil {
			return nil, fmt.Errorf("approved delete of %s: %w", p.KeyID, err)
		}
		return json.Marshal(map[string]any{"deleted": p.KeyID})

	case keyActionCancelDelete:
		c, ok := keys.(keystore.DeletionCanceller)
		if !ok {
			return nil, fmt.Errorf("approved cancel of %s: this keystore backend has no scheduled deletions", p.KeyID)
		}
		// The window may have closed while the proposal waited for approval.
		can, err := c.CanCancelDeletion(p.KeyID, time.Now())
		if err != nil {
			return nil, fmt.Errorf("approved cancel of %s: %w", p.KeyID, err)
		}
		if !can {
			return nil, fmt.Errorf("approved cancel of %s: %w", p.KeyID, keystore.ErrNotCancellable)
		}
		if err := c.CancelDeletion(ctx, p.KeyID); err != nil {
			return nil, fmt.Errorf("approved cancel of %s: %w", p.KeyID, err)
		}
		return json.Marshal(map[string]any{"cancelled": p.KeyID})

	case keyActionRotate:
		// Same G-35 rule as the direct endpoint: a key backing a CA must
		// go through CA re-key, not raw rotation.
		if activeCAStore != nil {
			if caID, found, err := ca.KeyInUseByCA(activeCAStore, p.KeyID); err == nil && found {
				return nil, fmt.Errorf("key %s backs CA %s; use CA re-key, not raw key rotation", p.KeyID, caID)
			}
		}
		meta, err := keys.Metadata(p.KeyID)
		if err != nil {
			return nil, fmt.Errorf("approved rotate of %s: %w", p.KeyID, err)
		}
		result, err := keys.RotateKey(p.KeyID, meta.Algorithm)
		if err != nil {
			return nil, fmt.Errorf("approved rotate of %s: %w", p.KeyID, err)
		}
		return json.Marshal(map[string]any{"rotated": p.KeyID, "previous_id": result.PreviousID})

	case keyActionExport, keyActionBackup, keyActionEscrow, keyActionEscrowRecover,
		keyActionLeafEscrow, keyActionLeafEscrowRecover, keyActionBYOKExport,
		keyActionCAImport, keyActionCATrustAnchorRemove, keyActionCARotate:
		// Approval grants; it never exports. Key bytes and passphrases
		// must not rest in the pending_actions table: the proposer
		// redeems this grant at the originating endpoint.
		return json.Marshal(map[string]any{"export_granted": true, "key_id": p.KeyID})

	default:
		return nil, fmt.Errorf("unknown key action %q", action.ActionType)
	}
}
