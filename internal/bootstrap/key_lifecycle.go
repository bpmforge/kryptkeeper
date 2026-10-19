// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"kryptkeeper/internal/logging"
	"time"

	"kryptkeeper/internal/ca"
	"kryptkeeper/internal/keystore"
)

// W9-09 (D-087/FR-P49): per-key lifecycle — owner/ACL beyond the global
// admin gate, max-age auto-rotation, and a compromise flow that
// force-rotates before driving re-issuance of affected certificates.

// KeyPolicy is one key's lifecycle row.
type KeyPolicy struct {
	KeyID         string     `json:"key_id"`
	Owner         string     `json:"owner"`
	ACL           []string   `json:"acl"`
	MaxAgeDays    int        `json:"max_age_days"`
	RotatedAt     time.Time  `json:"rotated_at"`
	CompromisedAt *time.Time `json:"compromised_at,omitempty"`
}

// CertReissuer is the seam the compromise flow drives re-issuance through.
// Leaf re-issuance needs the subject's CSR or a managed target (the hub
// never holds subject private keys), so production wiring plugs the
// RenewalExecutor here for managed targets.
type CertReissuer interface {
	ReissueCertificate(ctx context.Context, fingerprint string) error
}

// CertRevoker revokes a certificate through the same path as the API, so the
// OCSP/CRL caches are invalidated. CertificateProvider satisfies it.
type CertRevoker interface {
	RevokeCertificate(ctx context.Context, fingerprint string, req CertificateRevokeRequest) (CertificateRevokeResult, error)
}

const (
	// ActionKeyCompromise is the pending-action type for the compromise flow
	// (W23-38). Always dual-controlled: it revokes certificates.
	ActionKeyCompromise = "key_compromise"
	// ActionScheduledCAKeyRotate is a proposal filed by the rotation sweep for
	// an overdue CA-backing key. Rotating a CA key is dual-controlled
	// (W23-15), so the scheduler proposes it rather than rotating directly.
	ActionScheduledCAKeyRotate = "ca_key_rotate_scheduled"

	// haLockKeyRotationSweep names the sweep's lease row in
	// ha_scheduler_locks (ha_coordinator.go).
	haLockKeyRotationSweep = "key-rotation-sweep"

	lifecycleSchedulerPrincipal = "system:key-rotation-scheduler"
	// keyCompromiseReason is RFC 5280 reasonCode keyCompromise.
	keyCompromiseReason = 1
)

var activeKeyLifecycle *KeyLifecycleManager

// SetActiveKeyLifecycle sets the process-wide manager that key operations
// consult for per-key ACLs. nil (the default) keeps the global admin gate only.
func SetActiveKeyLifecycle(m *KeyLifecycleManager) { activeKeyLifecycle = m }

// ActiveKeyLifecycle returns the manager set by SetActiveKeyLifecycle, or nil.
func ActiveKeyLifecycle() *KeyLifecycleManager { return activeKeyLifecycle }

// KeyLifecycleManager owns the key_lifecycle table and the flows over it.
// All collaborators are constructor-injected; rotator, caStore, certs and
// reissuer are optional (nil disables their leg of the dispatch).
type KeyLifecycleManager struct {
	db       *sql.DB
	postgres bool
	store    keystore.Store
	rotator  CARotator
	caStore  ca.Store
	certs    CertificateProvider
	reissuer CertReissuer
	revoker  CertRevoker
	// proposals receives scheduled CA-key rotation proposals; nil means the
	// sweep skips CA-backing keys (it never rotates them unapproved).
	proposals PendingActionStore
	// alert, when set, receives the compromise flow's alerts (W23-39).
	alert func(ctx context.Context, kind, keyID string, detail map[string]any)
	// leader gates the sweep to one replica; nil runs it unconditionally
	// (single replica, or no shared HA DB).
	leader *HACoordinator
	now    func() time.Time
}

// KeyLifecycleOption configures optional collaborators.
type KeyLifecycleOption func(*KeyLifecycleManager)

func WithLifecycleCARotation(rotator CARotator, caStore ca.Store) KeyLifecycleOption {
	return func(m *KeyLifecycleManager) { m.rotator = rotator; m.caStore = caStore }
}

func WithLifecycleReissue(certs CertificateProvider, reissuer CertReissuer) KeyLifecycleOption {
	return func(m *KeyLifecycleManager) { m.certs = certs; m.reissuer = reissuer }
}

// WithLifecycleRevoker enables the revoke leg of the compromise flow.
func WithLifecycleRevoker(r CertRevoker) KeyLifecycleOption {
	return func(m *KeyLifecycleManager) { m.revoker = r }
}

// WithLifecycleProposals routes the sweep's CA-key rotations through the
// approval queue.
func WithLifecycleProposals(store PendingActionStore) KeyLifecycleOption {
	return func(m *KeyLifecycleManager) { m.proposals = store }
}

// WithLifecycleAlerts routes the compromise flow's alerts (key.compromised,
// key.reissue_deferred, key.reissue_failed) to fn.
func WithLifecycleAlerts(fn func(ctx context.Context, kind, keyID string, detail map[string]any)) KeyLifecycleOption {
	return func(m *KeyLifecycleManager) { m.alert = fn }
}

// WithLifecycleLeader gates the periodic rotation sweep on the HA lease so only
// the lease holder rotates: plain keys rotate directly, so two replicas
// sweeping at once would rotate the same key twice.
func WithLifecycleLeader(c *HACoordinator) KeyLifecycleOption {
	return func(m *KeyLifecycleManager) { m.leader = c }
}

func WithLifecycleClock(now func() time.Time) KeyLifecycleOption {
	return func(m *KeyLifecycleManager) { m.now = now }
}

func NewKeyLifecycleManager(db *sql.DB, postgres bool, store keystore.Store, opts ...KeyLifecycleOption) (*KeyLifecycleManager, error) {
	if db == nil {
		return nil, fmt.Errorf("key lifecycle requires a database")
	}
	if store == nil {
		return nil, fmt.Errorf("key lifecycle requires a keystore")
	}
	m := &KeyLifecycleManager{db: db, postgres: postgres, store: store, now: time.Now}
	for _, opt := range opts {
		opt(m)
	}
	return m, nil
}

func (m *KeyLifecycleManager) rebind(q string) string {
	if !m.postgres {
		return q
	}
	out := make([]byte, 0, len(q)+8)
	n := 0
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			n++
			out = append(out, fmt.Sprintf("$%d", n)...)
			continue
		}
		out = append(out, q[i])
	}
	return string(out)
}

// SetPolicy creates or replaces a key's lifecycle policy. The key must
// exist in the keystore — a policy for a phantom key is a filing error.
// rotated_at starts (or is preserved) so max-age counts from a real
// rotation, not from every policy edit.
func (m *KeyLifecycleManager) SetPolicy(keyID, owner string, acl []string, maxAgeDays int) error {
	if keyID == "" || owner == "" {
		return fmt.Errorf("key lifecycle: key id and owner are required")
	}
	if maxAgeDays < 0 {
		return fmt.Errorf("key lifecycle: max_age_days must be >= 0")
	}
	if _, err := m.store.Metadata(keyID); err != nil {
		return fmt.Errorf("key lifecycle: %w", err)
	}
	if acl == nil {
		acl = []string{}
	}
	aclJSON, err := json.Marshal(acl)
	if err != nil {
		return fmt.Errorf("key lifecycle: acl marshal: %w", err)
	}
	now := m.now().UTC().Format(time.RFC3339)
	_, err = m.db.Exec(m.rebind(`
		INSERT INTO key_lifecycle (key_id, owner, acl, max_age_days, rotated_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (key_id) DO UPDATE SET
			owner = excluded.owner,
			acl = excluded.acl,
			max_age_days = excluded.max_age_days,
			updated_at = excluded.updated_at`),
		keyID, owner, string(aclJSON), maxAgeDays, now, now, now)
	if err != nil {
		return fmt.Errorf("key lifecycle: persist policy: %w", err)
	}
	return nil
}

// GetPolicy returns a key's policy, reporting absence without error.
func (m *KeyLifecycleManager) GetPolicy(keyID string) (KeyPolicy, bool, error) {
	row := m.db.QueryRow(m.rebind(`
		SELECT key_id, owner, acl, max_age_days, rotated_at, compromised_at
		FROM key_lifecycle WHERE key_id = ?`), keyID)
	var p KeyPolicy
	var aclJSON, rotatedAt string
	var compromisedAt sql.NullString
	if err := row.Scan(&p.KeyID, &p.Owner, &aclJSON, &p.MaxAgeDays, &rotatedAt, &compromisedAt); err != nil {
		if err == sql.ErrNoRows {
			return KeyPolicy{}, false, nil
		}
		return KeyPolicy{}, false, fmt.Errorf("key lifecycle: load policy: %w", err)
	}
	if err := json.Unmarshal([]byte(aclJSON), &p.ACL); err != nil {
		return KeyPolicy{}, false, fmt.Errorf("key lifecycle: acl parse for %s: %w", keyID, err)
	}
	t, err := time.Parse(time.RFC3339, rotatedAt)
	if err != nil {
		return KeyPolicy{}, false, fmt.Errorf("key lifecycle: rotated_at parse for %s: %w", keyID, err)
	}
	p.RotatedAt = t
	if compromisedAt.Valid {
		ct, err := time.Parse(time.RFC3339, compromisedAt.String)
		if err != nil {
			return KeyPolicy{}, false, fmt.Errorf("key lifecycle: compromised_at parse for %s: %w", keyID, err)
		}
		p.CompromisedAt = &ct
	}
	return p, true, nil
}

// keyPolicyUnavailableError marks an Authorize failure that is an
// infrastructure fault (policy store unreachable or unreadable), not a
// decision about the caller. The op is still refused, but as 503 rather than
// a 403 authz denial.
type keyPolicyUnavailableError struct{ err error }

func (e *keyPolicyUnavailableError) Error() string { return e.err.Error() }
func (e *keyPolicyUnavailableError) Unwrap() error { return e.err }

// Authorize decides whether principal may perform mutating key operations
// on keyID. A key with no policy keeps the global admin-only gate. A key
// WITH a policy is manageable only by its owner or ACL principals — an
// admin not on the list is refused; that is the "beyond the global-admin
// gate" custody boundary. (Policy edits themselves remain admin-gated at
// the handler layer so a lost owner cannot brick a key.)
func (m *KeyLifecycleManager) Authorize(keyID, principal string, isAdmin bool) error {
	policy, found, err := m.GetPolicy(keyID)
	if err != nil {
		return &keyPolicyUnavailableError{err: err}
	}
	if !found {
		if !isAdmin {
			return fmt.Errorf("key %s: admin role required", keyID)
		}
		return nil
	}
	if principal == policy.Owner {
		return nil
	}
	for _, p := range policy.ACL {
		if principal == p {
			return nil
		}
	}
	return fmt.Errorf("key %s: principal %q is not the owner and not on the key's ACL", keyID, principal)
}

// rotateDispatch honours W9-04/G-35: a key backing a CA must rotate
// through the CA re-key flow (which re-issues the CA's own certificate);
// raw keystore rotation would silently break the CA.
func (m *KeyLifecycleManager) rotateDispatch(ctx context.Context, keyID string) error {
	if m.rotator != nil && m.caStore != nil {
		if caID, found, err := ca.KeyInUseByCA(m.caStore, keyID); err == nil && found {
			if _, err := m.rotator.RotateCAKey(ctx, caID, ""); err != nil {
				return fmt.Errorf("ca re-key for %s (key %s): %w", caID, keyID, err)
			}
			return nil
		}
	}
	meta, err := m.store.Metadata(keyID)
	if err != nil {
		return fmt.Errorf("keystore metadata %s: %w", keyID, err)
	}
	if _, err := m.store.RotateKey(keyID, meta.Algorithm); err != nil {
		return fmt.Errorf("keystore rotate %s: %w", keyID, err)
	}
	return nil
}

// backingCA reports the CA a key backs, if the CA wiring is present.
func (m *KeyLifecycleManager) backingCA(keyID string) (string, bool) {
	if m.rotator == nil || m.caStore == nil {
		return "", false
	}
	caID, found, err := ca.KeyInUseByCA(m.caStore, keyID)
	return caID, err == nil && found
}

// proposeCARotation files a scheduled CA re-key for approval unless one is
// already pending for the key. It reports whether a new proposal was filed.
func (m *KeyLifecycleManager) proposeCARotation(ctx context.Context, keyID, caID string) (bool, error) {
	if m.proposals == nil {
		return false, errors.New("CA key rotation needs dual-control approval and no approval queue is configured; not rotated")
	}
	pending, err := m.proposals.List(ctx, "pending")
	if err != nil {
		return false, fmt.Errorf("list pending actions: %w", err)
	}
	for _, a := range pending {
		if a.ActionType != ActionScheduledCAKeyRotate {
			continue
		}
		var p struct {
			KeyID string `json:"key_id"`
		}
		if json.Unmarshal(a.Params, &p) == nil && p.KeyID == keyID {
			return false, nil
		}
	}
	params, _ := json.Marshal(map[string]string{"key_id": keyID, "ca_id": caID}) // static map: cannot fail
	if _, err := m.proposals.Create(ctx, PendingAction{
		ActionType: ActionScheduledCAKeyRotate, Params: params, ProposedBy: lifecycleSchedulerPrincipal,
		Rationale: fmt.Sprintf("key %s backing CA %s is older than its max_age_days policy; scheduled re-key needs a second human", keyID, caID),
	}); err != nil {
		return false, fmt.Errorf("file rotation proposal: %w", err)
	}
	return true, nil
}

// NewScheduledCARotationExecutor carries out an approved
// ActionScheduledCAKeyRotate: the CA re-key, then the max-age stamp.
func NewScheduledCARotationExecutor(m *KeyLifecycleManager) ActionExecutor {
	return func(ctx context.Context, action PendingAction, approver AuthPrincipal) (json.RawMessage, error) {
		if !isAdminRole(approver.Role) {
			return nil, errors.New("rotating a CA key needs a pki-admin approver")
		}
		var p struct {
			KeyID string `json:"key_id"`
			CAID  string `json:"ca_id"`
		}
		if err := json.Unmarshal(action.Params, &p); err != nil || p.KeyID == "" || p.CAID == "" {
			return nil, errors.New("bad params")
		}
		// The proposal may be stale (the CA re-keyed meanwhile): rotate only
		// what the approver was shown.
		if caID, ok := m.backingCA(p.KeyID); !ok || caID != p.CAID {
			return nil, errors.New("key no longer backs the CA this rotation was proposed for")
		}
		res, err := m.rotator.RotateCAKey(ctx, p.CAID, "")
		if err != nil {
			return nil, fmt.Errorf("ca re-key for %s: %w", p.CAID, err)
		}
		if err := m.stampRotated(p.KeyID); err != nil {
			logging.Infof("SCHEDULED ROTATION NOT STAMPED for %s: %v", p.KeyID, err)
		}
		return json.Marshal(map[string]string{"ca_id": p.CAID, "key_id": res.KeyID})
	}
}

func (m *KeyLifecycleManager) stampRotated(keyID string) error {
	now := m.now().UTC().Format(time.RFC3339)
	_, err := m.db.Exec(m.rebind(
		`UPDATE key_lifecycle SET rotated_at = ?, updated_at = ? WHERE key_id = ?`),
		now, now, keyID)
	return err
}

// RotationSweepReport is one sweep's outcome.
type RotationSweepReport struct {
	Rotated []string
	// Proposed lists CA-backing keys whose rotation was filed for approval.
	Proposed []string
	Errors   map[string]string
}

// RunRotationSweep rotates every key whose max-age has elapsed. Per-key
// failures are recorded and the sweep continues — one stuck key must not
// freeze the fleet. Compromised keys are skipped: they were already
// force-rotated and their state is an operator matter, not a schedule's.
func (m *KeyLifecycleManager) RunRotationSweep(ctx context.Context) (RotationSweepReport, error) {
	report := RotationSweepReport{Errors: map[string]string{}}
	rows, err := m.db.Query(
		`SELECT key_id, max_age_days, rotated_at FROM key_lifecycle
		 WHERE max_age_days > 0 AND compromised_at IS NULL`)
	if err != nil {
		return report, fmt.Errorf("key lifecycle: sweep query: %w", err)
	}
	type due struct{ keyID string }
	var overdue []due
	for rows.Next() {
		var keyID, rotatedAt string
		var maxAgeDays int
		if err := rows.Scan(&keyID, &maxAgeDays, &rotatedAt); err != nil {
			rows.Close()
			return report, fmt.Errorf("key lifecycle: sweep scan: %w", err)
		}
		rotated, err := time.Parse(time.RFC3339, rotatedAt)
		if err != nil {
			report.Errors[keyID] = fmt.Sprintf("rotated_at unparseable: %v", err)
			continue
		}
		if m.now().Sub(rotated) > time.Duration(maxAgeDays)*24*time.Hour {
			overdue = append(overdue, due{keyID: keyID})
		}
	}
	if err := rows.Close(); err != nil {
		return report, fmt.Errorf("key lifecycle: sweep rows: %w", err)
	}

	for _, d := range overdue {
		if caID, ok := m.backingCA(d.keyID); ok {
			proposed, err := m.proposeCARotation(ctx, d.keyID, caID)
			switch {
			case err != nil:
				report.Errors[d.keyID] = err.Error()
			case proposed:
				report.Proposed = append(report.Proposed, d.keyID)
			}
			continue
		}
		if err := m.rotateDispatch(ctx, d.keyID); err != nil {
			report.Errors[d.keyID] = err.Error()
			continue
		}
		if err := m.stampRotated(d.keyID); err != nil {
			// The rotation happened; a missing stamp would re-rotate next
			// sweep. Loud, and reported as an error for the operator.
			logging.Infof("KEY ROTATION NOT STAMPED for %s — next sweep will rotate again: %v", d.keyID, err)
			report.Errors[d.keyID] = fmt.Sprintf("rotated but stamp failed: %v", err)
			continue
		}
		report.Rotated = append(report.Rotated, d.keyID)
	}
	return report, nil
}

// StartRotationScheduler runs the sweep every interval until ctx ends. With a
// leader configured, only the lease holder sweeps and the lease is handed back
// on shutdown so a peer takes over without waiting for it to lapse.
func (m *KeyLifecycleManager) StartRotationScheduler(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		if m.leader != nil {
			defer func() {
				if err := m.leader.Release(context.WithoutCancel(ctx), haLockKeyRotationSweep); err != nil {
					logging.Infof("key rotation sweep: release lease: %v", err)
				}
			}()
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.sweepTick(ctx, interval)
			}
		}
	}()
}

// sweepTick is one scheduled sweep, skipped unless this replica holds the
// lease. A lease error fails closed (skip) rather than open: a duplicate key
// rotation is worse than a late one.
func (m *KeyLifecycleManager) sweepTick(ctx context.Context, interval time.Duration) {
	if m.leader != nil {
		ok, err := m.leader.TryAcquire(ctx, haLockKeyRotationSweep, 2*interval)
		if err != nil {
			logging.Warnf("key rotation sweep: ha lock check failed, skipping this tick: %v", err)
			return
		}
		if !ok {
			return
		}
	}
	report, err := m.RunRotationSweep(ctx)
	if err != nil {
		logging.Warnf("key rotation sweep failed: %v", err)
		return
	}
	if len(report.Rotated) > 0 || len(report.Errors) > 0 {
		logging.Infof("key rotation sweep: rotated=%v errors=%v", report.Rotated, report.Errors)
	}
}

// CompromiseReport is what MarkCompromised did.
type CompromiseReport struct {
	KeyID    string   `json:"key_id"`
	Rotated  bool     `json:"rotated"`
	Affected []string `json:"affected"`
	// Revoked lists the certificates revoked with reason keyCompromise.
	Revoked []string `json:"revoked"`
	// InventoryOnly is the subset of Revoked that was only marked in the hub
	// inventory (no issuing CA here, so no CRL/OCSP effect): the operator
	// must still revoke those at the real issuer.
	InventoryOnly []string `json:"inventory_only"`
	// Reissued lists the certificates re-issued on their managed target;
	// Deferred those with no managed target the hub can push to (the subject
	// must re-enrol); Failed maps a fingerprint to why re-issue did not
	// complete. The three are disjoint.
	Reissued []string          `json:"reissued"`
	Deferred []string          `json:"deferred"`
	Failed   map[string]string `json:"failed"`
	// Steps records the phases in the order they ran:
	// rotate, flag, revoke, reissue.
	Steps  []string          `json:"steps"`
	Errors map[string]string `json:"errors"`
}

func (m *KeyLifecycleManager) raise(ctx context.Context, kind, keyID string, detail map[string]any) {
	if m.alert != nil {
		m.alert(ctx, kind, keyID, detail)
	}
}

// MarkCompromised force-rotates the key, THEN stamps it compromised, revokes
// every certificate the backed CA issued, and drives their re-issuance --
// strictly in that order: a failed rotation leaves nothing stamped, revoked or
// re-issued (0 side effects), and re-issuing before rotating would sign the
// replacements with the compromised key. Each affected certificate is flagged
// renewal_status="reissue_required" and handed to the reissuer seam.
func (m *KeyLifecycleManager) MarkCompromised(ctx context.Context, keyID string) (CompromiseReport, error) {
	report := CompromiseReport{KeyID: keyID, InventoryOnly: []string{}, Errors: map[string]string{}, Failed: map[string]string{}}
	if _, found, err := m.GetPolicy(keyID); err != nil {
		return report, err
	} else if !found {
		return report, fmt.Errorf("key lifecycle: no policy for %s — set one before running the compromise flow", keyID)
	}

	// Resolve the backed CA BEFORE rotating: rotation re-keys the CA, and
	// the affected set is defined by what the old key signed.
	affectedCAID, _ := m.backingCA(keyID)

	if err := m.rotateDispatch(ctx, keyID); err != nil {
		return report, fmt.Errorf("compromise force-rotate failed for %s (nothing stamped, revoked or re-issued): %w", keyID, err)
	}
	report.Rotated = true
	report.Steps = append(report.Steps, "rotate")
	if err := m.stampRotated(keyID); err != nil {
		logging.Infof("COMPROMISE ROTATION NOT STAMPED for %s: %v", keyID, err)
		report.Errors[keyID] = fmt.Sprintf("rotated but stamp failed: %v", err)
	}

	now := m.now().UTC().Format(time.RFC3339)
	if _, err := m.db.Exec(m.rebind(
		`UPDATE key_lifecycle SET compromised_at = ?, updated_at = ? WHERE key_id = ?`),
		now, now, keyID); err != nil {
		return report, fmt.Errorf("key lifecycle: compromise stamp (key already rotated): %w", err)
	}
	report.Steps = append(report.Steps, "flag")

	if affectedCAID == "" || m.certs == nil {
		m.raise(ctx, "key.compromised", keyID, map[string]any{"affected": 0, "revoked": 0})
		return report, nil
	}
	list, err := listAllCertificates(ctx, m.certs, CertificateListQuery{CAID: affectedCAID})
	if err != nil {
		report.Errors["list"] = err.Error()
		m.raise(ctx, "key.compromised", keyID, map[string]any{"affected": 0, "revoked": 0, "list_error": err.Error()})
		return report, nil
	}

	// Certificates that are revoked (just now, or before the compromise) keep
	// renewal_status "revoked": reissue_required would overwrite it in the
	// inventory and make a revoked certificate look merely due for renewal.
	revoked := map[string]bool{}
	if m.revoker != nil {
		report.Steps = append(report.Steps, "revoke")
		for _, item := range list.Items {
			fp := item.FingerprintSHA256
			if item.RevokedAt != nil || item.RenewalStatus == string(RenewalStatusRevoked) {
				revoked[fp] = true
				continue
			}
			res, err := m.revoker.RevokeCertificate(ctx, fp, CertificateRevokeRequest{
				ReasonCode: keyCompromiseReason, ReasonText: "issuing key compromised",
			})
			if err != nil {
				report.Errors[fp] = fmt.Sprintf("revoke: %v", err)
				continue
			}
			if res.RevocationScope == RevocationScopeInventoryOnly {
				report.InventoryOnly = append(report.InventoryOnly, fp)
			}
			report.Revoked = append(report.Revoked, fp)
			revoked[fp] = true
		}
	}

	m.raise(ctx, "key.compromised", keyID, map[string]any{"affected": len(list.Items), "revoked": len(report.Revoked), "inventory_only": len(report.InventoryOnly)})

	report.Steps = append(report.Steps, "reissue")
	for _, item := range list.Items {
		fp := item.FingerprintSHA256
		report.Affected = append(report.Affected, fp)
		if !revoked[fp] {
			if _, err := m.certs.UpdateEstate(ctx, fp, EstateUpdate{RenewalStatus: string(RenewalStatusReissueRequired)}); err != nil {
				report.Errors[fp] = fmt.Sprintf("flag reissue_required: %v", err)
			}
		}
		if m.reissuer == nil {
			continue
		}
		switch err := m.reissuer.ReissueCertificate(ctx, fp); {
		case err == nil:
			report.Reissued = append(report.Reissued, fp)
		case errors.Is(err, ErrReissueDeferred):
			report.Deferred = append(report.Deferred, fp)
		default:
			report.Failed[fp] = err.Error()
		}
	}
	if len(report.Deferred) > 0 {
		m.raise(ctx, "key.reissue_deferred", keyID, map[string]any{"fingerprints": report.Deferred})
	}
	if len(report.Failed) > 0 {
		m.raise(ctx, "key.reissue_failed", keyID, map[string]any{"failed": report.Failed})
	}
	return report, nil
}

// NewKeyCompromiseExecutor carries out an approved ActionKeyCompromise.
func NewKeyCompromiseExecutor(m *KeyLifecycleManager, audit AuditProvider) ActionExecutor {
	return func(ctx context.Context, action PendingAction, approver AuthPrincipal) (json.RawMessage, error) {
		if !isAdminRole(approver.Role) {
			return nil, errors.New("the key compromise flow needs a pki-admin approver")
		}
		var p struct {
			KeyID string `json:"key_id"`
		}
		if err := json.Unmarshal(action.Params, &p); err != nil || p.KeyID == "" {
			return nil, errors.New("bad params")
		}
		report, runErr := m.MarkCompromised(ctx, p.KeyID)
		summary, _ := json.Marshal(report) // plain struct: cannot fail
		outcome := AuditOutcomeExecuted
		if runErr != nil {
			outcome = AuditOutcomeFailure
		}
		if audit != nil {
			entry := AuditEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339), Action: "key.compromise", ActorType: "user", ActorID: approver.ID,
				ResourceType: "key", ResourceID: p.KeyID, Outcome: outcome, ChangeSummary: string(summary), Tenant: action.Tenant,
			}
			if err := audit.AppendEntry(ctx, entry); err != nil {
				logging.Errorf("key.compromise for %s: audit row not written: %v", p.KeyID, err)
			}
		}
		if runErr != nil {
			return nil, runErr
		}
		return summary, nil
	}
}
