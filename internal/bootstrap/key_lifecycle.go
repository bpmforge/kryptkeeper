// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
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
	now      func() time.Time
}

// KeyLifecycleOption configures optional collaborators.
type KeyLifecycleOption func(*KeyLifecycleManager)

func WithLifecycleCARotation(rotator CARotator, caStore ca.Store) KeyLifecycleOption {
	return func(m *KeyLifecycleManager) { m.rotator = rotator; m.caStore = caStore }
}

func WithLifecycleReissue(certs CertificateProvider, reissuer CertReissuer) KeyLifecycleOption {
	return func(m *KeyLifecycleManager) { m.certs = certs; m.reissuer = reissuer }
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

// Authorize decides whether principal may perform mutating key operations
// on keyID. A key with no policy keeps the global admin-only gate. A key
// WITH a policy is manageable only by its owner or ACL principals — an
// admin not on the list is refused; that is the "beyond the global-admin
// gate" custody boundary. (Policy edits themselves remain admin-gated at
// the handler layer so a lost owner cannot brick a key.)
func (m *KeyLifecycleManager) Authorize(keyID, principal string, isAdmin bool) error {
	policy, found, err := m.GetPolicy(keyID)
	if err != nil {
		return err
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
	Errors  map[string]string
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
		if err := m.rotateDispatch(ctx, d.keyID); err != nil {
			report.Errors[d.keyID] = err.Error()
			continue
		}
		if err := m.stampRotated(d.keyID); err != nil {
			// The rotation happened; a missing stamp would re-rotate next
			// sweep. Loud, and reported as an error for the operator.
			log.Printf("KEY ROTATION NOT STAMPED for %s — next sweep will rotate again: %v", d.keyID, err)
			report.Errors[d.keyID] = fmt.Sprintf("rotated but stamp failed: %v", err)
			continue
		}
		report.Rotated = append(report.Rotated, d.keyID)
	}
	return report, nil
}

// StartRotationScheduler runs the sweep every interval until ctx ends.
func (m *KeyLifecycleManager) StartRotationScheduler(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				report, err := m.RunRotationSweep(ctx)
				if err != nil {
					log.Printf("key rotation sweep failed: %v", err)
					continue
				}
				if len(report.Rotated) > 0 || len(report.Errors) > 0 {
					log.Printf("key rotation sweep: rotated=%v errors=%v", report.Rotated, report.Errors)
				}
			}
		}
	}()
}

// CompromiseReport is what MarkCompromised did.
type CompromiseReport struct {
	KeyID    string
	Rotated  bool
	Affected []string
	Errors   map[string]string
}

// MarkCompromised stamps the key, force-rotates it, THEN drives
// re-issuance of every certificate issued by the CA the key backed —
// strictly in that order: re-issuing first would sign replacements with
// the compromised key. Each affected certificate is flagged
// renewal_status="reissue_required" and handed to the reissuer seam.
func (m *KeyLifecycleManager) MarkCompromised(ctx context.Context, keyID string) (CompromiseReport, error) {
	report := CompromiseReport{KeyID: keyID, Errors: map[string]string{}}
	if _, found, err := m.GetPolicy(keyID); err != nil {
		return report, err
	} else if !found {
		return report, fmt.Errorf("key lifecycle: no policy for %s — set one before running the compromise flow", keyID)
	}

	// Resolve the backed CA BEFORE rotating: rotation re-keys the CA, and
	// the affected set is defined by what the old key signed.
	var affectedCAID string
	if m.caStore != nil {
		if caID, found, err := ca.KeyInUseByCA(m.caStore, keyID); err == nil && found {
			affectedCAID = caID
		}
	}

	now := m.now().UTC().Format(time.RFC3339)
	if _, err := m.db.Exec(m.rebind(
		`UPDATE key_lifecycle SET compromised_at = ?, updated_at = ? WHERE key_id = ?`),
		now, now, keyID); err != nil {
		return report, fmt.Errorf("key lifecycle: compromise stamp: %w", err)
	}

	if err := m.rotateDispatch(ctx, keyID); err != nil {
		// No re-issuance on a failed rotation — replacements must never be
		// signed by the compromised key.
		return report, fmt.Errorf("compromise force-rotate failed for %s (no re-issuance attempted): %w", keyID, err)
	}
	report.Rotated = true
	if err := m.stampRotated(keyID); err != nil {
		log.Printf("COMPROMISE ROTATION NOT STAMPED for %s: %v", keyID, err)
		report.Errors[keyID] = fmt.Sprintf("rotated but stamp failed: %v", err)
	}

	if affectedCAID == "" || m.certs == nil {
		return report, nil
	}
	list, err := listAllCertificates(ctx, m.certs, CertificateListQuery{CAID: affectedCAID})
	if err != nil {
		report.Errors["list"] = err.Error()
		return report, nil
	}
	for _, item := range list.Items {
		fp := item.FingerprintSHA256
		report.Affected = append(report.Affected, fp)
		if _, err := m.certs.UpdateEstate(ctx, fp, EstateUpdate{RenewalStatus: string(RenewalStatusReissueRequired)}); err != nil {
			report.Errors[fp] = fmt.Sprintf("flag reissue_required: %v", err)
		}
		if m.reissuer != nil {
			if err := m.reissuer.ReissueCertificate(ctx, fp); err != nil {
				report.Errors[fp] = fmt.Sprintf("reissue: %v", err)
			}
		}
	}
	return report, nil
}
