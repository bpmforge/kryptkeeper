// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

// Delivery plugins in the hub (W20-20, D-113..D-120): the store of plugin
// versions, enabling through the approval queue, and the compiled-plugin
// cache renewals dispatch to. The sandbox itself is
// internal/plugins/delivery.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"kryptkeeper/internal/plugins/delivery"
)

// ActionEnableDeliveryPlugin is the pending-action type for enabling a
// plugin version whose capabilities need a second person (D-116).
const ActionEnableDeliveryPlugin = "delivery_plugin.enable"

// Plugin trust tiers (D-117). An upload's tier comes from its signature
// (W20-24): the compiled-in plugin key makes it first-party, an operator-
// trusted key verified (PluginTierVerified), no signature community.
const (
	PluginTierFirstParty = "first-party"
	PluginTierCommunity  = "community"
)

var (
	errPluginNotFound      = errors.New("delivery plugin not found")
	errPluginVersionExists = errors.New("that plugin version is already installed")
	errPluginNotEnabled    = errors.New("delivery plugin is not enabled")
	errPluginInUse         = errors.New("delivery plugin is enabled; disable it first")
	errPluginsOff          = errors.New("delivery plugins are turned off (KRYPTKEEPER_DELIVERY_PLUGINS=off)")
)

// DeliveryPluginsEnabledFromEnv reports whether plugins may run at all.
// KRYPTKEEPER_DELIVERY_PLUGINS=off is the kill switch.
func DeliveryPluginsEnabledFromEnv() bool {
	return !strings.EqualFold(strings.TrimSpace(os.Getenv("KRYPTKEEPER_DELIVERY_PLUGINS")), "off")
}

// DeliveryPluginVersion is one installed version, without its module bytes.
type DeliveryPluginVersion struct {
	PluginID        string       `json:"plugin_id"`
	Version         string       `json:"version"`
	SHA256          string       `json:"sha256"`
	Tier            string       `json:"trust_tier"`
	CapabilityTier  string       `json:"capability_tier"`
	Status          string       `json:"status"`
	Manifest        abi.Manifest `json:"manifest"`
	InstalledBy     string       `json:"installed_by"`
	InstalledAt     string       `json:"installed_at"`
	ApprovedBy      string       `json:"approved_by,omitempty"`
	ApprovedAt      string       `json:"approved_at,omitempty"`
	PendingActionID string       `json:"pending_action_id,omitempty"`
	SignerKeyID     string       `json:"signer_key_id,omitempty"`
}

// DeliveryPlugin is a plugin and its versions, newest first.
type DeliveryPlugin struct {
	ID             string                  `json:"id"`
	EnabledVersion string                  `json:"enabled_version,omitempty"`
	Versions       []DeliveryPluginVersion `json:"versions"`
}

// DeliveryPluginManager owns the plugin tables and the process's one
// plugin runtime. Nil means plugins are off.
type DeliveryPluginManager struct {
	db       *sql.DB
	postgres bool
	actions  PendingActionStore
	trust    *PluginTrust
	now      func() time.Time

	mu    sync.Mutex
	rt    *delivery.Runtime
	cache map[string]*delivery.Plugin // by sha256
}

// NewDeliveryPluginManager returns nil when plugins are switched off or
// there is no database; every caller treats nil as "plugins off". trust
// may be nil: unsigned uploads are then community and signed ones refused.
func NewDeliveryPluginManager(db *sql.DB, postgres bool, actions PendingActionStore, trust *PluginTrust) *DeliveryPluginManager {
	if db == nil || !DeliveryPluginsEnabledFromEnv() {
		return nil
	}
	return &DeliveryPluginManager{db: db, postgres: postgres, actions: actions, trust: trust, now: time.Now, cache: map[string]*delivery.Plugin{}}
}

func (m *DeliveryPluginManager) q(query string) string {
	if !m.postgres {
		return query
	}
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			fmt.Fprintf(&b, "$%d", n)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (m *DeliveryPluginManager) stamp() string { return m.now().UTC().Format(time.RFC3339) }

func (m *DeliveryPluginManager) runtime(ctx context.Context) (*delivery.Runtime, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rt == nil {
		rt, err := delivery.NewRuntime(ctx)
		if err != nil {
			return nil, err
		}
		m.rt = rt
	}
	return m.rt, nil
}

// Install stores a new plugin version, disabled. The module must match the
// manifest's sha256 and compile; signature, if given, is over the exact
// manifestJSON bytes and sets the trust tier (a bad one refuses the install).
// Approval rules do not change with the tier: they follow capabilities.
func (m *DeliveryPluginManager) Install(ctx context.Context, manifestJSON, wasm []byte, signature, by string) (DeliveryPluginVersion, error) {
	man, err := abi.ParseManifest(manifestJSON)
	if err != nil {
		return DeliveryPluginVersion{}, err
	}
	tier, signer, err := m.trust.Classify(manifestJSON, signature)
	if err != nil {
		return DeliveryPluginVersion{}, err
	}
	sum := sha256.Sum256(wasm)
	if hex.EncodeToString(sum[:]) != man.Artifact.SHA256 {
		return DeliveryPluginVersion{}, delivery.ErrHashMismatch
	}
	rt, err := m.runtime(ctx)
	if err != nil {
		return DeliveryPluginVersion{}, err
	}
	p, err := rt.Load(ctx, manifestJSON, wasm, man.Capabilities)
	if err != nil {
		return DeliveryPluginVersion{}, err
	}
	_ = p.Close(ctx)

	now := m.stamp()
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return DeliveryPluginVersion{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var exists int
	if err := tx.QueryRowContext(ctx, m.q(`SELECT COUNT(*) FROM delivery_plugin_versions WHERE plugin_id = ? AND version = ?`), man.ID, man.Version).Scan(&exists); err != nil {
		return DeliveryPluginVersion{}, err
	}
	if exists > 0 {
		return DeliveryPluginVersion{}, errPluginVersionExists
	}
	if _, err := tx.ExecContext(ctx, m.q(`INSERT INTO delivery_plugins (id, created_at, updated_at) VALUES (?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET updated_at = excluded.updated_at`), man.ID, now, now); err != nil {
		return DeliveryPluginVersion{}, err
	}
	if _, err := tx.ExecContext(ctx, m.q(`INSERT INTO delivery_plugin_versions
		(plugin_id, version, sha256, manifest_json, wasm, tier, status, installed_by, installed_at, signature, signer_key_id)
		VALUES (?, ?, ?, ?, ?, ?, 'installed', ?, ?, ?, ?)`),
		man.ID, man.Version, man.Artifact.SHA256, string(manifestJSON), wasm, tier, by, now, strings.TrimSpace(signature), signer); err != nil {
		return DeliveryPluginVersion{}, err
	}
	if err := tx.Commit(); err != nil {
		return DeliveryPluginVersion{}, err
	}
	return m.version(ctx, man.ID, man.Version)
}

const versionColumns = `plugin_id, version, sha256, manifest_json, tier, status, installed_by, installed_at,
	COALESCE(approved_by, ''), COALESCE(approved_at, ''), COALESCE(pending_action_id, ''), signer_key_id`

func scanVersion(row interface{ Scan(...any) error }) (DeliveryPluginVersion, error) {
	var v DeliveryPluginVersion
	var manifest string
	if err := row.Scan(&v.PluginID, &v.Version, &v.SHA256, &manifest, &v.Tier, &v.Status, &v.InstalledBy, &v.InstalledAt,
		&v.ApprovedBy, &v.ApprovedAt, &v.PendingActionID, &v.SignerKeyID); err != nil {
		return v, err
	}
	if err := json.Unmarshal([]byte(manifest), &v.Manifest); err != nil {
		return v, fmt.Errorf("plugin %s %s: stored manifest: %w", v.PluginID, v.Version, err)
	}
	v.CapabilityTier = v.Manifest.Capabilities.Tier()
	return v, nil
}

func (m *DeliveryPluginManager) version(ctx context.Context, id, version string) (DeliveryPluginVersion, error) {
	v, err := scanVersion(m.db.QueryRowContext(ctx, m.q(`SELECT `+versionColumns+` FROM delivery_plugin_versions WHERE plugin_id = ? AND version = ?`), id, version))
	if errors.Is(err, sql.ErrNoRows) {
		return v, errPluginNotFound
	}
	return v, err
}

// List returns every plugin with its versions.
func (m *DeliveryPluginManager) List(ctx context.Context) ([]DeliveryPlugin, error) {
	rows, err := m.db.QueryContext(ctx, `SELECT id, COALESCE(enabled_version, '') FROM delivery_plugins ORDER BY id`)
	if err != nil {
		return nil, err
	}
	var out []DeliveryPlugin
	for rows.Next() {
		var p DeliveryPlugin
		if err := rows.Scan(&p.ID, &p.EnabledVersion); err != nil {
			_ = rows.Close()
			return nil, err
		}
		out = append(out, p)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		vs, err := m.versions(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Versions = vs
	}
	if out == nil {
		out = []DeliveryPlugin{}
	}
	return out, nil
}

// Get returns one plugin.
func (m *DeliveryPluginManager) Get(ctx context.Context, id string) (DeliveryPlugin, error) {
	p := DeliveryPlugin{ID: id}
	err := m.db.QueryRowContext(ctx, m.q(`SELECT COALESCE(enabled_version, '') FROM delivery_plugins WHERE id = ?`), id).Scan(&p.EnabledVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return p, errPluginNotFound
	}
	if err != nil {
		return p, err
	}
	p.Versions, err = m.versions(ctx, id)
	return p, err
}

func (m *DeliveryPluginManager) versions(ctx context.Context, id string) ([]DeliveryPluginVersion, error) {
	rows, err := m.db.QueryContext(ctx, m.q(`SELECT `+versionColumns+` FROM delivery_plugin_versions WHERE plugin_id = ? ORDER BY installed_at DESC, version DESC`), id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DeliveryPluginVersion{}
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// RequestEnable enables a version directly when the operator alone may
// (Standard capabilities, or an upgrade that adds none), and otherwise
// proposes it to the approval queue, where someone else must approve
// (D-116). The previously enabled version keeps running until then.
func (m *DeliveryPluginManager) RequestEnable(ctx context.Context, id, version, principal, tenant string) (DeliveryPluginVersion, string, error) {
	v, err := m.version(ctx, id, version)
	if err != nil {
		return v, "", err
	}
	if v.Status == "enabled" {
		return v, "", nil
	}
	if v.Status == "pending_approval" && v.PendingActionID != "" {
		return v, v.PendingActionID, nil
	}
	p, err := m.Get(ctx, id)
	if err != nil {
		return v, "", err
	}
	direct := v.CapabilityTier == abi.TierStandard
	if !direct && p.EnabledVersion != "" {
		if cur, err := m.version(ctx, id, p.EnabledVersion); err == nil && v.Manifest.Capabilities.Within(cur.Manifest.Capabilities) {
			direct = true
		}
	}
	if direct {
		if err := m.enable(ctx, id, version, principal); err != nil {
			return v, "", err
		}
		v, err = m.version(ctx, id, version)
		return v, "", err
	}
	if m.actions == nil {
		return v, "", errors.New("the approval queue is unavailable, so this plugin cannot be enabled")
	}
	params, _ := json.Marshal(map[string]string{"plugin_id": id, "version": version, "sha256": v.SHA256})
	act, err := m.actions.Create(ctx, PendingAction{
		ActionType: ActionEnableDeliveryPlugin, Params: params, ProposedBy: principal, Tenant: tenant,
		Rationale: fmt.Sprintf("enable delivery plugin %s %s (%s capabilities, %s)", id, version, v.CapabilityTier, v.Tier),
	})
	if err != nil {
		return v, "", err
	}
	if _, err := m.db.ExecContext(ctx, m.q(`UPDATE delivery_plugin_versions SET status = 'pending_approval', pending_action_id = ? WHERE plugin_id = ? AND version = ?`), act.ID, id, version); err != nil {
		return v, "", err
	}
	v, err = m.version(ctx, id, version)
	return v, act.ID, err
}

// ExecuteEnable carries out an approved ActionEnableDeliveryPlugin. The
// queue has already refused self-approval and approvers without the queue
// role; enabling a plugin additionally needs a pki-admin, since an operator
// may not install plugins either.
func (m *DeliveryPluginManager) ExecuteEnable(ctx context.Context, action PendingAction, approver AuthPrincipal) (json.RawMessage, error) {
	if !isAdminRole(approver.Role) {
		return nil, errors.New("enabling a delivery plugin needs a pki-admin approver")
	}
	var p struct {
		PluginID string `json:"plugin_id"`
		Version  string `json:"version"`
		SHA256   string `json:"sha256"`
	}
	if err := json.Unmarshal(action.Params, &p); err != nil {
		return nil, fmt.Errorf("bad params: %w", err)
	}
	v, err := m.version(ctx, p.PluginID, p.Version)
	if err != nil {
		return nil, err
	}
	// The approval is for exactly these bytes and this request.
	if v.SHA256 != p.SHA256 || v.Status != "pending_approval" || v.PendingActionID != action.ID {
		return nil, errors.New("this approval no longer matches the plugin version it was requested for")
	}
	if err := m.enable(ctx, p.PluginID, p.Version, approver.ID); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]string{"plugin_id": p.PluginID, "enabled_version": p.Version})
}

func (m *DeliveryPluginManager) enable(ctx context.Context, id, version, approver string) error {
	now := m.stamp()
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, m.q(`UPDATE delivery_plugin_versions SET status = 'superseded' WHERE plugin_id = ? AND status = 'enabled' AND version <> ?`), id, version); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, m.q(`UPDATE delivery_plugin_versions SET status = 'enabled', approved_by = ?, approved_at = ? WHERE plugin_id = ? AND version = ?`), approver, now, id, version); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, m.q(`UPDATE delivery_plugins SET enabled_version = ?, updated_at = ? WHERE id = ?`), version, now, id); err != nil {
		return err
	}
	return tx.Commit()
}

// Disable stops a plugin: renewals through it fail until it is enabled again.
func (m *DeliveryPluginManager) Disable(ctx context.Context, id string) error {
	p, err := m.Get(ctx, id)
	if err != nil {
		return err
	}
	if p.EnabledVersion == "" {
		return nil
	}
	now := m.stamp()
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, m.q(`UPDATE delivery_plugin_versions SET status = 'disabled' WHERE plugin_id = ? AND version = ?`), id, p.EnabledVersion); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, m.q(`UPDATE delivery_plugins SET enabled_version = NULL, updated_at = ? WHERE id = ?`), now, id); err != nil {
		return err
	}
	return tx.Commit()
}

// Remove deletes a disabled plugin and every version of it.
func (m *DeliveryPluginManager) Remove(ctx context.Context, id string) error {
	p, err := m.Get(ctx, id)
	if err != nil {
		return err
	}
	if p.EnabledVersion != "" {
		return errPluginInUse
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, m.q(`DELETE FROM delivery_plugin_versions WHERE plugin_id = ?`), id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, m.q(`DELETE FROM delivery_plugins WHERE id = ?`), id); err != nil {
		return err
	}
	return tx.Commit()
}

// Enabled returns the runnable plugin for id: its enabled version, loaded
// from the stored bytes (hash re-checked) with exactly the manifest's
// capabilities, which is what the approval granted.
func (m *DeliveryPluginManager) Enabled(ctx context.Context, id string) (*delivery.Plugin, DeliveryPluginVersion, error) {
	p, err := m.Get(ctx, id)
	if err != nil {
		return nil, DeliveryPluginVersion{}, err
	}
	if p.EnabledVersion == "" {
		return nil, DeliveryPluginVersion{}, errPluginNotEnabled
	}
	v, err := m.version(ctx, id, p.EnabledVersion)
	if err != nil {
		return nil, v, err
	}
	m.mu.Lock()
	cached := m.cache[v.SHA256]
	m.mu.Unlock()
	if cached != nil {
		return cached, v, nil
	}
	var manifestJSON string
	var wasm []byte
	if err := m.db.QueryRowContext(ctx, m.q(`SELECT manifest_json, wasm FROM delivery_plugin_versions WHERE plugin_id = ? AND version = ?`), id, v.Version).Scan(&manifestJSON, &wasm); err != nil {
		return nil, v, err
	}
	rt, err := m.runtime(ctx)
	if err != nil {
		return nil, v, err
	}
	loaded, err := rt.Load(ctx, []byte(manifestJSON), wasm, v.Manifest.Capabilities)
	if err != nil {
		return nil, v, err
	}
	m.mu.Lock()
	m.cache[v.SHA256] = loaded
	m.mu.Unlock()
	return loaded, v, nil
}
