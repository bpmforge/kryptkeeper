// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/agentinstall"
)

var errManagedTargetNotFound = errors.New("managed target not found")
var errManagedTargetInvalidMode = errors.New("invalid discovery_mode, install_mode, or renewal_method")

// Fixed enums for a managed target's operational modes (D-062/FR-P24).
// Reject anything outside these sets at create/update time (L-03) — the DB
// CHECK constraints are a second, not the only, line of defense.
var (
	validDiscoveryModes = map[string]bool{"agent": true, "network": true, "cloud": true, "winrm": true, "none": true}
	validInstallModes   = map[string]bool{"agent": true, "ssh": true, "f5": true, "citrix": true, "k8s": true, "iis": true, "keychain": true, "cloud": true, "acme": true, "plugin": true}
	validRenewalMethods = map[string]bool{"acme": true, "est": true, "scep": true, "manual": true}
)

// ManagedTarget is a user-authored fleet entity: "here is a host, and here
// is how it's discovered / renewed / installed." Today the fleet is
// implicit-by-agent-registration; this is the foundation that makes
// agentless a first-class, configurable mode (see docs/GOLDEN_STATE.md).
//
// DiscoveryMode/InstallMode are still not consumed anywhere -- the renewal
// scheduler has no hub-side auto-renewal execution path at all (only an
// owner-notification trigger, see renewal_scheduler.go's own doc comment),
// and every non-agent InstallMode (ssh/f5/citrix/cloud) is a future
// ticket (W5-10..12); "honor the per-target mode" for those two remains
// disclosed as NOT yet true, see G-79. RenewalThresholdDays IS consumed
// (W8-15): the renewal scheduler resolves it per candidate certificate via a
// host-string match (same heuristic as MatchEndpoints below) and falls back
// to its process-wide RENEWAL_THRESHOLD_DAYS env default when unset.
type ManagedTarget struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Host          string `json:"host"`
	DiscoveryMode string `json:"discovery_mode"`
	InstallMode   string `json:"install_mode"`
	RenewalMethod string `json:"renewal_method"`
	// RenewalThresholdDays is the per-target auto-renew threshold (W8-15,
	// FR-P33) -- the other half of RenewalMethod (000028). 0 means "no
	// override": the renewal scheduler falls back to its process-wide
	// RENEWAL_THRESHOLD_DAYS env default (see renewal_scheduler.go). Mirrors
	// CredentialRef/Schedule's empty-string-means-unset convention, just for
	// an int -- 0 is never a legal threshold value on its own so it is safe
	// to reuse as the "unset" sentinel.
	RenewalThresholdDays int    `json:"renewal_threshold_days,omitempty"`
	CredentialRef        string `json:"credential_ref,omitempty"`
	Schedule             string `json:"schedule,omitempty"`
	// Install profile + opt-in for the hub-side renewal sweep (S-17, on the
	// W5-13 engine). All-empty profile or auto_renew=false means the
	// scheduler never touches this target; it only ever notifies.
	InstallServerType   string `json:"install_server_type,omitempty"`
	InstallCertPath     string `json:"install_cert_path,omitempty"`
	InstallKeyPath      string `json:"install_key_path,omitempty"`
	InstallReloadMethod string `json:"install_reload_method,omitempty"`
	// VerifyHostPort is where scheduled renewals dial to confirm the served
	// leaf after install ("host:port"). Empty = <host>:443.
	VerifyHostPort string `json:"verify_host_port,omitempty"`
	AutoRenew      bool   `json:"auto_renew"`
	// AutoRenewSetBy is the principal that last configured this target's key
	// egress (auto_renew, credential, install profile) while holding
	// certificate.renew. Server-stamped, never read from a request body; the
	// scheduler will not push to an auto_renew target where it is empty
	// (RC1-A-01).
	AutoRenewSetBy string `json:"auto_renew_set_by,omitempty"`
	// SSHHostKey is the operator-confirmed SSH host key pin in authorized_keys
	// format (W24-09). Empty = legacy: fall back to the credential's
	// host_public_key. SSHHostKeyFingerprint is derived on read, never stored.
	SSHHostKey            string `json:"ssh_host_key,omitempty"`
	SSHHostKeyFingerprint string `json:"ssh_host_key_fingerprint,omitempty"`
	// PluginID names the delivery plugin for install_mode "plugin"
	// (W20-20); PluginSettings are its target_schema values. Secrets never
	// go here: they live in the credential named by CredentialRef.
	PluginID       string            `json:"plugin_id,omitempty"`
	PluginSettings map[string]string `json:"plugin_settings,omitempty"`
	// KeyHandlingMode (W23-46) declares where the private key lives; empty =
	// derived from install_mode. EffectiveKeyHandlingMode is response-only,
	// never persisted and never accepted from a request body.
	KeyHandlingMode          string `json:"key_handling_mode,omitempty"`
	EffectiveKeyHandlingMode string `json:"effective_key_handling_mode,omitempty"`
	// CredentialPrivileged is response-only: the target's credential carries
	// the W34-11 privileged flag. Never persisted, never read from a request.
	CredentialPrivileged bool `json:"credential_privileged,omitempty"`
	// Response-only scan state and Blocked verdict (W34-10); see
	// target_state_store.go. Never persisted through Create/Update and never
	// read from a request body.
	RenewalPrivilegeRequired bool         `json:"renewal_privilege_required"`
	LastPrivilegeMode        string       `json:"last_privilege_mode,omitempty"`
	UnreadableCount          int          `json:"unreadable_count"`
	LastScannedAt            string       `json:"last_scanned_at,omitempty"`
	Blocked                  *TargetBlock `json:"blocked,omitempty"`
	Tenant                   string       `json:"tenant"`
	CreatedAt                string       `json:"created_at"`
	UpdatedAt                string       `json:"updated_at"`
}

// ManagedTargetUpdate is a partial PATCH — nil fields are left unchanged.
// Tenant is deliberately not patchable here (no re-mapping flow exists for
// any tenant-owned resource in this codebase yet; CA/template tenant is
// likewise create-time-only, see W2-02).
type ManagedTargetUpdate struct {
	Name                 *string
	Host                 *string
	DiscoveryMode        *string
	InstallMode          *string
	RenewalMethod        *string
	RenewalThresholdDays *int
	CredentialRef        *string
	Schedule             *string
	InstallServerType    *string
	InstallCertPath      *string
	InstallKeyPath       *string
	InstallReloadMethod  *string
	VerifyHostPort       *string
	AutoRenew            *bool
	PluginID             *string
	PluginSettings       *map[string]string
	// AutoRenewSetBy is stamped by the handler after its authorization check.
	AutoRenewSetBy  *string
	KeyHandlingMode *string
	SSHHostKey      *string
}

// ManagedTargetEndpointMatch is one endpoint (scanned or agent-reported)
// whose observed host matches a managed target's declared Host. There is
// no foreign key linking either endpoints or agent_endpoints to
// managed_targets -- neither table existed with this target concept in
// mind -- so this is a deliberate, disclosed heuristic match: endpoints
// via hostname OR ip_address equality, agent_endpoints via server_name
// equality. A target whose Host is an IP will only match scanned
// endpoints (agent_endpoints has no IP-bearing column at all).
type ManagedTargetEndpointMatch struct {
	Source     string `json:"source"` // "scanned" | "agent"
	EndpointID string `json:"endpoint_id,omitempty"`
	AgentID    string `json:"agent_id,omitempty"`
	Host       string `json:"host"`
	Port       *int   `json:"port,omitempty"`
	ServerType string `json:"server_type,omitempty"`
}

// ManagedTargetStore persists managed targets and resolves their endpoint
// join. List returns every target unfiltered -- tenant scoping is applied
// by the caller (handlers_targets.go), matching the established
// filterCAsByTenant/filterTemplatesByTenant convention in this codebase
// rather than pushing tenant SQL into every store.
type ManagedTargetStore interface {
	EnsureSchema(ctx context.Context) error
	Create(ctx context.Context, t ManagedTarget) (ManagedTarget, error)
	Get(ctx context.Context, id string) (ManagedTarget, error)
	List(ctx context.Context) ([]ManagedTarget, error)
	Update(ctx context.Context, id string, u ManagedTargetUpdate) (ManagedTarget, error)
	Delete(ctx context.Context, id string) error
	// MatchEndpoints resolves a target's declared Host against endpoints
	// (scanned) and agent_endpoints (agent-reported). Callers MUST verify
	// tenant visibility of the target themselves before calling this --
	// endpoints/agent_endpoints have no tenant column of their own, so
	// this method itself does not (and cannot) tenant-filter; the tenant
	// boundary is enforced entirely by gating "which targets you may look
	// up" (NFR-P2, acceptance #3 -- see handlers_targets.go).
	MatchEndpoints(ctx context.Context, host string) ([]ManagedTargetEndpointMatch, error)
}

func validateManagedTargetModes(discoveryMode, installMode, renewalMethod string) error {
	if !validDiscoveryModes[discoveryMode] || !validInstallModes[installMode] || !validRenewalMethods[renewalMethod] {
		return errManagedTargetInvalidMode
	}
	return nil
}

var errManagedTargetPluginID = errors.New("install_mode plugin needs plugin_id, and only plugin targets may set it")

// validatePluginTarget ties plugin_id to install_mode "plugin" (W20-20).
func validatePluginTarget(installMode, pluginID string) error {
	if (installMode == "plugin") != (strings.TrimSpace(pluginID) != "") {
		return errManagedTargetPluginID
	}
	return nil
}

func pluginSettingsJSON(m map[string]string) string {
	if len(m) == 0 {
		return "{}"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func parsePluginSettings(s string) map[string]string {
	if s == "" || s == "{}" {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil
	}
	return m
}

var errManagedTargetInvalidThreshold = errors.New("renewal_threshold_days must be between 1 and 365 days, or 0 to use the process default")

// maxRenewalThresholdDays bounds the per-target override. Anything larger
// than a year is a typo or an attempt to make the scheduler renew a
// certificate on every tick (RC1-A-02).
const maxRenewalThresholdDays = 365

// validateRenewalThresholdDays keeps the "0 means unset" sentinel of the DB
// CHECK constraint (migration 000032): 0 is the documented "no override"
// value, anything else must be within 1..maxRenewalThresholdDays.
func validateRenewalThresholdDays(days int) error {
	if days < 0 || days > maxRenewalThresholdDays {
		return errManagedTargetInvalidThreshold
	}
	return nil
}

var errManagedTargetVerifyHostPort = errors.New("verify_host_port must be host:port")

// validateVerifyHostPort accepts empty (the <host>:443 default) or a
// host:port with a numeric port in 1-65535.
func validateVerifyHostPort(v string) error {
	if v == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(v)
	if err != nil || host == "" {
		return errManagedTargetVerifyHostPort
	}
	if n, perr := strconv.Atoi(port); perr != nil || n < 1 || n > 65535 {
		return errManagedTargetVerifyHostPort
	}
	if verifyHostForbidden(host) {
		return errManagedTargetVerifyHostPort
	}
	return nil
}

// verifyHostForbidden refuses literal loopback/link-local/unspecified
// addresses and loopback names at configuration time (RC1-A-04). A name that
// merely resolves to one is caught later, at dial time, by the egress guard.
func verifyHostForbidden(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip, err := netip.ParseAddr(h)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

func newManagedTargetID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "target-" + hex.EncodeToString(b), nil
}

// managedTargetSchema mirrors migration 000028_managed_targets -- see G-33:
// a migration existing is not sufficient, every DB-backed store in this
// codebase must self-heal its own schema since migrations are never
// actually run against a live deployment.
const managedTargetSchema = `
CREATE TABLE IF NOT EXISTS managed_targets (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    host           TEXT NOT NULL,
    discovery_mode TEXT NOT NULL DEFAULT 'agent'
                   CHECK (discovery_mode IN ('agent', 'network', 'cloud', 'winrm', 'none')),
    install_mode   TEXT NOT NULL DEFAULT 'agent'
                   CHECK (install_mode IN ('agent', 'ssh', 'f5', 'citrix', 'k8s', 'iis', 'keychain', 'cloud', 'acme', 'plugin')),
    renewal_method TEXT NOT NULL DEFAULT 'acme'
                   CHECK (renewal_method IN ('acme', 'est', 'scep', 'manual')),
    renewal_threshold_days INTEGER
                   CHECK (renewal_threshold_days IS NULL OR renewal_threshold_days > 0),
    credential_ref TEXT,
    schedule       TEXT,
    install_server_type   TEXT,
    install_cert_path     TEXT,
    install_key_path      TEXT,
    install_reload_method TEXT,
    verify_host_port TEXT,
    auto_renew     INTEGER NOT NULL DEFAULT 0,
    plugin_id      TEXT,
    plugin_settings TEXT NOT NULL DEFAULT '{}',
    auto_renew_set_by TEXT,
    key_handling_mode TEXT,
    ssh_host_key TEXT,
    tenant         TEXT NOT NULL DEFAULT 'default',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_managed_targets_tenant ON managed_targets(tenant);
CREATE INDEX IF NOT EXISTS idx_managed_targets_host ON managed_targets(host);`

// --- SQLite implementation ---

type sqliteManagedTargetStore struct{ db *sql.DB }

func (s *sqliteManagedTargetStore) EnsureSchema(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, managedTargetSchema); err != nil {
		return err
	}
	// Best-effort upgrade for pre-W8-15 tables created without
	// renewal_threshold_days (mirrors agent_store_db.go's token_hash
	// upgrade). Ignore the error: a duplicate-column failure means it
	// already exists.
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE managed_targets ADD COLUMN renewal_threshold_days INTEGER") // best-effort upgrade: duplicate-column error = already migrated
	// S-17 install-profile columns (migration 000047) -- same best-effort
	// self-heal; duplicate-column errors mean they already exist.
	for _, ddl := range []string{
		"ALTER TABLE managed_targets ADD COLUMN install_server_type TEXT",
		"ALTER TABLE managed_targets ADD COLUMN install_cert_path TEXT",
		"ALTER TABLE managed_targets ADD COLUMN install_key_path TEXT",
		"ALTER TABLE managed_targets ADD COLUMN install_reload_method TEXT",
		"ALTER TABLE managed_targets ADD COLUMN verify_host_port TEXT",
		"ALTER TABLE managed_targets ADD COLUMN auto_renew INTEGER NOT NULL DEFAULT 0",
		// W20-20 (migration 000068) -- the install_mode CHECK itself
		// needs the migration's rebuild; these only add the columns.
		"ALTER TABLE managed_targets ADD COLUMN plugin_id TEXT",
		"ALTER TABLE managed_targets ADD COLUMN plugin_settings TEXT NOT NULL DEFAULT '{}'",
		// RC1-A-01 (migration 000072).
		"ALTER TABLE managed_targets ADD COLUMN auto_renew_set_by TEXT",
		// W23-46 (migration 000128).
		"ALTER TABLE managed_targets ADD COLUMN key_handling_mode TEXT",
		// W24-09 (migration 000141).
		"ALTER TABLE managed_targets ADD COLUMN ssh_host_key TEXT",
		// W34-15 (migration 000344).
		"ALTER TABLE managed_targets ADD COLUMN last_preflight TEXT",
		// W34-10 (migrations 000342, 000345).
		"ALTER TABLE managed_targets ADD COLUMN renewal_privilege_required INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE managed_targets ADD COLUMN last_privilege_mode TEXT",
		"ALTER TABLE managed_targets ADD COLUMN unreadable_count INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE managed_targets ADD COLUMN last_scanned_at TEXT",
		"ALTER TABLE managed_targets ADD COLUMN blocked_kind TEXT",
		"ALTER TABLE managed_targets ADD COLUMN blocked_reason TEXT",
		"ALTER TABLE managed_targets ADD COLUMN blocked_at TEXT",
	} {
		_, _ = s.db.ExecContext(ctx, ddl) // best-effort upgrade: duplicate-column error = already migrated
	}
	return nil
}

func (s *sqliteManagedTargetStore) Create(ctx context.Context, t ManagedTarget) (ManagedTarget, error) {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO managed_targets
		  (id, name, host, discovery_mode, install_mode, renewal_method, renewal_threshold_days, credential_ref, schedule, install_server_type, install_cert_path, install_key_path, install_reload_method, verify_host_port, auto_renew, plugin_id, plugin_settings, auto_renew_set_by, key_handling_mode, ssh_host_key, tenant, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Name, t.Host, t.DiscoveryMode, t.InstallMode, t.RenewalMethod,
		nullInt(t.RenewalThresholdDays), nullString(t.CredentialRef), nullString(t.Schedule),
		nullString(t.InstallServerType), nullString(t.InstallCertPath), nullString(t.InstallKeyPath), nullString(t.InstallReloadMethod), nullString(t.VerifyHostPort), boolToInt(t.AutoRenew),
		nullString(t.PluginID), pluginSettingsJSON(t.PluginSettings), nullString(t.AutoRenewSetBy), nullString(t.KeyHandlingMode), nullString(t.SSHHostKey),
		t.Tenant, t.CreatedAt, t.UpdatedAt)
	if err != nil {
		return ManagedTarget{}, err
	}
	return t, nil
}

func (s *sqliteManagedTargetStore) Get(ctx context.Context, id string) (ManagedTarget, error) {
	return scanManagedTarget(s.db.QueryRowContext(ctx, `
		SELECT id, name, host, discovery_mode, install_mode, renewal_method, renewal_threshold_days, credential_ref, schedule, install_server_type, install_cert_path, install_key_path, install_reload_method, verify_host_port, auto_renew, plugin_id, plugin_settings, auto_renew_set_by, key_handling_mode, ssh_host_key, tenant, created_at, updated_at
		FROM managed_targets WHERE id = ?`, id))
}

func (s *sqliteManagedTargetStore) List(ctx context.Context) ([]ManagedTarget, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, host, discovery_mode, install_mode, renewal_method, renewal_threshold_days, credential_ref, schedule, install_server_type, install_cert_path, install_key_path, install_reload_method, verify_host_port, auto_renew, plugin_id, plugin_settings, auto_renew_set_by, key_handling_mode, ssh_host_key, tenant, created_at, updated_at
		FROM managed_targets ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	return scanManagedTargetRows(rows)
}

func (s *sqliteManagedTargetStore) Update(ctx context.Context, id string, u ManagedTargetUpdate) (ManagedTarget, error) {
	return applyManagedTargetUpdate(ctx, s, id, u)
}

func (s *sqliteManagedTargetStore) Delete(ctx context.Context, id string) error {
	return deleteManagedTargetRow(ctx, s.db, "DELETE FROM managed_targets WHERE id = ?", id)
}

func (s *sqliteManagedTargetStore) MatchEndpoints(ctx context.Context, host string) ([]ManagedTargetEndpointMatch, error) {
	return matchManagedTargetEndpoints(ctx, s.db, host, "?", "?", "?")
}

// --- Postgres implementation ---

type postgresManagedTargetStore struct{ db *sql.DB }

func (s *postgresManagedTargetStore) EnsureSchema(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, managedTargetSchema); err != nil {
		return err
	}
	// Best-effort upgrade for pre-W8-15 tables created without
	// renewal_threshold_days. Ignore the error: a duplicate-column failure
	// means it already exists.
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE managed_targets ADD COLUMN renewal_threshold_days INTEGER") // best-effort upgrade: duplicate-column error = already migrated
	// S-17 install-profile columns (migration 000047) -- same best-effort
	// self-heal; duplicate-column errors mean they already exist.
	for _, ddl := range []string{
		"ALTER TABLE managed_targets ADD COLUMN install_server_type TEXT",
		"ALTER TABLE managed_targets ADD COLUMN install_cert_path TEXT",
		"ALTER TABLE managed_targets ADD COLUMN install_key_path TEXT",
		"ALTER TABLE managed_targets ADD COLUMN install_reload_method TEXT",
		"ALTER TABLE managed_targets ADD COLUMN verify_host_port TEXT",
		"ALTER TABLE managed_targets ADD COLUMN auto_renew INTEGER NOT NULL DEFAULT 0",
		// W20-20 (migration 000068) -- the install_mode CHECK itself
		// needs the migration's rebuild; these only add the columns.
		"ALTER TABLE managed_targets ADD COLUMN plugin_id TEXT",
		"ALTER TABLE managed_targets ADD COLUMN plugin_settings TEXT NOT NULL DEFAULT '{}'",
		// RC1-A-01 (migration 000072).
		"ALTER TABLE managed_targets ADD COLUMN auto_renew_set_by TEXT",
		// W23-46 (migration 000128).
		"ALTER TABLE managed_targets ADD COLUMN key_handling_mode TEXT",
		// W24-09 (migration 000141).
		"ALTER TABLE managed_targets ADD COLUMN ssh_host_key TEXT",
		// W34-15 (migration 000344).
		"ALTER TABLE managed_targets ADD COLUMN last_preflight TEXT",
		// W34-10 (migrations 000342, 000345).
		"ALTER TABLE managed_targets ADD COLUMN renewal_privilege_required BOOLEAN NOT NULL DEFAULT FALSE",
		"ALTER TABLE managed_targets ADD COLUMN last_privilege_mode TEXT",
		"ALTER TABLE managed_targets ADD COLUMN unreadable_count INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE managed_targets ADD COLUMN last_scanned_at TEXT",
		"ALTER TABLE managed_targets ADD COLUMN blocked_kind TEXT",
		"ALTER TABLE managed_targets ADD COLUMN blocked_reason TEXT",
		"ALTER TABLE managed_targets ADD COLUMN blocked_at TEXT",
	} {
		_, _ = s.db.ExecContext(ctx, ddl) // best-effort upgrade: duplicate-column error = already migrated
	}
	return nil
}

func (s *postgresManagedTargetStore) Create(ctx context.Context, t ManagedTarget) (ManagedTarget, error) {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO managed_targets
		  (id, name, host, discovery_mode, install_mode, renewal_method, renewal_threshold_days, credential_ref, schedule, install_server_type, install_cert_path, install_key_path, install_reload_method, verify_host_port, auto_renew, plugin_id, plugin_settings, auto_renew_set_by, key_handling_mode, ssh_host_key, tenant, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)`,
		t.ID, t.Name, t.Host, t.DiscoveryMode, t.InstallMode, t.RenewalMethod,
		nullInt(t.RenewalThresholdDays), nullString(t.CredentialRef), nullString(t.Schedule),
		nullString(t.InstallServerType), nullString(t.InstallCertPath), nullString(t.InstallKeyPath), nullString(t.InstallReloadMethod), nullString(t.VerifyHostPort), boolToInt(t.AutoRenew),
		nullString(t.PluginID), pluginSettingsJSON(t.PluginSettings), nullString(t.AutoRenewSetBy), nullString(t.KeyHandlingMode), nullString(t.SSHHostKey),
		t.Tenant, t.CreatedAt, t.UpdatedAt)
	if err != nil {
		return ManagedTarget{}, err
	}
	return t, nil
}

func (s *postgresManagedTargetStore) Get(ctx context.Context, id string) (ManagedTarget, error) {
	return scanManagedTarget(s.db.QueryRowContext(ctx, `
		SELECT id, name, host, discovery_mode, install_mode, renewal_method, renewal_threshold_days, credential_ref, schedule, install_server_type, install_cert_path, install_key_path, install_reload_method, verify_host_port, auto_renew, plugin_id, plugin_settings, auto_renew_set_by, key_handling_mode, ssh_host_key, tenant, created_at, updated_at
		FROM managed_targets WHERE id = $1`, id))
}

func (s *postgresManagedTargetStore) List(ctx context.Context) ([]ManagedTarget, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, host, discovery_mode, install_mode, renewal_method, renewal_threshold_days, credential_ref, schedule, install_server_type, install_cert_path, install_key_path, install_reload_method, verify_host_port, auto_renew, plugin_id, plugin_settings, auto_renew_set_by, key_handling_mode, ssh_host_key, tenant, created_at, updated_at
		FROM managed_targets ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	return scanManagedTargetRows(rows)
}

func (s *postgresManagedTargetStore) Update(ctx context.Context, id string, u ManagedTargetUpdate) (ManagedTarget, error) {
	return applyManagedTargetUpdate(ctx, s, id, u)
}

func (s *postgresManagedTargetStore) Delete(ctx context.Context, id string) error {
	return deleteManagedTargetRow(ctx, s.db, "DELETE FROM managed_targets WHERE id = $1", id)
}

func (s *postgresManagedTargetStore) MatchEndpoints(ctx context.Context, host string) ([]ManagedTargetEndpointMatch, error) {
	return matchManagedTargetEndpoints(ctx, s.db, host, "$1", "$2", "$3")
}

// --- shared helpers ---

func scanManagedTarget(row *sql.Row) (ManagedTarget, error) {
	var t ManagedTarget
	var thresholdDays, autoRenew sql.NullInt64
	var credRef, schedule, instType, instCert, instKey, instReload, verifyHP, pluginID, pluginSettings, setBy, keyMode, sshHostKey sql.NullString
	err := row.Scan(&t.ID, &t.Name, &t.Host, &t.DiscoveryMode, &t.InstallMode, &t.RenewalMethod,
		&thresholdDays, &credRef, &schedule, &instType, &instCert, &instKey, &instReload, &verifyHP, &autoRenew, &pluginID, &pluginSettings, &setBy, &keyMode, &sshHostKey, &t.Tenant, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ManagedTarget{}, errManagedTargetNotFound
	}
	if err != nil {
		return ManagedTarget{}, err
	}
	t.RenewalThresholdDays = int(thresholdDays.Int64)
	t.CredentialRef = credRef.String
	t.Schedule = schedule.String
	t.InstallServerType = instType.String
	t.InstallCertPath = instCert.String
	t.InstallKeyPath = instKey.String
	t.InstallReloadMethod = instReload.String
	t.VerifyHostPort = verifyHP.String
	t.AutoRenew = autoRenew.Int64 != 0
	t.PluginID = pluginID.String
	t.PluginSettings = parsePluginSettings(pluginSettings.String)
	t.AutoRenewSetBy = setBy.String
	t.KeyHandlingMode = keyMode.String
	t.SSHHostKey = sshHostKey.String
	t.SSHHostKeyFingerprint = agentinstall.FingerprintOfLine(t.SSHHostKey)
	return t, nil
}

func scanManagedTargetRows(rows *sql.Rows) ([]ManagedTarget, error) {
	defer rows.Close()
	items := []ManagedTarget{}
	for rows.Next() {
		var t ManagedTarget
		var thresholdDays, autoRenew sql.NullInt64
		var credRef, schedule, instType, instCert, instKey, instReload, verifyHP, pluginID, pluginSettings, setBy, keyMode, sshHostKey sql.NullString
		if err := rows.Scan(&t.ID, &t.Name, &t.Host, &t.DiscoveryMode, &t.InstallMode, &t.RenewalMethod,
			&thresholdDays, &credRef, &schedule, &instType, &instCert, &instKey, &instReload, &verifyHP, &autoRenew, &pluginID, &pluginSettings, &setBy, &keyMode, &sshHostKey, &t.Tenant, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		t.RenewalThresholdDays = int(thresholdDays.Int64)
		t.CredentialRef = credRef.String
		t.Schedule = schedule.String
		t.InstallServerType = instType.String
		t.InstallCertPath = instCert.String
		t.InstallKeyPath = instKey.String
		t.InstallReloadMethod = instReload.String
		t.VerifyHostPort = verifyHP.String
		t.AutoRenew = autoRenew.Int64 != 0
		t.PluginID = pluginID.String
		t.PluginSettings = parsePluginSettings(pluginSettings.String)
		t.AutoRenewSetBy = setBy.String
		t.KeyHandlingMode = keyMode.String
		t.SSHHostKey = sshHostKey.String
		t.SSHHostKeyFingerprint = agentinstall.FingerprintOfLine(t.SSHHostKey)
		items = append(items, t)
	}
	return items, rows.Err()
}

// nullInt maps the "0 means unset" sentinel (see ManagedTarget.RenewalThresholdDays)
// to a genuine SQL NULL, mirroring nullString's empty-string handling.
func nullInt(n int) sql.NullInt64 {
	if n <= 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(n), Valid: true}
}

func deleteManagedTargetRow(ctx context.Context, db *sql.DB, query, id string) error {
	res, err := db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errManagedTargetNotFound
	}
	return nil
}

// mergeManagedTargetUpdate applies the non-nil fields of u to current. The
// handlers use it to see the target a PATCH would produce before authorizing it.
func mergeManagedTargetUpdate(current *ManagedTarget, u ManagedTargetUpdate) {
	if u.Name != nil {
		current.Name = strings.TrimSpace(*u.Name)
	}
	if u.Host != nil {
		current.Host = strings.TrimSpace(*u.Host)
	}
	if u.DiscoveryMode != nil {
		current.DiscoveryMode = *u.DiscoveryMode
	}
	if u.InstallMode != nil {
		current.InstallMode = *u.InstallMode
	}
	if u.RenewalMethod != nil {
		current.RenewalMethod = *u.RenewalMethod
	}
	if u.RenewalThresholdDays != nil {
		current.RenewalThresholdDays = *u.RenewalThresholdDays
	}
	if u.CredentialRef != nil {
		current.CredentialRef = *u.CredentialRef
	}
	if u.Schedule != nil {
		current.Schedule = *u.Schedule
	}
	if u.InstallServerType != nil {
		current.InstallServerType = strings.TrimSpace(*u.InstallServerType)
	}
	if u.InstallCertPath != nil {
		current.InstallCertPath = strings.TrimSpace(*u.InstallCertPath)
	}
	if u.InstallKeyPath != nil {
		current.InstallKeyPath = strings.TrimSpace(*u.InstallKeyPath)
	}
	if u.InstallReloadMethod != nil {
		current.InstallReloadMethod = strings.TrimSpace(*u.InstallReloadMethod)
	}
	if u.VerifyHostPort != nil {
		current.VerifyHostPort = strings.TrimSpace(*u.VerifyHostPort)
	}
	if u.AutoRenew != nil {
		current.AutoRenew = *u.AutoRenew
	}
	if u.PluginID != nil {
		current.PluginID = strings.TrimSpace(*u.PluginID)
	}
	if u.PluginSettings != nil {
		current.PluginSettings = *u.PluginSettings
	}
	if u.AutoRenewSetBy != nil {
		current.AutoRenewSetBy = *u.AutoRenewSetBy
	}
	if u.SSHHostKey != nil {
		current.SSHHostKey = strings.TrimSpace(*u.SSHHostKey)
		current.SSHHostKeyFingerprint = agentinstall.FingerprintOfLine(current.SSHHostKey)
	}
	if u.KeyHandlingMode != nil {
		current.KeyHandlingMode = strings.TrimSpace(*u.KeyHandlingMode)
	}
}

// applyManagedTargetUpdate is the engine-agnostic PATCH tail: fetch the
// current row, apply non-nil fields, re-validate the enum triple (a PATCH
// that only touches Name must not still be able to leave an invalid mode
// combination if two of the three fields are touched independently), write
// it back via the same store's Create-shaped INSERT-or-nothing... actually
// via a plain UPDATE built per-engine by the caller's db handle.
func applyManagedTargetUpdate(ctx context.Context, store ManagedTargetStore, id string, u ManagedTargetUpdate) (ManagedTarget, error) {
	current, err := store.Get(ctx, id)
	if err != nil {
		return ManagedTarget{}, err
	}
	mergeManagedTargetUpdate(&current, u)
	if err := validatePluginTarget(current.InstallMode, current.PluginID); err != nil {
		return ManagedTarget{}, err
	}
	if current.Name == "" || current.Host == "" {
		return ManagedTarget{}, fmt.Errorf("name and host are required")
	}
	if err := validateManagedTargetModes(current.DiscoveryMode, current.InstallMode, current.RenewalMethod); err != nil {
		return ManagedTarget{}, err
	}
	if err := validateKeyHandlingMode(current.KeyHandlingMode, current.InstallMode); err != nil {
		return ManagedTarget{}, err
	}
	if err := validateRenewalThresholdDays(current.RenewalThresholdDays); err != nil {
		return ManagedTarget{}, err
	}
	if err := validateVerifyHostPort(current.VerifyHostPort); err != nil {
		return ManagedTarget{}, err
	}
	current.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	var db *sql.DB
	var query string
	switch s := store.(type) {
	case *sqliteManagedTargetStore:
		db = s.db
		query = `UPDATE managed_targets SET name=?, host=?, discovery_mode=?, install_mode=?, renewal_method=?, renewal_threshold_days=?, credential_ref=?, schedule=?, install_server_type=?, install_cert_path=?, install_key_path=?, install_reload_method=?, verify_host_port=?, auto_renew=?, plugin_id=?, plugin_settings=?, auto_renew_set_by=?, key_handling_mode=?, ssh_host_key=?, updated_at=? WHERE id=?`
	case *postgresManagedTargetStore:
		db = s.db
		query = `UPDATE managed_targets SET name=$1, host=$2, discovery_mode=$3, install_mode=$4, renewal_method=$5, renewal_threshold_days=$6, credential_ref=$7, schedule=$8, install_server_type=$9, install_cert_path=$10, install_key_path=$11, install_reload_method=$12, verify_host_port=$13, auto_renew=$14, plugin_id=$15, plugin_settings=$16, auto_renew_set_by=$17, key_handling_mode=$18, ssh_host_key=$19, updated_at=$20 WHERE id=$21`
	default:
		return ManagedTarget{}, fmt.Errorf("unsupported managed target store implementation %T", store)
	}
	if _, err := db.ExecContext(ctx, query,
		current.Name, current.Host, current.DiscoveryMode, current.InstallMode, current.RenewalMethod,
		nullInt(current.RenewalThresholdDays), nullString(current.CredentialRef), nullString(current.Schedule),
		nullString(current.InstallServerType), nullString(current.InstallCertPath), nullString(current.InstallKeyPath), nullString(current.InstallReloadMethod), nullString(current.VerifyHostPort), boolToInt(current.AutoRenew),
		nullString(current.PluginID), pluginSettingsJSON(current.PluginSettings), nullString(current.AutoRenewSetBy), nullString(current.KeyHandlingMode), nullString(current.SSHHostKey),
		current.UpdatedAt, id); err != nil {
		return ManagedTarget{}, err
	}
	return current, nil
}

// matchManagedTargetEndpoints resolves host against endpoints (scanned,
// matched on hostname OR ip_address) and agent_endpoints (agent-reported,
// matched on server_name) -- see ManagedTargetEndpointMatch's doc comment
// for why this is a heuristic string match, not a foreign key.
//
// ph1/ph2 are the placeholders for the scanned query's two `host` args
// (hostname = ph1 OR ip_address = ph2). For sqlite's positional `?` they
// are identical text ("?", "?") since each occurrence binds positionally
// regardless of spelling; for postgres's NUMBERED placeholders they MUST
// be distinct ("$1", "$2") -- two bound args against one repeated $1
// fails at Bind ("bind message supplies 2 parameters, but prepared
// statement requires 1"). Caught by advisor review before close; sqlite's
// leniency here is exactly why this bug was invisible to every sqlite-only
// test in this package.
func matchManagedTargetEndpoints(ctx context.Context, db *sql.DB, host, ph1, ph2, ph3 string) ([]ManagedTargetEndpointMatch, error) {
	out := []ManagedTargetEndpointMatch{}

	// Scanned endpoints carry a tenant (L-11); a scoped ctx restricts the
	// match to the target's own tenant so two tenants naming the same host
	// never see each other's scan results.
	scannedQuery := fmt.Sprintf(`SELECT id, hostname, ip_address, port FROM endpoints WHERE (hostname = %s OR ip_address = %s)`, ph1, ph2)
	args := []any{host, host}
	if tenant, filter := discoveryFilterTenant(ctx); filter {
		scannedQuery += fmt.Sprintf(" AND tenant = %s", ph3)
		args = append(args, tenant)
	}
	scannedRows, err := db.QueryContext(ctx, scannedQuery, args...)
	if err != nil {
		return nil, err
	}
	for scannedRows.Next() {
		var id string
		var hostname, ipAddress sql.NullString
		var port int
		if err := scannedRows.Scan(&id, &hostname, &ipAddress, &port); err != nil {
			scannedRows.Close()
			return nil, err
		}
		matchedHost := hostname.String
		if matchedHost == "" {
			matchedHost = ipAddress.String
		}
		p := port
		out = append(out, ManagedTargetEndpointMatch{Source: "scanned", EndpointID: id, Host: matchedHost, Port: &p})
	}
	if err := scannedRows.Err(); err != nil {
		scannedRows.Close()
		return nil, err
	}
	scannedRows.Close()

	agentQuery := fmt.Sprintf(`SELECT agent_id, server_name, server_type FROM agent_endpoints WHERE server_name = %s`, ph1)
	agentRows, err := db.QueryContext(ctx, agentQuery, host)
	if err != nil {
		return nil, err
	}
	defer agentRows.Close()
	for agentRows.Next() {
		var agentID string
		var serverName, serverType sql.NullString
		if err := agentRows.Scan(&agentID, &serverName, &serverType); err != nil {
			return nil, err
		}
		out = append(out, ManagedTargetEndpointMatch{Source: "agent", AgentID: agentID, Host: serverName.String, ServerType: serverType.String})
	}
	return out, agentRows.Err()
}

// newManagedTargetStoreFromEnv opens the same SQLite/Postgres DB as other
// providers and ensures the managed_targets schema exists (G-33: migration
// 000028 alone cannot be assumed to have run). Returns nil on any failure
// -- nil-tolerant, matching tenant_store.go/finding_exception_store.go/
// notification_dedup.go, the modal recent pattern in this package (not an
// in-memory fallback, which no current-generation store in this codebase
// uses).
// NewManagedTargetStoreFromEnv is the exported proxy cmd/kryptkeeper uses to
// hand the discovery scheduler the target list (W18-12).
func NewManagedTargetStoreFromEnv() ManagedTargetStore { return newManagedTargetStoreFromEnv() }

func newManagedTargetStoreFromEnv() ManagedTargetStore {
	state := newDBProviderState[ManagedTargetStore](
		"managed-target",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_TARGETS_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_TARGETS_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_TARGETS_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) ManagedTargetStore { return &sqliteManagedTargetStore{db: db} },
		func(db *sql.DB) ManagedTargetStore { return &postgresManagedTargetStore{db: db} },
	)
	if state.openErr != nil || state.store == nil {
		_ = dbProviderUnavailable("managed-target", state.openErr) // logs the outage itself; return value is the same sentinel
		return nil
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		_ = dbProviderUnavailable("managed-target", err) // logs the outage itself; return value is the same sentinel
		return nil
	}
	return state.store
}

// targetPreflightStore persists the latest privilege preflight report (JSON,
// secret-free) per target (W34-15, migration 000344). It is a separate
// interface so existing ManagedTargetStore implementations are unaffected.
type targetPreflightStore interface {
	SetLastPreflight(ctx context.Context, id, reportJSON string) error
	GetLastPreflight(ctx context.Context, id string) (string, error)
}

func setLastPreflight(ctx context.Context, db *sql.DB, query, id, reportJSON string) error {
	res, err := db.ExecContext(ctx, query, reportJSON, id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func getLastPreflight(ctx context.Context, db *sql.DB, query, id string) (string, error) {
	var v sql.NullString
	if err := db.QueryRowContext(ctx, query, id).Scan(&v); err != nil {
		return "", err
	}
	return v.String, nil
}

func (s *sqliteManagedTargetStore) SetLastPreflight(ctx context.Context, id, reportJSON string) error {
	return setLastPreflight(ctx, s.db, "UPDATE managed_targets SET last_preflight = ? WHERE id = ?", id, reportJSON)
}

func (s *sqliteManagedTargetStore) GetLastPreflight(ctx context.Context, id string) (string, error) {
	return getLastPreflight(ctx, s.db, "SELECT last_preflight FROM managed_targets WHERE id = ?", id)
}

func (s *postgresManagedTargetStore) SetLastPreflight(ctx context.Context, id, reportJSON string) error {
	return setLastPreflight(ctx, s.db, "UPDATE managed_targets SET last_preflight = $1 WHERE id = $2", id, reportJSON)
}

func (s *postgresManagedTargetStore) GetLastPreflight(ctx context.Context, id string) (string, error) {
	return getLastPreflight(ctx, s.db, "SELECT last_preflight FROM managed_targets WHERE id = $1", id)
}
