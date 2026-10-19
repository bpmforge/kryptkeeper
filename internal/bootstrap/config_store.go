// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

const configKeyEscalationChannel = "notifications.escalation_channel"

var errConfigUnknownKey = errors.New("unknown config key")
var errConfigOverrideNotFound = errors.New("config override not found")

const configValueMaxLen = 8192

// configKeyDef is one entry in the documented set of runtime settings
// (acceptance #1): the DB key, the env var it shadows as a bootstrap
// default, the UI-facing grouping, and whether the value is secret (write-only
// over the API -- acceptance #2). This registry is the single source of
// truth for which keys the store and handlers accept; an unregistered key is
// rejected with 400 rather than silently stored, mirroring
// validCredentialTypes' fixed-enum convention in outbound_credential_store.go.
type configKeyDef struct {
	Key      string
	EnvVar   string
	Category string
	Secret   bool
	// RestartRequired marks settings whose consumer is built once at process
	// start (W33-04): the value is stored and reported but only takes effect
	// after a restart.
	RestartRequired bool
}

const (
	configCategoryNotifications = "notifications"
	configCategoryRenewalPolicy = "renewal_policy"
	configCategoryDiscovery     = "discovery"
	configCategorySSO           = "sso"
	configCategorySAML          = "saml"
	configCategorySCIM          = "scim"
	configCategoryKeyBackend    = "key_backend"
	configCategorySLO           = "slo"
	configCategoryObservability = "observability"
)

// configRegistry is the documented set of runtime settings this store
// covers: notification channels, renewal policy, discovery provider, and SSO
// (acceptance #1). Each entry's EnvVar is the real env var already read
// elsewhere in this codebase (cmd/kryptkeeper/main.go, notification_*.go,
// renewal_scheduler.go, discovery_provider.go, auth_config.go) -- this
// registry does not introduce new env vars, it documents and overrides the
// existing ones.
var configRegistry = []configKeyDef{
	{Key: "notifications.slack_webhook_url", EnvVar: "SLACK_WEBHOOK_URL", Category: configCategoryNotifications, Secret: true},
	// notifications.webhook_url: W8-16 was filed instructing this to match
	// slack_webhook_url's Secret setting, describing it as Secret:false --
	// that description is wrong; slack_webhook_url has been Secret:true since
	// it was introduced above (W8-03, be9ea46). Matching what slack_webhook_url
	// actually is (true) rather than the ticket's incorrect description of it,
	// which is also the more defensible choice on its own merits: like a Slack
	// incoming-webhook URL, a generic webhook target commonly embeds a
	// bearer-token-equivalent in its path or query string, so treating it as
	// non-secret would return that credential in plaintext to any principal
	// who can read config.
	{Key: "notifications.webhook_url", EnvVar: "WEBHOOK_URL", Category: configCategoryNotifications, Secret: true},
	{Key: "notifications.webhook_secret", EnvVar: "WEBHOOK_SECRET", Category: configCategoryNotifications, Secret: true},
	{Key: "notifications.webhook_secret_previous", EnvVar: "WEBHOOK_SECRET_PREVIOUS", Category: configCategoryNotifications, Secret: true},
	{Key: "notifications.smtp_host", EnvVar: "SMTP_HOST", Category: configCategoryNotifications, Secret: false},
	{Key: "notifications.smtp_port", EnvVar: "SMTP_PORT", Category: configCategoryNotifications, Secret: false},
	{Key: "notifications.smtp_username", EnvVar: "SMTP_USERNAME", Category: configCategoryNotifications, Secret: false},
	{Key: "notifications.smtp_password", EnvVar: "SMTP_PASSWORD", Category: configCategoryNotifications, Secret: true},
	{Key: "notifications.smtp_from", EnvVar: "SMTP_FROM", Category: configCategoryNotifications, Secret: false},
	{Key: "notifications.pagerduty_routing_key", EnvVar: "PAGERDUTY_ROUTING_KEY", Category: configCategoryNotifications, Secret: true},
	// Escalation target is Secret because for slack/webhook/pagerduty it is a
	// URL or routing key that can embed a token (the spec said Secret:false;
	// the W30 brief forbids returning any channel secret unmasked).
	{Key: "notifications.escalation_channel", EnvVar: "KRYPTKEEPER_NOTIFY_ESCALATION_CHANNEL", Category: configCategoryNotifications, Secret: false},
	{Key: "notifications.escalation_target", EnvVar: "KRYPTKEEPER_NOTIFY_ESCALATION_TARGET", Category: configCategoryNotifications, Secret: true},
	// W32-27: ChatOps approval posting. Bot token / app password are Secret
	// (write-only over the API); the team maps are JSON objects.
	{Key: "notifications.slack_bot_token", EnvVar: "SLACK_BOT_TOKEN", Category: configCategoryNotifications, Secret: true},
	{Key: "notifications.slack_team_channels", EnvVar: "SLACK_TEAM_CHANNELS", Category: configCategoryNotifications, Secret: false},
	{Key: "notifications.teams_app_id", EnvVar: "TEAMS_APP_ID", Category: configCategoryNotifications, Secret: false},
	{Key: "notifications.teams_app_password", EnvVar: "TEAMS_APP_PASSWORD", Category: configCategoryNotifications, Secret: true},
	{Key: "notifications.teams_team_channels", EnvVar: "TEAMS_TEAM_CHANNELS", Category: configCategoryNotifications, Secret: false},
	{Key: "renewal_policy.threshold_days", EnvVar: "RENEWAL_THRESHOLD_DAYS", Category: configCategoryRenewalPolicy, Secret: false},
	{Key: "renewal_policy.poll_hours", EnvVar: "RENEWAL_POLL_HOURS", Category: configCategoryRenewalPolicy, Secret: false},
	{Key: "renewal_policy.alert_cooldown_hours", EnvVar: "RENEWAL_ALERT_COOLDOWN_HOURS", Category: configCategoryRenewalPolicy, Secret: false},
	{Key: "renewal_policy.retry_base_minutes", EnvVar: "RENEWAL_RETRY_BASE_MINUTES", Category: configCategoryRenewalPolicy, Secret: false},
	{Key: "renewal_policy.retry_cap_hours", EnvVar: "RENEWAL_RETRY_CAP_HOURS", Category: configCategoryRenewalPolicy, Secret: false},
	{Key: "discovery.provider", EnvVar: "APP_DISCOVERY_PROVIDER", Category: configCategoryDiscovery, Secret: false},
	{Key: "ct.domains", EnvVar: "KRYPTKEEPER_CT_DOMAINS", Category: configCategoryDiscovery, Secret: false},
	{Key: "discovery.kube_clusters", EnvVar: "KRYPTKEEPER_K8S_CLUSTERS", Category: configCategoryDiscovery, Secret: false},
	{Key: "discovery.mesh_leaf_retention_days", EnvVar: "KRYPTKEEPER_MESH_LEAF_RETENTION_DAYS", Category: configCategoryDiscovery, Secret: false},
	{Key: "discovery.saas_endpoints", EnvVar: "KRYPTKEEPER_SAAS_ENDPOINTS", Category: configCategoryDiscovery, Secret: false},
	{Key: "discovery.cloud_scopes", EnvVar: "KRYPTKEEPER_CLOUD_SCOPES", Category: configCategoryDiscovery, Secret: false},
	{Key: "sso.oidc_issuer", EnvVar: "APP_OIDC_ISSUER", Category: configCategorySSO, Secret: false},
	{Key: "sso.oidc_audience", EnvVar: "APP_OIDC_AUDIENCE", Category: configCategorySSO, Secret: false},
	{Key: "sso.oidc_discovery_url", EnvVar: "APP_OIDC_DISCOVERY_URL", Category: configCategorySSO, Secret: false},
	{Key: "sso.oidc_jwks_json", EnvVar: "APP_OIDC_JWKS_JSON", Category: configCategorySSO, Secret: true},
	// W33-04. saml.sp_entity_id is the SP issuer; there is deliberately no
	// metadata-url key (no consumer exists). The certificate is a public PEM.
	{Key: "saml.sp_entity_id", EnvVar: "APP_SAML_SP_ISSUER", Category: configCategorySAML},
	{Key: "saml.idp_sso_url", EnvVar: "APP_SAML_IDP_SSO_URL", Category: configCategorySAML},
	{Key: "saml.idp_issuer", EnvVar: "APP_SAML_IDP_ISSUER", Category: configCategorySAML},
	{Key: "saml.idp_certificate", EnvVar: "APP_SAML_IDP_CERTIFICATE", Category: configCategorySAML},
	{Key: "scim.enabled", EnvVar: "APP_SCIM_ENABLED", Category: configCategorySCIM},
	{Key: "scim.token", EnvVar: "APP_SCIM_TOKEN", Category: configCategorySCIM, Secret: true},
	{Key: "key_backend.kind", EnvVar: "KRYPTKEEPER_KEY_BACKEND", Category: configCategoryKeyBackend, RestartRequired: true},
	{Key: "key_backend.pkcs11_module", EnvVar: "KRYPTKEEPER_PKCS11_LIB", Category: configCategoryKeyBackend, RestartRequired: true},
	{Key: "slo.renewal_success_objective", EnvVar: "KRYPTKEEPER_SLO_RENEWAL_OBJECTIVE", Category: configCategorySLO, Secret: false},
	{Key: "slo.issuance_success_objective", EnvVar: "KRYPTKEEPER_SLO_ISSUANCE_OBJECTIVE", Category: configCategorySLO, Secret: false},
	{Key: "metrics.bearer_token", EnvVar: "KRYPTKEEPER_METRICS_BEARER_TOKEN", Category: configCategoryObservability, Secret: true},
	{Key: "slo.issuance_latency_p95_seconds", EnvVar: "KRYPTKEEPER_SLO_LATENCY_P95_SECONDS", Category: configCategorySLO, Secret: false},
	agentlessPrivilegeModeDef,
}

var configRegistryByKey = func() map[string]configKeyDef {
	m := make(map[string]configKeyDef, len(configRegistry))
	for _, def := range configRegistry {
		m[def.Key] = def
	}
	return m
}()

func lookupConfigKey(key string) (configKeyDef, bool) {
	def, ok := configRegistryByKey[key]
	return def, ok
}

// ConfigEntry is a raw DB-backed override row. Value is populated only for
// non-secret keys; a secret key's plaintext never leaves sealEnvelope/
// openEnvelope, and Value is always empty for it here too -- callers that
// need a secret's plaintext use ConfigStore.Resolve, never this struct.
type ConfigEntry struct {
	Key       string
	Value     string
	HasValue  bool
	UpdatedAt string
	UpdatedBy string
}

// EffectiveSetting is what the API surface returns: the registry metadata
// plus where the effective value currently comes from. Value is populated
// only when the key is not secret and a value (DB or env) is present --
// secret keys report Configured instead, never the plaintext (acceptance
// #2: "secrets write-only over the API").
type EffectiveSetting struct {
	Key        string `json:"key"`
	Category   string `json:"category"`
	EnvVar     string `json:"env_var"`
	Secret     bool   `json:"secret"`
	Source     string `json:"source"` // "database" | "env_default" | "unset"
	Value      string `json:"value,omitempty"`
	Configured bool   `json:"configured"`
	// EffectiveSource is "override" when a DB override supplies the value,
	// else "env" (W33-04). Source is kept unchanged for existing consumers.
	EffectiveSource string `json:"effective_source"`
	RestartRequired bool   `json:"restart_required,omitempty"`
	UpdatedAt       string `json:"updated_at,omitempty"`
	UpdatedBy       string `json:"updated_by,omitempty"`
}

const (
	configSourceDatabase   = "database"
	configSourceEnvDefault = "env_default"
	configSourceUnset      = "unset"
)

// ConfigStore persists DB overrides for the registered runtime settings
// (acceptance #1: env remains the bootstrap default, DB overrides at
// runtime). It stores exactly what was written -- resolving the effective
// value (DB override, else env default) is EffectiveSettings, not a store
// method, so the store stays a plain key/value CRUD surface like every
// other *_store.go in this package.
type ConfigStore interface {
	EnsureSchema(ctx context.Context) error
	// Get returns the DB override for key, if any. ok is false when no
	// override row exists (not an error) -- the caller falls back to the
	// env default. Value is populated only for non-secret keys.
	Get(ctx context.Context, key string) (entry ConfigEntry, ok bool, err error)
	// List returns every DB override row. Value is populated only for
	// non-secret keys -- secret rows come back with HasValue=true, Value="".
	List(ctx context.Context) ([]ConfigEntry, error)
	// Set upserts an override for key. Returns errConfigUnknownKey if key is
	// not in configRegistry. Encrypts value before persisting when the key
	// is registered secret.
	Set(ctx context.Context, key, value, updatedBy string) error
	// Delete removes an override, reverting the effective value to the env
	// default. Returns errConfigOverrideNotFound if no override existed.
	Delete(ctx context.Context, key string) error
	// Resolve decrypts and returns a secret key's plaintext DB override.
	// NOT for HTTP handlers -- see OutboundCredentialStore.Resolve's doc
	// comment for the same radioactive-key-material discipline; this exists
	// for a future internal consumer (e.g. an SMTP sender reading the DB
	// override instead of os.Getenv) to build against, matching
	// newOutboundCredentialStoreFromEnv's "implemented, not yet
	// instantiated" precedent (W5-10).
	Resolve(ctx context.Context, key string) ([]byte, error)
}

// EffectiveSettings merges configRegistry with store's DB overrides and each
// key's env default, in registry order. store may be nil (DB unavailable),
// in which case every key reports its env default (or unset) -- this never
// fails closed to an error, since the bootstrap-default behavior must keep
// working even when the config store itself is down.
func EffectiveSettings(ctx context.Context, store ConfigStore) ([]EffectiveSetting, error) {
	out := make([]EffectiveSetting, 0, len(configRegistry))
	for _, def := range configRegistry {
		setting := EffectiveSetting{
			Key:      def.Key,
			Category: def.Category,
			EnvVar:   def.EnvVar,
			Secret:   def.Secret,

			EffectiveSource: "env",
			RestartRequired: def.RestartRequired,
		}

		var override ConfigEntry
		var hasOverride bool
		if store != nil {
			entry, ok, err := store.Get(ctx, def.Key)
			if err != nil {
				return nil, fmt.Errorf("get %q: %w", def.Key, err)
			}
			override, hasOverride = entry, ok
		}

		envVal := strings.TrimSpace(os.Getenv(def.EnvVar))
		switch {
		case hasOverride:
			setting.Source = configSourceDatabase
			setting.EffectiveSource = "override"
			setting.Configured = true
			setting.UpdatedAt = override.UpdatedAt
			setting.UpdatedBy = override.UpdatedBy
			if !def.Secret {
				setting.Value = override.Value
			}
		case envVal != "":
			setting.Source = configSourceEnvDefault
			setting.Configured = true
			if !def.Secret {
				setting.Value = envVal
			}
		default:
			setting.Source = configSourceUnset
			setting.Configured = false
		}

		out = append(out, setting)
	}
	return out, nil
}

// runtimeConfigSchema mirrors migration 000030_runtime_config -- see G-33:
// every DB-backed store in this codebase self-heals its own schema since
// migrations are never actually run against a live deployment.
const runtimeConfigSchema = `
CREATE TABLE IF NOT EXISTS runtime_config (
    key         TEXT PRIMARY KEY,
    value       TEXT,
    envelope    TEXT,
    updated_at  TEXT NOT NULL,
    updated_by  TEXT
);`

// --- SQLite implementation ---

type sqliteConfigStore struct {
	db         *sql.DB
	passphrase []byte
}

func (s *sqliteConfigStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, runtimeConfigSchema)
	return err
}

func (s *sqliteConfigStore) Get(ctx context.Context, key string) (ConfigEntry, bool, error) {
	return scanConfigEntry(s.db.QueryRowContext(ctx, `
		SELECT key, value, updated_at, updated_by FROM runtime_config WHERE key = ?`, key))
}

func (s *sqliteConfigStore) List(ctx context.Context) ([]ConfigEntry, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT key, value, updated_at, updated_by FROM runtime_config ORDER BY key ASC`)
	if err != nil {
		return nil, err
	}
	return scanConfigEntryRows(rows)
}

func (s *sqliteConfigStore) Set(ctx context.Context, key, value, updatedBy string) error {
	return setConfigEntry(ctx, s.db, s.passphrase, `
		INSERT INTO runtime_config (key, value, envelope, updated_at, updated_by)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, envelope = excluded.envelope,
			updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
		key, value, updatedBy)
}

func (s *sqliteConfigStore) Delete(ctx context.Context, key string) error {
	return deleteConfigEntry(ctx, s.db, "DELETE FROM runtime_config WHERE key = ?", key)
}

func (s *sqliteConfigStore) Resolve(ctx context.Context, key string) ([]byte, error) {
	return resolveConfigEntry(ctx, s.db, s.passphrase, "SELECT envelope FROM runtime_config WHERE key = ?", key)
}

// --- Postgres implementation ---

type postgresConfigStore struct {
	db         *sql.DB
	passphrase []byte
}

func (s *postgresConfigStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, runtimeConfigSchema)
	return err
}

func (s *postgresConfigStore) Get(ctx context.Context, key string) (ConfigEntry, bool, error) {
	return scanConfigEntry(s.db.QueryRowContext(ctx, `
		SELECT key, value, updated_at, updated_by FROM runtime_config WHERE key = $1`, key))
}

func (s *postgresConfigStore) List(ctx context.Context) ([]ConfigEntry, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT key, value, updated_at, updated_by FROM runtime_config ORDER BY key ASC`)
	if err != nil {
		return nil, err
	}
	return scanConfigEntryRows(rows)
}

func (s *postgresConfigStore) Set(ctx context.Context, key, value, updatedBy string) error {
	return setConfigEntry(ctx, s.db, s.passphrase, `
		INSERT INTO runtime_config (key, value, envelope, updated_at, updated_by)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, envelope = excluded.envelope,
			updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
		key, value, updatedBy)
}

func (s *postgresConfigStore) Delete(ctx context.Context, key string) error {
	return deleteConfigEntry(ctx, s.db, "DELETE FROM runtime_config WHERE key = $1", key)
}

func (s *postgresConfigStore) Resolve(ctx context.Context, key string) ([]byte, error) {
	return resolveConfigEntry(ctx, s.db, s.passphrase, "SELECT envelope FROM runtime_config WHERE key = $1", key)
}

// --- shared helpers ---

// sloObjectiveBounds are the allowed ranges. The ratio upper bound (<1) and
// lower bound (>0.5) stop an operator from muting paging with an objective
// that can never be breached (or is always breached).
var sloObjectiveBounds = map[string]struct {
	lo, hi       float64
	loInc, hiInc bool
}{
	"slo.renewal_success_objective":    {0.5, 1, false, false},
	"slo.issuance_success_objective":   {0.5, 1, false, false},
	"slo.issuance_latency_p95_seconds": {0.01, 3600, true, true},
}

// validateConfigValue checks per-key value constraints; only slo.* keys are
// constrained today.
func validateConfigValue(key, value string) error {
	if key == configKeyAgentlessPrivilegeMode {
		return validateAgentlessPrivilegeMode(value)
	}
	b, ok := sloObjectiveBounds[key]
	if !ok {
		return nil
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	inRange := err == nil && !math.IsNaN(v) && !math.IsInf(v, 0) &&
		(v > b.lo || (b.loInc && v == b.lo)) && (v < b.hi || (b.hiInc && v == b.hi))
	if !inRange {
		return fmt.Errorf("must be a number between %g and %g", b.lo, b.hi)
	}
	return nil
}

func setConfigEntry(ctx context.Context, db *sql.DB, passphrase []byte, query, key, value, updatedBy string) error {
	def, ok := lookupConfigKey(key)
	if !ok {
		return errConfigUnknownKey
	}
	if len(value) > configValueMaxLen {
		return fmt.Errorf("value exceeds %d bytes", configValueMaxLen)
	}

	if err := validateConfigValue(key, value); err != nil {
		return err
	}

	if key == configKeyEscalationChannel {
		switch value {
		case "", "email", "slack", "pagerduty", "webhook":
		default:
			return errors.New("escalation channel must be one of email, slack, pagerduty, webhook or empty")
		}
	}

	var plainValue sql.NullString
	var envelope sql.NullString
	if def.Secret {
		sealed, err := sealEnvelope(passphrase, []byte(value))
		if err != nil {
			return fmt.Errorf("seal value: %w", err)
		}
		envelope = sql.NullString{String: sealed, Valid: true}
	} else {
		plainValue = sql.NullString{String: value, Valid: true}
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.ExecContext(ctx, query, key, plainValue, envelope, now, updatedBy)
	return err
}

func scanConfigEntry(row *sql.Row) (ConfigEntry, bool, error) {
	var e ConfigEntry
	var value, updatedBy sql.NullString
	err := row.Scan(&e.Key, &value, &e.UpdatedAt, &updatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return ConfigEntry{}, false, nil
	}
	if err != nil {
		return ConfigEntry{}, false, err
	}
	e.Value = value.String
	e.HasValue = value.Valid
	e.UpdatedBy = updatedBy.String
	return e, true, nil
}

func scanConfigEntryRows(rows *sql.Rows) ([]ConfigEntry, error) {
	defer rows.Close()
	items := []ConfigEntry{}
	for rows.Next() {
		var e ConfigEntry
		var value, updatedBy sql.NullString
		if err := rows.Scan(&e.Key, &value, &e.UpdatedAt, &updatedBy); err != nil {
			return nil, err
		}
		e.Value = value.String
		e.HasValue = value.Valid
		e.UpdatedBy = updatedBy.String
		items = append(items, e)
	}
	return items, rows.Err()
}

func deleteConfigEntry(ctx context.Context, db *sql.DB, query, key string) error {
	res, err := db.ExecContext(ctx, query, key)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errConfigOverrideNotFound
	}
	return nil
}

func resolveConfigEntry(ctx context.Context, db *sql.DB, passphrase []byte, query, key string) ([]byte, error) {
	def, ok := lookupConfigKey(key)
	if !ok {
		return nil, errConfigUnknownKey
	}
	if !def.Secret {
		return nil, fmt.Errorf("config key %q is not secret; use Get", key)
	}
	var envelope sql.NullString
	err := db.QueryRowContext(ctx, query, key).Scan(&envelope)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !envelope.Valid) {
		return nil, errConfigOverrideNotFound
	}
	if err != nil {
		return nil, err
	}
	return openEnvelope(passphrase, envelope.String)
}

// newConfigStoreFromEnv opens the runtime_config store and ensures its
// schema exists (G-33). Returns nil on any failure -- nil-tolerant,
// matching every other newXFromEnv in this package. Reuses
// outboundCredentialPassphraseFromEnv: both stores encrypt app-boundary
// secrets at rest with the same Argon2id+AES-256-GCM envelope, so sharing
// the passphrase resolution is the existing convention, not a new coupling.
func newConfigStoreFromEnv() ConfigStore {
	passphrase := outboundCredentialPassphraseFromEnv()
	if len(passphrase) == 0 {
		// Fail closed: an empty passphrase still "encrypts" secret settings
		// (Argon2id derives a key from "" same as any string), leaving them
		// decryptable by anyone with the DB and no secret at all -- exactly
		// what acceptance #2's write-only guarantee exists to prevent.
		_ = dbProviderUnavailable("runtime-config", fmt.Errorf("APP_CREDENTIAL_STORE_PASSPHRASE or KRYPTKEEPER_KEYSTORE_PASSPHRASE must be set")) // logs the outage itself; return value is the same sentinel
		return nil
	}
	state := newDBProviderState[ConfigStore](
		"runtime-config",
		func() (string, error) {
			return resolveSQLiteDSNFromEnv("APP_CONFIG_DB_DSN", "KRYPTKEEPER_DATA_DIR", "kryptkeeper.db")
		},
		func() string {
			return resolvePostgresDSNFromEnv("APP_CONFIG_DB_DSN", "KRYPTKEEPER_DB_DSN", "DATABASE_URL")
		},
		fmt.Errorf("postgres mode requires APP_CONFIG_DB_DSN, KRYPTKEEPER_DB_DSN, or DATABASE_URL"),
		func(db *sql.DB) ConfigStore {
			return &sqliteConfigStore{db: db, passphrase: passphrase}
		},
		func(db *sql.DB) ConfigStore {
			return &postgresConfigStore{db: db, passphrase: passphrase}
		},
	)
	if state.openErr != nil || state.store == nil {
		_ = dbProviderUnavailable("runtime-config", state.openErr) // logs the outage itself; return value is the same sentinel
		return nil
	}
	if err := state.store.EnsureSchema(context.Background()); err != nil {
		_ = dbProviderUnavailable("runtime-config", err) // logs the outage itself; return value is the same sentinel
		return nil
	}
	return state.store
}

// ssoLockoutGuardedKeys are the OIDC keys whose override can lock out every
// IdP login; a PUT of one is refused unless a break-glass local admin exists
// (W33-06, auth_config.go ssoOverrideGuard).
var ssoLockoutGuardedKeys = map[string]bool{
	"sso.oidc_issuer":        true,
	"sso.oidc_audience":      true,
	"sso.oidc_discovery_url": true,
	"sso.oidc_jwks_json":     true,
}

// WebhookSigning is the resolved webhook HMAC configuration.
type WebhookSigning struct {
	Secret, Previous string
	PreviousUntil    time.Time
}

// webhookPreviousWindow is how long the previous secret keeps co-signing.
const webhookPreviousWindow = 24 * time.Hour

// ResolveWebhookSigning reads the signing secret and the rotation secret from
// the store (falling back to env). The previous secret's window starts when it
// was stored; an env-only previous secret has no timestamp, so the window
// starts at envSince (process start).
func ResolveWebhookSigning(ctx context.Context, store ConfigStore, envSince time.Time) WebhookSigning {
	resolve := func(key, envVar string) (string, bool) {
		if store != nil {
			if v, err := store.Resolve(ctx, key); err == nil {
				return string(v), true
			}
		}
		return strings.TrimSpace(os.Getenv(envVar)), false
	}
	var out WebhookSigning
	out.Secret, _ = resolve("notifications.webhook_secret", "WEBHOOK_SECRET")
	var fromStore bool
	out.Previous, fromStore = resolve("notifications.webhook_secret_previous", "WEBHOOK_SECRET_PREVIOUS")
	if out.Previous == "" {
		return out
	}
	since := envSince
	if fromStore {
		if entry, ok, err := store.Get(ctx, "notifications.webhook_secret_previous"); err == nil && ok {
			if t, perr := time.Parse(time.RFC3339, entry.UpdatedAt); perr == nil {
				since = t
			}
		}
	}
	out.PreviousUntil = since.Add(webhookPreviousWindow)
	return out
}
