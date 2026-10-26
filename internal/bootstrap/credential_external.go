// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

// External credentials (W38-07, D-324). The row holds a reference; Resolve
// fetches the secret from the source's manager for each use, assembles the
// payload the consuming credential type expects, validates it, audits the
// attempt (never the value) and hands the bytes to the caller, which zeroizes
// them like any other credential plaintext.
//
// Honest limits: the bytes this file builds and the HTTP body it reads are
// wiped, but a Go string cannot be zeroized, so the values a plugin returns
// and the decoded KV strings live in the garbage collector's hands until it
// frees them. That is why the default is to fetch every time and keep nothing.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"kryptkeeper/internal/connectors"
	"kryptkeeper/internal/logging"
	plugindelivery "kryptkeeper/internal/plugins/delivery"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
)

// ExternalReference says where in the manager an external credential's secret
// is, and the non-secret fields that complete its payload.
type ExternalReference struct {
	// Reference is the manager-specific locator. vault_kv2: "path" (relative
	// to the source's mount) and optionally "version". plugin: the plugin's
	// own keys (CyberArk "safe"/"object", Secret Server "secret_id"), and
	// "map" to rename the manager's fields onto the payload's.
	Reference map[string]string `json:"reference"`
	// Static are fixed, non-secret payload fields the manager does not hold
	// (an SSH host_public_key, a WinRM base_url). Secret-looking names are
	// refused: the hub never stores a secret for an external credential.
	Static map[string]string `json:"static,omitempty"`
}

// secretFieldName spots field names that carry a secret. "secret_name" (a
// Kubernetes TLS secret's name) is configuration, so a bare "secret" is matched
// only as the field or as secret_key, secret_value or secret_id.
var secretFieldName = regexp.MustCompile(`(?i)(password|passphrase|token|private|api[_-]?key|key_pem|credential|(^|_)secret($|_key|_value|_id))`)

const (
	maxReferenceKeys  = 16
	maxReferenceValue = 512
)

// validate checks the reference for a source kind before it is stored.
func (r ExternalReference) validate(kind string) error {
	if len(r.Reference) == 0 || len(r.Reference) > maxReferenceKeys || len(r.Static) > maxReferenceKeys {
		return fmt.Errorf("reference needs 1..%d keys and static at most %d", maxReferenceKeys, maxReferenceKeys)
	}
	for _, m := range []map[string]string{r.Reference, r.Static} {
		for k, v := range m {
			if k == "" || len(k) > 64 || len(v) > maxReferenceValue {
				return errors.New("reference and static keys are 1..64 characters and values at most 512")
			}
		}
	}
	for k := range r.Static {
		if secretFieldName.MatchString(k) {
			return fmt.Errorf("static field %q looks like a secret; fetch it from the source instead", k)
		}
	}
	if kind == CredentialSourceVaultKV2 {
		p := strings.Trim(r.Reference["path"], "/")
		if p == "" || strings.Contains(p, "..") || strings.Contains(p, "//") {
			return errors.New("reference.path is required (the secret's path under the mount, e.g. ssh/web1)")
		}
		if v := r.Reference["version"]; v != "" {
			if n, err := strconv.Atoi(v); err != nil || n < 0 {
				return errors.New("reference.version must be a whole number (0 or absent reads the latest)")
			}
		}
		for k := range r.Reference {
			if k != "path" && k != "version" {
				return fmt.Errorf("reference.%s is not a vault_kv2 key (path, version)", k)
			}
		}
	}
	return nil
}

// CredentialResolveError is a failed external fetch. Class is the audit
// vocabulary; the message is safe to show a caller: it never carries a secret.
type CredentialResolveError struct {
	Class string
	Msg   string
}

func (e *CredentialResolveError) Error() string { return e.Msg }

func resolveErr(class, format string, a ...any) *CredentialResolveError {
	return &CredentialResolveError{Class: class, Msg: fmt.Sprintf(format, a...)}
}

// Audit classes for credential.resolve failures.
const (
	resolveClassNotFound    = "not_found"
	resolveClassDenied      = "denied"
	resolveClassUnavailable = "source_unavailable"
	resolveClassInvalid     = "invalid_payload"
	resolveClassConfig      = "config"
	resolveClassRateLimited = "rate_limited"
	resolveClassAuth        = "login_failed"
)

// resolveFailure is the caller-facing error for a failed Resolve: an external
// credential's failure carries its clear reason (which source, what it said),
// while a local one keeps the plain text it always had.
func resolveFailure(ref string, err error) error {
	var re *CredentialResolveError
	if errors.As(err, &re) {
		return fmt.Errorf("credential %q could not be resolved: %s", ref, re.Msg)
	}
	return fmt.Errorf("credential %q could not be resolved", ref)
}

// credentialAuditSink is the audit trail credential.resolve rows go to. The
// stores are built from the environment in about twenty places and none of
// them holds an AuditProvider, so the hub registers it once at startup, the
// way the HA failover observer is. Nil (tests, tools) writes no row.
var credentialAuditSink atomic.Pointer[AuditProvider]

// SetCredentialAuditProvider registers where credential.resolve rows go.
func SetCredentialAuditProvider(p AuditProvider) {
	if p == nil {
		credentialAuditSink.Store(nil)
		return
	}
	credentialAuditSink.Store(&p)
}

type localCredentialReader interface {
	resolveLocalOnly(ctx context.Context, id string) ([]byte, error)
	Get(ctx context.Context, id string) (OutboundCredentialMeta, error)
}

// externalCredentialResolver fetches external credentials. One per store.
type externalCredentialResolver struct {
	sources CredentialSourceStore
	local   localCredentialReader
	// plugins yields the manager that runs credentials plugins; nil result
	// means plugins are off.
	plugins func() *DeliveryPluginManager
	// vaultClient builds the egress-guarded client for a Vault source; a test
	// seam, production uses upstreamConnectorMTLSClient.
	vaultClient func(cfg CredentialSourceConfig) (*http.Client, error)
	// pluginClient replaces the guarded device client for plugin sources; a
	// test seam, nil in production.
	pluginClient *http.Client
	audit        func(ctx context.Context, e AuditEntry)
	now          func() time.Time

	mu    sync.Mutex
	cache map[string]cachedCredential
}

type cachedCredential struct {
	payload []byte
	expires time.Time
}

func newExternalCredentialResolver(sources CredentialSourceStore, local localCredentialReader, plugins func() *DeliveryPluginManager) *externalCredentialResolver {
	return &externalCredentialResolver{sources: sources, local: local, plugins: plugins, now: time.Now, cache: map[string]cachedCredential{}}
}

// externalRow is the part of an outbound_credentials row external resolution
// needs.
type externalRow struct {
	ID, Type, Tenant, SourceID string
	Ref                        ExternalReference
}

// resolve returns the payload for one external credential.
func (r *externalCredentialResolver) resolve(ctx context.Context, row externalRow) ([]byte, error) {
	payload, cached, kind, err := r.fetch(ctx, row)
	r.record(ctx, row, kind, cached, err)
	return payload, err
}

func (r *externalCredentialResolver) fetch(ctx context.Context, row externalRow) (payload []byte, cached bool, kind string, err error) {
	if r.sources == nil {
		return nil, false, "", resolveErr(resolveClassConfig, "credential sources are not available: the hub has no database for them")
	}
	src, err := r.sources.Get(ctx, row.SourceID)
	if err != nil {
		return nil, false, "", resolveErr(resolveClassConfig, "credential source %q not found; it may have been deleted", row.SourceID)
	}
	kind = src.Kind
	// A source belongs to one tenant, like credentials do: an external
	// credential may only use a source of its own tenant.
	if normalizeTenant(src.Tenant) != normalizeTenant(row.Tenant) {
		return nil, false, kind, resolveErr(resolveClassConfig, "credential source %q belongs to another tenant", src.ID)
	}
	if p, ok := r.cacheGet(row.ID); ok {
		return p, true, kind, nil
	}
	var fields map[string]string
	var lease int
	switch src.Kind {
	case CredentialSourceVaultKV2:
		fields, err = r.fetchVault(ctx, src, row.Ref)
	case CredentialSourcePlugin:
		fields, lease, err = r.fetchPlugin(ctx, src, row.Ref)
	default:
		err = resolveErr(resolveClassConfig, "credential source %q has unknown kind %q", src.ID, src.Kind)
	}
	if err != nil {
		return nil, false, kind, err
	}
	payload, err = assemblePayload(row.Type, fields, row.Ref.Static)
	if err != nil {
		return nil, false, kind, resolveErr(resolveClassInvalid, "the secret fetched from %s does not fit a %s credential: %v", src.Name, row.Type, err)
	}
	r.cachePut(row.ID, payload, src.Config.CacheTTLSeconds, lease)
	return payload, false, kind, nil
}

// testExternalCredential runs a full fetch and assembly for a reference that
// is not stored, so an operator can see it work before relying on it. Only the
// payload's field names leave; the payload is zeroized here. The attempt is
// audited like any other resolve, under a "test:" resource id.
func testExternalCredential(ctx context.Context, r *externalCredentialResolver, sourceID, tenant, credentialType string, ref ExternalReference) ([]string, error) {
	if err := validateCredentialType(credentialType); err != nil {
		return nil, err
	}
	payload, err := r.resolve(ctx, externalRow{ID: "test:" + sourceID, Type: credentialType, Tenant: tenant, SourceID: sourceID, Ref: ref})
	if err != nil {
		return nil, err
	}
	defer zeroize(payload)
	var obj map[string]any
	if json.Unmarshal(payload, &obj) != nil {
		return []string{"value"}, nil // a raw api_token string
	}
	names := make([]string, 0, len(obj))
	for k := range obj {
		names = append(names, k)
	}
	sort.Strings(names)
	return names, nil
}

// --- cache (opt-in, short) ---

func (r *externalCredentialResolver) cacheGet(id string) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.cache[id]
	if !ok {
		return nil, false
	}
	if !r.now().Before(c.expires) {
		zeroize(c.payload)
		delete(r.cache, id)
		return nil, false
	}
	return append([]byte(nil), c.payload...), true
}

func (r *externalCredentialResolver) cachePut(id string, payload []byte, ttlSeconds, leaseSeconds int) {
	if ttlSeconds <= 0 {
		return
	}
	if leaseSeconds > 0 {
		ttlSeconds = min(ttlSeconds, leaseSeconds)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.cache[id]; ok {
		zeroize(old.payload)
	}
	r.cache[id] = cachedCredential{payload: append([]byte(nil), payload...), expires: r.now().Add(time.Duration(ttlSeconds) * time.Second)}
}

// --- vault_kv2 ---

// vaultLogin is the api_token credential that logs in to Vault or OpenBao.
type vaultLogin struct {
	Token    string `json:"token"`
	RoleID   string `json:"role_id"`
	SecretID string `json:"secret_id"`
}

func (r *externalCredentialResolver) fetchVault(ctx context.Context, src CredentialSource, ref ExternalReference) (map[string]string, error) {
	raw, err := r.local.resolveLocalOnly(ctx, src.CredentialRef)
	if err != nil {
		return nil, resolveErr(resolveClassConfig, "credential source %q: its login credential %q could not be read: %v", src.Name, src.CredentialRef, err)
	}
	defer zeroize(raw)
	var login vaultLogin
	if err := json.Unmarshal(raw, &login); err != nil || (login.Token == "" && (login.RoleID == "" || login.SecretID == "")) {
		return nil, resolveErr(resolveClassConfig, `credential source %q: login credential %q must be JSON with "token", or "role_id" and "secret_id"`, src.Name, src.CredentialRef)
	}
	mk := r.vaultClient
	if mk == nil {
		mk = defaultVaultClient
	}
	client, err := mk(src.Config)
	if err != nil {
		return nil, resolveErr(resolveClassConfig, "credential source %q: %v", src.Name, err)
	}
	version, _ := strconv.Atoi(ref.Reference["version"])
	mount := strings.Trim(src.Config.Mount, "/")
	if mount == "" {
		mount = "secret"
	}
	api := &connectors.VaultAPI{
		Label: "vault_kv2", BaseURL: src.Config.BaseURL, Namespace: src.Config.Namespace,
		Token: login.Token, RoleID: login.RoleID, SecretID: login.SecretID, AppRoleMount: src.Config.AppRoleMount, Client: client,
	}
	secret, err := api.ReadKV2(ctx, mount, ref.Reference["path"], version)
	switch {
	case errors.Is(err, connectors.ErrKV2NotFound):
		return nil, resolveErr(resolveClassNotFound, "%s: nothing at %s/%s%s (missing path, deleted or destroyed version)", src.Name, mount, strings.Trim(ref.Reference["path"], "/"), versionNote(version))
	case errors.Is(err, connectors.ErrKV2Denied):
		return nil, resolveErr(resolveClassDenied, "%s denied reading %s/%s: the login has no read policy on that path", src.Name, mount, strings.Trim(ref.Reference["path"], "/"))
	case err != nil:
		var rl *connectors.RateLimitError
		if errors.As(err, &rl) {
			return nil, resolveErr(resolveClassRateLimited, "%s is rate limiting this hub", src.Name)
		}
		class := resolveClassUnavailable
		if strings.Contains(err.Error(), "approle login failed") {
			class = resolveClassAuth
		}
		return nil, resolveErr(class, "%s could not be read: %v", src.Name, err)
	}
	out := make(map[string]string, len(secret.Data))
	for k, v := range secret.Data {
		switch t := v.(type) {
		case string:
			out[k] = t
		case float64:
			out[k] = strconv.FormatFloat(t, 'f', -1, 64)
		case bool:
			out[k] = strconv.FormatBool(t)
		default:
			return nil, resolveErr(resolveClassInvalid, "%s: field %q is not a string, number or boolean", src.Name, k)
		}
	}
	return out, nil
}

func versionNote(v int) string {
	if v > 0 {
		return fmt.Sprintf(" version %d", v)
	}
	return ""
}

// defaultVaultClient is the egress-guarded client for a Vault source:
// https is required (the login and the secret ride on every request), proxies
// and cross-host redirects are refused, private space is reachable unless the
// operator denies it, and a pinned CA replaces the system roots.
func defaultVaultClient(cfg CredentialSourceConfig) (*http.Client, error) {
	_, roots, err := connectors.TLSMaterial("", "", cfg.CACertPEM)
	if err != nil {
		return nil, err
	}
	return upstreamConnectorMTLSClient(30*time.Second, true, nil, roots), nil
}

// --- plugin ---

func (r *externalCredentialResolver) fetchPlugin(ctx context.Context, src CredentialSource, ref ExternalReference) (map[string]string, int, error) {
	var mgr *DeliveryPluginManager
	if r.plugins != nil {
		mgr = r.plugins()
	}
	if mgr == nil {
		return nil, 0, resolveErr(resolveClassConfig, "credential source %q uses a plugin, and plugins are off", src.Name)
	}
	p, v, err := mgr.Enabled(ctx, src.Config.PluginID)
	if err != nil {
		return nil, 0, resolveErr(resolveClassConfig, "credential source %q: plugin %q is not an enabled plugin", src.Name, src.Config.PluginID)
	}
	if v.Kind != abi.KindCredentials {
		return nil, 0, resolveErr(resolveClassConfig, "credential source %q: plugin %q is a %s plugin, not a credentials plugin", src.Name, v.PluginID, v.Kind)
	}
	env, err := buildPluginEnv(ctx, localCredentialStoreView{r.local}, r.pluginClient, v, src.CredentialRef, nil)
	if err != nil {
		return nil, 0, resolveErr(resolveClassConfig, "credential source %q: %v", src.Name, err)
	}
	env.Timeout = 30 * time.Second
	env.Events = func(e plugindelivery.Event) {
		switch e.Kind {
		case "refused":
			r.appendAudit(ctx, AuditEntry{Action: "delivery_plugin.refused", ResourceType: "delivery_plugin", ResourceID: v.PluginID,
				Outcome: AuditOutcomeDenied, ChangeSummary: fmt.Sprintf("kind=credentials version=%s %s", v.Version, e.Detail)})
		case "log":
			logging.Infof("credentials plugin %s: %s", v.PluginID, e.Detail)
		}
	}
	res, err := p.CredentialsGet(ctx, env, ref.Reference)
	if err != nil {
		return nil, 0, resolveErr(pluginErrClass(err), "%s (plugin %s) could not provide the credential: %v", src.Name, v.PluginID, err)
	}
	return res.Fields, res.LeaseSeconds, nil
}

func pluginErrClass(err error) string {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "no such") || strings.Contains(msg, "not found") || strings.Contains(msg, " 404"):
		return resolveClassNotFound
	case strings.Contains(msg, "denied") || strings.Contains(msg, "not authorised") || strings.Contains(msg, "may not view") || strings.Contains(msg, " 403"):
		return resolveClassDenied
	case strings.Contains(msg, "could not log in") || strings.Contains(msg, "token was refused"):
		return resolveClassAuth
	}
	return resolveClassUnavailable
}

// localCredentialStoreView adapts the local reader to the OutboundCredentialStore
// buildPluginEnv takes, restricted to what it calls (Get and Resolve), and
// refusing a source login that is itself external, which would loop.
type localCredentialStoreView struct{ localCredentialReader }

func (v localCredentialStoreView) Resolve(ctx context.Context, id string) ([]byte, error) {
	return v.resolveLocalOnly(ctx, id)
}
func (localCredentialStoreView) EnsureSchema(context.Context) error { return nil }
func (localCredentialStoreView) Create(context.Context, string, string, string, string, []byte) (OutboundCredentialMeta, error) {
	return OutboundCredentialMeta{}, errors.New("read-only view")
}
func (localCredentialStoreView) List(context.Context) ([]OutboundCredentialMeta, error) {
	return nil, errors.New("read-only view")
}
func (localCredentialStoreView) Delete(context.Context, string) error {
	return errors.New("read-only view")
}

// --- audit ---

func (r *externalCredentialResolver) record(ctx context.Context, row externalRow, kind string, cached bool, err error) {
	outcome, detail := AuditOutcomeSuccess, "outcome=ok"
	if err != nil {
		outcome = AuditOutcomeFailure
		class := resolveClassUnavailable
		var re *CredentialResolveError
		if errors.As(err, &re) {
			class = re.Class
		}
		detail = "outcome=error class=" + class
	}
	if cached {
		detail += " cached=true"
	}
	summary := fmt.Sprintf("source=%s:%s credential_type=%s %s", kind, row.SourceID, row.Type, detail)
	r.appendAudit(ctx, AuditEntry{Action: "credential.resolve", ResourceType: "credential", ResourceID: row.ID,
		Outcome: outcome, ChangeSummary: summary, Tenant: row.Tenant})
}

func (r *externalCredentialResolver) appendAudit(ctx context.Context, e AuditEntry) {
	e.Timestamp = r.now().UTC().Format(time.RFC3339)
	e.ActorType, e.ActorID = "system", "credential-resolver"
	if r.audit != nil {
		r.audit(ctx, e)
		return
	}
	p := credentialAuditSink.Load()
	if p == nil {
		return
	}
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditAppendTimeout)
	defer cancel()
	if err := (*p).AppendEntry(actx, e); err != nil {
		logging.Errorf("audit append failed action=%s resource_id=%s: %v", e.Action, e.ResourceID, err)
	}
}
