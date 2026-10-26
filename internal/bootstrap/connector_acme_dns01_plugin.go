// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

// W38-08, D-325: dns-01 through a signed dns01 plugin. An ACME connector with
// dns_provider "plugin" names a plugin (dns_plugin_id) and the outbound
// credential holding that plugin's credential fields (dns_plugin_credential,
// an api_token credential: the same mechanism delivery and notify plugins
// use). The plugin only writes and deletes the TXT record. Propagation is
// checked by the hub's own resolvers (connector_acme_dnscheck.go) and the CA
// validates, so a plugin can neither make a challenge pass nor see anything
// but the record name, the digest and its own credential.
//
// The plugin manager is process-wide and reaches the connector the way the
// shared DCV tracker does (sharedDCVTracker): connectors are rebuilt from
// stored rows at six call sites, none of which has the manager, and the
// manager is resolved per call so plugins turned off fail closed.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"kryptkeeper/internal/logging"
	plugindelivery "kryptkeeper/internal/plugins/delivery"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
)

// dnsPluginTimeout bounds one present or cleanup call, vendor lookups
// included; the challenge waits behind it, so it is short.
const dnsPluginTimeout = 30 * time.Second

// dnsPluginTTL is the TTL asked of the provider; plugins raise it to the
// provider's own minimum.
const dnsPluginTTL = 60

// dnsPluginHost is what a plugin-backed provider needs from the process.
type dnsPluginHost struct {
	plugins func() *DeliveryPluginManager
	audit   AuditProvider
	client  *http.Client // nil: the guarded device client (egress policy applies)
}

var sharedDNSPluginHost atomic.Pointer[dnsPluginHost]

// SetDNSPluginHost wires the plugin manager and audit log into ACME dns-01
// plugin providers. main calls it once at startup; without it a connector
// using dns_provider "plugin" fails closed.
func SetDNSPluginHost(plugins func() *DeliveryPluginManager, audit AuditProvider) {
	sharedDNSPluginHost.Store(&dnsPluginHost{plugins: plugins, audit: audit})
}

func init() {
	// The registry entry makes "plugin" a valid dns_provider name; the
	// provider itself needs the connector's credential store and tenant, so
	// acmeIssuerConnector.dnsProvider builds it.
	registerDNSProvider("plugin", func(acmeConnectorConfig, acmeCredentialPayload) (dnsProvider, error) {
		return nil, errors.New("acme connector dns_provider plugin is built by the connector")
	})
}

// validateDNSPluginConfig is the connector-create check for dns_provider
// "plugin". Whether the plugin is installed, enabled and a dns01 plugin is
// checked when it is used: it can be enabled after the connector exists.
func validateDNSPluginConfig(cfg acmeConnectorConfig) error {
	if strings.TrimSpace(cfg.DNSPluginID) == "" || strings.TrimSpace(cfg.DNSPluginCredential) == "" {
		return errors.New("dns_provider plugin needs dns_plugin_id (an enabled dns01 plugin) and dns_plugin_credential (the outbound credential holding its fields)")
	}
	return nil
}

// pluginDNS is a dnsProvider backed by a dns01 plugin.
type pluginDNS struct {
	host     *dnsPluginHost
	creds    OutboundCredentialStore
	connID   string
	tenant   string
	pluginID string
	credRef  string
}

func (c *acmeIssuerConnector) newPluginDNS() (dnsProvider, error) {
	if err := validateDNSPluginConfig(c.cfg); err != nil {
		return nil, fmt.Errorf("acme connector: %w", err)
	}
	host := c.dnsPluginHost
	if host == nil {
		host = sharedDNSPluginHost.Load()
	}
	if host == nil || host.plugins == nil {
		return nil, errPluginsOff
	}
	return &pluginDNS{
		host: host, creds: c.creds, connID: c.id, tenant: c.tenant,
		pluginID: strings.TrimSpace(c.cfg.DNSPluginID), credRef: strings.TrimSpace(c.cfg.DNSPluginCredential),
	}, nil
}

// resolve returns the enabled dns01 plugin and an environment carrying the
// credential, refusing a credential another tenant owns.
func (p *pluginDNS) resolve(ctx context.Context) (*plugindelivery.Plugin, DeliveryPluginVersion, plugindelivery.Env, error) {
	mgr := p.host.plugins()
	if mgr == nil {
		return nil, DeliveryPluginVersion{}, plugindelivery.Env{}, errPluginsOff
	}
	plug, v, err := mgr.Enabled(ctx, p.pluginID)
	if err != nil {
		return nil, v, plugindelivery.Env{}, fmt.Errorf("dns-01 plugin %q: %w", p.pluginID, err)
	}
	if v.Kind != abi.KindDNS01 {
		return nil, v, plugindelivery.Env{}, fmt.Errorf("plugin %q is a %s plugin, not a dns01 plugin", p.pluginID, v.Kind)
	}
	if p.creds == nil {
		return nil, v, plugindelivery.Env{}, errors.New("outbound credential store not configured (set APP_CREDENTIAL_STORE_PASSPHRASE or KRYPTKEEPER_KEYSTORE_PASSPHRASE)")
	}
	meta, err := p.creds.Get(ctx, p.credRef)
	if err != nil || normalizeTenant(meta.Tenant) != normalizeTenant(p.tenant) {
		// One message for "missing" and "someone else's": a connector must
		// not learn that another tenant's credential exists.
		return nil, v, plugindelivery.Env{}, fmt.Errorf("credential %q does not exist", p.credRef)
	}
	env, err := buildPluginEnv(ctx, p.creds, p.host.client, v, p.credRef, nil)
	if err != nil {
		return nil, v, env, err
	}
	env.Timeout = dnsPluginTimeout
	return plug, v, env, nil
}

func normalizeTenant(t string) string {
	if t == "" {
		return DefaultTenant
	}
	return t
}

// events audits calls the sandbox refused and keeps plugin log lines.
func (p *pluginDNS) events(ctx context.Context, v DeliveryPluginVersion, refused *int) func(plugindelivery.Event) {
	return func(e plugindelivery.Event) {
		switch e.Kind {
		case "refused":
			*refused++
			p.audit(ctx, "delivery_plugin.refused", v, AuditOutcomeDenied, e.Detail)
		case "log":
			logging.Infof("dns01 plugin %s: %s", v.PluginID, e.Detail)
		}
	}
}

func (p *pluginDNS) audit(ctx context.Context, action string, v DeliveryPluginVersion, outcome AuditOutcome, detail string) {
	if p.host.audit == nil {
		return
	}
	if err := p.host.audit.AppendEntry(context.WithoutCancel(ctx), AuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339), Action: action, ActorType: "system", ActorID: "acme:" + p.connID,
		ResourceType: "delivery_plugin", ResourceID: v.PluginID, Outcome: outcome,
		ChangeSummary: fmt.Sprintf("kind=dns01 version=%s sha256=%s %s", v.Version, v.SHA256, detail),
	}); err != nil {
		logging.Warnf("audit append failed action=%s: %v", action, err)
	}
}

// Present publishes the record and returns the zone the plugin reported, for
// the hub's propagation check, and a cleanup that removes it.
func (p *pluginDNS) Present(ctx context.Context, fqdn, value string) (string, func(context.Context) error, error) {
	plug, v, env, err := p.resolve(ctx)
	if err != nil {
		return "", nil, err
	}
	refused := 0
	env.Events = p.events(ctx, v, &refused)
	res, err := plug.DNS01Present(ctx, env, fqdn, value, dnsPluginTTL)
	outcome := AuditOutcomeSuccess
	if err != nil {
		outcome = AuditOutcomeFailure
	}
	p.audit(ctx, "delivery_plugin.dns01_present", v, outcome, fmt.Sprintf("fqdn=%s zone=%s refused_calls=%d", fqdn, res.Zone, refused))
	if err != nil {
		return "", nil, fmt.Errorf("dns-01 plugin %s: %w", v.PluginID, err)
	}
	cleanup := func(ctx context.Context) error {
		plug, v, env, err := p.resolve(ctx)
		if err != nil {
			return err
		}
		refused := 0
		env.Events = p.events(ctx, v, &refused)
		err = plug.DNS01Cleanup(ctx, env, fqdn, value, res.RecordID)
		outcome := AuditOutcomeSuccess
		if err != nil {
			outcome = AuditOutcomeFailure
		}
		p.audit(ctx, "delivery_plugin.dns01_cleanup", v, outcome, fmt.Sprintf("fqdn=%s refused_calls=%d", fqdn, refused))
		if err != nil {
			return fmt.Errorf("dns-01 plugin %s cleanup: %w", v.PluginID, err)
		}
		return nil
	}
	return res.Zone, cleanup, nil
}
