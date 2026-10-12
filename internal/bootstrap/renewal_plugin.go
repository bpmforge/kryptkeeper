// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

// Renewal through delivery plugins (W20-20): install_mode "plugin" targets
// push renewed material through their enabled plugin, sandboxed, with the
// hub's own verify and rollback (internal/plugins/delivery.Deliver).

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"kryptkeeper/internal/agentinstall"
	"kryptkeeper/internal/plugins/delivery"
)

// WithPluginDeliverer arms install_mode "plugin" targets with the process's
// plugin manager; audit receives one row per plugin run and per refused
// host call. A nil manager (plugins off) makes plugin targets fail plainly.
func (e *RenewalExecutor) WithPluginDeliverer(m *DeliveryPluginManager, audit AuditProvider) *RenewalExecutor {
	e.plugins = m
	e.pluginAudit = audit
	return e
}

// pluginRun is a plugin, the version that runs, and the environment one
// target gives it.
type pluginRun struct {
	plugin  *delivery.Plugin
	version DeliveryPluginVersion
	env     delivery.Env
}

// preparePlugin resolves the target's enabled plugin and its credential,
// and checks both against the plugin's schemas (D-119): required fields
// present, defaults applied, and nothing the schema does not name handed
// to the plugin.
func (e *RenewalExecutor) preparePlugin(ctx context.Context, target ManagedTarget) (pluginRun, error) {
	if e.plugins == nil {
		return pluginRun{}, errPluginsOff
	}
	p, v, err := e.plugins.Enabled(ctx, target.PluginID)
	if err != nil {
		return pluginRun{}, fmt.Errorf("delivery plugin %q: %w", target.PluginID, err)
	}
	if v.Manifest.Capabilities.RemoteExec {
		return pluginRun{}, fmt.Errorf("delivery plugin %q needs remote_exec, which plugin targets do not support yet", target.PluginID)
	}
	if strings.TrimSpace(target.CredentialRef) == "" {
		return pluginRun{}, errRenewalNoCredential
	}
	if e.creds == nil {
		return pluginRun{}, errors.New("outbound credential store not configured (set APP_CREDENTIAL_STORE_PASSPHRASE or KRYPTKEEPER_KEYSTORE_PASSPHRASE)")
	}
	meta, err := e.creds.Get(ctx, target.CredentialRef)
	if err != nil {
		return pluginRun{}, fmt.Errorf("credential %q: %w", target.CredentialRef, err)
	}
	if meta.CredentialType != CredentialTypeAPIToken {
		return pluginRun{}, fmt.Errorf("%w: plugin targets need an %s credential holding a JSON object of the plugin's credential fields; %q is %s",
			errRenewalBadCredential, CredentialTypeAPIToken, target.CredentialRef, meta.CredentialType)
	}
	plaintext, err := e.creds.Resolve(ctx, target.CredentialRef)
	if err != nil {
		return pluginRun{}, fmt.Errorf("credential %q: %w", target.CredentialRef, err)
	}
	defer zeroize(plaintext)
	var raw map[string]string
	if err := json.Unmarshal(plaintext, &raw); err != nil {
		return pluginRun{}, fmt.Errorf("%w: credential %q is not a JSON object of string fields", errRenewalBadCredential, target.CredentialRef)
	}

	client, err := pluginHTTPClient(e.pushClient, raw[credentialFieldTLSCA])
	if err != nil {
		return pluginRun{}, fmt.Errorf("%w: credential %q: %v", errRenewalBadCredential, target.CredentialRef, err)
	}
	env := delivery.Env{Credential: map[string]string{}, Target: map[string]string{}, HTTPClient: client}
	var missing []string
	for name, f := range v.Manifest.CredentialSchema {
		val, ok := raw[name]
		if !ok || val == "" {
			val = f.Default
		}
		if f.Required && val == "" {
			missing = append(missing, "credential."+name)
			continue
		}
		if val != "" {
			env.Credential[name] = val
		}
		if f.Secret {
			env.Secrets = append(env.Secrets, name)
		}
	}
	for name, f := range v.Manifest.TargetSchema {
		val := target.PluginSettings[name]
		if val == "" {
			val = f.Default
		}
		if f.Required && val == "" {
			missing = append(missing, "plugin_settings."+name)
			continue
		}
		if val != "" {
			env.Target[name] = val
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return pluginRun{}, fmt.Errorf("delivery plugin %q is missing required fields: %s", target.PluginID, strings.Join(missing, ", "))
	}
	return pluginRun{plugin: p, version: v, env: env}, nil
}

// credentialFieldTLSCA is a credential field the hub itself reads: a PEM CA
// bundle the device's management certificate chains to (devices often use
// an internal CA). It extends trust for this target's plugin HTTPS only and
// reaches the plugin only if its schema names the field.
const credentialFieldTLSCA = "tls_ca_pem"

// pluginHTTPClient is base (or a default client) trusting the system roots
// plus caPEM, when given. The plugin cannot change TLS trust itself.
func pluginHTTPClient(base *http.Client, caPEM string) (*http.Client, error) {
	if strings.TrimSpace(caPEM) == "" {
		return base, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, errors.New("tls_ca_pem holds no PEM certificate")
	}
	return &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}}, nil
}

// pushViaPlugin delivers already-renewed material through the target's
// plugin. The result's Verified and RolledBack are the hub's findings.
func (e *RenewalExecutor) pushViaPlugin(ctx context.Context, target ManagedTarget, profile RenewalInstallProfile, chainPEM, keyPEM []byte, leafFP string) (agentinstall.InstallResult, error) {
	run, err := e.preparePlugin(ctx, target)
	if err != nil {
		return agentinstall.InstallResult{}, err
	}
	refused := 0
	run.env.Events = func(ev delivery.Event) {
		switch ev.Kind {
		case "refused":
			refused++
			e.appendPluginAudit(ctx, "delivery_plugin.refused", target.PluginID, AuditOutcomeDenied,
				fmt.Sprintf("target=%s version=%s %s", target.ID, run.version.Version, ev.Detail))
		case "log":
			log.Printf("delivery plugin %s (target %s): %s", target.PluginID, target.ID, ev.Detail)
		}
	}
	verifyHostPort := profile.VerifyHostPort
	if verifyHostPort == "" {
		verifyHostPort = net.JoinHostPort(target.Host, "443")
	}
	verify := e.verifier
	if verify == nil {
		verify = agentinstall.HubVerifier
	}
	res := run.plugin.Deliver(ctx, run.env, delivery.DeliverRequest{
		Name: pushObjectName(target.Name), CertPEM: chainPEM, KeyPEM: keyPEM,
		VerifyHostPort: verifyHostPort, ExpectedFingerprint: leafFP,
	}, verify)
	outcome := AuditOutcomeSuccess
	if !res.Verified && res.Outcome != agentinstall.OutcomeInstalled {
		outcome = AuditOutcomeFailure
	}
	e.appendPluginAudit(ctx, "delivery_plugin.push", target.PluginID, outcome,
		fmt.Sprintf("target=%s version=%s sha256=%s outcome=%s verified=%t rolled_back=%t refused_calls=%d",
			target.ID, run.version.Version, run.version.SHA256, res.Outcome, res.Verified, res.RolledBack, refused))
	var pushErr error
	if outcome == AuditOutcomeFailure {
		pushErr = fmt.Errorf("delivery plugin %s: %s: %s", target.PluginID, res.Outcome, res.Detail)
	}
	return res, pushErr
}

func (e *RenewalExecutor) appendPluginAudit(ctx context.Context, action, pluginID string, outcome AuditOutcome, detail string) {
	if e.pluginAudit == nil {
		return
	}
	if err := e.pluginAudit.AppendEntry(context.WithoutCancel(ctx), AuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339), Action: action, ActorType: "system", ActorID: "renewal",
		ResourceType: "delivery_plugin", ResourceID: pluginID, Outcome: outcome, ChangeSummary: detail,
	}); err != nil {
		log.Printf("audit append failed action=%s: %v", action, err)
	}
}
