// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

// Notification channel backed by a notify plugin (W38-02, D-321). A rule picks
// it with channel "plugin" and target "<plugin_id>/<credential_ref>": the
// plugin says how to talk to the service, the credential (an api_token
// credential holding a JSON object of the plugin's credential_schema fields)
// says where and with what key. The plugin runs in the same sandbox as a
// delivery plugin; the hub checks its kind, grants and hosts exactly as there.
//
// A failed send comes back as an ordinary error, so the delivery worker's
// retry and escalation treat it like a Slack or webhook failure. This file
// does not retry (W38-03 owns backoff).

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"kryptkeeper/internal/logging"
	"kryptkeeper/internal/notifications/delivery"
	plugindelivery "kryptkeeper/internal/plugins/delivery"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
)

// pluginChannelName is the delivery channel notify plugins are reached through.
const pluginChannelName = "plugin"

// pluginNotifyTimeout bounds one alert, well under the delivery worker's
// patience: a chat or incident API that takes longer is down for our purposes.
const pluginNotifyTimeout = 30 * time.Second

// PluginNotifyChannel is a delivery.Channel named "plugin".
type PluginNotifyChannel struct {
	plugins func() *DeliveryPluginManager
	creds   func() OutboundCredentialStore
	audit   AuditProvider
	client  *http.Client // nil: the guarded device client (egress policy applies)
}

// NewPluginNotifyChannel returns the channel. plugins is resolved per send so
// the channel can be registered before the manager exists; creds opens the
// outbound credential store on first use, so a hub without a credential
// passphrase still starts and the send fails closed. audit receives one row
// per send.
func NewPluginNotifyChannel(plugins func() *DeliveryPluginManager, audit AuditProvider) *PluginNotifyChannel {
	var once sync.Once
	var store OutboundCredentialStore
	return &PluginNotifyChannel{plugins: plugins, audit: audit, creds: func() OutboundCredentialStore {
		once.Do(func() { store = newOutboundCredentialStoreFromEnv() })
		return store
	}}
}

func (c *PluginNotifyChannel) Name() string { return pluginChannelName }

// Configured reports whether plugins are on, so the alerts UI can tell an
// unavailable channel from a failing one.
func (c *PluginNotifyChannel) Configured(context.Context) bool {
	return c.plugins != nil && c.plugins() != nil
}

// parsePluginTarget splits a rule target into plugin id and credential ref.
func parsePluginTarget(target string) (pluginID, credentialRef string, err error) {
	pluginID, credentialRef, ok := strings.Cut(strings.TrimSpace(target), "/")
	if !ok || pluginID == "" || strings.TrimSpace(credentialRef) == "" || strings.Contains(credentialRef, "/") {
		return "", "", errors.New("target must be <plugin_id>/<credential_id>")
	}
	return pluginID, credentialRef, nil
}

// prepare resolves the target's enabled notify plugin and its environment.
func (c *PluginNotifyChannel) prepare(ctx context.Context, target string) (*plugindelivery.Plugin, DeliveryPluginVersion, plugindelivery.Env, error) {
	pluginID, credRef, err := parsePluginTarget(target)
	if err != nil {
		return nil, DeliveryPluginVersion{}, plugindelivery.Env{}, err
	}
	var mgr *DeliveryPluginManager
	if c.plugins != nil {
		mgr = c.plugins()
	}
	if mgr == nil {
		return nil, DeliveryPluginVersion{}, plugindelivery.Env{}, errPluginsOff
	}
	p, v, err := mgr.Enabled(ctx, pluginID)
	if err != nil {
		return nil, v, plugindelivery.Env{}, fmt.Errorf("notify plugin %q: %w", pluginID, err)
	}
	if v.Kind != abi.KindNotify {
		return nil, v, plugindelivery.Env{}, fmt.Errorf("plugin %q is a %s plugin, not a notify plugin", pluginID, v.Kind)
	}
	var creds OutboundCredentialStore
	if c.creds != nil {
		creds = c.creds()
	}
	env, err := buildPluginEnv(ctx, creds, c.client, v, credRef, nil)
	if err != nil {
		return nil, v, env, err
	}
	return p, v, env, nil
}

// Send delivers ev through the plugin the target names.
func (c *PluginNotifyChannel) Send(ctx context.Context, ev delivery.Event) error {
	p, v, env, err := c.prepare(ctx, ev.Target)
	if err != nil {
		return err
	}
	refused := 0
	env.Timeout = pluginNotifyTimeout
	env.Events = func(e plugindelivery.Event) {
		switch e.Kind {
		case "refused":
			refused++
			c.appendAudit(ctx, "delivery_plugin.refused", v.PluginID, AuditOutcomeDenied,
				fmt.Sprintf("kind=notify version=%s %s", v.Version, e.Detail))
		case "log":
			logging.Infof("notify plugin %s: %s", v.PluginID, e.Detail)
		}
	}
	res, sendErr := p.Notify(ctx, env, notifyRequest(ev))
	outcome := AuditOutcomeSuccess
	if sendErr != nil {
		outcome = AuditOutcomeFailure
	}
	c.appendAudit(ctx, "delivery_plugin.notify", v.PluginID, outcome,
		fmt.Sprintf("kind=notify version=%s sha256=%s event=%s delivered=%t refused_calls=%d", v.Version, v.SHA256, ev.ID, res.Delivered, refused))
	if sendErr != nil {
		return fmt.Errorf("notify plugin %s: %w", v.PluginID, sendErr)
	}
	return nil
}

// notifyRequest maps a hub event onto the plugin's request. The event id is
// the dedupe key: the delivery worker keeps it stable across retries, so a
// retry folds into one alert at services that de-duplicate.
func notifyRequest(ev delivery.Event) abi.NotifySendRequest {
	class := ev.Class
	if class == "" {
		class = "notification"
	}
	sev := ev.Priority
	switch sev {
	case abi.SeverityCritical, abi.SeverityHigh, abi.SeverityMedium, abi.SeverityLow:
	default:
		sev = abi.SeverityMedium
	}
	return abi.NotifySendRequest{
		EventClass: class, Severity: sev, Title: ev.Subject, Body: ev.Message,
		Fields: ev.Fields, DeepLink: ev.DeepLink, DedupeKey: ev.ID,
	}
}

func (c *PluginNotifyChannel) appendAudit(ctx context.Context, action, pluginID string, outcome AuditOutcome, detail string) {
	if c.audit == nil {
		return
	}
	if err := c.audit.AppendEntry(context.WithoutCancel(ctx), AuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339), Action: action, ActorType: "system", ActorID: "notifications",
		ResourceType: "delivery_plugin", ResourceID: pluginID, Outcome: outcome, ChangeSummary: detail,
	}); err != nil {
		logging.Warnf("audit append failed action=%s: %v", action, err)
	}
}

// pluginChannelTargetFunc validates a "plugin" rule target for the principal
// creating the rule: the plugin exists, is enabled and is a notify plugin,
// and the credential exists, is visible to the principal and has the type
// plugins read. It returns a message fit for a 400, or "" when the target
// is good. Checking at rule-create time refuses a bad rule up front instead
// of failing every alert later.
type pluginChannelTargetFunc func(ctx context.Context, pd AuthPrincipal, target string) string

func newPluginChannelTarget(c *PluginNotifyChannel) pluginChannelTargetFunc {
	return func(ctx context.Context, pd AuthPrincipal, target string) string {
		pluginID, credRef, err := parsePluginTarget(target)
		if err != nil {
			return err.Error()
		}
		var mgr *DeliveryPluginManager
		if c != nil && c.plugins != nil {
			mgr = c.plugins()
		}
		if mgr == nil {
			return errPluginsOff.Error()
		}
		_, v, err := mgr.Enabled(ctx, pluginID)
		if err != nil {
			return fmt.Sprintf("plugin %q is not an enabled plugin", pluginID)
		}
		if v.Kind != abi.KindNotify {
			return fmt.Sprintf("plugin %q is a %s plugin, not a notify plugin", pluginID, v.Kind)
		}
		creds := c.creds()
		if creds == nil {
			return "the outbound credential store is not configured"
		}
		meta, err := creds.Get(ctx, credRef)
		if err != nil || !stampedTenantVisible(pd, meta.Tenant) {
			return fmt.Sprintf("credential %q does not exist", credRef)
		}
		if meta.CredentialType != CredentialTypeAPIToken {
			return fmt.Sprintf("credential %q must be an %s credential holding the plugin's credential fields", credRef, CredentialTypeAPIToken)
		}
		return ""
	}
}
