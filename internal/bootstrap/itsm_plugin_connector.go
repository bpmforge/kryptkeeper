// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

// ITSM connections backed by a ticket plugin (W38-09, D-326). A connection of
// kind "plugin" names a plugin_id and a credential_ref; the plugin says how to
// talk to the ticket service, the credential (an api_token credential holding
// a JSON object of the plugin's credential_schema fields, which includes the
// service's subdomain base URL) says where and with what key. The plugin runs
// in the same sandbox as every other plugin; the hub checks its kind, grants
// and hosts exactly as there.
//
// This file is only the Connector. Dedupe, the reconcile loop, retries with
// backoff, alerts and the ticket audit rows stay in internal/notifications/itsm
// and are the same as for ServiceNow and Jira. Approval sync is not offered to
// plugins in 1.1: the connector does not implement itsm.ApprovalConnector, so
// the approval bridge skips plugin connections.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"kryptkeeper/internal/logging"
	"kryptkeeper/internal/notifications/itsm"
	plugindelivery "kryptkeeper/internal/plugins/delivery"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
)

// itsmPluginTimeout bounds one ticket call; the ITSM service retries a slow
// service on its own backoff, so a long wait here only delays the drain loop.
const itsmPluginTimeout = 30 * time.Second

// ITSMPluginConnectors builds Connectors for "plugin" ITSM connections.
type ITSMPluginConnectors struct {
	plugins func() *DeliveryPluginManager
	creds   func() OutboundCredentialStore
	audit   AuditProvider
	client  *http.Client // nil: the guarded device client (egress policy applies)
}

// NewITSMPluginConnectors returns the factory source. plugins is resolved per
// call so it can be wired before the manager exists; the credential store opens
// on first use, so a hub without a credential passphrase still starts and a
// plugin connection fails closed.
func NewITSMPluginConnectors(plugins func() *DeliveryPluginManager, audit AuditProvider) *ITSMPluginConnectors {
	var once sync.Once
	var store OutboundCredentialStore
	return &ITSMPluginConnectors{plugins: plugins, audit: audit, creds: func() OutboundCredentialStore {
		once.Do(func() { store = newOutboundCredentialStoreFromEnv() })
		return store
	}}
}

// Factory is the itsm.PluginConnectorFactory over these connectors.
func (c *ITSMPluginConnectors) Factory() itsm.PluginConnectorFactory {
	return func(ctx context.Context, conn itsm.Connection) (itsm.Connector, error) {
		pc := &itsmPluginConnector{src: c, credRef: conn.CredentialRef, pluginID: conn.PluginID}
		if _, _, err := pc.load(ctx); err != nil {
			return nil, err
		}
		return pc, nil
	}
}

type itsmPluginConnector struct {
	src      *ITSMPluginConnectors
	credRef  string
	pluginID string
}

var _ itsm.Connector = (*itsmPluginConnector)(nil)
var _ itsm.Prober = (*itsmPluginConnector)(nil)

// load resolves the connection's enabled ticket plugin.
func (p *itsmPluginConnector) load(ctx context.Context) (*plugindelivery.Plugin, DeliveryPluginVersion, error) {
	var mgr *DeliveryPluginManager
	if p.src.plugins != nil {
		mgr = p.src.plugins()
	}
	if mgr == nil {
		return nil, DeliveryPluginVersion{}, errPluginsOff
	}
	plugin, v, err := mgr.Enabled(ctx, p.pluginID)
	if err != nil {
		return nil, v, fmt.Errorf("ticket plugin %q: %w", p.pluginID, err)
	}
	if v.Kind != abi.KindTicket {
		return nil, v, fmt.Errorf("plugin %q is a %s plugin, not a ticket plugin", p.pluginID, v.Kind)
	}
	return plugin, v, nil
}

// call runs one ticket op. The credential is resolved here, per call, and the
// Env holding it lives only for the call.
func (p *itsmPluginConnector) call(ctx context.Context, op string, run func(*plugindelivery.Plugin, plugindelivery.Env) error) error {
	plugin, v, err := p.load(ctx)
	if err != nil {
		return err
	}
	var creds OutboundCredentialStore
	if p.src.creds != nil {
		creds = p.src.creds()
	}
	env, err := buildPluginEnv(ctx, creds, p.src.client, v, p.credRef, nil)
	if err != nil {
		return err
	}
	refused := 0
	env.Timeout = itsmPluginTimeout
	env.Events = func(e plugindelivery.Event) {
		switch e.Kind {
		case "refused":
			refused++
			p.src.appendAudit(ctx, "delivery_plugin.refused", v.PluginID, AuditOutcomeDenied,
				fmt.Sprintf("kind=ticket op=%s version=%s %s", op, v.Version, e.Detail))
		case "log":
			logging.Infof("ticket plugin %s: %s", v.PluginID, e.Detail)
		}
	}
	runErr := run(plugin, env)
	outcome := AuditOutcomeSuccess
	if runErr != nil {
		outcome = AuditOutcomeFailure
	}
	// A successful exists is the hourly reconcile of every ticket; auditing it
	// would bury the create and resolve rows the trail exists for.
	if op != "exists" || runErr != nil {
		p.src.appendAudit(ctx, "delivery_plugin.ticket", v.PluginID, outcome,
			fmt.Sprintf("kind=ticket op=%s version=%s sha256=%s refused_calls=%d", op, v.Version, v.SHA256, refused))
	}
	return classifyTicketError(runErr)
}

// classifyTicketError maps what a plugin run returned onto the ITSM service's
// two retry classes. A plugin-reported permanent failure (a credential the
// service refuses, a payload it rejects) marks the event failed; everything
// else, including a plugin that errors or traps, is retried with backoff, so a
// plugin bug or a service outage never drops a ticket.
func classifyTicketError(err error) error {
	if err == nil {
		return nil
	}
	var te *plugindelivery.TicketError
	if errors.As(err, &te) && !te.Temporary {
		return fmt.Errorf("%w: %s", itsm.ErrPermanent, te.Detail)
	}
	return fmt.Errorf("%w: %s", itsm.ErrTemporary, err.Error())
}

func (p *itsmPluginConnector) Kind() string { return itsm.KindPlugin }

// Find reports no ticket: the ticket ABI has no find op. The consequence is
// that a ticket created just before a hub crash that lost the row update is
// not adopted on the next drain, and a second one is made (D-326).
func (p *itsmPluginConnector) Find(context.Context, string) (*itsm.TicketRef, error) {
	return nil, nil
}

func (p *itsmPluginConnector) Create(ctx context.Context, ev itsm.Event) (itsm.TicketRef, error) {
	te := abi.TicketEvent{
		ID: ev.ID, Class: ev.Class, CN: ev.CN, Serial: ev.Serial, Risk: ev.Risk, DeepLink: ev.DeepLink,
		Fingerprint: ev.Fingerprint, TicketType: ev.TicketType,
	}
	if !ev.NotAfter.IsZero() {
		te.NotAfter = ev.NotAfter.UTC().Format(time.RFC3339)
	}
	var ref itsm.TicketRef
	err := p.call(ctx, "create", func(pl *plugindelivery.Plugin, env plugindelivery.Env) error {
		res, err := pl.TicketCreate(ctx, env, te)
		ref = itsm.TicketRef{Key: res.Key, URL: res.URL}
		return err
	})
	return ref, err
}

func (p *itsmPluginConnector) Exists(ctx context.Context, ref itsm.TicketRef) (bool, error) {
	var exists bool
	err := p.call(ctx, "exists", func(pl *plugindelivery.Plugin, env plugindelivery.Env) error {
		var err error
		exists, err = pl.TicketExists(ctx, env, ref.Key, ref.URL)
		return err
	})
	return exists, err
}

func (p *itsmPluginConnector) Resolve(ctx context.Context, ref itsm.TicketRef, comment string) error {
	return p.call(ctx, "resolve", func(pl *plugindelivery.Plugin, env plugindelivery.Env) error {
		return pl.TicketResolve(ctx, env, ref.Key, ref.URL, comment)
	})
}

// Probe is "test connection": ticket.exists for a key no ticket has. A reply
// of "no such ticket" proves the service is reachable and the credential works
// without creating anything.
func (p *itsmPluginConnector) Probe(ctx context.Context) error {
	return p.call(ctx, "probe", func(pl *plugindelivery.Plugin, env plugindelivery.Env) error {
		_, err := pl.TicketExists(ctx, env, abi.ProbeTicketKey, "")
		return err
	})
}

func (c *ITSMPluginConnectors) appendAudit(ctx context.Context, action, pluginID string, outcome AuditOutcome, detail string) {
	if c.audit == nil {
		return
	}
	if err := c.audit.AppendEntry(context.WithoutCancel(ctx), AuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339), Action: action, ActorType: "system", ActorID: "itsm-queue",
		ResourceType: "delivery_plugin", ResourceID: pluginID, Outcome: outcome, ChangeSummary: detail,
	}); err != nil {
		logging.Warnf("audit append failed action=%s: %v", action, err)
	}
}

// itsmPluginCheckFunc validates a "plugin" connection's plugin and credential
// for the principal creating it, returning a message fit for a 400, or "".
// Checking at create time refuses a bad connection up front instead of
// failing every ticket later.
type itsmPluginCheckFunc func(ctx context.Context, pd AuthPrincipal, pluginID, credentialRef string) string

func newITSMPluginCheck(c *ITSMPluginConnectors) itsmPluginCheckFunc {
	return func(ctx context.Context, pd AuthPrincipal, pluginID, credRef string) string {
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
		if v.Kind != abi.KindTicket {
			return fmt.Sprintf("plugin %q is a %s plugin, not a ticket plugin", pluginID, v.Kind)
		}
		creds := c.creds()
		if creds == nil {
			return "the outbound credential store is not configured"
		}
		meta, err := creds.Get(ctx, credRef)
		if err != nil || !stampedTenantVisible(pd, meta.Tenant) {
			return "unknown credential_ref"
		}
		if meta.CredentialType != CredentialTypeAPIToken {
			return fmt.Sprintf("credential %q must be an %s credential holding the plugin's credential fields", credRef, CredentialTypeAPIToken)
		}
		return ""
	}
}
