// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"strings"
)

// RC1-A-01. /api/v1/targets/** is gated at discovery.manage, but an
// auto_renew target with a credential_ref makes the renewal scheduler renew the
// hub certificate whose CN/SAN equals the target's host and push its private
// key to wherever the credential points. Configuring that is therefore an
// act of renewing, not of discovering: it needs certificate.renew, and naming
// a credential additionally needs the admin bar that governs credentials
// (handlers_credentials.go lets only pki-admin list, create or delete them, so
// nobody else can be "allowed to see" one). The principal that passes is
// stamped on the target as AutoRenewSetBy, which the scheduler requires.

var (
	errTargetCredentialUnknown = errors.New("credential_ref does not name a credential you may use")
	errTargetPluginUnknown     = errors.New("plugin_id does not name an installed delivery plugin")
	errTargetStoreUnavailable  = errors.New("credential or plugin store unavailable")
)

// targetEgressDeps are the stores the handlers validate references against.
type targetEgressDeps struct {
	credentials OutboundCredentialStore
	plugins     *DeliveryPluginManager
}

// targetEgressChanges lists the egress-sensitive fields that differ between
// old and next, and whether a credential is being newly named.
//
// Always sensitive: turning auto_renew on, naming a credential, naming a
// plugin. Once the resulting target is armed by any of those, the fields that
// decide where the key lands (host, install profile, plugin settings,
// renewal method) are sensitive too; on a target with no credential, plugin or
// auto_renew they are inert and stay under discovery.manage.
func targetEgressChanges(old, next ManagedTarget) (fields []string, newCredential bool) {
	if next.AutoRenew && !old.AutoRenew {
		fields = append(fields, "auto_renew")
	}
	if next.CredentialRef != "" && next.CredentialRef != old.CredentialRef {
		fields = append(fields, "credential_ref")
		newCredential = true
	}
	if next.PluginID != "" && next.PluginID != old.PluginID {
		fields = append(fields, "plugin_id")
	}
	if !next.AutoRenew && next.CredentialRef == "" && next.PluginID == "" {
		return fields, newCredential
	}
	for _, c := range []struct {
		name    string
		changed bool
	}{
		{"host", next.Host != old.Host},
		{"install_mode", next.InstallMode != old.InstallMode},
		{"renewal_method", next.RenewalMethod != old.RenewalMethod},
		{"install_server_type", next.InstallServerType != old.InstallServerType},
		{"install_cert_path", next.InstallCertPath != old.InstallCertPath},
		{"install_key_path", next.InstallKeyPath != old.InstallKeyPath},
		{"install_reload_method", next.InstallReloadMethod != old.InstallReloadMethod},
		{"verify_host_port", next.VerifyHostPort != old.VerifyHostPort},
		{"plugin_settings", !maps.Equal(next.PluginSettings, old.PluginSettings)},
		// Replacing the pin on an armed target redirects where the key is pushed.
		{"ssh_host_key", next.SSHHostKey != old.SSHHostKey},
	} {
		if c.changed {
			fields = append(fields, c.name)
		}
	}
	return fields, newCredential
}

// authorizeTargetEgress decides whether pd may make the change old -> next.
// stamp is true when pd, holding certificate.renew, configured or re-affirmed
// key egress and must be recorded as the target's AutoRenewSetBy. reaffirm is
// an explicit auto_renew=true in the request: it re-stamps an unchanged armed
// target (how targets armed before the stamp existed are re-armed).
func authorizeTargetEgress(pd AuthPrincipal, roles *CustomRoleStore, old, next ManagedTarget, reaffirm bool) (fields []string, stamp, allowed bool, need string) {
	fields, newCredential := targetEgressChanges(old, next)
	perms, admin := principalPermissions(pd, roles)
	mayRenew := admin || perms["certificate.renew"]
	switch {
	case newCredential && !admin:
		return fields, false, false, "pki-admin (credentials are admin-governed) and certificate.renew"
	case len(fields) > 0 && !mayRenew:
		return fields, false, false, "certificate.renew"
	}
	stamp = mayRenew && next.AutoRenew && (len(fields) > 0 || reaffirm)
	return fields, stamp, true, ""
}

// validateTargetReferences checks that the credential and plugin a target names
// exist, so a typo or a probe cannot arm a target that points nowhere, and that
// a credential bound to another tenant is not borrowed across the boundary.
func (d targetEgressDeps) validateTargetReferences(ctx context.Context, pd AuthPrincipal, old, next ManagedTarget) error {
	if next.CredentialRef != "" && next.CredentialRef != old.CredentialRef {
		if d.credentials == nil {
			return errTargetStoreUnavailable
		}
		meta, err := d.credentials.Get(ctx, next.CredentialRef)
		if err != nil {
			return errTargetCredentialUnknown
		}
		// Credentials carry the creator's tenant; legacy rows ("") belong to
		// the default tenant.
		if !stampedTenantVisible(pd, meta.Tenant) {
			return errTargetCredentialUnknown
		}
	}
	if next.PluginID != "" && next.PluginID != old.PluginID {
		if d.plugins == nil {
			return errTargetPluginUnknown
		}
		if _, err := d.plugins.Get(ctx, next.PluginID); err != nil {
			return errTargetPluginUnknown
		}
	}
	return nil
}

// refuseTargetEgress writes the 403 and the audit row for a refused change.
func refuseTargetEgress(w http.ResponseWriter, r *http.Request, ap AuditProvider, pd AuthPrincipal, action, id string, fields []string, need string) {
	emitAuditEventDetail(r, ap, pd.ID, action, "target", id, AuditOutcomeDenied,
		"needs="+need+" fields="+strings.Join(fields, ","))
	writeForbidden(w, "configuring "+strings.Join(fields, ", ")+" on a target needs "+need)
}
