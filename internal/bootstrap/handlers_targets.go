// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"kryptkeeper/internal/logging"

	"kryptkeeper/internal/agentinstall"
	"kryptkeeper/internal/egress"
)

// RegisterTargetHandlers mounts the /api/v1/targets CRUD surface (W5-09,
// D-062, FR-P24). store may be nil (DB unavailable) -- every handler
// reports 503 in that case rather than silently no-op'ing.
func RegisterTargetHandlers(mux *http.ServeMux, auth *Authenticator, store ManagedTargetStore, tenantStore TenantStore, auditProvider AuditProvider, credentials OutboundCredentialStore, plugins *DeliveryPluginManager) {
	registerTargetHandlers(mux, auth, store, tenantStore, auditProvider, targetEgressDeps{credentials: credentials, plugins: plugins})
}

// targetVisibleToTenant reports whether a managed target belongs to the
// principal's tenant. Unlike CA/template (a separate mapping table,
// unmapped => DefaultTenant), tenant is a direct column stamped at create
// time -- no store lookup needed, mirroring filterPendingActionsByTenant's
// reasoning: the tenant travels with the row, so this can't leak across
// tenants via a failed lookup because there is no lookup.
func targetVisibleToTenant(pd AuthPrincipal, target ManagedTarget) bool {
	return tenantBypass(pd) || target.Tenant == pd.Tenant
}

func filterManagedTargetsByTenant(pd AuthPrincipal, items []ManagedTarget) []ManagedTarget {
	if tenantBypass(pd) {
		return items
	}
	out := make([]ManagedTarget, 0, len(items))
	for _, t := range items {
		if t.Tenant == pd.Tenant {
			out = append(out, t)
		}
	}
	return out
}

func registerTargetHandlers(mux *http.ServeMux, auth *Authenticator, store ManagedTargetStore, tenantStore TenantStore, auditProvider AuditProvider, egressDeps targetEgressDeps) {
	authenticate := func(w http.ResponseWriter, r *http.Request) (AuthPrincipal, bool) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			writeUnauthorized(w)
			return AuthPrincipal{}, false
		}
		return pd, true
	}

	mux.HandleFunc("/api/v1/targets", func(w http.ResponseWriter, r *http.Request) {
		pd, ok := authenticate(w, r)
		if !ok {
			return
		}
		if store == nil {
			emitAuditEvent(r, auditProvider, pd.ID, "target.list", "target", "targets", AuditOutcomeFailure)
			writeServiceUnavailable(w, "managed target store unavailable")
			return
		}

		switch r.Method {
		case http.MethodGet:
			items, err := store.List(r.Context())
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.list", "target", "targets", AuditOutcomeFailure)
				writeServiceUnavailable(w, "list failed")
				return
			}
			writeJSONData(w, withTargetState(r.Context(), store, egressDeps.credentials, withCredentialPrivileged(r.Context(), egressDeps.credentials, withEffectiveModes(filterManagedTargetsByTenant(pd, items)))))

		case http.MethodPost:
			var req struct {
				Name                 string `json:"name"`
				Host                 string `json:"host"`
				DiscoveryMode        string `json:"discovery_mode"`
				InstallMode          string `json:"install_mode"`
				RenewalMethod        string `json:"renewal_method"`
				RenewalThresholdDays int    `json:"renewal_threshold_days"`
				CredentialRef        string `json:"credential_ref"`
				Schedule             string `json:"schedule"`
				InstallServerType    string `json:"install_server_type"`
				InstallCertPath      string `json:"install_cert_path"`
				InstallKeyPath       string `json:"install_key_path"`
				InstallReloadMethod  string `json:"install_reload_method"`
				VerifyHostPort       string `json:"verify_host_port"`
				AutoRenew            bool   `json:"auto_renew"`
				SSHHostKey           string `json:"ssh_host_key"`
				// W20-20: install_mode "plugin" targets name their plugin
				// and its target_schema values.
				PluginID       string            `json:"plugin_id"`
				PluginSettings map[string]string `json:"plugin_settings"`
				// W23-46: optional; empty = derived from install_mode.
				KeyHandlingMode string `json:"key_handling_mode"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&req); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.create", "target", "targets", AuditOutcomeFailure)
				writeBadRequest(w, "invalid request body")
				return
			}
			req.Name = strings.TrimSpace(req.Name)
			req.Host = strings.TrimSpace(req.Host)
			if req.Name == "" || req.Host == "" {
				emitAuditEvent(r, auditProvider, pd.ID, "target.create", "target", "targets", AuditOutcomeFailure)
				writeBadRequest(w, "name and host are required")
				return
			}
			if req.DiscoveryMode == "" {
				req.DiscoveryMode = "agent"
			}
			if req.InstallMode == "" {
				req.InstallMode = "agent"
			}
			if req.RenewalMethod == "" {
				req.RenewalMethod = "acme"
			}
			if err := validateManagedTargetModes(req.DiscoveryMode, req.InstallMode, req.RenewalMethod); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.create", "target", "targets", AuditOutcomeFailure)
				writeBadRequest(w, "invalid discovery_mode, install_mode, or renewal_method")
				return
			}
			if err := validateRenewalThresholdDays(req.RenewalThresholdDays); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.create", "target", "targets", AuditOutcomeFailure)
				writeBadRequest(w, err.Error())
				return
			}
			if err := validateVerifyHostPort(req.VerifyHostPort); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.create", "target", "targets", AuditOutcomeFailure)
				writeBadRequest(w, err.Error())
				return
			}
			if err := validatePluginTarget(req.InstallMode, req.PluginID); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.create", "target", "targets", AuditOutcomeFailure)
				writeBadRequest(w, err.Error())
				return
			}
			req.SSHHostKey = strings.TrimSpace(req.SSHHostKey)
			if err := validateSSHHostKey(req.InstallMode, req.SSHHostKey); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.create", "target", "targets", AuditOutcomeFailure)
				writeBadRequest(w, err.Error())
				return
			}
			req.KeyHandlingMode = strings.TrimSpace(req.KeyHandlingMode)
			if err := validateKeyHandlingMode(req.KeyHandlingMode, req.InstallMode); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.create", "target", "targets", AuditOutcomeFailure)
				writeBadRequest(w, err.Error())
				return
			}

			tenant := DefaultTenant
			if !tenantBypass(pd) {
				tenant = pd.Tenant
				if tenantStore != nil {
					exists, terr := tenantStore.TenantExists(r.Context(), tenant)
					if terr != nil {
						emitAuditEvent(r, auditProvider, pd.ID, "target.create", "target", "targets", AuditOutcomeFailure)
						writeServiceUnavailable(w, "tenant lookup failed")
						return
					}
					if !exists {
						emitAuditEvent(r, auditProvider, pd.ID, "target.create", "target", "targets", AuditOutcomeDenied)
						writeBadRequest(w, "unknown tenant")
						return
					}
				}
			}

			id, err := newManagedTargetID()
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.create", "target", "targets", AuditOutcomeFailure)
				writeServiceUnavailable(w, "id generation failed")
				return
			}
			now := time.Now().UTC().Format(time.RFC3339)
			newTarget := ManagedTarget{
				ID:                    id,
				Name:                  req.Name,
				Host:                  req.Host,
				DiscoveryMode:         req.DiscoveryMode,
				InstallMode:           req.InstallMode,
				RenewalMethod:         req.RenewalMethod,
				RenewalThresholdDays:  req.RenewalThresholdDays,
				CredentialRef:         req.CredentialRef,
				Schedule:              req.Schedule,
				InstallServerType:     strings.TrimSpace(req.InstallServerType),
				InstallCertPath:       strings.TrimSpace(req.InstallCertPath),
				InstallKeyPath:        strings.TrimSpace(req.InstallKeyPath),
				InstallReloadMethod:   strings.TrimSpace(req.InstallReloadMethod),
				VerifyHostPort:        strings.TrimSpace(req.VerifyHostPort),
				AutoRenew:             req.AutoRenew,
				SSHHostKey:            req.SSHHostKey,
				SSHHostKeyFingerprint: agentinstall.FingerprintOfLine(req.SSHHostKey),
				PluginID:              strings.TrimSpace(req.PluginID),
				PluginSettings:        req.PluginSettings,
				KeyHandlingMode:       req.KeyHandlingMode,
				Tenant:                tenant,
				CreatedAt:             now,
				UpdatedAt:             now,
			}
			fields, stamp, allowed, need := authorizeTargetEgress(pd, auth.roleStore, ManagedTarget{}, newTarget, req.AutoRenew)
			if !allowed {
				refuseTargetEgress(w, r, auditProvider, pd, "target.create", "targets", fields, need)
				return
			}
			var armedBy string
			if stamp {
				var ok bool
				if armedBy, ok = armStamp(w, r, auditProvider, pd, "target.create", "targets"); !ok {
					return
				}
			}
			if err := egressDeps.validateTargetReferences(r.Context(), pd, ManagedTarget{}, newTarget); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.create", "target", "targets", AuditOutcomeFailure)
				writeTargetReferenceError(w, err)
				return
			}
			if stamp {
				newTarget.AutoRenewSetBy = armedBy
			}
			created, err := store.Create(r.Context(), newTarget)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.create", "target", "targets", AuditOutcomeFailure)
				writeServiceUnavailable(w, "create failed")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "target.create", "target", created.ID, AuditOutcomeSuccess)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			writeJSONData(w, withEffectiveMode(created))

		default:
			writeMethodNotAllowed(w, "GET, POST")
		}
	})

	// Exact pattern wins over the "/api/v1/targets/" subtree below; real ids
	// are target-<hex>, so "hostkey" cannot collide with one.
	mux.HandleFunc("/api/v1/targets/hostkey", func(w http.ResponseWriter, r *http.Request) {
		pd, ok := authenticate(w, r)
		if !ok {
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		var req struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4*1024)).Decode(&req); err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "target.hostkey.probe", "target", "", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}
		req.Host = strings.TrimSpace(req.Host)
		if req.Port == 0 {
			req.Port = 22
		}
		if req.Host == "" || req.Port < 1 || req.Port > 65535 || verifyHostForbidden(req.Host) {
			emitAuditEvent(r, auditProvider, pd.ID, "target.hostkey.probe", "target", req.Host, AuditOutcomeFailure)
			writeBadRequest(w, "a routable host and a port between 1 and 65535 are required")
			return
		}
		key, err := probeTargetHostKey(r.Context(), req.Host, req.Port)
		if err != nil {
			emitAuditEvent(r, auditProvider, pd.ID, "target.hostkey.probe", "target", req.Host, AuditOutcomeFailure)
			msg := err.Error()
			if errors.Is(err, egress.ErrBlockedDestination) {
				msg = "address is not permitted"
			}
			writeErrorEnvelope(w, http.StatusBadGateway, "bad_gateway", "host key probe failed: "+msg)
			return
		}
		emitAuditEvent(r, auditProvider, pd.ID, "target.hostkey.probe", "target", req.Host, AuditOutcomeSuccess)
		writeJSONData(w, map[string]any{
			"host": req.Host, "port": req.Port, "algorithm": key.Type(),
			"ssh_host_key":       agentinstall.HostKeyLine(key),
			"fingerprint_sha256": agentinstall.HostKeyFingerprint(key),
		})
	})

	// Wizard variant of the privilege bundle (no stored target yet). Exact
	// pattern, so it cannot collide with a target id.
	mux.HandleFunc("/api/v1/targets/privilege-bundle", func(w http.ResponseWriter, r *http.Request) {
		pd, ok := authenticate(w, r)
		if !ok {
			return
		}
		handleTargetPrivilegeBundle(w, r, pd, "", store, auth.roleStore, auditProvider)
	})

	mux.HandleFunc("/api/v1/targets/", func(w http.ResponseWriter, r *http.Request) {
		pd, ok := authenticate(w, r)
		if !ok {
			return
		}
		if store == nil {
			emitAuditEvent(r, auditProvider, pd.ID, "target.get", "target", "", AuditOutcomeFailure)
			writeServiceUnavailable(w, "managed target store unavailable")
			return
		}

		tail := strings.TrimPrefix(r.URL.Path, "/api/v1/targets/")
		if id, ok := strings.CutSuffix(tail, "/preflight"); ok && id != "" && !strings.Contains(id, "/") {
			handleTargetPreflight(w, r, pd, id, store, egressDeps.credentials, auth.roleStore, auditProvider)
			return
		}
		if id, ok := strings.CutSuffix(tail, "/unblock"); ok && id != "" && !strings.Contains(id, "/") {
			handleTargetUnblock(w, r, pd, id, store, auth.roleStore, auditProvider)
			return
		}
		if id, ok := strings.CutSuffix(tail, "/privilege-bundle"); ok && id != "" && !strings.Contains(id, "/") {
			handleTargetPrivilegeBundle(w, r, pd, id, store, auth.roleStore, auditProvider)
			return
		}
		if tail == "" || strings.Contains(strings.TrimSuffix(tail, "/endpoints"), "/") {
			emitAuditEvent(r, auditProvider, pd.ID, "target.get", "target", tail, AuditOutcomeFailure)
			writeNotFound(w, "target not found")
			return
		}

		if strings.HasSuffix(tail, "/endpoints") {
			if r.Method != http.MethodGet {
				writeMethodNotAllowed(w, http.MethodGet)
				return
			}
			id := strings.TrimSuffix(tail, "/endpoints")
			target, err := store.Get(r.Context(), id)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.endpoints", "target", id, AuditOutcomeFailure)
				writeNotFound(w, "target not found")
				return
			}
			// NFR-P2 (acceptance #3): agent_endpoints has no tenant column
			// of its own -- for agent matches the ONLY thing enforcing tenant
			// scope is that this join is reachable solely through a
			// tenant-authorized target fetch. Scanned endpoints are further
			// restricted to the target's tenant below. Do not expose an
			// endpoints view that bypasses this check.
			if !targetVisibleToTenant(pd, target) {
				emitAuditEvent(r, auditProvider, pd.ID, "target.endpoints", "target", id, AuditOutcomeDenied)
				writeForbidden(w, "forbidden")
				return
			}
			matchCtx := r.Context()
			if multiTenancyEnabled() {
				matchCtx = context.WithValue(matchCtx, discoveryScopeKey{}, discoveryScope{tenant: discoveryTenantValue(target.Tenant), filter: true})
			}
			matches, err := store.MatchEndpoints(matchCtx, target.Host)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.endpoints", "target", id, AuditOutcomeFailure)
				writeServiceUnavailable(w, "endpoint match failed")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "target.endpoints", "target", id, AuditOutcomeSuccess)
			writeJSONData(w, matches)
			return
		}

		id := tail
		switch r.Method {
		case http.MethodGet:
			target, err := store.Get(r.Context(), id)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.get", "target", id, AuditOutcomeFailure)
				writeNotFound(w, "target not found")
				return
			}
			if !targetVisibleToTenant(pd, target) {
				emitAuditEvent(r, auditProvider, pd.ID, "target.get", "target", id, AuditOutcomeDenied)
				writeForbidden(w, "forbidden")
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "target.get", "target", id, AuditOutcomeSuccess)
			writeJSONData(w, withTargetState(r.Context(), store, egressDeps.credentials, withCredentialPrivileged(r.Context(), egressDeps.credentials, []ManagedTarget{withEffectiveMode(target)}))[0])

		case http.MethodPatch:
			existing, err := store.Get(r.Context(), id)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.update", "target", id, AuditOutcomeFailure)
				writeNotFound(w, "target not found")
				return
			}
			if !targetVisibleToTenant(pd, existing) {
				emitAuditEvent(r, auditProvider, pd.ID, "target.update", "target", id, AuditOutcomeDenied)
				writeForbidden(w, "forbidden")
				return
			}
			var req struct {
				Name                 *string            `json:"name"`
				Host                 *string            `json:"host"`
				DiscoveryMode        *string            `json:"discovery_mode"`
				InstallMode          *string            `json:"install_mode"`
				RenewalMethod        *string            `json:"renewal_method"`
				RenewalThresholdDays *int               `json:"renewal_threshold_days"`
				CredentialRef        *string            `json:"credential_ref"`
				Schedule             *string            `json:"schedule"`
				InstallServerType    *string            `json:"install_server_type"`
				InstallCertPath      *string            `json:"install_cert_path"`
				InstallKeyPath       *string            `json:"install_key_path"`
				InstallReloadMethod  *string            `json:"install_reload_method"`
				VerifyHostPort       *string            `json:"verify_host_port"`
				AutoRenew            *bool              `json:"auto_renew"`
				SSHHostKey           *string            `json:"ssh_host_key"`
				PluginID             *string            `json:"plugin_id"`
				PluginSettings       *map[string]string `json:"plugin_settings"`
				KeyHandlingMode      *string            `json:"key_handling_mode"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&req); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.update", "target", id, AuditOutcomeFailure)
				writeBadRequest(w, "invalid request body")
				return
			}
			update := ManagedTargetUpdate{
				Name: req.Name, Host: req.Host, DiscoveryMode: req.DiscoveryMode,
				InstallMode: req.InstallMode, RenewalMethod: req.RenewalMethod,
				RenewalThresholdDays: req.RenewalThresholdDays,
				CredentialRef:        req.CredentialRef, Schedule: req.Schedule,
				InstallServerType: req.InstallServerType, InstallCertPath: req.InstallCertPath,
				InstallKeyPath: req.InstallKeyPath, InstallReloadMethod: req.InstallReloadMethod,
				VerifyHostPort: req.VerifyHostPort,
				AutoRenew:      req.AutoRenew,
				PluginID:       req.PluginID, PluginSettings: req.PluginSettings,
				SSHHostKey:      req.SSHHostKey,
				KeyHandlingMode: req.KeyHandlingMode,
			}
			merged := existing
			mergeManagedTargetUpdate(&merged, update)
			if req.SSHHostKey != nil {
				if err := validateSSHHostKey(merged.InstallMode, merged.SSHHostKey); err != nil {
					emitAuditEvent(r, auditProvider, pd.ID, "target.update", "target", id, AuditOutcomeFailure)
					writeBadRequest(w, err.Error())
					return
				}
			}
			if err := validateKeyHandlingMode(merged.KeyHandlingMode, merged.InstallMode); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.update", "target", id, AuditOutcomeFailure)
				writeBadRequest(w, err.Error())
				return
			}
			reaffirm := req.AutoRenew != nil && *req.AutoRenew
			fields, stamp, allowed, need := authorizeTargetEgress(pd, auth.roleStore, existing, merged, reaffirm)
			if !allowed {
				refuseTargetEgress(w, r, auditProvider, pd, "target.update", id, fields, need)
				return
			}
			var armedBy string
			if stamp {
				var ok bool
				if armedBy, ok = armStamp(w, r, auditProvider, pd, "target.update", id); !ok {
					return
				}
			}
			if err := egressDeps.validateTargetReferences(r.Context(), pd, existing, merged); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.update", "target", id, AuditOutcomeFailure)
				writeTargetReferenceError(w, err)
				return
			}
			if stamp {
				update.AutoRenewSetBy = &armedBy
			}
			updated, err := store.Update(r.Context(), id, update)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.update", "target", id, AuditOutcomeFailure)
				if errors.Is(err, errManagedTargetInvalidMode) {
					writeBadRequest(w, "invalid discovery_mode, install_mode, or renewal_method")
					return
				}
				if errors.Is(err, errManagedTargetInvalidThreshold) || errors.Is(err, errManagedTargetPluginID) || errors.Is(err, errManagedTargetVerifyHostPort) {
					writeBadRequest(w, err.Error())
					return
				}
				if errors.Is(err, errManagedTargetNotFound) {
					writeNotFound(w, "target not found")
					return
				}
				writeBadRequest(w, err.Error())
				return
			}
			emitAuditEvent(r, auditProvider, pd.ID, "target.update", "target", id, AuditOutcomeSuccess)
			writeJSONData(w, withEffectiveMode(updated))

		case http.MethodDelete:
			existing, err := store.Get(r.Context(), id)
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.delete", "target", id, AuditOutcomeFailure)
				writeNotFound(w, "target not found")
				return
			}
			if !targetVisibleToTenant(pd, existing) {
				emitAuditEvent(r, auditProvider, pd.ID, "target.delete", "target", id, AuditOutcomeDenied)
				writeForbidden(w, "forbidden")
				return
			}
			if err := store.Delete(r.Context(), id); err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "target.delete", "target", id, AuditOutcomeFailure)
				writeServiceUnavailable(w, "delete failed")
				return
			}
			// No FK: the bindings of a deleted target would otherwise outlive it.
			if bs := activeCertTargetBindingStore; bs != nil {
				if err := bs.DeleteByTarget(r.Context(), id); err != nil {
					logging.Warnf("target %s deleted but removing its certificate bindings failed: %v", id, err)
				}
			}
			emitAuditEvent(r, auditProvider, pd.ID, "target.delete", "target", id, AuditOutcomeSuccess)
			w.WriteHeader(http.StatusNoContent)

		default:
			writeMethodNotAllowed(w, "GET, PATCH, DELETE")
		}
	})
}

// probeTargetHostKey is a test seam for the host-key probe dial.
var probeTargetHostKey = func(ctx context.Context, host string, port int) (ssh.PublicKey, error) {
	return agentinstall.ProbeHostKey(ctx, host, port, 10*time.Second)
}

// validateSSHHostKey checks an operator-supplied pin: only ssh/keychain targets
// dial over SSH, and the value must be authorized_keys format. Empty = no pin.
func validateSSHHostKey(installMode, line string) error {
	if line == "" {
		return nil
	}
	if installMode != "ssh" && installMode != "keychain" {
		return errors.New("ssh_host_key is only valid for install_mode ssh or keychain")
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line)); err != nil {
		return errors.New("ssh_host_key must be authorized_keys format")
	}
	return nil
}

func writeTargetReferenceError(w http.ResponseWriter, err error) {
	if errors.Is(err, errTargetStoreUnavailable) {
		writeServiceUnavailable(w, "outbound credential or delivery plugin store not configured")
		return
	}
	writeBadRequest(w, err.Error())
}

// pinnedHostKeyFor picks the key a dial must match: the operator-confirmed pin
// stored on the target wins; a target with none (created before W24-09) falls
// back to the credential's embedded host_public_key.
func pinnedHostKeyFor(t ManagedTarget, credentialKey ssh.PublicKey) ssh.PublicKey {
	if t.SSHHostKey != "" {
		if k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(t.SSHHostKey)); err == nil {
			return k
		}
	}
	return credentialKey
}

// recordHostKeyMismatch is written by the dial site (not the HTTP handler) so
// scheduled scans and renewals leave the same trail as manual ones.
func recordHostKeyMismatch(ctx context.Context, ap AuditProvider, targetID string, mm *agentinstall.HostKeyMismatchError) {
	if ap == nil || mm == nil {
		return
	}
	if err := ap.AppendEntry(ctx, AuditEntry{
		Action: "target.hostkey.mismatch", ActorType: "system", ActorID: "discovery",
		ResourceType: "target", ResourceID: targetID,
		Outcome: AuditOutcomeFailure, ChangeSummary: mm.Error(),
	}); err != nil {
		logging.Infof("audit target.hostkey.mismatch %s: %v", targetID, err)
	}
}
