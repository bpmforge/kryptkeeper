// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"kryptkeeper/internal/agentdiscovery"
)

// WinRMPreflighter probes what a Windows credential can do on its host
// without changing it. Injected so the handler test needs no listener;
// production passes agentdiscovery.PreflightWinRM with env-configured trust.
type WinRMPreflighter func(ctx context.Context, cfg agentdiscovery.WinRMConfig) agentdiscovery.WinRMPreflight

// ProductionWinRMPreflighter builds listener trust the same way the
// renewal executor does, so the preflight verifies exactly what the
// install will.
func ProductionWinRMPreflighter(ctx context.Context, cfg agentdiscovery.WinRMConfig) agentdiscovery.WinRMPreflight {
	roots, err := agentdiscovery.WinRMRootCAsFromEnv()
	if err != nil {
		return agentdiscovery.WinRMPreflight{Level: agentdiscovery.PreflightUnreachable, Detail: err.Error()}
	}
	cfg.RootCAs = roots
	return agentdiscovery.PreflightWinRM(ctx, cfg, nil)
}

// Found 2026-08-20 walking the Target Setup wizard as an end user: the
// Credential step asks for "a credential already configured for this hub"
// — and NOTHING could configure one. The store's Create had no callers
// outside tests: no HTTP handler, no CLI. Every path that resolves a
// credential_ref (ssh/f5/citrix/k8s/iis push, adcs_live inventory, AD
// sync) was therefore unusable in a real deployment.
//
// The store itself anticipated this handler — its Get doc comment says
// "this is the method an eventual HTTP handler would call" — so this file
// is the planned missing piece, not a redesign.
//
// The contract that matters: plaintext goes IN and never comes back out.
// Responses carry metadata only; Resolve stays a Go-internal call. There
// is deliberately no update/rotate route — that is W5-10's disclosed gap,
// and adding one here would un-disclose it.

// validateSSHCredentialPayload checks the sudo_* combination at the API edge so
// a bad mix fails at create time, not at the first scan. Errors never carry
// payload values.
func validateSSHCredentialPayload(raw json.RawMessage) error {
	var p sshCredentialPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return errors.New("ssh_key payload is not the documented JSON object shape")
	}
	return p.validatePrivilege()
}

func newOutboundCredentialID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "cred-" + hex.EncodeToString(buf), nil
}

func registerCredentialHandlers(mux *http.ServeMux, auth *Authenticator, store OutboundCredentialStore, auditProvider AuditProvider, preflight WinRMPreflighter) {
	authorize := func(w http.ResponseWriter, r *http.Request, action string) (AuthPrincipal, bool) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", action, "credential", "-", AuditOutcomeDenied)
			writeUnauthorized(w)
			return AuthPrincipal{}, false
		}
		// A credential reaches devices as root/Administrator. Creating or
		// deleting one is an admin act, same bar as the key endpoints.
		if !isAdminRole(pd.Role) {
			emitAuditEvent(r, auditProvider, pd.ID, action, "credential", "-", AuditOutcomeDenied)
			writeForbidden(w, "admin role required for outbound credentials")
			return AuthPrincipal{}, false
		}
		return pd, true
	}

	unconfigured := func(w http.ResponseWriter) bool {
		if store != nil {
			return false
		}
		// newOutboundCredentialStoreFromEnv fails closed without a
		// passphrase; name the fix rather than returning a bare 503.
		writeServiceUnavailable(w, "outbound credential store not configured (set APP_CREDENTIAL_STORE_PASSPHRASE or KRYPTKEEPER_KEYSTORE_PASSPHRASE)")
		return true
	}

	mux.HandleFunc("/api/v1/credentials", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			pd, ok := authorize(w, r, "credential.list")
			if !ok || unconfigured(w) {
				return
			}
			principal := pd.ID
			metas, err := store.List(r.Context())
			if err != nil {
				emitAuditEvent(r, auditProvider, principal, "credential.list", "credential", "-", AuditOutcomeFailure)
				writeServiceUnavailable(w, "credential store unavailable")
				return
			}
			visible := make([]OutboundCredentialMeta, 0, len(metas))
			for _, m := range metas {
				if stampedTenantVisible(pd, m.Tenant) {
					visible = append(visible, m)
				}
			}
			metas = visible
			writeJSONData(w, map[string]any{"items": metas})

		case http.MethodPost:
			pd, ok := authorize(w, r, "credential.create")
			if !ok || unconfigured(w) {
				return
			}
			principal := pd.ID
			var req struct {
				Name           string `json:"name"`
				CredentialType string `json:"credential_type"`
				// Payload is the secret material, shaped by the consumer
				// (an SSH PEM + user, a WinRM URL + password, ...). The
				// store encrypts it opaquely; it never appears in any
				// response, log, or audit detail.
				Payload json.RawMessage `json:"payload"`
				// Source is "local" (the default: payload is encrypted and
				// stored here) or "external" (W38-07, D-324: only a reference
				// is stored and the secret is fetched from SourceID's manager
				// at each use; payload must then be absent).
				Source    string            `json:"source"`
				SourceID  string            `json:"source_id"`
				Reference map[string]string `json:"reference"`
				Static    map[string]string `json:"static"`
			}
			decodeErr := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024)).Decode(&req)
			if rejectOversizeBody(w, decodeErr) {
				return
			}
			if req.Source == CredentialSourceExternal {
				createExternalCredential(w, r, pd, store, auditProvider, req.Name, req.CredentialType, req.SourceID, ExternalReference{Reference: req.Reference, Static: req.Static}, len(req.Payload) > 0, decodeErr)
				return
			}
			if req.Source != "" && req.Source != CredentialSourceLocal {
				emitAuditEvent(r, auditProvider, principal, "credential.create", "credential", "-", AuditOutcomeFailure)
				writeBadRequest(w, `source must be "local" or "external"`)
				return
			}
			if decodeErr != nil ||
				strings.TrimSpace(req.Name) == "" || len(req.Payload) == 0 {
				emitAuditEvent(r, auditProvider, principal, "credential.create", "credential", "-", AuditOutcomeFailure)
				writeBadRequest(w, "name, credential_type and payload are required")
				return
			}
			if req.CredentialType == CredentialTypeSSHKey {
				if err := validateSSHCredentialPayload(req.Payload); err != nil {
					emitAuditEvent(r, auditProvider, principal, "credential.create", "credential", req.Name, AuditOutcomeFailure)
					writeBadRequest(w, err.Error())
					return
				}
			}
			id, err := newOutboundCredentialID()
			if err != nil {
				writeServiceUnavailable(w, "could not generate credential id")
				return
			}
			meta, err := store.Create(r.Context(), id, strings.TrimSpace(req.Name), req.CredentialType, pd.Tenant, []byte(req.Payload))
			if err != nil {
				emitAuditEvent(r, auditProvider, principal, "credential.create", "credential", req.Name, AuditOutcomeFailure)
				writeBadRequest(w, err.Error())
				return
			}
			emitAuditEventDetail(r, auditProvider, principal, "credential.create", "credential", meta.ID, AuditOutcomeSuccess,
				fmt.Sprintf(`{"name":%q,"type":%q}`, meta.Name, meta.CredentialType))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(struct {
				Data OutboundCredentialMeta `json:"data"`
			}{Data: meta})

		default:
			writeMethodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
		}
	})

	mux.HandleFunc("/api/v1/credentials/", func(w http.ResponseWriter, r *http.Request) {
		if id, isPreflight := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/credentials/"), "/preflight"); isPreflight {
			handleCredentialPreflight(w, r, id, store, auditProvider, preflight, authorize, unconfigured)
			return
		}
		if id, isPriv := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/credentials/"), "/privileged"); isPriv {
			handleCredentialPrivileged(w, r, id, store, auditProvider, authorize, unconfigured)
			return
		}
		if r.Method != http.MethodDelete {
			writeMethodNotAllowed(w, http.MethodDelete)
			return
		}
		pd, ok := authorize(w, r, "credential.delete")
		if !ok || unconfigured(w) {
			return
		}
		principal := pd.ID
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/credentials/")
		if id == "" || strings.Contains(id, "/") {
			writeBadRequest(w, "credential id required")
			return
		}
		existing, err := store.Get(r.Context(), id)
		if err != nil {
			emitAuditEvent(r, auditProvider, principal, "credential.delete", "credential", id, AuditOutcomeFailure)
			writeNotFound(w, "credential not found")
			return
		}
		if !stampedTenantVisible(pd, existing.Tenant) {
			emitAuditEvent(r, auditProvider, principal, "credential.delete", "credential", id, AuditOutcomeDenied)
			writeNotFound(w, "credential not found")
			return
		}
		if err := store.Delete(r.Context(), id); err != nil {
			emitAuditEvent(r, auditProvider, principal, "credential.delete", "credential", id, AuditOutcomeFailure)
			writeServiceUnavailable(w, "delete failed")
			return
		}
		emitAuditEvent(r, auditProvider, principal, "credential.delete", "credential", id, AuditOutcomeSuccess)
		w.WriteHeader(http.StatusNoContent)
	})
}

// createExternalCredential stores a credential whose secret stays in an
// external manager (W38-07, D-324). The request carries no secret and the store
// keeps none: just the source and the reference.
func createExternalCredential(w http.ResponseWriter, r *http.Request, pd AuthPrincipal, store OutboundCredentialStore, auditProvider AuditProvider,
	name, credentialType, sourceID string, ref ExternalReference, hasPayload bool, decodeErr error) {
	const action = "credential.create"
	fail := func(msg string) {
		emitAuditEvent(r, auditProvider, pd.ID, action, "credential", strings.TrimSpace(name), AuditOutcomeFailure)
		writeBadRequest(w, msg)
	}
	creator, ok := store.(externalCredentialCreator)
	switch {
	case !ok:
		writeServiceUnavailable(w, "this credential store cannot hold external credentials")
	case decodeErr != nil || strings.TrimSpace(name) == "" || strings.TrimSpace(sourceID) == "":
		fail("name, credential_type, source_id and reference are required for an external credential")
	case hasPayload:
		fail("an external credential stores no secret: remove payload, and name the secret with reference")
	default:
		meta, err := creator.CreateExternal(r.Context(), mustCredentialID(), strings.TrimSpace(name), credentialType, pd.Tenant, strings.TrimSpace(sourceID), ref)
		switch {
		case errors.Is(err, errCredentialSourceNotFound):
			fail(fmt.Sprintf("credential source %q does not exist", sourceID))
		case err != nil:
			fail(err.Error())
		default:
			emitAuditEventDetail(r, auditProvider, pd.ID, action, "credential", meta.ID, AuditOutcomeSuccess,
				fmt.Sprintf(`{"name":%q,"type":%q,"source":"external","source_id":%q}`, meta.Name, meta.CredentialType, meta.SourceID))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(struct {
				Data OutboundCredentialMeta `json:"data"`
			}{Data: meta})
		}
	}
}

func mustCredentialID() string {
	id, err := newOutboundCredentialID()
	if err != nil {
		return "cred-" + fmt.Sprint(time.Now().UnixNano())
	}
	return id
}

// handleCredentialPreflight is W18-11: POST /api/v1/credentials/{id}/preflight.
// The plaintext is resolved here, used for one WinRM session, and never
// leaves the process; the response carries the verdict only.
func handleCredentialPreflight(w http.ResponseWriter, r *http.Request, id string, store OutboundCredentialStore,
	auditProvider AuditProvider, preflight WinRMPreflighter,
	authorize func(http.ResponseWriter, *http.Request, string) (AuthPrincipal, bool), unconfigured func(http.ResponseWriter) bool) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	pd, ok := authorize(w, r, "credential.preflight")
	if !ok || unconfigured(w) {
		return
	}
	principal := pd.ID
	if id == "" || strings.Contains(id, "/") {
		writeBadRequest(w, "credential id required")
		return
	}
	meta, err := store.Get(r.Context(), id)
	if err != nil {
		emitAuditEvent(r, auditProvider, principal, "credential.preflight", "credential", id, AuditOutcomeFailure)
		writeNotFound(w, "credential not found")
		return
	}
	// Preflight resolves the plaintext, so another tenant's credential must be
	// as unreachable here as on delete.
	if !stampedTenantVisible(pd, meta.Tenant) {
		emitAuditEvent(r, auditProvider, principal, "credential.preflight", "credential", id, AuditOutcomeDenied)
		writeNotFound(w, "credential not found")
		return
	}
	if meta.CredentialType != CredentialTypeWindowsPassword {
		emitAuditEvent(r, auditProvider, principal, "credential.preflight", "credential", id, AuditOutcomeFailure)
		writeBadRequest(w, fmt.Sprintf("preflight is defined for %s credentials only; %q is %s", CredentialTypeWindowsPassword, id, meta.CredentialType))
		return
	}
	if preflight == nil {
		writeServiceUnavailable(w, "WinRM preflight not available")
		return
	}
	plaintext, err := store.Resolve(r.Context(), id)
	if err != nil {
		emitAuditEvent(r, auditProvider, principal, "credential.preflight", "credential", id, AuditOutcomeFailure)
		writeServiceUnavailable(w, resolveFailure(id, err).Error())
		return
	}
	var payload struct {
		BaseURL  string `json:"base_url"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(plaintext, &payload); err != nil || payload.BaseURL == "" || payload.Username == "" {
		writeBadRequest(w, "credential payload lacks base_url/username")
		return
	}
	verdict := preflight(r.Context(), agentdiscovery.WinRMConfig{EndpointURL: payload.BaseURL, Username: payload.Username, Password: payload.Password})
	// The verdict is auditable; the detail may quote the host's fault text
	// but never the credential.
	emitAuditEventDetail(r, auditProvider, principal, "credential.preflight", "credential", id, AuditOutcomeSuccess,
		fmt.Sprintf(`{"level":%q,"can_discover":%t,"can_install":%t}`, verdict.Level, verdict.CanDiscover, verdict.CanInstall))
	writeJSONData(w, struct {
		CredentialID string `json:"credential_id"`
		agentdiscovery.WinRMPreflight
	}{CredentialID: id, WinRMPreflight: verdict})
}

// handleCredentialPrivileged sets or clears the manual privileged flag (W34-11,
// D-208): flag and audit only, no approval gate. The automatic path is the sudo
// preflight; both audit credential.privileged.set with the reason and source.
func handleCredentialPrivileged(w http.ResponseWriter, r *http.Request, id string, store OutboundCredentialStore,
	auditProvider AuditProvider,
	authorize func(http.ResponseWriter, *http.Request, string) (AuthPrincipal, bool), unconfigured func(http.ResponseWriter) bool) {
	if r.Method != http.MethodPut {
		writeMethodNotAllowed(w, http.MethodPut)
		return
	}
	pd, ok := authorize(w, r, "credential.privileged.set")
	if !ok || unconfigured(w) {
		return
	}
	if id == "" || strings.Contains(id, "/") {
		writeBadRequest(w, "credential id required")
		return
	}
	var req struct {
		Privileged *bool  `json:"privileged"`
		Reason     string `json:"reason"`
	}
	decodeErr := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4*1024)).Decode(&req)
	if rejectOversizeBody(w, decodeErr) {
		return
	}
	if decodeErr != nil || req.Privileged == nil || len(req.Reason) > 500 {
		emitAuditEvent(r, auditProvider, pd.ID, "credential.privileged.set", "credential", id, AuditOutcomeFailure)
		writeBadRequest(w, "privileged (boolean) is required; reason is at most 500 characters")
		return
	}
	meta, err := store.Get(r.Context(), id)
	if err != nil || !stampedTenantVisible(pd, meta.Tenant) {
		outcome := AuditOutcomeFailure
		if err == nil {
			outcome = AuditOutcomeDenied
		}
		emitAuditEvent(r, auditProvider, pd.ID, "credential.privileged.set", "credential", id, outcome)
		writeNotFound(w, "credential not found")
		return
	}
	ps, ok := store.(credentialPrivilegeStore)
	if !ok {
		emitAuditEvent(r, auditProvider, pd.ID, "credential.privileged.set", "credential", id, AuditOutcomeFailure)
		writeServiceUnavailable(w, "this credential store cannot carry the privileged flag")
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if *req.Privileged && reason == "" {
		reason = "marked privileged by an administrator"
	}
	if err := ps.SetPrivileged(r.Context(), id, *req.Privileged, reason, "manual:"+pd.ID); err != nil {
		emitAuditEvent(r, auditProvider, pd.ID, "credential.privileged.set", "credential", id, AuditOutcomeFailure)
		writeServiceUnavailable(w, "could not update the credential")
		return
	}
	emitAuditEventDetail(r, auditProvider, pd.ID, "credential.privileged.set", "credential", id, AuditOutcomeSuccess,
		fmt.Sprintf(`{"privileged":%t,"reason":%q,"source":"manual"}`, *req.Privileged, reason))
	updated, err := store.Get(r.Context(), id)
	if err != nil {
		updated = meta
	}
	writeJSONData(w, updated)
}
