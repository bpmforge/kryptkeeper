// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"kryptkeeper/internal/notifications/chatops"
	"kryptkeeper/internal/notifications/chatops/teams"
)

const (
	maxChatopsTeamsBodyBytes = 256 << 10
	teamsAppIDEnv            = "TEAMS_APP_ID"
)

// chatopsUserProvider returns the authenticator's user directory (nil-safe).
func chatopsUserProvider(auth *Authenticator) UserProvider {
	if auth == nil {
		return nil
	}
	return auth.userProvider
}

// RegisterChatopsTeamsHandlers mounts the Teams (Azure Bot Service) activity
// endpoint. It carries no Bearer token: the Bot Framework JWT is the
// authentication. validator and guard may be nil (defaults: the public Bot
// Framework key set and a fresh ReplayGuard); the validator's AppID is
// overridden per request from TEAMS_APP_ID, and an empty value fails closed.
// idStore may be nil: the endpoint then answers 503 after authentication.
func RegisterChatopsTeamsHandlers(mux *http.ServeMux, users UserProvider, auditProvider AuditProvider,
	idStore chatops.IdentityStore, validator *teams.Validator, guard *chatops.ReplayGuard) {
	if validator == nil {
		validator = teams.NewValidator()
	}
	if guard == nil {
		guard = chatops.NewReplayGuard()
	}
	mux.HandleFunc("/api/v1/chatops/teams/activities", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		refuse := func(reason string) {
			emitAuditEventDetail(r, auditProvider, "teams", "chatops.signature_failed", "chatops", "teams", AuditOutcomeDenied, "reason="+reason)
			writeUnauthorized(w)
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxChatopsTeamsBodyBytes))
		if err != nil {
			emitAuditEvent(r, auditProvider, "teams", "chatops.signature_failed", "chatops", "teams", AuditOutcomeDenied)
			if rejectOversizeBody(w, err) {
				return
			}
			writeBadRequest(w, "request body unreadable")
			return
		}
		// The activity is decoded only to learn serviceUrl for the token's
		// serviceurl claim check; nothing in it is trusted before Validate passes.
		act, perr := teams.ParseActivity(raw)
		if perr != nil && !errors.Is(perr, teams.ErrIgnored) {
			refuse("malformed")
			return
		}
		v := *validator
		v.AppID = os.Getenv(teamsAppIDEnv)
		if err := v.Validate(r.Context(), r.Header.Get("Authorization"), act.ServiceURL); err != nil {
			refuse("invalid_token")
			return
		}
		if errors.Is(perr, teams.ErrIgnored) {
			writeJSONData(w, map[string]string{"status": "ignored"})
			return
		}
		now := time.Now()
		if act.ID == "" || act.CheckFresh(now) != nil {
			refuse("stale")
			return
		}
		if guard.Seen("teams:"+act.ID, now) {
			refuse("replay")
			return
		}
		verb := act.Action("kk_action")
		kind, id, perr := chatops.ParseValue(act.Action("kind") + ":" + act.Action("id"))
		if perr != nil || (verb != "approve" && verb != "reject") {
			emitAuditEvent(r, auditProvider, "teams", "chatops.interaction", "chatops", "teams", AuditOutcomeFailure)
			writeBadRequest(w, "invalid interaction action")
			return
		}
		tenant, oid := act.ChannelData.Tenant.ID, act.From.AADObjectID
		ext := chatops.PlatformTeams + ":" + tenant + "/" + oid
		detail := "external_id=" + truncateForLog(ext) + " verb=" + verb + " target=" + kind + ":" + id
		if idStore == nil {
			emitAuditEventDetail(r, auditProvider, "teams", "chatops.interaction", "chatops", id, AuditOutcomeFailure, detail)
			writeServiceUnavailable(w, "chatops identity map unavailable")
			return
		}
		var m chatops.Mapping
		found := false
		if tenant != "" && oid != "" {
			m, found, err = idStore.Lookup(r.Context(), chatops.Identity{Platform: chatops.PlatformTeams, Workspace: tenant, ExternalID: oid})
			if err != nil {
				emitAuditEventDetail(r, auditProvider, "teams", "chatops.interaction", "chatops", id, AuditOutcomeFailure, detail)
				writeServiceUnavailable(w, "chatops identity map unavailable")
				return
			}
		}
		if !found {
			// Also enforces the AAD-tenant restriction: only tenants with a mapping can act.
			emitAuditEventDetail(r, auditProvider, "teams", "chatops.interaction", "chatops", id, AuditOutcomeDenied, detail+" reason=unmapped")
			writeForbidden(w, "forbidden")
			return
		}
		status, msg := chatopsDecide(r.Context(), mux, users, m, ext, act.From.Name, kind, id, verb)
		emitAuditEventDetail(r, auditProvider, m.KryptkeeperUser, "chatops.interaction", "chatops", id, chatopsOutcome(status), detail)
		chatopsRespond(w, status, msg)
	})
}
