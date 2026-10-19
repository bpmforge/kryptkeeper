// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"kryptkeeper/internal/logging"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"kryptkeeper/internal/notifications/chatops"
)

const (
	maxChatopsBodyBytes = 64 << 10
	slackSigningEnv     = "SLACK_SIGNING_SECRET"
)

var chatopsIDRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// chatopsIdentityStoreForActions derives the identity-map store from the
// pending-action store's DB handle (same database, self-healing sidecar table);
// other store types yield nil.
func chatopsIdentityStoreForActions(s PendingActionStore) chatops.IdentityStore {
	if p, ok := s.(*dbPendingActionStore); ok && p != nil {
		return chatopsSQLStore(p.db, p.ph)
	}
	return nil
}

func chatopsSQLStore(db *sql.DB, ph func(int) string) chatops.IdentityStore {
	st := chatops.NewSQLIdentityStore(db, ph)
	if err := st.EnsureSchema(context.Background()); err != nil {
		logging.Warnf("chatops identity map schema unavailable: %v", err)
		return nil
	}
	return st
}

func chatopsTenant(t string) string {
	if strings.TrimSpace(t) == "" {
		return DefaultTenant
	}
	return t
}

// RegisterChatopsHandlers mounts the Slack interaction endpoint (authenticated
// by Slack's request signature, not a Bearer token) and the admin identity-map
// API. store may be nil: the endpoints then answer 503 and no state changes.
func RegisterChatopsHandlers(mux *http.ServeMux, auth *Authenticator, store chatops.IdentityStore, auditProvider AuditProvider) {
	guard := chatops.NewReplayGuard()
	var users UserProvider
	if auth != nil {
		users = auth.userProvider
	}

	mux.HandleFunc("/api/v1/chatops/slack/interactions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxChatopsBodyBytes))
		if err != nil {
			emitAuditEvent(r, auditProvider, "slack", "chatops.signature_failed", "chatops", "slack", AuditOutcomeDenied)
			if rejectOversizeBody(w, err) {
				return
			}
			writeBadRequest(w, "request body unreadable")
			return
		}
		// Verify against the raw body BEFORE parsing or acting on anything.
		now := time.Now()
		vErr := chatops.VerifySlackSignature(os.Getenv(slackSigningEnv), r.Header, raw, now)
		if vErr == nil && guard.Seen(r.Header.Get("X-Slack-Signature"), now) {
			vErr = chatops.ErrReplay
		}
		if vErr != nil {
			emitAuditEventDetail(r, auditProvider, "slack", "chatops.signature_failed", "chatops", "slack", AuditOutcomeDenied, "reason="+vErr.Error())
			writeUnauthorized(w)
			return
		}
		in, err := chatops.ParseInteraction(raw)
		if err != nil {
			emitAuditEvent(r, auditProvider, "slack", "chatops.interaction", "chatops", "slack", AuditOutcomeFailure)
			writeBadRequest(w, "invalid interaction payload")
			return
		}
		kind, id, err := chatops.ParseValue(in.Value)
		verb := ""
		switch in.ActionID {
		case chatops.ActionApprove:
			verb = "approve"
		case chatops.ActionReject:
			verb = "reject"
		}
		if err != nil || verb == "" {
			emitAuditEvent(r, auditProvider, "slack", "chatops.interaction", "chatops", "slack", AuditOutcomeFailure)
			writeBadRequest(w, "invalid interaction action")
			return
		}
		ext := chatops.PlatformSlack + ":" + in.TeamID + "/" + in.UserID
		detail := "external_id=" + truncateForLog(ext) + " verb=" + verb + " target=" + kind + ":" + id
		if store == nil {
			emitAuditEventDetail(r, auditProvider, "slack", "chatops.interaction", "chatops", id, AuditOutcomeFailure, detail)
			writeServiceUnavailable(w, "chatops identity map unavailable")
			return
		}
		m, ok, err := store.Lookup(r.Context(), chatops.Identity{Platform: chatops.PlatformSlack, Workspace: in.TeamID, ExternalID: in.UserID})
		if err != nil {
			emitAuditEventDetail(r, auditProvider, "slack", "chatops.interaction", "chatops", id, AuditOutcomeFailure, detail)
			writeServiceUnavailable(w, "chatops identity map unavailable")
			return
		}
		if !ok {
			emitAuditEventDetail(r, auditProvider, "slack", "chatops.interaction", "chatops", id, AuditOutcomeDenied, detail+" reason=unmapped")
			writeForbidden(w, "forbidden")
			return
		}
		status, msg := chatopsDecide(r.Context(), mux, users, m, ext, in.UserName, kind, id, verb)
		emitAuditEventDetail(r, auditProvider, m.KryptkeeperUser, "chatops.interaction", "chatops", id, chatopsOutcome(status), detail)
		chatopsRespond(w, status, msg)
	})

	mux.HandleFunc("/api/v1/chatops/identity-map", func(w http.ResponseWriter, r *http.Request) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "chatops.identity_map", "chatops", "identity-map", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		audit := func(action, res string, o AuditOutcome) {
			emitAuditEvent(r, auditProvider, pd.ID, action, "chatops", res, o)
		}
		if !isAdminRole(pd.Role) {
			audit("chatops.identity_map."+chatopsOp(r.Method), "identity-map", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}
		if store == nil {
			writeServiceUnavailable(w, "chatops identity map unavailable")
			return
		}
		tenant := chatopsTenant(pd.Tenant)
		switch r.Method {
		case http.MethodGet:
			list, err := store.List(r.Context(), tenant)
			if err != nil {
				writeServiceUnavailable(w, "chatops identity map unavailable")
				return
			}
			writeJSONData(w, list)
		case http.MethodPut, http.MethodDelete:
			var body struct {
				Platform        string `json:"platform"`
				Workspace       string `json:"workspace"`
				ExternalID      string `json:"external_id"`
				KryptkeeperUser string `json:"kryptkeeper_user"`
			}
			if r.Method == http.MethodDelete {
				q := r.URL.Query()
				body.Platform, body.Workspace, body.ExternalID = q.Get("platform"), q.Get("workspace"), q.Get("external_id")
			} else if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
				audit("chatops.identity_map.set", "identity-map", AuditOutcomeFailure)
				writeBadRequest(w, "invalid JSON body")
				return
			}
			op := chatopsOp(r.Method)
			idn := chatops.Identity{Platform: body.Platform, Workspace: body.Workspace, ExternalID: body.ExternalID}
			if (idn.Platform != chatops.PlatformSlack && idn.Platform != chatops.PlatformTeams) || !chatopsIDRE.MatchString(idn.Workspace) || !chatopsIDRE.MatchString(idn.ExternalID) {
				audit("chatops.identity_map."+op, "identity-map", AuditOutcomeFailure)
				writeBadRequest(w, "platform must be slack or teams; workspace and external_id must be 1-64 characters of [A-Za-z0-9_.-]")
				return
			}
			res := idn.Platform + ":" + idn.Workspace + "/" + idn.ExternalID
			existing, found, err := store.Lookup(r.Context(), idn)
			if err != nil {
				audit("chatops.identity_map."+op, res, AuditOutcomeFailure)
				writeServiceUnavailable(w, "chatops identity map unavailable")
				return
			}
			if found && chatopsTenant(existing.Tenant) != tenant {
				// Another tenant's mapping: indistinguishable from absent on delete, refused on set.
				audit("chatops.identity_map."+op, res, AuditOutcomeDenied)
				if r.Method == http.MethodDelete {
					writeNotFound(w, "mapping not found")
				} else {
					writeForbidden(w, "forbidden")
				}
				return
			}
			if r.Method == http.MethodDelete {
				if !found {
					audit("chatops.identity_map.delete", res, AuditOutcomeFailure)
					writeNotFound(w, "mapping not found")
					return
				}
				if err := store.Delete(r.Context(), idn); err != nil {
					audit("chatops.identity_map.delete", res, AuditOutcomeFailure)
					writeServiceUnavailable(w, "chatops identity map unavailable")
					return
				}
				audit("chatops.identity_map.delete", res, AuditOutcomeSuccess)
				writeJSONData(w, map[string]string{"status": "deleted"})
				return
			}
			u, uok, uerr := chatopsFindUser(r.Context(), users, body.KryptkeeperUser)
			if uerr != nil {
				audit("chatops.identity_map.set", res, AuditOutcomeFailure)
				writeServiceUnavailable(w, "user directory unavailable")
				return
			}
			if !uok || chatopsTenant(u.Tenant) != tenant {
				audit("chatops.identity_map.set", res, AuditOutcomeFailure)
				writeBadRequest(w, "kryptkeeper_user must be an existing user in your tenant")
				return
			}
			m := chatops.Mapping{Identity: idn, KryptkeeperUser: u.ID, Tenant: tenant, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
			if err := store.Upsert(r.Context(), m); err != nil {
				audit("chatops.identity_map.set", res, AuditOutcomeFailure)
				writeServiceUnavailable(w, "chatops identity map unavailable")
				return
			}
			emitAuditEventDetail(r, auditProvider, pd.ID, "chatops.identity_map.set", "chatops", res, AuditOutcomeSuccess, "kryptkeeper_user="+u.ID)
			writeJSONData(w, m)
		default:
			writeMethodNotAllowed(w, "GET, PUT, DELETE")
		}
	})
}

// chatopsOutcome maps a chatopsDecide status to the audit outcome.
func chatopsOutcome(status int) AuditOutcome {
	switch {
	case status >= 500:
		return AuditOutcomeFailure
	case status >= 300 && status != http.StatusAccepted:
		return AuditOutcomeDenied
	}
	return AuditOutcomeSuccess
}

// chatopsRespond writes a chatopsDecide result: 202 passes the inner quorum body
// through unchanged, 2xx wraps the status word, anything else is an error envelope.
func chatopsRespond(w http.ResponseWriter, status int, msg string) {
	switch {
	case status == http.StatusAccepted:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(msg))
	case status < 300:
		writeJSONData(w, map[string]string{"status": msg})
	default:
		writeErrorEnvelope(w, status, chatopsErrorCode(status), msg)
	}
}

func chatopsOp(method string) string {
	if method == http.MethodDelete {
		return "delete"
	}
	return "set"
}

func chatopsErrorCode(status int) string {
	switch status {
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusConflict:
		return "conflict"
	case http.StatusBadGateway:
		return "bad_gateway"
	}
	return "service_unavailable"
}

func chatopsFindUser(ctx context.Context, users UserProvider, id string) (UserRecord, bool, error) {
	if users == nil || strings.TrimSpace(id) == "" {
		return UserRecord{}, false, nil
	}
	return lookupPrincipalUser(ctx, users, id)
}

// recordingWriter captures the inner handler's response (httptest is test-only).
type recordingWriter struct {
	hdr  http.Header
	code int
	body bytes.Buffer
}

func (w *recordingWriter) Header() http.Header { return w.hdr }
func (w *recordingWriter) WriteHeader(c int) {
	if w.code == 0 {
		w.code = c
	}
}
func (w *recordingWriter) Write(b []byte) (int, error) {
	w.WriteHeader(http.StatusOK)
	return w.body.Write(b)
}

// chatopsDecide resolves the mapping to an active user, builds the principal, and serves the real
// approve/reject route on mux with the channel + injected principal in ctx. No handler is bypassed:
// role gate, proposer refusal, tenant gate, quorum, execution and audit all run unchanged.
// Return: 200 + "approved"/"rejected"; 202 + the inner JSON body (quorum not yet met);
// otherwise an error status and a message safe to show the chat user.
func chatopsDecide(ctx context.Context, mux *http.ServeMux, users UserProvider, m chatops.Mapping,
	externalID, displayName, kind, id, verb string) (int, string) {
	if (verb != "approve" && verb != "reject") || (kind != "approval" && kind != "action") {
		return http.StatusBadRequest, "invalid request"
	}
	u, ok, err := chatopsFindUser(ctx, users, m.KryptkeeperUser)
	if err != nil {
		return http.StatusServiceUnavailable, "user directory unavailable"
	}
	// Deprovisioned or unknown after the message was sent: the injected-principal
	// path skips AuthenticatePrincipalDetails, so this check replaces it.
	if !ok || !strings.EqualFold(strings.TrimSpace(u.Status), "active") || chatopsTenant(u.Tenant) != chatopsTenant(m.Tenant) {
		return http.StatusForbidden, "forbidden"
	}
	pd := AuthPrincipal{ID: u.ID, Role: u.Role, AuthType: AuthTypeLocal, Tenant: chatopsTenant(u.Tenant), TenantScoped: true}
	ch, err := NewApprovalChannel(ChannelChatOps, externalID)
	if err != nil {
		return http.StatusForbidden, "forbidden"
	}
	base := "/api/v1/approvals/"
	if kind == "action" {
		base = "/api/v1/pending-actions/"
	}
	body := ""
	if verb == "reject" {
		name := []rune(displayName)
		if len(name) > 64 {
			name = name[:64]
		}
		via := "Slack"
		if strings.HasPrefix(externalID, chatops.PlatformTeams+":") {
			via = "Teams"
		}
		b, _ := json.Marshal(map[string]string{"reason": "rejected from " + via + " by " + strings.Map(func(r rune) rune {
			if r < 0x20 {
				return -1
			}
			return r
		}, string(name))})
		body = string(b)
	}
	ictx := WithInjectedPrincipal(WithApprovalChannel(ctx, ch), pd)
	req, err := http.NewRequestWithContext(ictx, http.MethodPost, base+id+"/"+verb, strings.NewReader(body))
	if err != nil {
		return http.StatusBadGateway, "decision could not be processed"
	}
	req.Header.Set("Content-Type", "application/json")
	rw := &recordingWriter{hdr: http.Header{}}
	mux.ServeHTTP(rw, req)
	switch rw.code {
	case http.StatusOK, http.StatusCreated:
		if verb == "reject" {
			return http.StatusOK, "rejected"
		}
		return http.StatusOK, "approved"
	case http.StatusAccepted:
		return http.StatusAccepted, rw.body.String()
	case http.StatusForbidden, http.StatusConflict, http.StatusNotFound:
		return rw.code, chatopsInnerMessage(rw.body.Bytes(), rw.code)
	}
	return http.StatusBadGateway, "decision could not be processed"
}

func chatopsInnerMessage(b []byte, status int) string {
	var e struct {
		Message string `json:"message"`
		Detail  string `json:"detail"`
	}
	if json.Unmarshal(b, &e) == nil {
		if e.Message != "" {
			return e.Message
		}
		if e.Detail != "" {
			return e.Detail
		}
	}
	return http.StatusText(status)
}
