// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"kryptkeeper/internal/notifications/itsm"
)

// W32-12: approval via ITSM ticket. The bridge in internal/notifications/itsm
// polls tickets; this file supplies its Actor (the real approve route, served
// with an injected principal exactly as chatopsDecide does) and PrincipalMap,
// and the admin API that maps external approvers to hub users.

var (
	itsmApprovalIDRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	itsmExternalIDRE = regexp.MustCompile(`^[A-Za-z0-9_.@:+-]{1,200}$`)
)

// itsmApprovalActor decides a certificate approval as a mapped hub user. No
// handler is bypassed: tenant gate, template approver roles, proposer refusal
// and audit all run in the real route.
type itsmApprovalActor struct {
	mux   *http.ServeMux
	auth  *Authenticator
	users UserProvider
}

var _ itsm.Actor = (*itsmApprovalActor)(nil)

func (a *itsmApprovalActor) Approve(ctx context.Context, approvalID, userID, channel, externalID string) (itsm.Outcome, error) {
	if channel != ChannelITSM || !itsmApprovalIDRE.MatchString(approvalID) {
		return itsm.OutcomeRefused, nil
	}
	ch, err := NewApprovalChannel(ChannelITSM, externalID)
	if err != nil {
		return itsm.OutcomeRefused, nil
	}
	u, ok, err := chatopsFindUser(ctx, a.users, userID)
	if err != nil {
		return "", err
	}
	// Deprovisioned or unknown since the mapping was made: the injected-principal
	// path skips AuthenticatePrincipalDetails, so this check replaces it.
	if !ok || !strings.EqualFold(strings.TrimSpace(u.Status), "active") {
		return itsm.OutcomeRefused, nil
	}
	pd := AuthPrincipal{ID: u.ID, Role: u.Role, AuthType: AuthTypeLocal, Tenant: chatopsTenant(u.Tenant), TenantScoped: true}
	if a.auth == nil || !a.auth.mayDecide(pd) {
		return itsm.OutcomeRefused, nil
	}
	req, err := http.NewRequestWithContext(WithInjectedPrincipal(WithApprovalChannel(ctx, ch), pd),
		http.MethodPost, "/api/v1/approvals/"+approvalID+"/approve", strings.NewReader(""))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	rw := &recordingWriter{hdr: http.Header{}}
	a.mux.ServeHTTP(rw, req)
	switch rw.code {
	case http.StatusOK, http.StatusCreated:
		return itsm.OutcomeApproved, nil
	case http.StatusForbidden:
		return itsm.OutcomeRefused, nil
	case http.StatusNotFound:
		return itsm.OutcomeNotFound, nil
	case http.StatusConflict:
		return itsm.OutcomeAlreadyDecided, nil
	}
	return "", &itsmApprovalStatusError{status: rw.code}
}

type itsmApprovalStatusError struct{ status int }

func (e *itsmApprovalStatusError) Error() string {
	return "approve route answered " + http.StatusText(e.status)
}

// itsmPrincipalMap resolves a mapping to a user only while that user still
// belongs to the tenant the mapping was made in.
type itsmPrincipalMap struct {
	store *itsm.Store
	users UserProvider
}

var _ itsm.PrincipalMap = (*itsmPrincipalMap)(nil)

func (m *itsmPrincipalMap) Lookup(ctx context.Context, kind, externalID string) (string, bool, error) {
	mp, ok, err := m.store.LookupMapping(ctx, kind, externalID)
	if err != nil || !ok {
		return "", false, err
	}
	u, found, err := chatopsFindUser(ctx, m.users, mp.UserID)
	if err != nil || !found || chatopsTenant(u.Tenant) != chatopsTenant(mp.Tenant) {
		return "", false, err
	}
	return u.ID, true, nil
}

// registerITSMApprovalHandlers mounts /api/v1/itsm/principal-map (admin only,
// behind the /api/v1/itsm/** write gate) and starts the approval poller. svc
// may be nil: the route then answers 503 and no poller runs.
func registerITSMApprovalHandlers(mux *http.ServeMux, auth *Authenticator, svc *itsm.Service, auditProvider AuditProvider) {
	var users UserProvider
	if auth != nil {
		users = auth.userProvider
	}
	if svc != nil {
		store := svc.Store()
		b := itsm.NewBridge(itsm.BridgeConfig{
			Links: store, Events: store, Conns: svc.Connector,
			Actor:      &itsmApprovalActor{mux: mux, auth: auth, users: users},
			Principals: &itsmPrincipalMap{store: store, users: users},
			Audit:      ITSMAuditSink(auditProvider),
		})
		go b.Run(context.Background())
	}

	mux.HandleFunc("/api/v1/itsm/principal-map", func(w http.ResponseWriter, r *http.Request) {
		op := map[string]string{http.MethodGet: "list", http.MethodPost: "create", http.MethodDelete: "delete"}[r.Method]
		if op == "" {
			writeMethodNotAllowed(w, "GET, POST, DELETE")
			return
		}
		action := "itsm.principal_map." + op
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", action, "itsm_principal_map", "-", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		audit := func(res string, o AuditOutcome) {
			emitAuditEvent(r, auditProvider, pd.ID, action, "itsm_principal_map", res, o)
		}
		if !isAdminRole(pd.Role) {
			audit("-", AuditOutcomeDenied)
			writeForbidden(w, "admin role required")
			return
		}
		if svc == nil {
			audit("-", AuditOutcomeFailure)
			writeServiceUnavailable(w, "ITSM integration not available (no hub database)")
			return
		}
		tenant := chatopsTenant(pd.Tenant)
		store := svc.Store()
		if r.Method == http.MethodGet {
			list, err := store.ListMappings(r.Context(), tenant)
			if err != nil {
				audit("-", AuditOutcomeFailure)
				writeServiceUnavailable(w, "ITSM store unavailable")
				return
			}
			audit("-", AuditOutcomeSuccess)
			writeJSONData(w, map[string]any{"items": list})
			return
		}

		var body struct {
			Kind       string `json:"kind"`
			ExternalID string `json:"external_id"`
			UserID     string `json:"user_id"`
		}
		if r.Method == http.MethodDelete {
			body.Kind, body.ExternalID = r.URL.Query().Get("kind"), r.URL.Query().Get("external_id")
		} else if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
			audit("-", AuditOutcomeFailure)
			if rejectOversizeBody(w, err) {
				return
			}
			writeBadRequest(w, "invalid JSON body")
			return
		}
		res := body.Kind + ":" + body.ExternalID
		if (body.Kind != "servicenow" && body.Kind != "jira") || !itsmExternalIDRE.MatchString(body.ExternalID) {
			audit("-", AuditOutcomeFailure)
			writeBadRequest(w, "kind must be servicenow or jira; external_id must be 1-200 characters of [A-Za-z0-9_.@:+-]")
			return
		}
		existing, found, err := store.LookupMapping(r.Context(), body.Kind, body.ExternalID)
		if err != nil {
			audit(res, AuditOutcomeFailure)
			writeServiceUnavailable(w, "ITSM store unavailable")
			return
		}
		if found && chatopsTenant(existing.Tenant) != tenant {
			// Another tenant's mapping: indistinguishable from absent on delete, refused on create.
			audit(res, AuditOutcomeDenied)
			if r.Method == http.MethodDelete {
				writeNotFound(w, "mapping not found")
			} else {
				writeForbidden(w, "forbidden")
			}
			return
		}
		if r.Method == http.MethodDelete {
			if !found {
				audit(res, AuditOutcomeFailure)
				writeNotFound(w, "mapping not found")
				return
			}
			if err := store.DeleteMapping(r.Context(), body.Kind, body.ExternalID); err != nil {
				audit(res, AuditOutcomeFailure)
				writeServiceUnavailable(w, "ITSM store unavailable")
				return
			}
			audit(res, AuditOutcomeSuccess)
			writeJSONData(w, map[string]string{"status": "deleted"})
			return
		}
		u, uok, uerr := chatopsFindUser(r.Context(), users, body.UserID)
		if uerr != nil {
			audit(res, AuditOutcomeFailure)
			writeServiceUnavailable(w, "user directory unavailable")
			return
		}
		if !uok || chatopsTenant(u.Tenant) != tenant || !strings.EqualFold(strings.TrimSpace(u.Status), "active") {
			audit(res, AuditOutcomeFailure)
			writeBadRequest(w, "user_id must be an existing active user in your tenant")
			return
		}
		m := itsm.Mapping{Kind: body.Kind, ExternalID: body.ExternalID, UserID: u.ID, Tenant: tenant}
		if err := store.UpsertMapping(r.Context(), m); err != nil {
			audit(res, AuditOutcomeFailure)
			writeServiceUnavailable(w, "ITSM store unavailable")
			return
		}
		emitAuditEventDetail(r, auditProvider, pd.ID, action, "itsm_principal_map", res, AuditOutcomeSuccess, "user_id="+u.ID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(struct {
			Data itsm.Mapping `json:"data"`
		}{Data: m})
	})
}
