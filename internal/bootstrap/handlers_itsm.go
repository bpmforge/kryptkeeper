// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"kryptkeeper/internal/logging"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"kryptkeeper/internal/notifications/itsm"
)

// WithITSM gives the ITSM API (W32-10) the process's one itsm.Service. Nil
// (no database) is valid: the routes then answer 503.
func WithITSM(s *itsm.Service) ServerOption {
	return func(c *ServerConfig) { c.itsm = s }
}

// ITSMCredentialResolverFromEnv returns an itsm.CredentialResolver over the
// encrypted outbound credential store. The store opens on first use so a hub
// without a credential passphrase still starts; Resolve then fails closed.
func ITSMCredentialResolverFromEnv() itsm.CredentialResolver { return &lazyCredentialResolver{} }

type lazyCredentialResolver struct {
	once  sync.Once
	store OutboundCredentialStore
}

func (l *lazyCredentialResolver) Resolve(ctx context.Context, id string) ([]byte, error) {
	l.once.Do(func() { l.store = newOutboundCredentialStoreFromEnv() })
	if l.store == nil {
		return nil, errors.New("outbound credential store not configured")
	}
	return l.store.Resolve(ctx, id)
}

// ITSMAuditSink maps the background audit records of the ITSM queue onto the
// hub's audit trail as system actions (the approval_expiry.go pattern).
func ITSMAuditSink(auditProvider AuditProvider) func(context.Context, itsm.AuditRecord) {
	return func(ctx context.Context, rec itsm.AuditRecord) {
		if auditProvider == nil {
			return
		}
		outcome := AuditOutcomeSuccess
		if rec.Outcome != itsm.OutcomeSuccess {
			outcome = AuditOutcomeFailure
		}
		err := auditProvider.AppendEntry(ctx, AuditEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339), Action: rec.Action, ActorType: "system", ActorID: "itsm-queue",
			ResourceType: "itsm_event", ResourceID: rec.ResourceID, Outcome: outcome, Tenant: rec.Tenant, ChangeSummary: rec.ChangeSummary,
		})
		if err != nil {
			logging.Errorf("itsm: audit append failed action=%s id=%s: %v", rec.Action, rec.ResourceID, err)
		}
	}
}

const (
	itsmDefaultEventLimit = 50
	itsmMaxEventLimit     = 200
)

// registerITSMHandlers mounts /api/v1/itsm/{connections,events}. Admin only:
// a connection names a credential that creates tickets in the customer's ITSM.
func registerITSMHandlers(mux *http.ServeMux, auth *Authenticator, svc *itsm.Service, creds OutboundCredentialStore, auditProvider AuditProvider, pluginCheck itsmPluginCheckFunc) {
	authorize := func(w http.ResponseWriter, r *http.Request, action, resType string) (AuthPrincipal, bool) {
		pd, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", action, resType, "-", AuditOutcomeDenied)
			writeUnauthorized(w)
			return AuthPrincipal{}, false
		}
		if !isAdminRole(pd.Role) {
			emitAuditEvent(r, auditProvider, pd.ID, action, resType, "-", AuditOutcomeDenied)
			writeForbidden(w, "admin role required for ITSM connections")
			return AuthPrincipal{}, false
		}
		return pd, true
	}
	unconfigured := func(w http.ResponseWriter, r *http.Request, pd AuthPrincipal, action, resType, id string) bool {
		if svc != nil {
			return false
		}
		emitAuditEvent(r, auditProvider, pd.ID, action, resType, id, AuditOutcomeFailure)
		writeServiceUnavailable(w, "ITSM integration not available (no hub database)")
		return true
	}

	mux.HandleFunc("/api/v1/itsm/connections", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			pd, ok := authorize(w, r, "itsm.connection.list", "itsm_connection")
			if !ok || unconfigured(w, r, pd, "itsm.connection.list", "itsm_connection", "-") {
				return
			}
			all, err := svc.Store().ListConnections(r.Context())
			if err != nil {
				emitAuditEvent(r, auditProvider, pd.ID, "itsm.connection.list", "itsm_connection", "-", AuditOutcomeFailure)
				writeServiceUnavailable(w, "ITSM store unavailable")
				return
			}
			visible := make([]itsm.Connection, 0, len(all))
			for _, c := range all {
				if stampedTenantVisible(pd, c.Tenant) {
					visible = append(visible, c)
				}
			}
			writeJSONData(w, map[string]any{"items": visible})
		case http.MethodPost:
			createITSMConnection(w, r, authorize, unconfigured, svc, creds, auditProvider, pluginCheck)
		default:
			writeMethodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
		}
	})

	mux.HandleFunc("/api/v1/itsm/connections/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/itsm/connections/")
		if testID, isTest := strings.CutSuffix(id, "/test"); isTest && testID != "" && !strings.Contains(testID, "/") {
			testITSMConnection(w, r, testID, authorize, unconfigured, svc, auditProvider)
			return
		}
		switch r.Method {
		case http.MethodGet:
			pd, ok := authorize(w, r, "itsm.connection.get", "itsm_connection")
			if !ok || unconfigured(w, r, pd, "itsm.connection.get", "itsm_connection", id) {
				return
			}
			c, err := svc.Store().GetConnection(r.Context(), id)
			if err != nil || !stampedTenantVisible(pd, c.Tenant) {
				writeNotFound(w, "ITSM connection not found")
				return
			}
			writeJSONData(w, c)
		case http.MethodDelete:
			pd, ok := authorize(w, r, itsm.ActionConnectionDelete, "itsm_connection")
			if !ok || unconfigured(w, r, pd, itsm.ActionConnectionDelete, "itsm_connection", id) {
				return
			}
			if id == "" || strings.Contains(id, "/") {
				emitAuditEvent(r, auditProvider, pd.ID, itsm.ActionConnectionDelete, "itsm_connection", "-", AuditOutcomeFailure)
				writeBadRequest(w, "connection id required")
				return
			}
			c, err := svc.Store().GetConnection(r.Context(), id)
			if err != nil || !stampedTenantVisible(pd, c.Tenant) {
				emitAuditEvent(r, auditProvider, pd.ID, itsm.ActionConnectionDelete, "itsm_connection", id, AuditOutcomeFailure)
				writeNotFound(w, "ITSM connection not found")
				return
			}
			switch err := svc.Store().DeleteConnection(r.Context(), id); {
			case errors.Is(err, itsm.ErrConnectionInUse):
				emitAuditEvent(r, auditProvider, pd.ID, itsm.ActionConnectionDelete, "itsm_connection", id, AuditOutcomeFailure)
				writeConflict(w, "connection has ticket history; disable it instead")
			case err != nil:
				emitAuditEvent(r, auditProvider, pd.ID, itsm.ActionConnectionDelete, "itsm_connection", id, AuditOutcomeFailure)
				writeServiceUnavailable(w, "delete failed")
			default:
				emitAuditEvent(r, auditProvider, pd.ID, itsm.ActionConnectionDelete, "itsm_connection", id, AuditOutcomeSuccess)
				w.WriteHeader(http.StatusNoContent)
			}
		default:
			writeMethodNotAllowed(w, http.MethodGet+", "+http.MethodDelete)
		}
	})

	mux.HandleFunc("/api/v1/itsm/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		pd, ok := authorize(w, r, "itsm.event.list", "itsm_event")
		if !ok || unconfigured(w, r, pd, "itsm.event.list", "itsm_event", "-") {
			return
		}
		status := r.URL.Query().Get("status")
		switch status {
		case "", itsm.StatusPending, itsm.StatusCreated, itsm.StatusResolved, itsm.StatusFailed:
		default:
			writeBadRequest(w, "status must be pending, created, resolved or failed")
			return
		}
		limit := itsmDefaultEventLimit
		if raw := r.URL.Query().Get("limit"); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 1 {
				writeBadRequest(w, "limit must be a positive integer")
				return
			}
			limit = min(n, itsmMaxEventLimit)
		}
		rows, err := svc.Store().ListEvents(r.Context(), status, itsmMaxEventLimit)
		if err != nil {
			writeServiceUnavailable(w, "ITSM store unavailable")
			return
		}
		// Filter by tenant after the query so a page is never short because
		// another tenant's rows sorted first; the cap bounds the scan.
		visible := make([]itsm.EventRow, 0, limit)
		for _, e := range rows {
			if stampedTenantVisible(pd, e.Tenant) && len(visible) < limit {
				visible = append(visible, e)
			}
		}
		writeJSONData(w, map[string]any{"items": visible})
	})
}

func createITSMConnection(w http.ResponseWriter, r *http.Request,
	authorize func(http.ResponseWriter, *http.Request, string, string) (AuthPrincipal, bool),
	unconfigured func(http.ResponseWriter, *http.Request, AuthPrincipal, string, string, string) bool,
	svc *itsm.Service, creds OutboundCredentialStore, auditProvider AuditProvider, pluginCheck itsmPluginCheckFunc) {
	const action = itsm.ActionConnectionCreate
	pd, ok := authorize(w, r, action, "itsm_connection")
	if !ok || unconfigured(w, r, pd, action, "itsm_connection", "-") {
		return
	}
	reject := func(msg string) {
		emitAuditEvent(r, auditProvider, pd.ID, action, "itsm_connection", "-", AuditOutcomeFailure)
		writeBadRequest(w, msg)
	}
	var req struct {
		Kind          string          `json:"kind"`
		Name          string          `json:"name"`
		BaseURL       string          `json:"base_url"`
		CredentialRef string          `json:"credential_ref"`
		PluginID      string          `json:"plugin_id"`
		EventClasses  json.RawMessage `json:"event_classes"`
		Enabled       *bool           `json:"enabled"`
	}
	decodeErr := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req)
	if rejectOversizeBody(w, decodeErr) {
		emitAuditEvent(r, auditProvider, pd.ID, action, "itsm_connection", "-", AuditOutcomeFailure)
		return
	}
	req.Name, req.BaseURL, req.CredentialRef = strings.TrimSpace(req.Name), strings.TrimSpace(req.BaseURL), strings.TrimSpace(req.CredentialRef)
	req.PluginID = strings.TrimSpace(req.PluginID)
	switch {
	case decodeErr != nil:
		reject("invalid JSON body")
		return
	case req.Kind != "servicenow" && req.Kind != "jira" && req.Kind != itsm.KindPlugin:
		reject("kind must be servicenow, jira or plugin")
		return
	case req.Name == "":
		reject("name is required")
		return
	case req.Kind == itsm.KindPlugin && (req.PluginID == "" || req.BaseURL != ""):
		reject("a plugin connection needs plugin_id and no base_url: the credential holds the service address")
		return
	case req.Kind != itsm.KindPlugin && req.PluginID != "":
		reject("plugin_id is only for kind plugin")
		return
	case req.Kind != itsm.KindPlugin && !validITSMBaseURL(req.BaseURL):
		reject("base_url must be an https URL (http only for a loopback host)")
		return
	case req.CredentialRef == "":
		reject("credential_ref is required")
		return
	}
	classes, msg := parseITSMEventClasses(req.Kind, req.EventClasses)
	if msg != "" {
		reject(msg)
		return
	}
	if creds == nil {
		emitAuditEvent(r, auditProvider, pd.ID, action, "itsm_connection", "-", AuditOutcomeFailure)
		writeServiceUnavailable(w, "outbound credential store not configured (set APP_CREDENTIAL_STORE_PASSPHRASE or KRYPTKEEPER_KEYSTORE_PASSPHRASE)")
		return
	}
	// An invisible credential reads as unknown: its existence is not for this tenant to learn.
	meta, err := creds.Get(r.Context(), req.CredentialRef)
	if err != nil || !stampedTenantVisible(pd, meta.Tenant) {
		reject("unknown credential_ref")
		return
	}
	if req.Kind == itsm.KindPlugin {
		if pluginCheck == nil {
			reject("ticket plugins are not available on this hub")
			return
		}
		if msg := pluginCheck(r.Context(), pd, req.PluginID, req.CredentialRef); msg != "" {
			reject(msg)
			return
		}
	}
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		emitAuditEvent(r, auditProvider, pd.ID, action, "itsm_connection", "-", AuditOutcomeFailure)
		writeServiceUnavailable(w, "could not generate connection id")
		return
	}
	enabled := req.Enabled == nil || *req.Enabled
	conn, err := svc.Store().CreateConnection(r.Context(), itsm.Connection{
		ID: "itsm-" + hex.EncodeToString(buf), Kind: req.Kind, Name: req.Name, BaseURL: req.BaseURL,
		CredentialRef: req.CredentialRef, PluginID: req.PluginID, EventClasses: classes, Enabled: enabled, Tenant: pd.Tenant,
	}, time.Now())
	if err != nil {
		emitAuditEvent(r, auditProvider, pd.ID, action, "itsm_connection", "-", AuditOutcomeFailure)
		writeServiceUnavailable(w, "could not store connection")
		return
	}
	emitAuditEventDetail(r, auditProvider, pd.ID, action, "itsm_connection", conn.ID, AuditOutcomeSuccess,
		fmt.Sprintf(`{"name":%q,"kind":%q,"plugin_id":%q}`, conn.Name, conn.Kind, conn.PluginID))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(struct {
		Data itsm.Connection `json:"data"`
	}{Data: conn})
}

const itsmTestAction = "itsm.connection.test"

// testITSMConnection runs one read-only Find through the connection's real
// connector. The outcome is a short generic reason: the upstream response and
// the credential never reach the caller.
func testITSMConnection(w http.ResponseWriter, r *http.Request, id string,
	authorize func(http.ResponseWriter, *http.Request, string, string) (AuthPrincipal, bool),
	unconfigured func(http.ResponseWriter, *http.Request, AuthPrincipal, string, string, string) bool,
	svc *itsm.Service, auditProvider AuditProvider) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	pd, ok := authorize(w, r, itsmTestAction, "itsm_connection")
	if !ok || unconfigured(w, r, pd, itsmTestAction, "itsm_connection", id) {
		return
	}
	c, err := svc.Store().GetConnection(r.Context(), id)
	if err != nil || !stampedTenantVisible(pd, c.Tenant) {
		emitAuditEvent(r, auditProvider, pd.ID, itsmTestAction, "itsm_connection", id, AuditOutcomeFailure)
		writeNotFound(w, "ITSM connection not found")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	testErr := svc.TestConnection(ctx, id)
	detail, outcome := "connection OK", AuditOutcomeSuccess
	switch {
	case testErr == nil:
	case errors.Is(testErr, itsm.ErrPermanent):
		detail, outcome = "ITSM rejected the request; check the credential and its permissions", AuditOutcomeFailure
	case errors.Is(testErr, itsm.ErrTemporary):
		detail, outcome = "ITSM unreachable or temporarily unavailable", AuditOutcomeFailure
	default:
		detail, outcome = "connection could not be set up; check the credential and connection settings", AuditOutcomeFailure
	}
	emitAuditEventDetail(r, auditProvider, pd.ID, itsmTestAction, "itsm_connection", id, outcome,
		fmt.Sprintf(`{"ok":%t}`, testErr == nil))
	writeJSONData(w, map[string]any{"ok": testErr == nil, "detail": detail})
}

var itsmEventClassNames = []string{"renewal_failed", "approval_pending", "expiry_no_owner"}

// parseITSMEventClasses validates event_classes: an array of
// {class, ticket_type}. Absent or null means all classes (empty list). An
// omitted ticket_type takes the kind's default. Returns a 400 message on error.
func parseITSMEventClasses(kind string, raw json.RawMessage) ([]itsm.EventClass, string) {
	const shapeMsg = "event_classes must be an array of {class, ticket_type}"
	out := []itsm.EventClass{}
	if len(raw) == 0 || string(raw) == "null" {
		return out, ""
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil || out == nil {
		return nil, shapeMsg
	}
	seen := map[string]bool{}
	for i := range out {
		ec := &out[i]
		ec.Class, ec.TicketType = strings.TrimSpace(ec.Class), strings.TrimSpace(ec.TicketType)
		if !slices.Contains(itsmEventClassNames, ec.Class) {
			return nil, "event_classes class must be one of " + strings.Join(itsmEventClassNames, ", ")
		}
		if seen[ec.Class] {
			return nil, "event_classes lists class " + ec.Class + " more than once"
		}
		seen[ec.Class] = true
		switch kind {
		case "servicenow":
			if ec.TicketType == "" {
				ec.TicketType = "incident"
			}
			if ec.TicketType != "incident" && ec.TicketType != "change_request" {
				return nil, "servicenow ticket_type must be incident or change_request"
			}
		case itsm.KindPlugin:
			// Approval sync is native-only in 1.1 (D-326): a plugin ticket for an
			// approval could never be decided from the ticket, so offering it
			// would promise something the connector cannot do.
			if ec.Class == "approval_pending" {
				return nil, "plugin connections cannot carry approval_pending: approval sync is native-only (ServiceNow, Jira)"
			}
			// Free text the plugin interprets (a Zendesk or Freshservice ticket
			// type); empty means the plugin default.
			if len(ec.TicketType) > 255 || strings.ContainsFunc(ec.TicketType, unicode.IsControl) {
				return nil, "plugin ticket_type must be at most 255 characters"
			}
		default:
			if ec.TicketType == "" {
				ec.TicketType = "Task"
			}
			if len(ec.TicketType) > 255 || strings.ContainsFunc(ec.TicketType, unicode.IsControl) {
				return nil, "jira ticket_type must be an issue-type name of at most 255 characters"
			}
		}
	}
	return out, ""
}

// validITSMBaseURL requires https, or http only for a loopback host (tests and
// local stubs). Userinfo is refused so a credential cannot hide in the URL.
func validITSMBaseURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return true
		}
		ip := net.ParseIP(host)
		return ip != nil && ip.IsLoopback()
	}
	return false
}
