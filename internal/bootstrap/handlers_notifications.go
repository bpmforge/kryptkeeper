// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"kryptkeeper/internal/logging"
	"kryptkeeper/internal/notifications/itsm"
)

// silenceTargetVisibleFunc reports whether the principal may see the
// certificate/CA/template a silence names. A silence suppresses that target's
// expiry alerts, so creating one on another tenant's target is a write against it.
type silenceTargetVisibleFunc func(ctx context.Context, pd AuthPrincipal, targetType, targetID string) bool

// itsmConnectionVisibleFunc reports whether ITSM connection id exists and may
// be seen by pd. An itsm notification rule's target is a connection id, so
// creating one is a write against that connection.
type itsmConnectionVisibleFunc func(ctx context.Context, pd AuthPrincipal, id string) bool

// newITSMConnectionVisible builds the production check; nil svc (no hub
// database) and lookup failures deny.
func newITSMConnectionVisible(svc *itsm.Service) itsmConnectionVisibleFunc {
	return func(ctx context.Context, pd AuthPrincipal, id string) bool {
		if svc == nil {
			return false
		}
		c, err := svc.Store().GetConnection(ctx, id)
		return err == nil && stampedTenantVisible(pd, c.Tenant)
	}
}

// newSilenceTargetVisible builds the production target check. Lookup failures
// and unknown targets are invisible (deny by default).
func newSilenceTargetVisible(certs CertificateProvider, cas CAProvider, templates TemplateProvider) silenceTargetVisibleFunc {
	return func(ctx context.Context, pd AuthPrincipal, targetType, targetID string) bool {
		if tenantBypass(pd) {
			return true
		}
		switch targetType {
		case SilenceTargetCertificate:
			if certs == nil {
				return false
			}
			d, found, err := certs.GetCertificate(ctx, targetID)
			if err != nil || !found {
				return false
			}
			return len(filterCertificatesByTenant(ctx, activeTenantStore, pd, []CertificateItem{d.CertificateItem})) == 1
		case SilenceTargetCA:
			if cas == nil {
				return false
			}
			if _, found, err := cas.GetCA(ctx, targetID); err != nil || !found {
				return false
			}
			return caVisibleToTenant(ctx, activeTenantStore, pd, targetID)
		case SilenceTargetTemplate:
			if templates == nil {
				return false
			}
			if _, found, err := templates.GetTemplate(ctx, targetID); err != nil || !found {
				return false
			}
			return templateVisibleToTenant(ctx, activeTenantStore, pd, targetID)
		}
		return false
	}
}

// notificationRuleVisible reports whether rule id exists and belongs to the
// principal's tenant. Unscoped callers skip the lookup so existing
// not-found semantics are unchanged for them.
func notificationRuleVisible(ctx context.Context, p NotificationProvider, pd AuthPrincipal, id string) bool {
	if tenantBypass(pd) {
		return true
	}
	rules, err := p.ListRules(ctx)
	if err != nil {
		return false
	}
	for _, rule := range rules {
		if rule.ID == id {
			return stampedTenantVisible(pd, rule.Tenant)
		}
	}
	return false
}

// notificationRuleItem is the rules wire shape. A percent rule's stored
// threshold_days is a placeholder (the provider column requires > 0) and is
// never serialised; the sidecar option row is authoritative.
type notificationRuleItem struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ThresholdDays *int   `json:"threshold_days,omitempty"`
	ThresholdPct  *int   `json:"threshold_pct,omitempty"`
	TemplateID    string `json:"template_id,omitempty"`
	Channel       string `json:"channel"`
	Target        string `json:"target"`
	Enabled       bool   `json:"enabled"`
	CreatedAt     string `json:"created_at"`
}

func toNotificationRuleItem(rule NotificationRule, opts map[string]NotificationRuleOption) notificationRuleItem {
	item := notificationRuleItem{ID: rule.ID, Name: rule.Name, Channel: rule.Channel, Target: rule.Target,
		Enabled: rule.Enabled, CreatedAt: rule.CreatedAt}
	opt, ok := opts[rule.ID]
	if ok {
		item.TemplateID = opt.TemplateID
		item.ThresholdPct = opt.ThresholdPct
	}
	if !ok || opt.ThresholdPct == nil {
		days := rule.ThresholdDays
		item.ThresholdDays = &days
	}
	return item
}

// ruleOptionsFor returns the options for GET/PUT responses; a store outage
// degrades to "no options" rather than failing the read.
func ruleOptionsFor(ctx context.Context, store NotificationRuleOptionsStore) map[string]NotificationRuleOption {
	if store == nil {
		return nil
	}
	opts, err := store.List(ctx)
	if err != nil {
		logging.Warnf("notification rule options unavailable: %v", err)
		return nil
	}
	return opts
}

// itsmRuleTargetInvalid reports whether rule id is an itsm rule and target is
// not a connection the principal may see (UpdateRule always overwrites the
// target, so an empty one is invalid too).
func itsmRuleTargetInvalid(ctx context.Context, p NotificationProvider, ok itsmConnectionVisibleFunc, pd AuthPrincipal, id, target string) bool {
	rules, err := p.ListRules(ctx)
	if err != nil {
		return false
	}
	for _, rule := range rules {
		if rule.ID == id && rule.Channel == itsmChannelName {
			return ok == nil || !ok(ctx, pd, strings.TrimSpace(target))
		}
	}
	return false
}

func registerNotificationHandlers(mux *http.ServeMux, auth *Authenticator, notificationProvider NotificationProvider, auditProvider AuditProvider, itsmConnOK itsmConnectionVisibleFunc, targetVisible ...silenceTargetVisibleFunc) {
	registerNotificationHandlersWithPlugins(mux, auth, notificationProvider, auditProvider, itsmConnOK, nil, targetVisible...)
}

// pluginTargetProblem checks a "plugin" rule target; nil check (no plugin
// channel wired) refuses every target.
func pluginTargetProblem(ctx context.Context, check pluginChannelTargetFunc, pd AuthPrincipal, target string) string {
	if check == nil {
		return "notify plugins are not available on this hub"
	}
	return check(ctx, pd, strings.TrimSpace(target))
}

// pluginRuleTargetProblem is itsmRuleTargetInvalid for plugin rules: UpdateRule
// overwrites the target, so the new one must name a usable plugin and credential.
func pluginRuleTargetProblem(ctx context.Context, p NotificationProvider, check pluginChannelTargetFunc, pd AuthPrincipal, id, target string) string {
	rules, err := p.ListRules(ctx)
	if err != nil {
		return ""
	}
	for _, rule := range rules {
		if rule.ID == id && rule.Channel == pluginChannelName {
			return pluginTargetProblem(ctx, check, pd, target)
		}
	}
	return ""
}

// registerNotificationHandlersWithPlugins mounts the notification API;
// pluginTarget validates "plugin" channel targets (nil refuses them).
func registerNotificationHandlersWithPlugins(mux *http.ServeMux, auth *Authenticator, notificationProvider NotificationProvider, auditProvider AuditProvider, itsmConnOK itsmConnectionVisibleFunc, pluginTarget pluginChannelTargetFunc, targetVisible ...silenceTargetVisibleFunc) {
	// Without a target check (tests that never exercise tenancy) only unscoped
	// principals can create silences.
	var silenceTargetOK silenceTargetVisibleFunc = func(_ context.Context, pd AuthPrincipal, _, _ string) bool { return tenantBypass(pd) }
	if len(targetVisible) > 0 && targetVisible[0] != nil {
		silenceTargetOK = targetVisible[0]
	}
	ruleOptions := newNotificationRuleOptionsStoreFromEnvLogged()
	mux.HandleFunc("/api/v1/notifications/summary", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "notification.summary", "notification", "summary", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		if !canReadOperationalSummaries(principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "notification.summary", "notification", "summary", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}

		summary, err := notificationProvider.GetSummary(r.Context())
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "notification.summary", "notification", "summary", AuditOutcomeFailure)
			logging.Warnf("notification summary unavailable: %v", err)
			writeServiceUnavailable(w, "notification summary unavailable")
			return
		}

		emitAuditEvent(r, auditProvider, principal.ID, "notification.summary", "notification", "summary", AuditOutcomeSuccess)
		resp := struct {
			Data struct {
				Resource             string `json:"resource"`
				Principal            string `json:"principal"`
				PendingNotifications int    `json:"pending_notifications"`
				OwnershipEscalations int    `json:"ownership_escalations"`
				DeliveryFailures24h  int    `json:"delivery_failures_24h"`
			} `json:"data"`
		}{}
		resp.Data.Resource = "notification-summary"
		resp.Data.Principal = principal.ID
		resp.Data.PendingNotifications = summary.PendingNotifications
		resp.Data.OwnershipEscalations = summary.OwnershipEscalations
		resp.Data.DeliveryFailures24h = summary.DeliveryFailures24h

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logging.Warnf("failed to encode /api/v1/notifications/summary response: %v", err)
		}
	})

	mux.HandleFunc("/api/v1/notifications/deliveries", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "notification.deliveries.list", "notification", "deliveries", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		if !canReadOperationalSummaries(principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "notification.deliveries.list", "notification", "deliveries", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}

		statusFilter := strings.TrimSpace(r.URL.Query().Get("status"))
		if statusFilter != "" {
			switch statusFilter {
			case "queued", "sending", "sent", "failed", "acknowledged", "retrying":
			default:
				writeBadRequest(w, "invalid status value")
				return
			}
		}
		channelFilter := strings.TrimSpace(r.URL.Query().Get("channel"))
		if channelFilter != "" {
			switch strings.ToLower(channelFilter) {
			case "email", "slack", "pagerduty", "webhook", itsmChannelName, pluginChannelName:
				channelFilter = strings.ToLower(channelFilter)
			default:
				writeBadRequest(w, "invalid channel value")
				return
			}
		}
		query := NotificationDeliveryQuery{
			Status:  statusFilter,
			Channel: channelFilter,
			Limit:   parseLimit(r.URL.Query().Get("limit"), 25, 100),
			Cursor:  parseCursor(r.URL.Query().Get("cursor"), 0),
		}

		result, err := notificationProvider.ListDeliveries(r.Context(), query)
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "notification.deliveries.list", "notification", "deliveries", AuditOutcomeFailure)
			logging.Warnf("notification deliveries unavailable: %v", err)
			writeServiceUnavailable(w, "notification deliveries unavailable")
			return
		}

		emitAuditEvent(r, auditProvider, principal.ID, "notification.deliveries.list", "notification", "deliveries", AuditOutcomeSuccess)
		resp := struct {
			Data struct {
				Resource   string                 `json:"resource"`
				Principal  string                 `json:"principal"`
				Deliveries []NotificationDelivery `json:"deliveries"`
			} `json:"data"`
			Meta struct {
				Total      int  `json:"total"`
				Limit      int  `json:"limit"`
				NextCursor *int `json:"next_cursor"`
				PrevCursor *int `json:"prev_cursor"`
			} `json:"meta"`
		}{}
		resp.Data.Resource = "notification-deliveries"
		resp.Data.Principal = principal.ID
		resp.Data.Deliveries = result.Deliveries
		resp.Meta.Total = result.Total
		resp.Meta.Limit = result.Limit
		resp.Meta.NextCursor = result.NextCursor
		resp.Meta.PrevCursor = result.PrevCursor

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logging.Warnf("failed to encode /api/v1/notifications/deliveries response: %v", err)
		}
	})

	mux.HandleFunc("/api/v1/notifications/test-delivery", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "notification.test_delivery", "notification", "test-delivery", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		if !canManageNotifications(principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "notification.test_delivery", "notification", "test-delivery", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}

		var req struct {
			Channel string `json:"channel"`
			Target  string `json:"target"`
			Message string `json:"message"`
		}
		reader := http.MaxBytesReader(w, r.Body, 8*1024)
		defer reader.Close()
		if err := json.NewDecoder(reader).Decode(&req); err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "notification.test_delivery", "notification", "test-delivery", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}

		req.Channel = strings.ToLower(strings.TrimSpace(req.Channel))
		req.Target = strings.TrimSpace(req.Target)
		req.Message = strings.TrimSpace(req.Message)
		switch req.Channel {
		case "email", "slack", "pagerduty", "webhook":
		case pluginChannelName:
			if msg := pluginTargetProblem(r.Context(), pluginTarget, principal, req.Target); msg != "" {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.test_delivery", "notification", "test-delivery", AuditOutcomeFailure)
				writeBadRequest(w, msg)
				return
			}
		default:
			emitAuditEvent(r, auditProvider, principal.ID, "notification.test_delivery", "notification", "test-delivery", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}
		if req.Target == "" || len(req.Target) > 320 || req.Message == "" || tooLong(req.Message) {
			emitAuditEvent(r, auditProvider, principal.ID, "notification.test_delivery", "notification", "test-delivery", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}

		result, err := notificationProvider.TestDelivery(r.Context(), req.Channel, req.Target, req.Message)
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "notification.test_delivery", "notification", "test-delivery", AuditOutcomeFailure)
			logging.Warnf("notification test delivery failed: %v", err)
			writeServiceUnavailable(w, "notification test delivery unavailable")
			return
		}

		emitAuditEvent(r, auditProvider, principal.ID, "notification.test_delivery", "notification", result.ID, AuditOutcomeSuccess)
		resp := struct {
			Data struct {
				Resource  string `json:"resource"`
				Principal string `json:"principal"`
				Delivery  struct {
					ID       string `json:"id"`
					Channel  string `json:"channel"`
					Target   string `json:"target"`
					Status   string `json:"status"`
					QueuedAt string `json:"queued_at"`
					// Dispatched is false when the provider only records
					// messages (file, db): nothing was sent.
					Dispatched bool   `json:"dispatched"`
					Note       string `json:"note,omitempty"`
				} `json:"delivery"`
			} `json:"data"`
		}{}
		resp.Data.Resource = "notification-test-delivery"
		resp.Data.Principal = principal.ID
		resp.Data.Delivery.ID = result.ID
		resp.Data.Delivery.Channel = result.Channel
		resp.Data.Delivery.Target = result.Target
		resp.Data.Delivery.Status = result.Status
		resp.Data.Delivery.QueuedAt = result.QueuedAt
		resp.Data.Delivery.Dispatched = result.Dispatched
		resp.Data.Delivery.Note = result.Note

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logging.Warnf("failed to encode /api/v1/notifications/test-delivery response: %v", err)
		}
	})

	mux.HandleFunc("/api/v1/notifications/deliveries/retry", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "notification.delivery.retry", "notification", "delivery-retry", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		if !canManageNotifications(principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "notification.delivery.retry", "notification", "delivery-retry", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}

		var req struct {
			DeliveryID string `json:"delivery_id"`
			Reason     string `json:"reason"`
		}
		reader := http.MaxBytesReader(w, r.Body, 8*1024)
		defer reader.Close()
		if err := json.NewDecoder(reader).Decode(&req); err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "notification.delivery.retry", "notification", "delivery-retry", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}

		req.DeliveryID = strings.TrimSpace(req.DeliveryID)
		req.Reason = strings.TrimSpace(req.Reason)
		if req.DeliveryID == "" || tooLong(req.Reason) {
			emitAuditEvent(r, auditProvider, principal.ID, "notification.delivery.retry", "notification", "delivery-retry", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}

		result, err := notificationProvider.RetryDelivery(r.Context(), req.DeliveryID, req.Reason)
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "notification.delivery.retry", "notification", "delivery-retry", AuditOutcomeFailure)
			logging.Warnf("notification delivery retry failed: %v", err)
			writeServiceUnavailable(w, "notification delivery retry unavailable")
			return
		}

		emitAuditEvent(r, auditProvider, principal.ID, "notification.delivery.retry", "notification", req.DeliveryID, AuditOutcomeSuccess)
		resp := struct {
			Data struct {
				Resource   string `json:"resource"`
				Principal  string `json:"principal"`
				DeliveryID string `json:"delivery_id"`
				RetryJobID string `json:"retry_job_id"`
				Status     string `json:"status"`
				Reason     string `json:"reason"`
				QueuedAt   string `json:"queued_at"`
			} `json:"data"`
		}{}
		resp.Data.Resource = "notification-delivery-retry"
		resp.Data.Principal = principal.ID
		resp.Data.DeliveryID = result.DeliveryID
		resp.Data.RetryJobID = result.RetryJobID
		resp.Data.Status = result.Status
		resp.Data.Reason = result.Reason
		resp.Data.QueuedAt = result.QueuedAt

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logging.Warnf("failed to encode /api/v1/notifications/deliveries/retry response: %v", err)
		}
	})

	mux.HandleFunc("/api/v1/notifications/deliveries/ack", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "notification.delivery.ack", "notification", "delivery-ack", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		if !canManageNotifications(principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "notification.delivery.ack", "notification", "delivery-ack", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}

		var req struct {
			DeliveryID string `json:"delivery_id"`
			Note       string `json:"note"`
		}
		reader := http.MaxBytesReader(w, r.Body, 8*1024)
		defer reader.Close()
		if err := json.NewDecoder(reader).Decode(&req); err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "notification.delivery.ack", "notification", "delivery-ack", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}

		req.DeliveryID = strings.TrimSpace(req.DeliveryID)
		req.Note = strings.TrimSpace(req.Note)
		if req.DeliveryID == "" || tooLong(req.Note) {
			emitAuditEvent(r, auditProvider, principal.ID, "notification.delivery.ack", "notification", "delivery-ack", AuditOutcomeFailure)
			writeBadRequest(w, "invalid request body")
			return
		}

		result, err := notificationProvider.AckDelivery(r.Context(), req.DeliveryID, req.Note)
		if err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "notification.delivery.ack", "notification", "delivery-ack", AuditOutcomeFailure)
			logging.Warnf("notification delivery ack failed: %v", err)
			writeServiceUnavailable(w, "notification delivery ack unavailable")
			return
		}

		emitAuditEvent(r, auditProvider, principal.ID, "notification.delivery.ack", "notification", req.DeliveryID, AuditOutcomeSuccess)
		resp := struct {
			Data struct {
				Resource   string `json:"resource"`
				Principal  string `json:"principal"`
				DeliveryID string `json:"delivery_id"`
				Status     string `json:"status"`
				Note       string `json:"note"`
				UpdatedAt  string `json:"updated_at"`
			} `json:"data"`
		}{}
		resp.Data.Resource = "notification-delivery-ack"
		resp.Data.Principal = principal.ID
		resp.Data.DeliveryID = result.DeliveryID
		resp.Data.Status = result.Status
		resp.Data.Note = result.Note
		resp.Data.UpdatedAt = result.UpdatedAt

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logging.Warnf("failed to encode /api/v1/notifications/deliveries/ack response: %v", err)
		}
	})

	// Notification rules
	mux.HandleFunc("/api/v1/notifications/rules", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "notification.rules", "notification", "rules", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		switch r.Method {
		case http.MethodGet:
			if !canReadOperationalSummaries(principal) {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.list", "notification", "rules", AuditOutcomeDenied)
				writeForbidden(w, "insufficient permissions")
				return
			}
			rules, err := notificationProvider.ListRules(r.Context())
			if err != nil {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.list", "notification", "rules", AuditOutcomeFailure)
				writeServiceUnavailable(w, "notification rules unavailable")
				return
			}
			emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.list", "notification", "rules", AuditOutcomeSuccess)
			opts := ruleOptionsFor(r.Context(), ruleOptions)
			items := make([]notificationRuleItem, 0, len(rules))
			for _, rule := range rules {
				if !stampedTenantVisible(principal, rule.Tenant) {
					continue
				}
				items = append(items, toNotificationRuleItem(rule, opts))
			}
			resp := struct {
				Data struct {
					Resource string                 `json:"resource"`
					Items    []notificationRuleItem `json:"items"`
				} `json:"data"`
				Meta struct {
					Total int `json:"total"`
				} `json:"meta"`
			}{}
			resp.Data.Resource = "notification-rules"
			resp.Data.Items = items
			resp.Meta.Total = len(items)
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				logging.Warnf("failed to encode /api/v1/notifications/rules response: %v", err)
			}
		case http.MethodPost:
			if !canManageNotifications(principal) {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.create", "notification", "rules", AuditOutcomeDenied)
				writeForbidden(w, "insufficient permissions")
				return
			}
			var req struct {
				Name          string `json:"name"`
				ThresholdDays *int   `json:"threshold_days"`
				ThresholdPct  *int   `json:"threshold_pct"`
				UseDefaults   bool   `json:"use_defaults"`
				TemplateID    string `json:"template_id"`
				Channel       string `json:"channel"`
				Target        string `json:"target"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.create", "notification", "rules", AuditOutcomeFailure)
				http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
				return
			}
			req.Name = strings.TrimSpace(req.Name)
			req.Channel = strings.ToLower(strings.TrimSpace(req.Channel))
			req.Target = strings.TrimSpace(req.Target)
			req.TemplateID = strings.TrimSpace(req.TemplateID)
			switch req.Channel {
			case "email", "slack", "pagerduty", "webhook", itsmChannelName, pluginChannelName:
			default:
				emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.create", "notification", "rules", AuditOutcomeFailure)
				writeBadRequest(w, "invalid request body")
				return
			}
			if req.Channel == pluginChannelName {
				if msg := pluginTargetProblem(r.Context(), pluginTarget, principal, req.Target); msg != "" {
					emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.create", "notification", "rules", AuditOutcomeFailure)
					writeBadRequest(w, msg)
					return
				}
			}
			if req.Channel == itsmChannelName && (itsmConnOK == nil || !itsmConnOK(r.Context(), principal, req.Target)) {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.create", "notification", "rules", AuditOutcomeFailure)
				writeBadRequest(w, "target must be an existing ITSM connection id")
				return
			}
			modes := 0
			for _, set := range []bool{req.ThresholdDays != nil, req.ThresholdPct != nil, req.UseDefaults} {
				if set {
					modes++
				}
			}
			if req.Name == "" || req.Target == "" || modes != 1 || tooLong(req.Name) || len(req.Target) > 320 || len(req.TemplateID) > 128 ||
				(req.ThresholdDays != nil && (*req.ThresholdDays < 1 || *req.ThresholdDays > 3650)) ||
				(req.ThresholdPct != nil && (*req.ThresholdPct < 0 || *req.ThresholdPct > 100)) {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.create", "notification", "rules", AuditOutcomeFailure)
				writeBadRequest(w, "invalid request body")
				return
			}
			// Percent and template settings live in the sidecar store; without
			// it they would be silently dropped, so refuse instead.
			needsOptions := req.ThresholdDays == nil || req.TemplateID != ""
			if needsOptions && ruleOptions == nil {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.create", "notification", "rules", AuditOutcomeFailure)
				writeServiceUnavailable(w, "notification rule options unavailable")
				return
			}
			type newRule struct {
				name string
				days int
				pct  *int
			}
			var toCreate []newRule
			switch {
			case req.UseDefaults:
				for _, pct := range defaultThresholdPcts {
					label := strconv.Itoa(pct) + "%"
					if pct == 0 {
						label = "EXPIRED"
					}
					p := pct
					toCreate = append(toCreate, newRule{name: req.Name + " " + label, days: 1, pct: &p})
				}
			case req.ThresholdPct != nil:
				toCreate = []newRule{{name: req.Name, days: 1, pct: req.ThresholdPct}}
			default:
				toCreate = []newRule{{name: req.Name, days: *req.ThresholdDays}}
			}
			created := make([]NotificationRule, 0, len(toCreate))
			createdOpts := map[string]NotificationRuleOption{}
			fail := func() {
				// Roll back so a half-created set does not alert unexpectedly.
				for _, c := range created {
					if err := notificationProvider.DeleteRule(r.Context(), c.ID); err != nil {
						logging.Warnf("rolling back rule %s failed: %v", c.ID, err)
					}
					if ruleOptions != nil {
						if err := ruleOptions.Delete(r.Context(), c.ID); err != nil {
							logging.Warnf("rolling back options for rule %s failed: %v", c.ID, err)
						}
					}
				}
				emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.create", "notification", "rules", AuditOutcomeFailure)
				writeServiceUnavailable(w, "notification rule creation unavailable")
			}
			for _, nr := range toCreate {
				var rule NotificationRule
				if tc, ok := notificationProvider.(tenantRuleCreator); ok {
					rule, err = tc.CreateRuleForTenant(r.Context(), principal.Tenant, nr.name, nr.days, req.Channel, req.Target)
				} else {
					rule, err = notificationProvider.CreateRule(r.Context(), nr.name, nr.days, req.Channel, req.Target)
				}
				if err != nil {
					fail()
					return
				}
				created = append(created, rule)
				if nr.pct != nil || req.TemplateID != "" {
					opt := NotificationRuleOption{RuleID: rule.ID, ThresholdPct: nr.pct, TemplateID: req.TemplateID, Tenant: principal.Tenant}
					if err := ruleOptions.Set(r.Context(), opt); err != nil {
						fail()
						return
					}
					createdOpts[rule.ID] = opt
				}
			}
			ids := make([]string, 0, len(created))
			for _, c := range created {
				ids = append(ids, c.ID)
				emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.create", "notification", c.ID, AuditOutcomeSuccess)
			}
			resp := struct {
				Data notificationRuleItem `json:"data"`
				Meta *struct {
					Created []string `json:"created"`
				} `json:"meta,omitempty"`
			}{Data: toNotificationRuleItem(created[0], createdOpts)}
			if req.UseDefaults {
				resp.Meta = &struct {
					Created []string `json:"created"`
				}{Created: ids}
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				logging.Warnf("failed to encode POST /api/v1/notifications/rules response: %v", err)
			}
		default:
			writeMethodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
		}
	})

	mux.HandleFunc("/api/v1/notifications/rules/", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "notification.rules", "notification", "rules", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/notifications/rules/")
		if id == "" {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodPut:
			if !canManageNotifications(principal) {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.update", "notification", id, AuditOutcomeDenied)
				writeForbidden(w, "insufficient permissions")
				return
			}
			var req struct {
				Enabled bool   `json:"enabled"`
				Target  string `json:"target"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
				return
			}
			if !notificationRuleVisible(r.Context(), notificationProvider, principal, id) {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.update", "notification", id, AuditOutcomeDenied)
				writeNotFound(w, "notification rule not found")
				return
			}
			if itsmRuleTargetInvalid(r.Context(), notificationProvider, itsmConnOK, principal, id, req.Target) {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.update", "notification", id, AuditOutcomeFailure)
				writeBadRequest(w, "target must be an existing ITSM connection id")
				return
			}
			if msg := pluginRuleTargetProblem(r.Context(), notificationProvider, pluginTarget, principal, id, req.Target); msg != "" {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.update", "notification", id, AuditOutcomeFailure)
				writeBadRequest(w, msg)
				return
			}
			rule, err := notificationProvider.UpdateRule(r.Context(), id, req.Enabled, req.Target)
			if err != nil {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.update", "notification", id, AuditOutcomeFailure)
				writeNotFound(w, "notification rule not found")
				return
			}
			emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.update", "notification", id, AuditOutcomeSuccess)
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(struct {
				Data notificationRuleItem `json:"data"`
			}{Data: toNotificationRuleItem(rule, ruleOptionsFor(r.Context(), ruleOptions))}); err != nil {
				logging.Warnf("failed to encode PUT /api/v1/notifications/rules/{id} response: %v", err)
			}
		case http.MethodDelete:
			if !canManageNotifications(principal) {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.delete", "notification", id, AuditOutcomeDenied)
				writeForbidden(w, "insufficient permissions")
				return
			}
			if !notificationRuleVisible(r.Context(), notificationProvider, principal, id) {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.delete", "notification", id, AuditOutcomeDenied)
				writeNotFound(w, "notification rule not found")
				return
			}
			if err := notificationProvider.DeleteRule(r.Context(), id); err != nil {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.delete", "notification", id, AuditOutcomeFailure)
				writeNotFound(w, "notification rule not found")
				return
			}
			if ruleOptions != nil {
				if err := ruleOptions.Delete(r.Context(), id); err != nil {
					logging.Warnf("deleting options for rule %s failed: %v", id, err)
				}
			}
			emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.delete", "notification", id, AuditOutcomeSuccess)
			w.WriteHeader(http.StatusNoContent)
		default:
			writeMethodNotAllowed(w, http.MethodPut+", "+http.MethodDelete)
		}
	})

	// W1-10 (split from W1-06/G-60): the renewal scheduler already enforces
	// NotificationSilenceStore.IsSilenced — this is the missing
	// create/list/delete surface for the same store, so an operator can
	// actually use the feature. Constructed once at registration (matches
	// approval/tenant store convention) rather than threaded through
	// RegisterHandlers' signature, so no call site outside this file needs
	// to change.
	silenceStore := newNotificationSilenceStoreFromEnvLogged()

	mux.HandleFunc("/api/v1/notifications/silences", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "notification.silence", "notification", "silences", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if silenceStore == nil {
			writeServiceUnavailable(w, "notification-silence store unavailable")
			return
		}
		switch r.Method {
		case http.MethodGet:
			if !canReadOperationalSummaries(principal) {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.silence.list", "notification", "silences", AuditOutcomeDenied)
				writeForbidden(w, "forbidden")
				return
			}
			targetType := strings.TrimSpace(r.URL.Query().Get("target_type"))
			targetID := strings.TrimSpace(r.URL.Query().Get("target_id"))
			switch targetType {
			case SilenceTargetCertificate, SilenceTargetCA, SilenceTargetTemplate:
			default:
				writeBadRequest(w, "target_type must be certificate, ca, or template")
				return
			}
			if targetID == "" {
				writeBadRequest(w, "target_id is required")
				return
			}
			items, err := silenceStore.ListForTarget(r.Context(), targetType, targetID)
			if err == nil {
				visible := items[:0:0]
				for _, it := range items {
					if stampedTenantVisible(principal, it.Tenant) {
						visible = append(visible, it)
					}
				}
				items = visible
			}
			if err != nil {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.silence.list", "notification", "silences", AuditOutcomeFailure)
				writeServiceUnavailable(w, "notification silences unavailable")
				return
			}
			emitAuditEvent(r, auditProvider, principal.ID, "notification.silence.list", "notification", "silences", AuditOutcomeSuccess)
			resp := struct {
				Data struct {
					Resource string                `json:"resource"`
					Items    []NotificationSilence `json:"items"`
				} `json:"data"`
				Meta struct {
					Total int `json:"total"`
				} `json:"meta"`
			}{}
			resp.Data.Resource = "notification-silences"
			resp.Data.Items = items
			resp.Meta.Total = len(items)
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				logging.Warnf("failed to encode /api/v1/notifications/silences response: %v", err)
			}

		case http.MethodPost:
			if !canManageNotifications(principal) {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.silence.create", "notification", "silences", AuditOutcomeDenied)
				writeForbidden(w, "forbidden")
				return
			}
			var req struct {
				TargetType string `json:"target_type"`
				TargetID   string `json:"target_id"`
			}
			reader := http.MaxBytesReader(w, r.Body, 8*1024)
			defer reader.Close()
			if err := json.NewDecoder(reader).Decode(&req); err != nil {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.silence.create", "notification", "silences", AuditOutcomeFailure)
				writeBadRequest(w, "invalid request body")
				return
			}
			req.TargetType = strings.TrimSpace(req.TargetType)
			req.TargetID = strings.TrimSpace(req.TargetID)
			switch req.TargetType {
			case SilenceTargetCertificate, SilenceTargetCA, SilenceTargetTemplate:
			default:
				emitAuditEvent(r, auditProvider, principal.ID, "notification.silence.create", "notification", "silences", AuditOutcomeFailure)
				writeBadRequest(w, "target_type must be certificate, ca, or template")
				return
			}
			if req.TargetID == "" || tooLong(req.TargetID) {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.silence.create", "notification", "silences", AuditOutcomeFailure)
				writeBadRequest(w, "target_id is required")
				return
			}
			if !silenceTargetOK(r.Context(), principal, req.TargetType, req.TargetID) {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.silence.create", "notification", "silences", AuditOutcomeDenied)
				writeNotFound(w, "silence target not found")
				return
			}
			id, err := newNotificationSilenceID()
			if err != nil {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.silence.create", "notification", "silences", AuditOutcomeFailure)
				writeServiceUnavailable(w, "silence ID generation failed")
				return
			}
			sil := NotificationSilence{
				ID: id, TargetType: req.TargetType, TargetID: req.TargetID,
				CreatedBy: principal.ID, CreatedAt: time.Now().UTC().Format(time.RFC3339),
				Tenant: principal.Tenant,
			}
			if err := silenceStore.Create(r.Context(), sil); err != nil {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.silence.create", "notification", "silences", AuditOutcomeFailure)
				writeServiceUnavailable(w, "notification silence creation unavailable")
				return
			}
			emitAuditEvent(r, auditProvider, principal.ID, "notification.silence.create", "notification", sil.ID, AuditOutcomeSuccess)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			if err := json.NewEncoder(w).Encode(struct {
				Data NotificationSilence `json:"data"`
			}{Data: sil}); err != nil {
				logging.Warnf("failed to encode POST /api/v1/notifications/silences response: %v", err)
			}

		default:
			writeMethodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
		}
	})

	mux.HandleFunc("/api/v1/notifications/silences/", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "notification.silence", "notification", "silences", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if silenceStore == nil {
			writeServiceUnavailable(w, "notification-silence store unavailable")
			return
		}
		if r.Method != http.MethodDelete {
			writeMethodNotAllowed(w, http.MethodDelete)
			return
		}
		if !canManageNotifications(principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "notification.silence.delete", "notification", "silences", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/notifications/silences/")
		if id == "" {
			http.NotFound(w, r)
			return
		}
		if !tenantBypass(principal) {
			getter, ok := silenceStore.(interface {
				Get(ctx context.Context, id string) (NotificationSilence, error)
			})
			var existing NotificationSilence
			var gerr error = errNotificationSilenceNotFound
			if ok {
				existing, gerr = getter.Get(r.Context(), id)
			}
			if gerr != nil || !stampedTenantVisible(principal, existing.Tenant) {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.silence.delete", "notification", id, AuditOutcomeDenied)
				writeNotFound(w, "notification silence not found")
				return
			}
		}
		if err := silenceStore.Delete(r.Context(), id); err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "notification.silence.delete", "notification", id, AuditOutcomeFailure)
			writeNotFound(w, "notification silence not found")
			return
		}
		emitAuditEvent(r, auditProvider, principal.ID, "notification.silence.delete", "notification", id, AuditOutcomeSuccess)
		w.WriteHeader(http.StatusNoContent)
	})
	// W30-02: the owner_team routing table that "@owner_team" rules expand
	// through at dispatch (renewal_scheduler.go resolveTeamRoutes).
	teamRoutes := newNotificationTeamRouteStoreFromEnvLogged()

	mux.HandleFunc("/api/v1/notifications/team-routes", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "notification.team_route", "notification", "team-routes", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		switch r.Method {
		case http.MethodGet:
			if !canReadOperationalSummaries(principal) {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.team_route.list", "notification", "team-routes", AuditOutcomeDenied)
				writeForbidden(w, "forbidden")
				return
			}
			var items []NotificationTeamRoute
			if teamRoutes != nil {
				items, err = teamRoutes.List(r.Context())
			}
			if teamRoutes == nil || err != nil {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.team_route.list", "notification", "team-routes", AuditOutcomeFailure)
				writeServiceUnavailable(w, "notification team routes unavailable")
				return
			}
			visible := make([]NotificationTeamRoute, 0, len(items))
			for _, it := range items {
				if stampedTenantVisible(principal, it.Tenant) {
					visible = append(visible, it)
				}
			}
			emitAuditEvent(r, auditProvider, principal.ID, "notification.team_route.list", "notification", "team-routes", AuditOutcomeSuccess)
			resp := struct {
				Data struct {
					Items []NotificationTeamRoute `json:"items"`
				} `json:"data"`
				Meta struct {
					Total int `json:"total"`
				} `json:"meta"`
			}{}
			resp.Data.Items = visible
			resp.Meta.Total = len(visible)
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				logging.Warnf("failed to encode /api/v1/notifications/team-routes response: %v", err)
			}

		case http.MethodPost:
			if !canManageNotifications(principal) {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.team_route.create", "notification", "team-routes", AuditOutcomeDenied)
				writeForbidden(w, "forbidden")
				return
			}
			var req struct {
				OwnerTeam string `json:"owner_team"`
				Channel   string `json:"channel"`
				Target    string `json:"target"`
			}
			reader := http.MaxBytesReader(w, r.Body, 8*1024)
			defer reader.Close()
			if err := json.NewDecoder(reader).Decode(&req); err != nil {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.team_route.create", "notification", "team-routes", AuditOutcomeFailure)
				writeBadRequest(w, "invalid request body")
				return
			}
			req.OwnerTeam = strings.TrimSpace(req.OwnerTeam)
			req.Channel = strings.ToLower(strings.TrimSpace(req.Channel))
			req.Target = strings.TrimSpace(req.Target)
			switch req.Channel {
			case "email", "slack", "pagerduty", "webhook":
			case pluginChannelName:
				// A team can be routed to a notify plugin (Teams, PagerDuty,
				// Opsgenie) once the plugin and its credential are visible.
				if msg := pluginTargetProblem(r.Context(), pluginTarget, principal, req.Target); msg != "" {
					emitAuditEvent(r, auditProvider, principal.ID, "notification.team_route.create", "notification", "team-routes", AuditOutcomeFailure)
					writeBadRequest(w, msg)
					return
				}
			default:
				emitAuditEvent(r, auditProvider, principal.ID, "notification.team_route.create", "notification", "team-routes", AuditOutcomeFailure)
				writeBadRequest(w, "channel must be email, slack, pagerduty, webhook or plugin")
				return
			}
			if req.OwnerTeam == "" || len(req.OwnerTeam) > 120 || req.Target == "" || len(req.Target) > 320 || req.Target == routedRuleTarget {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.team_route.create", "notification", "team-routes", AuditOutcomeFailure)
				writeBadRequest(w, "owner_team (1-120 chars, or *) and target (1-320 chars) are required")
				return
			}
			if teamRoutes == nil {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.team_route.create", "notification", "team-routes", AuditOutcomeFailure)
				writeServiceUnavailable(w, "notification team routes unavailable")
				return
			}
			id, err := newNotificationTeamRouteID()
			if err != nil {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.team_route.create", "notification", "team-routes", AuditOutcomeFailure)
				writeServiceUnavailable(w, "route ID generation failed")
				return
			}
			route := NotificationTeamRoute{ID: id, OwnerTeam: req.OwnerTeam, Channel: req.Channel, Target: req.Target, Tenant: principal.Tenant}
			if err := teamRoutes.Create(r.Context(), route); err != nil {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.team_route.create", "notification", "team-routes", AuditOutcomeFailure)
				if errors.Is(err, errNotificationTeamRouteExists) {
					writeConflict(w, "team route already exists")
					return
				}
				writeServiceUnavailable(w, "notification team route creation unavailable")
				return
			}
			emitAuditEvent(r, auditProvider, principal.ID, "notification.team_route.create", "notification", route.ID, AuditOutcomeSuccess)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			if err := json.NewEncoder(w).Encode(struct {
				Data NotificationTeamRoute `json:"data"`
			}{Data: route}); err != nil {
				logging.Warnf("failed to encode POST /api/v1/notifications/team-routes response: %v", err)
			}

		default:
			writeMethodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
		}
	})

	mux.HandleFunc("/api/v1/notifications/team-routes/", func(w http.ResponseWriter, r *http.Request) {
		principal, err := auth.AuthenticatePrincipalDetails(r, time.Now())
		if err != nil {
			emitAuditEvent(r, auditProvider, "", "notification.team_route", "notification", "team-routes", AuditOutcomeDenied)
			writeUnauthorized(w)
			return
		}
		if r.Method != http.MethodDelete {
			writeMethodNotAllowed(w, http.MethodDelete)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/notifications/team-routes/")
		if !canManageNotifications(principal) {
			emitAuditEvent(r, auditProvider, principal.ID, "notification.team_route.delete", "notification", "team-routes", AuditOutcomeDenied)
			writeForbidden(w, "forbidden")
			return
		}
		if id == "" || strings.Contains(id, "/") {
			emitAuditEvent(r, auditProvider, principal.ID, "notification.team_route.delete", "notification", "team-routes", AuditOutcomeFailure)
			http.NotFound(w, r)
			return
		}
		if teamRoutes == nil {
			emitAuditEvent(r, auditProvider, principal.ID, "notification.team_route.delete", "notification", id, AuditOutcomeFailure)
			writeServiceUnavailable(w, "notification team routes unavailable")
			return
		}
		// Check visibility before deleting so another tenant's route is
		// indistinguishable from a missing one.
		existing, gerr := teamRoutes.Get(r.Context(), id)
		if gerr != nil || !stampedTenantVisible(principal, existing.Tenant) {
			emitAuditEvent(r, auditProvider, principal.ID, "notification.team_route.delete", "notification", id, AuditOutcomeDenied)
			writeNotFound(w, "notification team route not found")
			return
		}
		if err := teamRoutes.Delete(r.Context(), id); err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "notification.team_route.delete", "notification", id, AuditOutcomeFailure)
			writeNotFound(w, "notification team route not found")
			return
		}
		emitAuditEvent(r, auditProvider, principal.ID, "notification.team_route.delete", "notification", id, AuditOutcomeSuccess)
		w.WriteHeader(http.StatusNoContent)
	})
}
