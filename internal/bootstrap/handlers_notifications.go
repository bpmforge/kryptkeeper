// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
)

func registerNotificationHandlers(mux *http.ServeMux, auth *Authenticator, notificationProvider NotificationProvider, auditProvider AuditProvider) {
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
			log.Printf("notification summary unavailable: %v", err)
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
			log.Printf("failed to encode /api/v1/notifications/summary response: %v", err)
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
			case "email", "slack", "pagerduty", "webhook":
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
			log.Printf("notification deliveries unavailable: %v", err)
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
			log.Printf("failed to encode /api/v1/notifications/deliveries response: %v", err)
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
			log.Printf("notification test delivery failed: %v", err)
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
			log.Printf("failed to encode /api/v1/notifications/test-delivery response: %v", err)
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
			log.Printf("notification delivery retry failed: %v", err)
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
			log.Printf("failed to encode /api/v1/notifications/deliveries/retry response: %v", err)
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
			log.Printf("notification delivery ack failed: %v", err)
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
			log.Printf("failed to encode /api/v1/notifications/deliveries/ack response: %v", err)
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
			type ruleItem struct {
				ID            string `json:"id"`
				Name          string `json:"name"`
				ThresholdDays int    `json:"threshold_days"`
				Channel       string `json:"channel"`
				Target        string `json:"target"`
				Enabled       bool   `json:"enabled"`
				CreatedAt     string `json:"created_at"`
			}
			items := make([]ruleItem, len(rules))
			for i, rule := range rules {
				items[i] = ruleItem(rule)
			}
			resp := struct {
				Data struct {
					Resource string     `json:"resource"`
					Items    []ruleItem `json:"items"`
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
				log.Printf("failed to encode /api/v1/notifications/rules response: %v", err)
			}
		case http.MethodPost:
			if !canManageNotifications(principal) {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.create", "notification", "rules", AuditOutcomeDenied)
				writeForbidden(w, "insufficient permissions")
				return
			}
			var req struct {
				Name          string `json:"name"`
				ThresholdDays int    `json:"threshold_days"`
				Channel       string `json:"channel"`
				Target        string `json:"target"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
				return
			}
			req.Name = strings.TrimSpace(req.Name)
			req.Channel = strings.ToLower(strings.TrimSpace(req.Channel))
			req.Target = strings.TrimSpace(req.Target)
			switch req.Channel {
			case "email", "slack", "pagerduty", "webhook":
			default:
				writeBadRequest(w, "invalid request body")
				return
			}
			if req.Name == "" || req.Target == "" || req.ThresholdDays < 1 || req.ThresholdDays > 3650 || tooLong(req.Name) || len(req.Target) > 320 {
				writeBadRequest(w, "invalid request body")
				return
			}
			rule, err := notificationProvider.CreateRule(r.Context(), req.Name, req.ThresholdDays, req.Channel, req.Target)
			if err != nil {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.create", "notification", "rules", AuditOutcomeFailure)
				writeServiceUnavailable(w, "notification rule creation unavailable")
				return
			}
			emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.create", "notification", rule.ID, AuditOutcomeSuccess)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			if err := json.NewEncoder(w).Encode(struct {
				Data NotificationRule `json:"data"`
			}{Data: rule}); err != nil {
				log.Printf("failed to encode POST /api/v1/notifications/rules response: %v", err)
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
			rule, err := notificationProvider.UpdateRule(r.Context(), id, req.Enabled, req.Target)
			if err != nil {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.update", "notification", id, AuditOutcomeFailure)
				writeNotFound(w, "notification rule not found")
				return
			}
			emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.update", "notification", id, AuditOutcomeSuccess)
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(struct {
				Data NotificationRule `json:"data"`
			}{Data: rule}); err != nil {
				log.Printf("failed to encode PUT /api/v1/notifications/rules/{id} response: %v", err)
			}
		case http.MethodDelete:
			if !canManageNotifications(principal) {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.delete", "notification", id, AuditOutcomeDenied)
				writeForbidden(w, "insufficient permissions")
				return
			}
			if err := notificationProvider.DeleteRule(r.Context(), id); err != nil {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.rules.delete", "notification", id, AuditOutcomeFailure)
				writeNotFound(w, "notification rule not found")
				return
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
				log.Printf("failed to encode /api/v1/notifications/silences response: %v", err)
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
			id, err := newNotificationSilenceID()
			if err != nil {
				emitAuditEvent(r, auditProvider, principal.ID, "notification.silence.create", "notification", "silences", AuditOutcomeFailure)
				writeServiceUnavailable(w, "silence ID generation failed")
				return
			}
			sil := NotificationSilence{
				ID: id, TargetType: req.TargetType, TargetID: req.TargetID,
				CreatedBy: principal.ID, CreatedAt: time.Now().UTC().Format(time.RFC3339),
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
				log.Printf("failed to encode POST /api/v1/notifications/silences response: %v", err)
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
		if err := silenceStore.Delete(r.Context(), id); err != nil {
			emitAuditEvent(r, auditProvider, principal.ID, "notification.silence.delete", "notification", id, AuditOutcomeFailure)
			writeNotFound(w, "notification silence not found")
			return
		}
		emitAuditEvent(r, auditProvider, principal.ID, "notification.silence.delete", "notification", id, AuditOutcomeSuccess)
		w.WriteHeader(http.StatusNoContent)
	})
}
