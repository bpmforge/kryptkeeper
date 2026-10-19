// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newNotifRulesTestMux(t *testing.T) *http.ServeMux {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	// Use file notification provider (now with empty seeds)
	provider := newFileNotificationProvider()
	registerNotificationHandlers(mux, auth, provider, stubAuditProvider{}, nil)
	return mux
}

func TestNotificationRulesListEmpty(t *testing.T) {
	mux := newNotifRulesTestMux(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/notifications/rules", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Items []NotificationRule `json:"items"`
		} `json:"data"`
		Meta struct {
			Total int `json:"total"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Meta.Total != 0 {
		t.Errorf("expected 0 rules, got %d", resp.Meta.Total)
	}
}

func TestNotificationRulesCreate(t *testing.T) {
	mux := newNotifRulesTestMux(t)

	body, _ := json.Marshal(map[string]any{
		"name":           "30d expiry",
		"threshold_days": 30,
		"channel":        "email",
		"target":         "pki@example.com",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/rules", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data NotificationRule `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.ThresholdDays != 30 {
		t.Errorf("unexpected threshold_days %d", resp.Data.ThresholdDays)
	}
}

func TestNotificationRulesRequiresAuth(t *testing.T) {
	mux := newNotifRulesTestMux(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/notifications/rules", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestNotificationRulesUpdate(t *testing.T) {
	mux := newNotifRulesTestMux(t)

	// Create a rule first
	body, _ := json.Marshal(map[string]any{"name": "7d", "threshold_days": 7, "channel": "slack", "target": "#alerts"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/rules", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d", rec.Code)
	}
	var created struct {
		Data NotificationRule `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	// Update it
	updateBody, _ := json.Marshal(map[string]any{"enabled": false, "target": "#new-channel"})
	req2 := httptest.NewRequest(http.MethodPut, "/api/v1/notifications/rules/"+created.Data.ID, bytes.NewReader(updateBody))
	req2.Header.Set("Authorization", "Bearer test-token")
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("update: expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
}

// TestNotificationRulesReadOnlyRoleCannotMutate is the S-09/G-61 regression:
// the rules endpoints previously authenticated but never checked role/scope
// at all, letting any authenticated principal create/update/delete a rule.
// Mints a scope-less pki-auditor key (passes canReadOperationalSummaries,
// does not pass canManageNotifications) and proves GET succeeds while
// POST/PUT/DELETE are denied.
func TestNotificationRulesReadOnlyRoleCannotMutate(t *testing.T) {
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32-chars-minimum!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()
	mux := http.NewServeMux()
	registerNotificationHandlers(mux, auth, newFileNotificationProvider(), stubAuditProvider{}, nil)

	_, auditorKey, err := auth.CreateAPIKey("auditor-integration", "auditor-svc", "pki-auditor", nil, "", "", time.Now())
	if err != nil {
		t.Fatalf("create pki-auditor api key: %v", err)
	}
	auditorReq := func(method, url string, body []byte) *http.Request {
		var r *http.Request
		if body != nil {
			r = httptest.NewRequest(method, url, bytes.NewReader(body))
		} else {
			r = httptest.NewRequest(method, url, nil)
		}
		r.Header.Set("Authorization", "Bearer "+auditorKey)
		r.Header.Set("Content-Type", "application/json")
		return r
	}

	getRec := httptest.NewRecorder()
	mux.ServeHTTP(getRec, auditorReq(http.MethodGet, "/api/v1/notifications/rules", nil))
	if getRec.Code != http.StatusOK {
		t.Fatalf("expected pki-auditor GET to succeed (200), got %d: %s", getRec.Code, getRec.Body.String())
	}

	createBody, _ := json.Marshal(map[string]any{"name": "x", "threshold_days": 30, "channel": "email", "target": "t@example.com"})
	postRec := httptest.NewRecorder()
	mux.ServeHTTP(postRec, auditorReq(http.MethodPost, "/api/v1/notifications/rules", createBody))
	if postRec.Code != http.StatusForbidden {
		t.Fatalf("expected pki-auditor POST to be denied (403), got %d: %s", postRec.Code, postRec.Body.String())
	}

	putRec := httptest.NewRecorder()
	mux.ServeHTTP(putRec, auditorReq(http.MethodPut, "/api/v1/notifications/rules/whatever", []byte(`{"enabled":false}`)))
	if putRec.Code != http.StatusForbidden {
		t.Fatalf("expected pki-auditor PUT to be denied (403), got %d: %s", putRec.Code, putRec.Body.String())
	}

	deleteRec := httptest.NewRecorder()
	mux.ServeHTTP(deleteRec, auditorReq(http.MethodDelete, "/api/v1/notifications/rules/whatever", nil))
	if deleteRec.Code != http.StatusForbidden {
		t.Fatalf("expected pki-auditor DELETE to be denied (403), got %d: %s", deleteRec.Code, deleteRec.Body.String())
	}
}

func TestNotificationRulesDelete(t *testing.T) {
	mux := newNotifRulesTestMux(t)

	// Create a rule first
	body, _ := json.Marshal(map[string]any{"name": "del-me", "threshold_days": 14, "channel": "email", "target": "t@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/rules", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d", rec.Code)
	}
	var created struct {
		Data NotificationRule `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	// Delete it
	req2 := httptest.NewRequest(http.MethodDelete, "/api/v1/notifications/rules/"+created.Data.ID, nil)
	req2.Header.Set("Authorization", "Bearer test-token")
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusNoContent {
		t.Fatalf("delete: expected 204, got %d: %s", rec2.Code, rec2.Body.String())
	}
}
