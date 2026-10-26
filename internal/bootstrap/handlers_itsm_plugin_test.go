// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kryptkeeper/internal/notifications/itsm"
)

// The ITSM connection API accepts kind "plugin" (W38-09): it needs a plugin_id
// the plugin check approves, takes no base_url (the credential holds the
// service address), refuses approval_pending (approval sync is native-only),
// and is refused outright on a hub with no plugin check wired.
func TestITSMHandlers_PluginKind(t *testing.T) {
	h := newITSMHarness(t)
	var checked []string
	check := func(_ context.Context, _ AuthPrincipal, pluginID, credRef string) string {
		checked = append(checked, pluginID+"/"+credRef)
		if pluginID != "kryptkeeper.zendesk" {
			return "plugin \"" + pluginID + "\" is not an enabled plugin"
		}
		return ""
	}
	mux := http.NewServeMux()
	registerITSMHandlers(mux, h.auth, h.svc, h.creds, h.audit, check)
	nocheck := http.NewServeMux()
	registerITSMHandlers(nocheck, h.auth, h.svc, h.creds, h.audit, nil)

	post := func(m *http.ServeMux, body map[string]any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/itsm/connections", bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+h.adminKey)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		m.ServeHTTP(rec, req)
		return rec
	}
	good := func() map[string]any {
		return map[string]any{"kind": "plugin", "name": "Zendesk", "plugin_id": "kryptkeeper.zendesk", "credential_ref": h.credID,
			"event_classes": []map[string]string{{"class": "renewal_failed", "ticket_type": "incident"}}}
	}

	rec := post(mux, good())
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct{ Data itsm.Connection }
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.Kind != itsm.KindPlugin || resp.Data.PluginID != "kryptkeeper.zendesk" || resp.Data.BaseURL != "" ||
		len(resp.Data.EventClasses) != 1 || resp.Data.EventClasses[0].TicketType != "incident" {
		t.Fatalf("connection %+v", resp.Data)
	}
	if len(checked) != 1 || !strings.HasSuffix(checked[0], "/"+h.credID) {
		t.Fatalf("plugin check calls %v", checked)
	}

	for name, tc := range map[string]struct {
		m      *http.ServeMux
		mutate func(map[string]any)
		want   string
	}{
		"no plugin id":      {mux, func(b map[string]any) { delete(b, "plugin_id") }, "needs plugin_id"},
		"base url given":    {mux, func(b map[string]any) { b["base_url"] = "https://acme.zendesk.com" }, "no base_url"},
		"unknown plugin":    {mux, func(b map[string]any) { b["plugin_id"] = "no.such" }, "not an enabled plugin"},
		"native with id":    {mux, func(b map[string]any) { b["kind"], b["base_url"] = "jira", "https://j.example" }, "only for kind plugin"},
		"approval pending":  {mux, func(b map[string]any) { b["event_classes"] = []map[string]string{{"class": "approval_pending"}} }, "native-only"},
		"no plugin runtime": {nocheck, func(map[string]any) {}, "not available"},
	} {
		b := good()
		tc.mutate(b)
		rec := post(tc.m, b)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s: %d %s, want 400 containing %q", name, rec.Code, rec.Body.String(), tc.want)
		}
	}
}
