// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestLeakL10_NotificationRulesAndSilencesScopedToTenant(t *testing.T) {
	mux, acmeTok, globexTok := setupTenantWritePathTest(t)

	rec := leakDo(mux, http.MethodPost, "/api/v1/notifications/rules", globexTok, "globex",
		`{"name":"gx-rule","threshold_days":30,"channel":"email","target":"ops@globex.test"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed rule: %d %s", rec.Code, rec.Body.String())
	}
	var rule struct {
		Data NotificationRule `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &rule)
	gxRule := rule.Data.ID

	if rec := leakDo(mux, http.MethodGet, "/api/v1/notifications/rules", acmeTok, "acme", ""); strings.Contains(rec.Body.String(), gxRule) {
		t.Fatalf("acme listed globex rule: %s", rec.Body.String())
	}
	if rec := leakDo(mux, http.MethodPut, "/api/v1/notifications/rules/"+gxRule, acmeTok, "acme", `{"enabled":true,"target":"evil@x.test"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant rule update: want 404 got %d", rec.Code)
	}
	if rec := leakDo(mux, http.MethodDelete, "/api/v1/notifications/rules/"+gxRule, acmeTok, "acme", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant rule delete: want 404 got %d", rec.Code)
	}
	if rec := leakDo(mux, http.MethodGet, "/api/v1/notifications/rules", globexTok, "globex", ""); !strings.Contains(rec.Body.String(), gxRule) {
		t.Fatalf("globex lost its rule: %s", rec.Body.String())
	}

	// Silence on another tenant's certificate is refused.
	if rec := leakDo(mux, http.MethodPost, "/api/v1/notifications/silences", acmeTok, "acme",
		`{"target_type":"certificate","target_id":"fp-globex-cert"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant silence create: want 404 got %d %s", rec.Code, rec.Body.String())
	}
	rec = leakDo(mux, http.MethodPost, "/api/v1/notifications/silences", globexTok, "globex",
		`{"target_type":"certificate","target_id":"fp-globex-cert"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("own silence create: %d %s", rec.Code, rec.Body.String())
	}
	var sil struct {
		Data NotificationSilence `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &sil)

	rec = leakDo(mux, http.MethodGet, "/api/v1/notifications/silences?target_type=certificate&target_id=fp-globex-cert", acmeTok, "acme", "")
	if strings.Contains(rec.Body.String(), sil.Data.ID) {
		t.Fatalf("acme listed globex silence: %s", rec.Body.String())
	}
	if rec := leakDo(mux, http.MethodDelete, "/api/v1/notifications/silences/"+sil.Data.ID, acmeTok, "acme", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant silence delete: want 404 got %d", rec.Code)
	}
	if rec := leakDo(mux, http.MethodDelete, "/api/v1/notifications/silences/"+sil.Data.ID, globexTok, "globex", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("own silence delete: %d", rec.Code)
	}
	if rec := leakDo(mux, http.MethodPost, "/api/v1/notifications/silences", acmeTok, "acme",
		`{"target_type":"certificate","target_id":"fp-acme-cert"}`); rec.Code != http.StatusCreated {
		t.Fatalf("acme silence on own cert: %d %s", rec.Code, rec.Body.String())
	}
}

func TestLeakL10_DBRuleStoreRoundTripsTenant(t *testing.T) {
	p := newRuleTestStore(t)
	ctx := t.Context()
	if _, err := p.CreateRuleForTenant(ctx, "acme", "r", 30, "email", "a@x.test"); err != nil {
		t.Fatal(err)
	}
	rules, err := p.ListRules(ctx)
	if err != nil || len(rules) != 1 || rules[0].Tenant != "acme" {
		t.Fatalf("tenant not persisted: %+v %v", rules, err)
	}
}
