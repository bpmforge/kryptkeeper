// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

type targetResp struct {
	Data ManagedTarget `json:"data"`
}

func postTarget(t *testing.T, mux *http.ServeMux, token, body string) (int, ManagedTarget, string) {
	t.Helper()
	rec := doTargetsRequest(mux, http.MethodPost, "/api/v1/targets", token, body)
	var r targetResp
	_ = json.Unmarshal(rec.Body.Bytes(), &r)
	return rec.Code, r.Data, rec.Body.String()
}

func TestKeyHandlingModeRoundTripAllFour(t *testing.T) {
	mux, _, _, _, _ := newTargetsTestMux(t)
	cases := []struct{ mode, install string }{
		{KeyModeClientCSR, "agent"},
		{KeyModeHubGenerated, "ssh"},
		{KeyModeHSMResidentCA, "ssh"},
		{KeyModeMacOSNonExtractable, "keychain"},
	}
	for _, c := range cases {
		body := `{"name":"t-` + c.mode + `","host":"h.example.com","install_mode":"` + c.install + `","key_handling_mode":"` + c.mode + `"}`
		code, created, raw := postTarget(t, mux, "test-token", body)
		if code != http.StatusCreated {
			t.Fatalf("%s: create status %d: %s", c.mode, code, raw)
		}
		rec := doTargetsRequest(mux, http.MethodGet, "/api/v1/targets/"+created.ID, "test-token", "")
		var got targetResp
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Data.KeyHandlingMode != c.mode || got.Data.EffectiveKeyHandlingMode != c.mode {
			t.Fatalf("%s: round trip = %q / %q", c.mode, got.Data.KeyHandlingMode, got.Data.EffectiveKeyHandlingMode)
		}
	}
}

func TestKeyHandlingModeRejectsWindowsCNGAndTPM(t *testing.T) {
	mux, _, store, _, _ := newTargetsTestMux(t)
	for _, mode := range []string{"windows_cng", "cng", "tpm", "tpm_resident", "windows_non_exportable", "Windows-CNG", "TPM"} {
		body := `{"name":"w-` + mode + `","host":"h.example.com","install_mode":"ssh","key_handling_mode":"` + mode + `"}`
		code, _, raw := postTarget(t, mux, "test-token", body)
		if code != http.StatusBadRequest || !strings.Contains(raw, "v1.x") {
			t.Fatalf("%s: want 400 mentioning v1.x, got %d: %s", mode, code, raw)
		}
	}
	items, err := store.List(context.Background())
	if err != nil || len(items) != 0 {
		t.Fatalf("no target may be created by a rejected mode: %v %v", items, err)
	}
	if err := validateKeyHandlingMode("tpm", "ssh"); !errors.Is(err, errKeyHandlingModeUnsupported) {
		t.Fatalf("want errKeyHandlingModeUnsupported, got %v", err)
	}
}

func TestKeyHandlingModeRejectsUnknownAndIncompatible(t *testing.T) {
	mux, _, _, _, _ := newTargetsTestMux(t)
	for name, body := range map[string]string{
		"unknown":      `{"name":"a","host":"h","install_mode":"ssh","key_handling_mode":"bogus"}`,
		"keychain+ssh": `{"name":"b","host":"h","install_mode":"ssh","key_handling_mode":"macos_non_extractable"}`,
		"csr+ssh":      `{"name":"c","host":"h","install_mode":"ssh","key_handling_mode":"client_csr"}`,
		"hub+agent":    `{"name":"d","host":"h","install_mode":"agent","key_handling_mode":"hub_generated"}`,
	} {
		if code, _, raw := postTarget(t, mux, "test-token", body); code != http.StatusBadRequest {
			t.Fatalf("%s: want 400, got %d: %s", name, code, raw)
		}
	}
}

func TestEffectiveModeDerivedWhenUnset(t *testing.T) {
	for install, want := range map[string]string{
		"ssh": KeyModeHubGenerated, "plugin": KeyModeHubGenerated, "f5": KeyModeHubGenerated,
		"agent": KeyModeClientCSR, "acme": KeyModeClientCSR, "cloud": KeyModeClientCSR,
		"keychain": KeyModeMacOSNonExtractable,
	} {
		mode, source := effectiveKeyHandlingMode(ManagedTarget{InstallMode: install})
		if mode != want || source != "derived" {
			t.Fatalf("%s: got %s/%s, want %s/derived", install, mode, source, want)
		}
	}
	mux, _, _, _, _ := newTargetsTestMux(t)
	_, created, _ := postTarget(t, mux, "test-token", `{"name":"x","host":"h","install_mode":"ssh"}`)
	if created.KeyHandlingMode != "" || created.EffectiveKeyHandlingMode != KeyModeHubGenerated {
		t.Fatalf("unset must stay unset but report derived: %+v", created)
	}
}

func TestPatchRevalidatesMergedMode(t *testing.T) {
	mux, _, _, _, _ := newTargetsTestMux(t)
	code, created, raw := postTarget(t, mux, "test-token", `{"name":"p","host":"h","install_mode":"ssh","key_handling_mode":"hub_generated"}`)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, raw)
	}
	rec := doTargetsRequest(mux, http.MethodPatch, "/api/v1/targets/"+created.ID, "test-token", `{"install_mode":"agent"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("incompatible merged mode must be 400, got %d: %s", rec.Code, rec.Body.String())
	}
	rec = doTargetsRequest(mux, http.MethodPatch, "/api/v1/targets/"+created.ID, "test-token", `{"key_handling_mode":"tpm"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("tpm patch must be 400, got %d", rec.Code)
	}
	rec = doTargetsRequest(mux, http.MethodPatch, "/api/v1/targets/"+created.ID, "test-token", `{"effective_key_handling_mode":"client_csr","name":"p2"}`)
	var got targetResp
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != http.StatusOK || got.Data.EffectiveKeyHandlingMode != KeyModeHubGenerated {
		t.Fatalf("effective mode must not be settable from a body: %d %+v", rec.Code, got.Data)
	}
}

func TestKeyCustodyReportListsEffectiveModePerTarget(t *testing.T) {
	mux, auth, store, tenantStore, _ := newTargetsTestMux(t)
	t.Setenv("MULTI_TENANCY", "on")
	ctx := context.Background()
	for _, id := range []string{"tenant-a", "tenant-b"} {
		if _, err := tenantStore.CreateTenant(ctx, id, id); err != nil {
			t.Fatal(err)
		}
	}
	_, tokenA, err := auth.CreateAPIKey("user-a", "user-a", "pki-admin", []string{"*"}, "", "tenant-a", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, tokenB, err := auth.CreateAPIKey("user-b", "user-b", "pki-admin", []string{"*"}, "", "tenant-b", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, tg := range []ManagedTarget{
		{ID: "t1", Name: "b-web", Host: "b.example.com", DiscoveryMode: "none", InstallMode: "ssh", RenewalMethod: "manual", Tenant: "tenant-a", CreatedAt: now, UpdatedAt: now},
		{ID: "t2", Name: "a-agent", Host: "a.example.com", DiscoveryMode: "none", InstallMode: "agent", RenewalMethod: "manual", Tenant: "tenant-a", CreatedAt: now, UpdatedAt: now},
		{ID: "t3", Name: "c-mac", Host: "c.example.com", DiscoveryMode: "none", InstallMode: "keychain", RenewalMethod: "manual", KeyHandlingMode: KeyModeMacOSNonExtractable, Tenant: "tenant-a", CreatedAt: now, UpdatedAt: now},
		{ID: "t4", Name: "other-tenant", Host: "d.example.com", DiscoveryMode: "none", InstallMode: "ssh", RenewalMethod: "manual", Tenant: "tenant-b", CreatedAt: now, UpdatedAt: now},
	} {
		if _, err := store.Create(ctx, tg); err != nil {
			t.Fatal(err)
		}
	}
	registerKeyCustodyHandler(mux, auth, &fakeKeystore{}, store, nil)

	fetch := func(token string) []TargetKeyModeEntry {
		rec := doTargetsRequest(mux, http.MethodGet, "/api/v1/reports/key-custody", token, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("custody status %d: %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Data KeyCustodyReport `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		return resp.Data.Targets
	}
	a := fetch(tokenA)
	if len(a) != 3 || a[0].Name != "a-agent" || a[1].Name != "b-web" || a[2].Name != "c-mac" {
		t.Fatalf("tenant A entries (sorted by name) wrong: %+v", a)
	}
	if a[0].Mode != KeyModeClientCSR || a[0].Source != "derived" || a[1].Mode != KeyModeHubGenerated || a[2].Mode != KeyModeMacOSNonExtractable || a[2].Source != "explicit" {
		t.Fatalf("modes/sources wrong: %+v", a)
	}
	b := fetch(tokenB)
	if len(b) != 1 || b[0].TargetID != "t4" {
		t.Fatalf("tenant B must see only its own target: %+v", b)
	}
}

func TestExecuteRenewalRefusesClientCSRTarget(t *testing.T) {
	db := setupIntegrationDB(t)
	provider, engine := newIntegrationCAProvider(t, db)
	issued, err := provider.IssueCertificate(context.Background(), CertificateIssueRequest{
		CAID:       getFirstCAID(t, engine),
		CSRPEM:     generateTestCSRPEM(t, "csrmode.example.com", "csrmode.example.com"),
		TemplateID: "file-backed-default",
		TeamID:     "team-csrmode",
	})
	if err != nil {
		t.Fatal(err)
	}
	fake := &renewalFakeExecutor{files: map[string][]byte{}}
	exec := newRenewalTestEngine(t, provider, fake, testSSHCredentialJSON(t))
	target := sshTestTarget()
	target.KeyHandlingMode = KeyModeClientCSR // explicit label contradicts hub-side key generation

	res, err := exec.ExecuteRenewal(context.Background(), issued.CertificateItem.FingerprintSHA256, target, sshTestProfile())
	if !errors.Is(err, errRenewalKeyModeMismatch) {
		t.Fatalf("want errRenewalKeyModeMismatch, got %v", err)
	}
	if res.Renewed || res.NewFingerprint != "" || len(fake.files) != 0 {
		t.Fatalf("nothing may be issued or installed: %+v files=%v", res, fake.files)
	}
}
