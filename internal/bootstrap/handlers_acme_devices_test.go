// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"database/sql"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"kryptkeeper/internal/acme"
	kkdb "kryptkeeper/internal/db"
)

func newACMEDeviceMux(t *testing.T) (*http.ServeMux, *Authenticator, *acme.DBDeviceAllowlist, *scepRecordingAudit) {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "devices.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := acme.NewDBDeviceAllowlist(db, false)
	audit := &scepRecordingAudit{}
	mux := http.NewServeMux()
	RegisterACMEDeviceHandlers(mux, auth, store, audit)
	return mux, auth, store, audit
}

func TestACMEDeviceInventoryAddListRemove(t *testing.T) {
	mux, _, store, audit := newACMEDeviceMux(t)

	rec := scepAPI(t, mux, http.MethodPost, "/api/v1/acme/devices", "test-token", map[string]any{"identifier": "C02ABC/1.2.3", "label": "ceo laptop"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("add: %d %s", rec.Code, rec.Body.String())
	}
	if _, ok, _ := store.Lookup(context.Background(), "C02ABC/1.2.3"); !ok {
		t.Fatal("entry was not stored verbatim")
	}
	if dup := scepAPI(t, mux, http.MethodPost, "/api/v1/acme/devices", "test-token", map[string]any{"identifier": "C02ABC/1.2.3"}); dup.Code != http.StatusConflict {
		t.Errorf("duplicate: %d, want 409", dup.Code)
	}
	for _, bad := range []string{"", "a/b/c", "x\x01y", strings.Repeat("z", 65)} {
		if r := scepAPI(t, mux, http.MethodPost, "/api/v1/acme/devices", "test-token", map[string]any{"identifier": bad}); r.Code != http.StatusBadRequest {
			t.Errorf("identifier %q: %d, want 400", bad, r.Code)
		}
	}
	list := scepAPI(t, mux, http.MethodGet, "/api/v1/acme/devices", "test-token", nil)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "C02ABC/1.2.3") || !strings.Contains(list.Body.String(), `"tenant_id":"default"`) {
		t.Fatalf("list: %d %s", list.Code, list.Body.String())
	}
	if del := scepAPI(t, mux, http.MethodDelete, "/api/v1/acme/devices/"+url.PathEscape("C02ABC/1.2.3"), "test-token", nil); del.Code != http.StatusNoContent {
		t.Fatalf("remove: %d", del.Code)
	}
	if del := scepAPI(t, mux, http.MethodDelete, "/api/v1/acme/devices/"+url.PathEscape("C02ABC/1.2.3"), "test-token", nil); del.Code != http.StatusNotFound {
		t.Errorf("second remove: %d, want 404", del.Code)
	}
	if r := scepAPI(t, mux, http.MethodPut, "/api/v1/acme/devices", "test-token", nil); r.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT: %d, want 405", r.Code)
	}
	actions := map[string]int{}
	for _, e := range audit.entries {
		actions[e.Action]++
	}
	for _, a := range []string{"acme.device.add", "acme.device.list", "acme.device.remove"} {
		if actions[a] == 0 {
			t.Errorf("no audit row for %s: %v", a, actions)
		}
	}
}

func TestACMEDeviceInventoryRequiresPKIAdmin(t *testing.T) {
	mux, auth, _, audit := newACMEDeviceMux(t)
	_, opKey, err := auth.CreateAPIKey("operator", "operator-svc", "pki-operator", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		if rec := scepAPI(t, mux, m, "/api/v1/acme/devices", opKey, map[string]any{"identifier": "X"}); rec.Code != http.StatusForbidden {
			t.Errorf("%s as operator: %d, want 403", m, rec.Code)
		}
		if rec := scepAPI(t, mux, m, "/api/v1/acme/devices", "", map[string]any{}); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without token: %d, want 401", m, rec.Code)
		}
	}
	if rec := scepAPI(t, mux, http.MethodDelete, "/api/v1/acme/devices/X", opKey, nil); rec.Code != http.StatusForbidden {
		t.Errorf("DELETE as operator: %d, want 403", rec.Code)
	}
	denied := 0
	for _, e := range audit.entries {
		if e.Outcome == AuditOutcomeDenied {
			denied++
		}
	}
	if denied != 5 {
		t.Errorf("denied audit rows = %d, want 5", denied)
	}
}

type fakeTenants struct{ TenantStore }

func (fakeTenants) CATenant(_ context.Context, caID string) (string, error) {
	if caID == "ca-b" {
		return "team-b", nil
	}
	return DefaultTenant, nil
}

func TestACMEDeviceCheckHonoursTenancy(t *testing.T) {
	ctx := context.Background()
	list := acme.NewMemDeviceAllowlist()
	_ = list.Add(ctx, acme.DeviceEntry{Identifier: "SER-A"}) // default tenant
	_ = list.Add(ctx, acme.DeviceEntry{Identifier: "SER-B", TenantID: "team-b"})
	check := NewACMEDeviceCheck(list, fakeTenants{})

	// Tenancy off: presence in the inventory is enough.
	t.Setenv("MULTI_TENANCY", "")
	if ok, err := check(ctx, "ca-b", "SER-A"); err != nil || !ok {
		t.Fatalf("tenancy off: ok=%v err=%v", ok, err)
	}
	if ok, _ := check(ctx, "ca-a", "SER-unknown"); ok {
		t.Fatal("an unknown device must not be allowed")
	}

	t.Setenv("MULTI_TENANCY", "on")
	cases := []struct {
		ca, id string
		want   bool
	}{{"ca-a", "SER-A", true}, {"ca-b", "SER-B", true}, {"ca-b", "SER-A", false}, {"ca-a", "SER-B", false}}
	for _, c := range cases {
		if ok, err := check(ctx, c.ca, c.id); err != nil || ok != c.want {
			t.Errorf("tenancy on, CA %s device %s: ok=%v err=%v, want %v", c.ca, c.id, ok, err, c.want)
		}
	}
	if _, err := NewACMEDeviceCheck(list, nil)(ctx, "ca-a", "SER-A"); err == nil {
		t.Error("tenancy on with no tenant store must fail closed")
	}
}

func TestACMETemplateDeviceCheck(t *testing.T) {
	ctx := context.Background()
	check := NewACMETemplateDeviceCheck(fixedTemplates{items: map[string]TemplateItem{
		"on":       {ID: "on", Active: true, DeviceAttestation: true},
		"inactive": {ID: "inactive", DeviceAttestation: true},
		"off":      {ID: "off", Active: true},
	}})
	for id, want := range map[string]bool{"on": true, "inactive": false, "off": false, "missing": false, "": false} {
		if ok, err := check(ctx, id); err != nil || ok != want {
			t.Errorf("template %q: ok=%v err=%v, want %v", id, ok, err, want)
		}
	}
	if ok, _ := NewACMETemplateDeviceCheck(nil)(ctx, "on"); ok {
		t.Error("no template provider must refuse")
	}
}

type fixedTemplates struct {
	TemplateProvider
	items map[string]TemplateItem
}

func (f fixedTemplates) GetTemplate(_ context.Context, id string) (TemplateItem, bool, error) {
	it, ok := f.items[id]
	return it, ok, nil
}
