// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	kkdb "kryptkeeper/internal/db"
	"kryptkeeper/tests/plugins/conformance"
)

var (
	examplePluginOnce sync.Once
	examplePluginWasm []byte
	examplePluginDir  string
)

// examplePlugin builds plugins/example once per test binary.
func examplePlugin(t *testing.T) ([]byte, string) {
	t.Helper()
	examplePluginOnce.Do(func() {
		_, file, _, _ := runtime.Caller(0)
		examplePluginDir = filepath.Join(filepath.Dir(file), "..", "..", "plugins", "example")
		examplePluginWasm = conformance.Build(t, examplePluginDir)
	})
	return examplePluginWasm, examplePluginDir
}

// manifestVariant returns the example manifest pinned to wasm, at version,
// with mutate applied to its capabilities.
func manifestVariant(t *testing.T, version string, mutate func(caps map[string]any)) json.RawMessage {
	t.Helper()
	wasm, dir := examplePlugin(t)
	var m map[string]any
	if err := json.Unmarshal(conformance.PinManifest(t, dir, wasm), &m); err != nil {
		t.Fatal(err)
	}
	m["version"] = version
	if mutate != nil {
		mutate(m["capabilities"].(map[string]any))
	}
	raw, _ := json.Marshal(m)
	return raw
}

type pluginHarness struct {
	mux             *http.ServeMux
	mgr             *DeliveryPluginManager
	adminKey, opKey string
	audit           *scepRecordingAudit
}

func newPluginHarness(t *testing.T) *pluginHarness {
	t.Helper()
	t.Setenv("AUTH_MODE", "bootstrap")
	t.Setenv("APP_BOOTSTRAP_TOKEN", "test-token")
	t.Setenv("APP_API_KEY_PEPPER", "test-pepper-32chars-minimum!!!!!")
	t.Setenv("APP_API_KEY_AUTH_ENABLED", "true")
	auth := NewAuthenticatorFromEnv()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "plugins.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := kkdb.RunMigrations(db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	actions := &dbPendingActionStore{db: db, ph: sqlitePlaceholder}
	if err := actions.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	mgr := NewDeliveryPluginManager(db, false, actions, nil)
	audit := &scepRecordingAudit{}
	mux := http.NewServeMux()
	registerDeliveryPluginHandlers(mux, auth, mgr, audit)
	registerPluginCatalogueHandlers(mux, auth, mgr, audit)
	registerPendingActionHandlers(mux, auth, &reportCertProvider{}, actions, audit,
		map[string]ActionExecutor{ActionEnableDeliveryPlugin: mgr.ExecuteEnable})
	_, adminKey, err := auth.CreateAPIKey("admin-2", "second-admin", "pki-admin", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, opKey, err := auth.CreateAPIKey("operator", "operator-svc", "pki-operator", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return &pluginHarness{mux: mux, mgr: mgr, adminKey: adminKey, opKey: opKey, audit: audit}
}

func (h *pluginHarness) call(t *testing.T, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec
}

func (h *pluginHarness) install(t *testing.T, manifest json.RawMessage) *httptest.ResponseRecorder {
	wasm, _ := examplePlugin(t)
	return h.call(t, http.MethodPost, "/api/v1/delivery-plugins", "test-token",
		map[string]any{"manifest": manifest, "wasm_base64": base64.StdEncoding.EncodeToString(wasm)})
}

func pendingActionID(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var out struct {
		Data struct {
			Status          string `json:"status"`
			PendingActionID string `json:"pending_action_id"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusAccepted || out.Data.Status != "pending_approval" || out.Data.PendingActionID == "" {
		t.Fatalf("expected a pending approval, got %d %s", rec.Code, rec.Body.String())
	}
	return out.Data.PendingActionID
}

// W20-20, D-116: a plugin that receives private keys is enabled only when
// a second pki-admin approves it in the queue.
func TestDeliveryPluginCriticalEnableNeedsSecondAdmin(t *testing.T) {
	h := newPluginHarness(t)
	ctx := context.Background()
	if rec := h.install(t, manifestVariant(t, "1.0.0", nil)); rec.Code != http.StatusCreated {
		t.Fatalf("install: %d %s", rec.Code, rec.Body.String())
	}
	if _, _, err := h.mgr.Enabled(ctx, "kryptkeeper.example-device"); err == nil {
		t.Fatal("an installed plugin must not run before it is enabled")
	}

	actionID := pendingActionID(t, h.call(t, http.MethodPost, "/api/v1/delivery-plugins/kryptkeeper.example-device/versions/1.0.0/enable", "test-token", nil))

	if rec := h.call(t, http.MethodPost, "/api/v1/pending-actions/"+actionID+"/approve", "test-token", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("self-approval: %d, want 403", rec.Code)
	}
	if rec := h.call(t, http.MethodPost, "/api/v1/pending-actions/"+actionID+"/approve", h.opKey, nil); rec.Code == http.StatusOK {
		t.Fatal("a pki-operator enabled a key-receiving plugin")
	}
	if _, _, err := h.mgr.Enabled(ctx, "kryptkeeper.example-device"); err == nil {
		t.Fatal("plugin enabled without a valid approval")
	}

	// The operator's attempt marked the action failed; propose again.
	actionID = pendingActionID(t, h.call(t, http.MethodPost, "/api/v1/delivery-plugins/kryptkeeper.example-device/versions/1.0.0/enable", "test-token", nil))
	if actionID == "" {
		t.Fatal("no new action")
	}
}

func TestDeliveryPluginApprovalBySecondAdmin(t *testing.T) {
	h := newPluginHarness(t)
	ctx := context.Background()
	if rec := h.install(t, manifestVariant(t, "1.0.0", nil)); rec.Code != http.StatusCreated {
		t.Fatalf("install: %d %s", rec.Code, rec.Body.String())
	}
	actionID := pendingActionID(t, h.call(t, http.MethodPost, "/api/v1/delivery-plugins/kryptkeeper.example-device/versions/1.0.0/enable", "test-token", nil))
	if rec := h.call(t, http.MethodPost, "/api/v1/pending-actions/"+actionID+"/approve", h.adminKey, nil); rec.Code != http.StatusOK {
		t.Fatalf("second admin approve: %d %s", rec.Code, rec.Body.String())
	}
	p, v, err := h.mgr.Enabled(ctx, "kryptkeeper.example-device")
	if err != nil || p == nil || v.Version != "1.0.0" || v.ApprovedBy == "" || v.ApprovedBy == "bootstrap" {
		t.Fatalf("enabled %+v err %v", v, err)
	}

	// An upgrade that adds a capability goes back to approval, and the
	// approved version keeps running meanwhile.
	wider := manifestVariant(t, "1.1.0", func(c map[string]any) {
		c["network"] = map[string]any{"hosts_from_credential": "base_url", "hosts": []string{"api.cdn.example"}}
	})
	if rec := h.install(t, wider); rec.Code != http.StatusCreated {
		t.Fatalf("install 1.1.0: %d %s", rec.Code, rec.Body.String())
	}
	pendingActionID(t, h.call(t, http.MethodPost, "/api/v1/delivery-plugins/kryptkeeper.example-device/versions/1.1.0/enable", "test-token", nil))
	if _, v, _ := h.mgr.Enabled(ctx, "kryptkeeper.example-device"); v.Version != "1.0.0" {
		t.Fatalf("a pending upgrade replaced the approved version: running %s", v.Version)
	}

	// An upgrade within the approved capabilities is enabled directly.
	if rec := h.install(t, manifestVariant(t, "1.0.1", nil)); rec.Code != http.StatusCreated {
		t.Fatalf("install 1.0.1: %d", rec.Code)
	}
	if rec := h.call(t, http.MethodPost, "/api/v1/delivery-plugins/kryptkeeper.example-device/versions/1.0.1/enable", "test-token", nil); rec.Code != http.StatusOK {
		t.Fatalf("same-capability upgrade: %d %s", rec.Code, rec.Body.String())
	}
	if _, v, _ := h.mgr.Enabled(ctx, "kryptkeeper.example-device"); v.Version != "1.0.1" {
		t.Fatalf("running %s, want 1.0.1", v.Version)
	}

	// Remove refuses an enabled plugin; disable, then remove.
	if rec := h.call(t, http.MethodDelete, "/api/v1/delivery-plugins/kryptkeeper.example-device", "test-token", nil); rec.Code != http.StatusConflict {
		t.Fatalf("remove enabled: %d", rec.Code)
	}
	if rec := h.call(t, http.MethodPost, "/api/v1/delivery-plugins/kryptkeeper.example-device/disable", "test-token", nil); rec.Code != http.StatusOK {
		t.Fatalf("disable: %d", rec.Code)
	}
	if _, _, err := h.mgr.Enabled(ctx, "kryptkeeper.example-device"); err == nil {
		t.Fatal("a disabled plugin still runs")
	}
	if rec := h.call(t, http.MethodDelete, "/api/v1/delivery-plugins/kryptkeeper.example-device", "test-token", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("remove disabled: %d", rec.Code)
	}

	actions := map[string]bool{}
	for _, e := range h.audit.entries {
		actions[e.Action+":"+string(e.Outcome)] = true
	}
	for _, want := range []string{"delivery_plugin.install:success", "delivery_plugin.enable_requested:success", "delivery_plugin.enable:success",
		"action.approve:success", "delivery_plugin.disable:success", "delivery_plugin.remove:success"} {
		if !actions[want] {
			t.Errorf("audit lacks %s (have %v)", want, actions)
		}
	}
}

func TestDeliveryPluginStandardEnablesDirectly(t *testing.T) {
	h := newPluginHarness(t)
	// SUP-A08-1: hosts_from_credential is network access (high), so a
	// standard plugin has neither a private key nor any network capability.
	standard := manifestVariant(t, "2.0.0", func(c map[string]any) {
		delete(c, "receive_private_key")
		delete(c, "network")
	})
	if rec := h.install(t, standard); rec.Code != http.StatusCreated {
		t.Fatalf("install: %d %s", rec.Code, rec.Body.String())
	}
	if rec := h.call(t, http.MethodPost, "/api/v1/delivery-plugins/kryptkeeper.example-device/versions/2.0.0/enable", "test-token", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"enabled"`) {
		t.Fatalf("standard plugin: %d %s", rec.Code, rec.Body.String())
	}
}

func TestDeliveryPluginCredentialHostOnlyNeedsApproval(t *testing.T) {
	h := newPluginHarness(t)
	credOnly := manifestVariant(t, "2.0.0", func(c map[string]any) {
		delete(c, "receive_private_key")
		c["network"] = map[string]any{"hosts_from_credential": "base_url"}
	})
	if rec := h.install(t, credOnly); rec.Code != http.StatusCreated {
		t.Fatalf("install: %d %s", rec.Code, rec.Body.String())
	}
	rec := h.call(t, http.MethodPost, "/api/v1/delivery-plugins/kryptkeeper.example-device/versions/2.0.0/enable", "test-token", nil)
	if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), "pending_approval") {
		t.Fatalf("credential-host-only plugin must need a second approver: %d %s", rec.Code, rec.Body.String())
	}
}

func TestDeliveryPluginAPIRefusals(t *testing.T) {
	h := newPluginHarness(t)
	wasm, _ := examplePlugin(t)
	manifest := manifestVariant(t, "1.0.0", nil)

	tampered := append(append([]byte(nil), wasm...), 0)
	rec := h.call(t, http.MethodPost, "/api/v1/delivery-plugins", "test-token",
		map[string]any{"manifest": manifest, "wasm_base64": base64.StdEncoding.EncodeToString(tampered)})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("tampered module: %d", rec.Code)
	}
	rec = h.call(t, http.MethodPost, "/api/v1/delivery-plugins", h.opKey,
		map[string]any{"manifest": manifest, "wasm_base64": base64.StdEncoding.EncodeToString(wasm)})
	if rec.Code != http.StatusForbidden {
		t.Errorf("operator install: %d", rec.Code)
	}
	if rec := h.call(t, http.MethodGet, "/api/v1/delivery-plugins", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous list: %d", rec.Code)
	}
	if rec := h.install(t, manifest); rec.Code != http.StatusCreated {
		t.Fatalf("install: %d", rec.Code)
	}
	if rec := h.install(t, manifest); rec.Code != http.StatusConflict {
		t.Errorf("same version twice: %d", rec.Code)
	}

	// The kill switch: no manager, every route says plugins are off.
	t.Setenv("KRYPTKEEPER_DELIVERY_PLUGINS", "off")
	if NewDeliveryPluginManager(h.mgr.db, false, nil, nil) != nil {
		t.Fatal("KRYPTKEEPER_DELIVERY_PLUGINS=off still built a manager")
	}
	mux := http.NewServeMux()
	registerDeliveryPluginHandlers(mux, NewAuthenticatorFromEnv(), nil, h.audit)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/delivery-plugins", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	off := httptest.NewRecorder()
	mux.ServeHTTP(off, req)
	if off.Code != http.StatusServiceUnavailable || !strings.Contains(off.Body.String(), "turned off") {
		t.Errorf("plugins off: %d %s", off.Code, off.Body.String())
	}
}

// otherIDManifest returns the example manifest re-identified as id.
func otherIDManifest(t *testing.T, id, version string, mutate func(caps map[string]any)) json.RawMessage {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(manifestVariant(t, version, mutate), &m); err != nil {
		t.Fatal(err)
	}
	m["id"] = id
	raw, _ := json.Marshal(m)
	return raw
}

func (h *pluginHarness) enable(t *testing.T, id, version string) *httptest.ResponseRecorder {
	t.Helper()
	return h.call(t, http.MethodPost, "/api/v1/delivery-plugins/"+id+"/versions/"+version+"/enable", "test-token", nil)
}

// A-02: two plugin ids pinning the same module bytes must each load with
// their own manifest and grant, never share one cached instance.
func TestDeliveryPluginCacheIsPerIDAndVersion(t *testing.T) {
	h := newPluginHarness(t)
	ctx := context.Background()
	const idA, idB = "kryptkeeper.example-device", "kryptkeeper.example-other"
	std := func(c map[string]any) { delete(c, "receive_private_key"); delete(c, "network") }
	if rec := h.install(t, manifestVariant(t, "1.0.0", std)); rec.Code != http.StatusCreated {
		t.Fatalf("install A: %d %s", rec.Code, rec.Body.String())
	}
	if rec := h.install(t, otherIDManifest(t, idB, "1.0.0", nil)); rec.Code != http.StatusCreated {
		t.Fatalf("install B: %d %s", rec.Code, rec.Body.String())
	}
	if rec := h.enable(t, idA, "1.0.0"); rec.Code != http.StatusOK {
		t.Fatalf("enable A: %d %s", rec.Code, rec.Body.String())
	}
	actionID := pendingActionID(t, h.enable(t, idB, "1.0.0"))
	if rec := h.call(t, http.MethodPost, "/api/v1/pending-actions/"+actionID+"/approve", h.adminKey, nil); rec.Code != http.StatusOK {
		t.Fatalf("approve B: %d %s", rec.Code, rec.Body.String())
	}
	pa, va, err := h.mgr.Enabled(ctx, idA)
	if err != nil {
		t.Fatal(err)
	}
	pb, vb, err := h.mgr.Enabled(ctx, idB)
	if err != nil {
		t.Fatal(err)
	}
	if va.SHA256 != vb.SHA256 {
		t.Fatal("test needs both ids on the same module bytes")
	}
	if pa == pb {
		t.Fatal("two plugin ids with the same wasm share one loaded plugin (and grant)")
	}
	if pa2, _, _ := h.mgr.Enabled(ctx, idA); pa2 != pa {
		t.Fatal("the cache no longer reuses a loaded plugin for the same id and version")
	}
}

func (h *pluginHarness) setTier(t *testing.T, id, version, tier string) {
	t.Helper()
	if _, err := h.mgr.db.Exec(`UPDATE delivery_plugin_versions SET tier = ? WHERE plugin_id = ? AND version = ?`, tier, id, version); err != nil {
		t.Fatal(err)
	}
}

// A-03: the within-capabilities shortcut is for versions at least as
// trusted as the running one; a downgrade needs a second person.
func TestDeliveryPluginTrustDowngradeNeedsApproval(t *testing.T) {
	h := newPluginHarness(t)
	ctx := context.Background()
	const id = "kryptkeeper.example-device"
	for _, v := range []string{"1.0.0", "1.0.1", "1.0.2"} {
		if rec := h.install(t, manifestVariant(t, v, nil)); rec.Code != http.StatusCreated {
			t.Fatalf("install %s: %d %s", v, rec.Code, rec.Body.String())
		}
	}
	h.setTier(t, id, "1.0.0", PluginTierFirstParty)
	actionID := pendingActionID(t, h.enable(t, id, "1.0.0"))
	if rec := h.call(t, http.MethodPost, "/api/v1/pending-actions/"+actionID+"/approve", h.adminKey, nil); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}

	// community 1.0.1 with identical capabilities: pending, 1.0.0 keeps running.
	pendingActionID(t, h.enable(t, id, "1.0.1"))
	if _, v, _ := h.mgr.Enabled(ctx, id); v.Version != "1.0.0" {
		t.Fatalf("a trust downgrade replaced the approved version: running %s", v.Version)
	}

	// Same tier, within capabilities: direct.
	h.setTier(t, id, "1.0.2", PluginTierFirstParty)
	if rec := h.enable(t, id, "1.0.2"); rec.Code != http.StatusOK {
		t.Fatalf("same-tier upgrade: %d %s", rec.Code, rec.Body.String())
	}
	if _, v, _ := h.mgr.Enabled(ctx, id); v.Version != "1.0.2" {
		t.Fatalf("running %s, want 1.0.2", v.Version)
	}
}

func TestDeliveryPluginStandardDowngradeNeedsApproval(t *testing.T) {
	h := newPluginHarness(t)
	const id = "kryptkeeper.example-device"
	std := func(c map[string]any) { delete(c, "receive_private_key"); delete(c, "network") }
	for _, v := range []string{"1.0.0", "1.0.1"} {
		if rec := h.install(t, manifestVariant(t, v, std)); rec.Code != http.StatusCreated {
			t.Fatalf("install %s: %d", v, rec.Code)
		}
	}
	h.setTier(t, id, "1.0.0", PluginTierFirstParty)
	if rec := h.enable(t, id, "1.0.0"); rec.Code != http.StatusOK {
		t.Fatalf("enable first-party standard: %d %s", rec.Code, rec.Body.String())
	}
	pendingActionID(t, h.enable(t, id, "1.0.1"))
}

// A-05: plugins are instance-wide, so a tenant-scoped admin may not approve.
func TestDeliveryPluginExecuteEnableNeedsInstanceAdminUnderMultiTenancy(t *testing.T) {
	h := newPluginHarness(t)
	t.Setenv("MULTI_TENANCY", "true")
	action := PendingAction{ID: "a1", Params: json.RawMessage(`{}`)}
	_, err := h.mgr.ExecuteEnable(context.Background(), action, AuthPrincipal{ID: "t-admin", Role: "pki-admin"})
	if err == nil || !strings.Contains(err.Error(), "multi-tenancy") {
		t.Fatalf("tenant admin: %v", err)
	}
	_, err = h.mgr.ExecuteEnable(context.Background(), action, AuthPrincipal{ID: "root", Role: "pki-admin", SuperAdmin: true})
	if err == nil || strings.Contains(err.Error(), "multi-tenancy") {
		t.Fatalf("super-admin should pass the tenancy guard, got %v", err)
	}
}
