// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"kryptkeeper/internal/plugins/delivery"
)

// catalogueFixture serves a signed catalogue with one plugin over loopback.
type catalogueFixture struct {
	h         *pluginHarness
	srv       *httptest.Server
	hits      atomic.Int64
	signer    testSigner
	manifest  []byte
	wasm      []byte
	catalogue []byte
	// served is what the catalogue route returns; tests tamper with it.
	served atomic.Pointer[[]byte]
	// catalogueSig overrides the bundle served beside the catalogue.
	catalogueSig atomic.Pointer[string]
	servedWasm   atomic.Pointer[[]byte]
}

func newCatalogueFixture(t *testing.T) *catalogueFixture {
	t.Helper()
	prev := egressAllowLoopback
	egressAllowLoopback = true
	t.Cleanup(func() { egressAllowLoopback = prev })
	f := &catalogueFixture{h: newPluginHarness(t), signer: newTestSigner(t)}
	trust, err := NewPluginTrust(f.signer.pubPEM, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.h.mgr.trust = trust
	f.wasm, _ = examplePlugin(t)
	f.manifest = manifestVariant(t, "1.0.0", nil)

	mux := http.NewServeMux()
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.srv.Close)

	sum := sha256.Sum256(f.wasm)
	cat := delivery.Catalogue{Version: 1, GeneratedAt: "2026-10-25T00:00:00Z", Entries: []delivery.CatalogueEntry{{
		ID: "kryptkeeper.example-device", Kind: "delivery", Name: "Example", Publisher: "Kryptkeeper Authors", Version: "1.0.0",
		Description: "reference", ManifestURL: f.srv.URL + "/m.json", WasmURL: f.srv.URL + "/plugin.wasm", BundleURL: f.srv.URL + "/m.json.bundle",
		SHA256: hex.EncodeToString(sum[:]), Capabilities: []string{"receive_private_key", "network"},
	}}}
	f.catalogue, _ = json.Marshal(cat)
	f.served.Store(&f.catalogue)

	mux.HandleFunc("/catalogue.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(*f.served.Load()) })
	mux.HandleFunc("/catalogue.json.bundle", func(w http.ResponseWriter, _ *http.Request) {
		if s := f.catalogueSig.Load(); s != nil {
			_, _ = w.Write([]byte(*s))
			return
		}
		_, _ = w.Write([]byte(f.signer.sign(t, f.catalogue)))
	})
	mux.HandleFunc("/m.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(f.manifest) })
	mux.HandleFunc("/m.json.bundle", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(f.signer.sign(t, f.manifest))) })
	mux.HandleFunc("/plugin.wasm", func(w http.ResponseWriter, _ *http.Request) {
		if b := f.servedWasm.Load(); b != nil {
			_, _ = w.Write(*b)
			return
		}
		_, _ = w.Write(f.wasm)
	})
	f.h.mgr.EnableCatalogue(f.srv.URL+"/catalogue.json", "1.1.0")
	return f
}

func (f *catalogueFixture) installed(t *testing.T) int {
	t.Helper()
	list, err := f.h.mgr.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, p := range list {
		n += len(p.Versions)
	}
	return n
}

func TestPluginCatalogueListAndInstallMatchesUpload(t *testing.T) {
	f := newCatalogueFixture(t)
	h := f.h

	rec := h.call(t, http.MethodGet, "/api/v1/plugin-catalogue", "test-token", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"available"`) {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	rec = h.call(t, http.MethodPost, "/api/v1/plugin-catalogue/kryptkeeper.example-device/install", "test-token", nil)
	v := installedVersion(t, rec)
	// Signed with the first-party key, and still disabled.
	if v.Tier != PluginTierFirstParty || v.Status != "installed" || v.SignerKeyID != f.signer.id {
		t.Errorf("catalogue install: %+v", v)
	}
	last := h.audit.entries[len(h.audit.entries)-1]
	if !strings.Contains(last.ChangeSummary, "trust=first-party") {
		t.Errorf("audit detail: %q", last.ChangeSummary)
	}

	// The enable step is the upload path's: the example receives private keys
	// (Critical), so it needs a second approver.
	pendingActionID(t, h.call(t, http.MethodPost, "/api/v1/delivery-plugins/kryptkeeper.example-device/versions/1.0.0/enable", "test-token", nil))

	rec = h.call(t, http.MethodGet, "/api/v1/plugin-catalogue", "test-token", nil)
	if !strings.Contains(rec.Body.String(), `"status":"installed"`) {
		t.Errorf("list after install: %s", rec.Body)
	}
	// Installing it again is the same conflict an upload gives.
	if rec := h.call(t, http.MethodPost, "/api/v1/plugin-catalogue/kryptkeeper.example-device/install", "test-token", nil); rec.Code != http.StatusConflict {
		t.Errorf("reinstall: %d", rec.Code)
	}
	if rec := h.call(t, http.MethodPost, "/api/v1/plugin-catalogue/no.such-plugin/install", "test-token", nil); rec.Code != http.StatusNotFound {
		t.Errorf("unknown id: %d", rec.Code)
	}
}

func TestPluginCatalogueSignatureRefusals(t *testing.T) {
	f := newCatalogueFixture(t)
	h := f.h

	// Tampered: the served bytes are not what was signed.
	tampered := []byte(strings.Replace(string(f.catalogue), "reference", "backdoored", 1))
	f.served.Store(&tampered)
	if rec := h.call(t, http.MethodGet, "/api/v1/plugin-catalogue", "test-token", nil); rec.Code != http.StatusBadGateway {
		t.Errorf("tampered catalogue: %d", rec.Code)
	}
	f.served.Store(&f.catalogue)

	// Wrong identity: a valid signature from a key the hub does not trust.
	stranger := newTestSigner(t)
	sig := stranger.sign(t, f.catalogue)
	f.catalogueSig.Store(&sig)
	if rec := h.call(t, http.MethodGet, "/api/v1/plugin-catalogue", "test-token", nil); rec.Code != http.StatusBadGateway {
		t.Errorf("wrong identity: %d", rec.Code)
	}
	if rec := h.call(t, http.MethodPost, "/api/v1/plugin-catalogue/kryptkeeper.example-device/install", "test-token", nil); rec.Code != http.StatusBadGateway {
		t.Errorf("install from wrong-identity catalogue: %d", rec.Code)
	}

	// No signature at all is refused, not treated as community.
	none := ""
	f.catalogueSig.Store(&none)
	if rec := h.call(t, http.MethodGet, "/api/v1/plugin-catalogue", "test-token", nil); rec.Code != http.StatusBadGateway {
		t.Errorf("unsigned catalogue: %d", rec.Code)
	}
	if n := f.installed(t); n != 0 {
		t.Errorf("%d versions stored by refused installs", n)
	}
}

func TestPluginCatalogueSHA256MismatchRefused(t *testing.T) {
	f := newCatalogueFixture(t)
	bad := append(append([]byte{}, f.wasm...), 0)
	f.servedWasm.Store(&bad)
	rec := f.h.call(t, http.MethodPost, "/api/v1/plugin-catalogue/kryptkeeper.example-device/install", "test-token", nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "sha256") {
		t.Errorf("sha mismatch: %d %s", rec.Code, rec.Body)
	}
	if n := f.installed(t); n != 0 {
		t.Errorf("%d versions stored after a hash mismatch", n)
	}
}

func TestPluginCatalogueDisabledWhenURLEmpty(t *testing.T) {
	t.Setenv(pluginCatalogueEnv, "  ")
	if PluginCatalogueURLFromEnv() != "" {
		t.Fatal("a blank URL did not disable the catalogue")
	}
	h := newPluginHarness(t)
	h.mgr.EnableCatalogue(PluginCatalogueURLFromEnv(), "1.1.0")
	if h.mgr.catalogue != nil {
		t.Fatal("catalogue attached with an empty URL")
	}
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/plugin-catalogue"},
		{http.MethodPost, "/api/v1/plugin-catalogue/kryptkeeper.example-device/install"},
	} {
		if rec := h.call(t, c.method, c.path, "test-token", nil); rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s: %d", c.method, c.path, rec.Code)
		}
	}
}

func TestPluginCatalogueDefaultURL(t *testing.T) {
	// LookupEnv cannot distinguish unset from "" via t.Setenv, so clear it.
	t.Setenv(pluginCatalogueEnv, "x")
	unsetEnv(t, pluginCatalogueEnv)
	if got := PluginCatalogueURLFromEnv(); got != DefaultPluginCatalogueURL {
		t.Errorf("default URL: %q", got)
	}
}

func TestPluginCatalogueUsesEgressGuard(t *testing.T) {
	f := newCatalogueFixture(t)
	// Rebuild the client with loopback no longer allowed: the guard, not the
	// catalogue code, must stop the dial before the server sees a request.
	egressAllowLoopback = false
	f.h.mgr.EnableCatalogue(f.srv.URL+"/catalogue.json", "1.1.0")
	f.hits.Store(0)
	if rec := f.h.call(t, http.MethodGet, "/api/v1/plugin-catalogue", "test-token", nil); rec.Code != http.StatusBadGateway {
		t.Errorf("loopback catalogue: %d %s", rec.Code, rec.Body)
	}
	if f.hits.Load() != 0 {
		t.Errorf("the guard let %d requests through to a loopback host", f.hits.Load())
	}
}

func TestPluginCatalogueAdminOnlyAndAudited(t *testing.T) {
	f := newCatalogueFixture(t)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/plugin-catalogue"},
		{http.MethodPost, "/api/v1/plugin-catalogue/kryptkeeper.example-device/install"},
		{http.MethodPost, "/api/v1/plugin-catalogue/import"},
	} {
		if rec := f.h.call(t, c.method, c.path, f.h.opKey, nil); rec.Code != http.StatusForbidden {
			t.Errorf("operator %s %s: %d", c.method, c.path, rec.Code)
		}
	}
	if f.hits.Load() != 0 {
		t.Error("a refused request still reached the network")
	}
}

func TestPluginCatalogueOfflineImport(t *testing.T) {
	f := newCatalogueFixture(t)
	// An air-gapped hub has no catalogue URL; import must not need one.
	f.h.mgr.catalogue = nil
	f.hits.Store(0)
	b64 := base64.StdEncoding.EncodeToString
	body := func(cat []byte, catSig string) map[string]any {
		return map[string]any{
			"id": "kryptkeeper.example-device", "version": "1.0.0",
			"catalogue_base64": b64(cat), "catalogue_bundle": catSig,
			"manifest_base64": b64(f.manifest), "bundle": f.signer.sign(t, f.manifest), "wasm_base64": b64(f.wasm),
		}
	}
	tampered := []byte(strings.Replace(string(f.catalogue), "reference", "backdoored", 1))
	if rec := f.h.call(t, http.MethodPost, "/api/v1/plugin-catalogue/import", "test-token", body(tampered, f.signer.sign(t, f.catalogue))); rec.Code != http.StatusBadGateway {
		t.Errorf("tampered import: %d %s", rec.Code, rec.Body)
	}
	rec := f.h.call(t, http.MethodPost, "/api/v1/plugin-catalogue/import", "test-token", body(f.catalogue, f.signer.sign(t, f.catalogue)))
	if v := installedVersion(t, rec); v.Tier != PluginTierFirstParty {
		t.Errorf("imported tier %q", v.Tier)
	}
	if f.hits.Load() != 0 {
		t.Error("offline import touched the network")
	}
	// Files that are not the catalogue's entry are refused: a swapped module.
	other := body(f.catalogue, f.signer.sign(t, f.catalogue))
	other["wasm_base64"] = b64(append(append([]byte{}, f.wasm...), 1))
	other["version"] = "1.0.0"
	if rec := f.h.call(t, http.MethodPost, "/api/v1/plugin-catalogue/import", "test-token", other); rec.Code != http.StatusBadRequest {
		t.Errorf("swapped module: %d", rec.Code)
	}
}

// unsetEnv removes key for the test; the earlier t.Setenv restores it.
func unsetEnv(t *testing.T, key string) {
	t.Helper()
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}
}
