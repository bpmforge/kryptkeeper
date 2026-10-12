// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testSigner is a throwaway P-256 key generated per test.
type testSigner struct {
	key    *ecdsa.PrivateKey
	pubPEM []byte
	id     string
}

func newTestSigner(t *testing.T) testSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return testSigner{key: key, pubPEM: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), id: hex.EncodeToString(sum[:])}
}

// sign does what `cosign sign-blob --key` does: ECDSA over SHA-256 of the
// blob, ASN.1, base64.
func (s testSigner) sign(t *testing.T, blob []byte) string {
	t.Helper()
	digest := sha256.Sum256(blob)
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func readInterop(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "plugin-signing", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Real cosign v3 output, both forms, verifies; the tier follows which list
// holds the key.
func TestPluginSignatureCosignInterop(t *testing.T) {
	pub := readInterop(t, "cosign-interop.pub.txt")
	manifest := readInterop(t, "manifest.json")
	verified, err := NewPluginTrust(nil, pub)
	if err != nil {
		t.Fatal(err)
	}
	firstParty, err := NewPluginTrust(pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"manifest.json.bundle", "manifest.json.sig"} {
		sig := string(readInterop(t, name))
		if tier, id, err := verified.Classify(manifest, sig); err != nil || tier != PluginTierVerified || len(id) != 64 {
			t.Errorf("%s with an operator-trusted key: tier=%q id=%q err=%v", name, tier, id, err)
		}
		if tier, _, err := firstParty.Classify(manifest, sig); err != nil || tier != PluginTierFirstParty {
			t.Errorf("%s with the first-party key: tier=%q err=%v", name, tier, err)
		}
		tampered := []byte(strings.Replace(string(manifest), "1.0.0", "1.0.1", 1))
		if _, _, err := verified.Classify(tampered, sig); err == nil {
			t.Errorf("%s verified a manifest it was not made for", name)
		}
	}
}

func TestPluginSignatureClassify(t *testing.T) {
	signer, other := newTestSigner(t), newTestSigner(t)
	manifest := []byte(`{"id":"x","version":"1.0.0"}`)
	trust, err := NewPluginTrust(nil, signer.pubPEM)
	if err != nil {
		t.Fatal(err)
	}

	if tier, id, err := trust.Classify(manifest, "  "); err != nil || tier != PluginTierCommunity || id != "" {
		t.Errorf("unsigned: %q %q %v", tier, id, err)
	}
	if tier, id, err := trust.Classify(manifest, signer.sign(t, manifest)); err != nil || tier != PluginTierVerified || id != signer.id {
		t.Errorf("trusted signer: %q %q %v", tier, id, err)
	}
	// An unknown signer is refused, never downgraded to community.
	if _, _, err := trust.Classify(manifest, other.sign(t, manifest)); !errors.Is(err, errPluginSignature) {
		t.Errorf("unknown signer: %v", err)
	}
	var none *PluginTrust
	if _, _, err := none.Classify(manifest, signer.sign(t, manifest)); !errors.Is(err, errPluginSignature) {
		t.Errorf("no trust configured: %v", err)
	}
	if _, _, err := trust.Classify(manifest, "not base64!"); err == nil {
		t.Error("garbage signature accepted")
	}

	// A bundle whose digest names another manifest is refused before the
	// signature is even checked.
	bundle, _ := json.Marshal(map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"messageSignature": map[string]any{
			"messageDigest": map[string]string{"algorithm": "SHA2_256", "digest": base64.StdEncoding.EncodeToString(make([]byte, 32))},
			"signature":     signer.sign(t, manifest),
		},
	})
	if _, _, err := trust.Classify(manifest, string(bundle)); err == nil || !strings.Contains(err.Error(), "different manifest") {
		t.Errorf("mismatched bundle digest: %v", err)
	}
}

func TestPluginTrustKeyParsing(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rsaDER})
	if _, err := NewPluginTrust(nil, rsaPEM); err == nil || !strings.Contains(err.Error(), "P-256") {
		t.Errorf("an RSA key was accepted as a plugin-signing key: %v", err)
	}
	if _, err := NewPluginTrust(nil, []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")); err == nil {
		t.Error("a private key block was accepted")
	}
	// Comments around PEM blocks are fine, and several keys load.
	a, b := newTestSigner(t), newTestSigner(t)
	trust, err := NewPluginTrust([]byte("# no first-party key yet\n"), append(append([]byte("# vendor A\n"), a.pubPEM...), b.pubPEM...))
	if err != nil {
		t.Fatal(err)
	}
	if fp, v := trust.Counts(); fp != 0 || v != 2 {
		t.Errorf("counts: %d first-party, %d trusted", fp, v)
	}
	// The compiled-in file holds exactly the one Kryptkeeper plugin key; a
	// second key there is a rotation and should be a deliberate edit here.
	embedded, err := NewPluginTrust(firstPartyPluginKeys, nil)
	if err != nil {
		t.Fatalf("embedded first-party key file: %v", err)
	}
	if fp, _ := embedded.Counts(); fp != 1 {
		t.Errorf("embedded first-party keys: %d, want 1", fp)
	}
}

func TestPluginTrustFromEnv(t *testing.T) {
	signer := newTestSigner(t)
	path := filepath.Join(t.TempDir(), "trusted.txt")
	if err := os.WriteFile(path, signer.pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KRYPTKEEPER_PLUGIN_TRUSTED_KEYS", path)
	trust, err := PluginTrustFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if _, v := trust.Counts(); v != 1 {
		t.Errorf("trusted keys loaded: %d", v)
	}
	t.Setenv("KRYPTKEEPER_PLUGIN_TRUSTED_KEYS", filepath.Join(t.TempDir(), "missing.txt"))
	if _, err := PluginTrustFromEnv(); err == nil {
		t.Error("a missing trusted-keys file was ignored")
	}
	empty := filepath.Join(t.TempDir(), "empty.txt")
	_ = os.WriteFile(empty, []byte("\n"), 0o600) // an unwritten file fails the next check anyway
	t.Setenv("KRYPTKEEPER_PLUGIN_TRUSTED_KEYS", empty)
	if _, err := PluginTrustFromEnv(); err == nil {
		t.Error("an empty trusted-keys file was accepted")
	}
}

func (h *pluginHarness) installSigned(t *testing.T, manifest []byte, signature string) *httptest.ResponseRecorder {
	wasm, _ := examplePlugin(t)
	return h.call(t, http.MethodPost, "/api/v1/delivery-plugins", "test-token", map[string]any{
		"manifest_base64": base64.StdEncoding.EncodeToString(manifest),
		"signature":       signature,
		"wasm_base64":     base64.StdEncoding.EncodeToString(wasm),
	})
}

func installedVersion(t *testing.T, rec *httptest.ResponseRecorder) DeliveryPluginVersion {
	t.Helper()
	var out struct {
		Data DeliveryPluginVersion `json:"data"`
	}
	if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
		t.Fatalf("install: %d %s", rec.Code, rec.Body.String())
	}
	return out.Data
}

func TestDeliveryPluginSignedInstall(t *testing.T) {
	h := newPluginHarness(t)
	vendor, kk, stranger := newTestSigner(t), newTestSigner(t), newTestSigner(t)
	trust, err := NewPluginTrust(kk.pubPEM, vendor.pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	h.mgr.trust = trust

	// Unsigned stays community.
	if v := installedVersion(t, h.install(t, manifestVariant(t, "1.0.0", nil))); v.Tier != PluginTierCommunity || v.SignerKeyID != "" {
		t.Errorf("unsigned: tier %q signer %q", v.Tier, v.SignerKeyID)
	}

	// An operator-trusted signature is verified, and the signer is kept
	// and audited.
	m2 := manifestVariant(t, "2.0.0", nil)
	v := installedVersion(t, h.installSigned(t, m2, vendor.sign(t, m2)))
	if v.Tier != PluginTierVerified || v.SignerKeyID != vendor.id {
		t.Errorf("vendor-signed: tier %q signer %q", v.Tier, v.SignerKeyID)
	}
	last := h.audit.entries[len(h.audit.entries)-1]
	if !strings.Contains(last.ChangeSummary, "trust=verified") || !strings.Contains(last.ChangeSummary, "signer="+vendor.id) {
		t.Errorf("audit detail: %q", last.ChangeSummary)
	}
	if got, err := h.mgr.Get(context.Background(), "kryptkeeper.example-device"); err != nil || got.Versions[0].SignerKeyID != vendor.id {
		t.Errorf("stored signer: %+v %v", got, err)
	}

	// The compiled-in key makes it first-party; that does not skip the
	// second approver for a plugin that receives private keys.
	m3 := manifestVariant(t, "3.0.0", nil)
	if v := installedVersion(t, h.installSigned(t, m3, kk.sign(t, m3))); v.Tier != PluginTierFirstParty {
		t.Errorf("first-party: tier %q", v.Tier)
	}
	pendingActionID(t, h.call(t, http.MethodPost, "/api/v1/delivery-plugins/kryptkeeper.example-device/versions/3.0.0/enable", "test-token", nil))

	// Refusals: a bad signature, an unknown signer, and a signature sent
	// with a re-encoded manifest object. None is stored.
	m4 := manifestVariant(t, "4.0.0", nil)
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"signature over other bytes": h.installSigned(t, m4, vendor.sign(t, m2)),
		"unknown signer":             h.installSigned(t, m4, stranger.sign(t, m4)),
		"manifest object": h.call(t, http.MethodPost, "/api/v1/delivery-plugins", "test-token", map[string]any{
			"manifest": json.RawMessage(m4), "signature": vendor.sign(t, m4), "wasm_base64": "AA==",
		}),
	} {
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if _, err := h.mgr.version(context.Background(), "kryptkeeper.example-device", "4.0.0"); err == nil {
		t.Error("a refused install was stored")
	}
}
