// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kryptkeeper/internal/keystore"
	"kryptkeeper/internal/scep"
)

// A body over a handler's cap used to come back as the generic 400 "invalid
// request body", indistinguishable from malformed JSON. Each of these routes
// must answer 413 for an oversize body and keep 400 for a malformed one.
func TestOversizeBodyIs413NotBadRequest(t *testing.T) {
	mux := http.NewServeMux()
	h := newWriteGateHarness(t, mux)

	store, err := keystore.NewSoftwareStore(t.TempDir(), []byte("oversize-test-passphrase-32-by!!"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	registerKeyHandlers(mux, h.auth, store, h.audit, "software")
	registerBYOKHandlers(mux, h.auth, h.audit)
	registerDeliveryPluginHandlers(mux, h.auth, &DeliveryPluginManager{}, h.audit)
	registerCodeSigningHandler(mux, h.auth, nil, h.audit)
	RegisterEstateHandlers(mux, h.auth, nil, nil, h.audit)
	RegisterSCEPChallengeHandlers(mux, h.auth, struct{ scep.ChallengeStore }{}, "ca-1", h.audit)

	admin := h.key(t, "pki-admin")
	// Larger than the biggest cap on the list (maxPluginUpload).
	oversize := []byte(`{"pad":"` + strings.Repeat("a", maxPluginUpload+1024) + `"}`)

	routes := []struct{ name, path string }{
		{"scep challenge", "/api/v1/scep/challenges"},
		{"key generate", "/api/v1/keys"},
		{"key import", "/api/v1/keys/import"},
		{"key rotate", "/api/v1/keys/k1/rotate"},
		{"key export", "/api/v1/keys/k1/export"},
		{"byok export", "/api/v1/keys/byok/export"},
		{"delivery plugin install", "/api/v1/delivery-plugins"},
		{"code signing policy", "/api/v1/inventory/code-signing/policy-check"},
		{"estate takeover", "/api/v1/estate/takeover"},
	}
	for _, rt := range routes {
		t.Run(rt.name, func(t *testing.T) {
			if got := postRaw(h, admin, rt.path, oversize).Code; got != http.StatusRequestEntityTooLarge {
				t.Errorf("oversize body: got %d, want 413", got)
			}
			if got := postRaw(h, admin, rt.path, []byte(`{not json`)).Code; got != http.StatusBadRequest {
				t.Errorf("malformed body: got %d, want 400", got)
			}
		})
	}
}

func postRaw(h *writeGateHarness, token, path string, body []byte) *httptest.ResponseRecorder {
	return h.do(token, http.MethodPost, path, body)
}
