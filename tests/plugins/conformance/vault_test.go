// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package conformance

// Mock HashiCorp Vault KV v2 for the vault plugin (W27-27). It models the
// documented endpoints the plugin calls: auth/token/lookup-self, <mount>/config,
// metadata, versioned data read, data write with options.cas, and delete.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"kryptkeeper/internal/plugins/delivery"
)

const vaultToken = "hvs.conformance-token-987"

type vaultDevice struct {
	ts *httptest.Server
	*verStore
}

func newVaultDevice(t *testing.T) *vaultDevice {
	d := &vaultDevice{verStore: newVerStore(t, NewCert(t, "vault-initial"), NewCert(t, "vault-stale"))}
	d.ts = httptest.NewTLSServer(http.HandlerFunc(d.serve))
	t.Cleanup(d.ts.Close)
	return d
}

func (d *vaultDevice) Reset()               { d.mu.Lock(); d.reset(); d.mu.Unlock() }
func (d *vaultDevice) FailNext(step string) { d.failNext(step) }
func (d *vaultDevice) Served() string       { d.mu.Lock(); defer d.mu.Unlock(); return d.servedLocked() }

func (d *vaultDevice) Env() delivery.Env {
	return mockEnv(d.ts, map[string]string{"base_url": "https://example.com", "token": vaultToken},
		[]string{"token"}, map[string]string{"mount": "kv", "path": "certs/shop"})
}

func (d *vaultDevice) serve(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if r.Header.Get("X-Vault-Token") != vaultToken {
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
		return
	}
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch p := strings.TrimPrefix(r.URL.Path, "/v1/"); {
	case r.Method == "GET" && p == "auth/token/lookup-self":
		reply(map[string]any{"data": map[string]any{"id": "redacted"}})
	case r.Method == "GET" && p == "kv/config":
		reply(map[string]any{"data": map[string]any{"cas_required": false, "max_versions": 0}})
	case r.Method == "GET" && p == "kv/metadata/certs/shop":
		reply(map[string]any{"data": map[string]any{"current_version": d.latest(), "oldest_version": 0}})
	case r.Method == "GET" && p == "kv/data/certs/shop":
		n, _ := strconv.Atoi(r.URL.Query().Get("version"))
		if n == 0 {
			n = d.latest()
		}
		pem, ok := d.readLocked(n)
		if !ok {
			http.Error(w, `{"errors":[]}`, http.StatusNotFound)
			return
		}
		reply(map[string]any{"data": map[string]any{"data": map[string]any{"certificate": pem, "private_key": "k"}, "metadata": map[string]any{"version": n}}})
	case r.Method == "POST" && p == "kv/data/certs/shop":
		var b struct {
			Options struct {
				Cas *int `json:"cas"`
			} `json:"options"`
			Data map[string]string `json:"data"`
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b.Options.Cas == nil || *b.Options.Cas != d.latest() {
			http.Error(w, `{"errors":["check-and-set parameter did not match the current version"]}`, http.StatusBadRequest)
			return
		}
		n, ok := d.writeLocked(b.Data["certificate"])
		if !ok {
			http.Error(w, `{"errors":["internal"]}`, http.StatusInternalServerError)
			return
		}
		reply(map[string]any{"data": map[string]any{"version": n, "destroyed": false}})
	case r.Method == "POST" && p == "kv/delete/certs/shop":
		var b struct {
			Versions []int `json:"versions"`
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		for _, v := range b.Versions {
			if !d.disableLocked(v) {
				http.Error(w, "delete failed", http.StatusInternalServerError)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func TestVaultPluginConforms(t *testing.T) {
	rt := newRuntime(t)
	p := Load(t, rt, repoPath(t, "plugins/vault"))
	if p.Manifest().Verification != abi.VerificationReadback {
		t.Fatal("vault plugin must declare read-back verification")
	}
	Suite(t, p, newVaultDevice(t))
}

// Without the network grant the plugin cannot reach Vault: the delivery fails
// and the refused call is reported for audit.
func TestVaultPluginRefusesUngrantedNetwork(t *testing.T) {
	rt := newRuntime(t)
	p := loadWithout(t, rt, repoPath(t, "plugins/vault"), func(c *abi.Capabilities) { c.Network = nil })
	dev := newVaultDevice(t)
	var events []delivery.Event
	env := dev.Env()
	env.Events = func(e delivery.Event) { events = append(events, e) }
	cert := NewCert(t, "refused")
	res := p.Deliver(t.Context(), env, delivery.DeliverRequest{
		Name: "kk", CertPEM: cert.CertPEM, KeyPEM: cert.KeyPEM, ExpectedFingerprint: cert.Fingerprint, ReadbackVerify: true,
	}, nil)
	if res.Outcome != abi.OutcomeWriteFailed || res.Installed {
		t.Fatalf("result %+v", res)
	}
	refused := false
	for _, e := range events {
		refused = refused || e.Kind == "refused"
	}
	if !refused || dev.Served() != Fingerprint(string(dev.initial.CertPEM)) {
		t.Fatalf("refused=%v events=%+v", refused, events)
	}
}
