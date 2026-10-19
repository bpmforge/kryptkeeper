// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package conformance

// Mock GCP Secret Manager v1 and the Google OAuth token endpoint for the
// gcp-secretmanager plugin (W27-28): secrets.get, versions.get (name, state),
// secrets.addVersion and versions.access (payload.data base64) and
// versions.disable. Accessing a disabled version is FAILED_PRECONDITION (400).

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"kryptkeeper/internal/plugins/delivery"
)

const gcpSecret = "projects/proj-1/secrets/shop-cert"

type gcpsmDevice struct {
	ts    *httptest.Server
	saKey string
	*verStore
}

func newGCPSMDevice(t *testing.T) *gcpsmDevice {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	sa, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "kk@proj-1.iam.gserviceaccount.com",
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))})
	d := &gcpsmDevice{saKey: string(sa), verStore: newVerStore(t, NewCert(t, "gcpsm-initial"), NewCert(t, "gcpsm-stale"))}
	d.ts = httptest.NewTLSServer(http.HandlerFunc(d.serve))
	t.Cleanup(d.ts.Close)
	return d
}

func (d *gcpsmDevice) Reset()               { d.mu.Lock(); d.reset(); d.mu.Unlock() }
func (d *gcpsmDevice) FailNext(step string) { d.failNext(step) }
func (d *gcpsmDevice) Served() string       { d.mu.Lock(); defer d.mu.Unlock(); return d.servedLocked() }

func (d *gcpsmDevice) Env() delivery.Env {
	return anyHostEnv(d.ts, map[string]string{"service_account_json": d.saKey, "project_id": "proj-1"},
		[]string{"service_account_json"}, map[string]string{"secret_id": "shop-cert"})
}

func (d *gcpsmDevice) serve(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	if r.URL.Path == "/token" {
		_ = r.ParseForm()
		if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || strings.Count(r.PostForm.Get("assertion"), ".") != 2 {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		reply(map[string]any{"access_token": "gcp-token", "expires_in": 3599, "token_type": "Bearer"})
		return
	}
	if r.Header.Get("Authorization") != "Bearer gcp-token" {
		http.Error(w, `{"error":{"status":"UNAUTHENTICATED"}}`, http.StatusUnauthorized)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	name := func(n int) string { return fmt.Sprintf("%s/versions/%d", gcpSecret, n) }
	state := func(n int) string {
		if d.enabled[n-1] {
			return "ENABLED"
		}
		return "DISABLED"
	}
	switch {
	case r.Method == "GET" && path == "projects/proj-1/secrets":
		reply(map[string]any{"secrets": []any{}})
	case r.Method == "GET" && path == gcpSecret:
		reply(map[string]any{"name": gcpSecret})
	case r.Method == "GET" && path == gcpSecret+"/versions/latest":
		reply(map[string]any{"name": name(d.latest()), "state": state(d.latest())})
	case r.Method == "POST" && path == gcpSecret+":addVersion":
		var b struct {
			Payload struct {
				Data string `json:"data"`
			} `json:"payload"`
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		raw, _ := base64.StdEncoding.DecodeString(b.Payload.Data)
		n, ok := d.writeLocked(string(raw))
		if !ok {
			http.Error(w, `{"error":{"status":"INTERNAL"}}`, http.StatusInternalServerError)
			return
		}
		reply(map[string]any{"name": name(n), "state": "ENABLED"})
	case r.Method == "GET" && strings.HasPrefix(path, gcpSecret+"/versions/") && strings.HasSuffix(path, ":access"):
		n, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(path, gcpSecret+"/versions/"), ":access"))
		pem, ok := d.readLocked(n)
		if !ok {
			http.Error(w, `{"error":{"status":"FAILED_PRECONDITION"}}`, http.StatusBadRequest)
			return
		}
		reply(map[string]any{"name": name(n), "payload": map[string]any{"data": base64.StdEncoding.EncodeToString([]byte(pem))}})
	case r.Method == "POST" && strings.HasPrefix(path, gcpSecret+"/versions/") && strings.HasSuffix(path, ":disable"):
		n, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(path, gcpSecret+"/versions/"), ":disable"))
		if !d.disableLocked(n) {
			http.Error(w, `{"error":{"status":"INTERNAL"}}`, http.StatusInternalServerError)
			return
		}
		reply(map[string]any{"name": name(n), "state": "DISABLED"})
	default:
		http.NotFound(w, r)
	}
}

func TestGCPSecretManagerPluginConforms(t *testing.T) {
	rt := newRuntime(t)
	p := Load(t, rt, repoPath(t, "plugins/gcp-secretmanager"))
	if p.Manifest().Verification != abi.VerificationReadback {
		t.Fatal("gcp-secretmanager plugin must declare read-back verification")
	}
	Suite(t, p, newGCPSMDevice(t))
}
