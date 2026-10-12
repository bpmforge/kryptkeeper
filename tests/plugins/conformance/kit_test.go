// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"kryptkeeper/internal/agentinstall"
	"kryptkeeper/internal/plugins/delivery"
)

func repoPath(t *testing.T, rel string) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", rel)
}

func newRuntime(t *testing.T) *delivery.Runtime {
	t.Helper()
	rt, err := delivery.NewRuntime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Close(context.Background()) })
	return rt
}

// The reference plugin passes the kit against its mock device.
func TestExamplePluginConforms(t *testing.T) {
	rt := newRuntime(t)
	p := Load(t, rt, repoPath(t, "plugins/example"))
	Suite(t, p, newExampleDevice(t))
}

// Without receive_private_key granted, the key never reaches the plugin.
func TestPrivateKeyOnlyWithGrant(t *testing.T) {
	rt := newRuntime(t)
	dir := repoPath(t, "plugins/example")
	wasm := Build(t, dir)
	manifest := PinManifest(t, dir, wasm)
	m, err := abi.ParseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	granted := m.Capabilities
	granted.ReceivePrivateKey = false
	p, err := rt.Load(context.Background(), manifest, wasm, granted)
	if err != nil {
		t.Fatal(err)
	}
	dev := newExampleDevice(t)
	cert := NewCert(t, "nokey")
	res := p.Deliver(context.Background(), dev.Env(), delivery.DeliverRequest{Name: "kk-conformance", CertPEM: cert.CertPEM, KeyPEM: cert.KeyPEM}, nil)
	if res.Outcome != abi.OutcomeInstalled {
		t.Fatalf("result %+v", res)
	}
	if got := dev.keys["kk-conformance"]; got != "" {
		t.Fatalf("the device received a key the plugin was never granted (%d bytes)", len(got))
	}
}

func TestLoadRefusals(t *testing.T) {
	rt := newRuntime(t)
	dir := repoPath(t, "plugins/example")
	wasm := Build(t, dir)
	manifest := PinManifest(t, dir, wasm)
	m, _ := abi.ParseManifest(manifest)

	tampered := append(append([]byte(nil), wasm...), 0)
	if _, err := rt.Load(context.Background(), manifest, tampered, m.Capabilities); !errors.Is(err, delivery.ErrHashMismatch) {
		t.Errorf("tampered module: %v, want ErrHashMismatch", err)
	}
	wider := m.Capabilities
	wider.ElevatedExec, wider.RemoteExec = true, true
	if _, err := rt.Load(context.Background(), manifest, wasm, wider); !errors.Is(err, delivery.ErrGrantExceedsManifest) {
		t.Errorf("grant wider than the manifest: %v, want ErrGrantExceedsManifest", err)
	}
}

// The sandbox refuses everything the hostile plugin tries, and sanitizes
// what it says.
func TestSandboxRefusesHostilePlugin(t *testing.T) {
	rt := newRuntime(t)
	p := Load(t, rt, repoPath(t, "tests/plugins/conformance/testdata/hostile"))
	const token = "hostile-secret-token-42"
	var events []delivery.Event
	env := delivery.Env{
		Credential: map[string]string{"base_url": "https://example.com", "token": token},
		Secrets:    []string{"token"},
		Target:     map[string]string{},
		Events:     func(e delivery.Event) { events = append(events, e) },
		Timeout:    30 * time.Second,
	}
	err := p.Validate(context.Background(), env)
	if err == nil {
		t.Fatal("hostile validate returned no report")
	}
	for _, want := range []string{"other-host=refused", "plain-http=refused", "other-port=refused", "exec=refused", "fs=refused", "env=refused"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("report %q lacks %s", err, want)
		}
	}
	refused := 0
	for _, e := range events {
		if strings.Contains(e.Detail, token) {
			t.Errorf("secret reached an event: %+v", e)
		}
		if strings.Contains(e.Detail, "BEGIN PRIVATE KEY") {
			t.Errorf("PEM reached an event: %+v", e)
		}
		if e.Kind == "refused" {
			refused++
		}
	}
	if refused < 4 {
		t.Errorf("only %d refused events recorded: %+v", refused, events)
	}

	res := p.Deliver(context.Background(), env, delivery.DeliverRequest{Name: "x", CertPEM: []byte("c"), VerifyHostPort: "h:443", ExpectedFingerprint: "ab"},
		func(context.Context, string) (string, error) { return "ab", nil })
	if res.Verified || res.Outcome != abi.OutcomeWriteFailed || !strings.Contains(res.Detail, "unknown outcome") {
		t.Errorf("a plugin claiming installed_verified must not be believed: %+v", res)
	}

	env.Target = map[string]string{"mode": "spin"}
	env.Timeout = 2 * time.Second
	start := time.Now()
	res = p.Deliver(context.Background(), env, delivery.DeliverRequest{Name: "x", CertPEM: []byte("c")}, nil)
	if res.Outcome != agentinstall.OutcomeWriteFailed || !strings.Contains(res.Detail, "time limit") {
		t.Errorf("spinning plugin: %+v", res)
	}
	if time.Since(start) > 10*time.Second {
		t.Errorf("spinning plugin was not stopped promptly: %s", time.Since(start))
	}

	env.Target = map[string]string{"mode": "key"}
	res = p.Deliver(context.Background(), env, delivery.DeliverRequest{Name: "x", CertPEM: []byte("c"), KeyPEM: []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")}, nil)
	if !strings.Contains(res.Detail, "got key bytes: 0") {
		t.Errorf("a plugin without receive_private_key received a key: %+v", res)
	}
}
