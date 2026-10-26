// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

// Package conformance is the delivery plugin conformance kit (W20-19): it
// builds a plugin from source, loads it in the hub's own runtime, and grades
// it against a mock of its device. Every plugin, first-party or community,
// passes the same Suite; only the Device differs.
package conformance

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"kryptkeeper/internal/agentinstall"
	"kryptkeeper/internal/plugins/delivery"
)

// Build compiles the plugin module in dir for wasip1 and returns the bytes.
func Build(t testing.TB, dir string) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "plugin.wasm")
	cmd := exec.Command("go", "build", "-buildmode=c-shared", "-o", out, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "GOFLAGS=-mod=mod")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build plugin %s: %v\n%s", dir, err, b)
	}
	wasm, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return wasm
}

// PinManifest returns the manifest in dir with artifact.sha256 set to the
// hash of wasm, as a release pipeline would after building it.
func PinManifest(t testing.TB, dir string, wasm []byte) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(wasm)
	m["artifact"].(map[string]any)["sha256"] = hex.EncodeToString(sum[:])
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func withoutVerifyWindow(t testing.TB, manifest []byte) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(manifest, &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "verify_propagation_seconds")
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Load builds, pins and loads the plugin in dir with exactly the
// capabilities its manifest declares (what an approval grants).
func Load(t testing.TB, rt *delivery.Runtime, dir string) *delivery.Plugin {
	t.Helper()
	wasm := Build(t, dir)
	manifest := PinManifest(t, dir, wasm)
	m, err := abi.ParseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if m.VerifyPropagationSeconds > 0 {
		// The shipped window (validated above) is for real CDN rollouts; the
		// Suite's devices switch instantly, and its mismatch cases would
		// otherwise wait the whole window. The window itself is covered by
		// internal/plugins/delivery's fake-clock tests (W27-37).
		manifest = withoutVerifyWindow(t, manifest)
	}
	p, err := rt.Load(context.Background(), manifest, wasm, m.Capabilities)
	if err != nil {
		t.Fatalf("load %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = p.Close(context.Background()) })
	return p
}

// Device is a mock of the plugin's target, driven by the Suite.
type Device interface {
	// Env reaches the mock: credential, target settings, HTTP client.
	Env() delivery.Env
	// Served is the SHA-256 fingerprint of the certificate in service.
	Served() string
	// FailNext makes the next "upload", "bind" or "rollback" fail. For a
	// plugin declaring verification "readback" it also accepts "verify":
	// from then until Reset, every read-back of the newly written object
	// answers with a different certificate, except the plugin's own first
	// read-back inside Push (so the failure is the hub's, not Push's).
	FailNext(step string)
	// Reset restores the starting state: an initial certificate in service
	// and no failures pending.
	Reset()
}

// Cert is a throwaway certificate and key for one delivery.
type Cert struct {
	CertPEM, KeyPEM []byte
	Fingerprint     string
}

// NewCert makes a self-signed certificate; the kit only needs distinct
// fingerprints, not a chain.
func NewCert(t testing.TB, cn string) Cert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return Cert{
		CertPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:      pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		Fingerprint: hex.EncodeToString(sum[:]),
	}
}

// Fingerprint returns the SHA-256 of a PEM certificate's DER.
func Fingerprint(certPEM string) string {
	b, _ := pem.Decode([]byte(certPEM))
	if b == nil {
		return ""
	}
	sum := sha256.Sum256(b.Bytes)
	return hex.EncodeToString(sum[:])
}

// Suite grades a plugin against its device. It asserts what the hub relies
// on: outcomes from the fixed vocabulary, verification and rollback decided
// by the hub, an honest RolledBack, and no secret in anything the plugin
// says. A plugin whose manifest declares verification "readback" is verified
// through its verify op (the hub fingerprints the stored PEM) instead of a
// TLS dial; the Device then models a secret store.
func Suite(t *testing.T, p *delivery.Plugin, dev Device) {
	ctx := context.Background()
	if p.Kind() != abi.KindDelivery {
		t.Fatalf("plugin kind %q is not delivery; use the suite for its kind", p.Kind())
	}
	readback := p.Manifest().Verification == abi.VerificationReadback
	servedVerifier := func(context.Context, string) (string, error) { return dev.Served(), nil }
	staleVerifier := func(context.Context, string) (string, error) {
		return strings.Repeat("0", 64), nil
	}
	// stale arms the failure the hub must catch: a TLS verifier that sees a
	// different certificate, or a store whose read-back returns one.
	stale := func() agentinstall.Verifier {
		if readback {
			dev.FailNext("verify")
			return nil
		}
		return staleVerifier
	}
	deliver := func(t *testing.T, cert Cert, verify agentinstall.Verifier) (agentinstall.InstallResult, []delivery.Event) {
		var events []delivery.Event
		env := dev.Env()
		env.Events = func(e delivery.Event) { events = append(events, e) }
		env.Timeout = time.Minute
		req := delivery.DeliverRequest{
			Name: "kk-conformance", CertPEM: cert.CertPEM, KeyPEM: cert.KeyPEM,
			VerifyHostPort: "device.invalid:443", ExpectedFingerprint: cert.Fingerprint,
		}
		if readback {
			req.VerifyHostPort, req.ReadbackVerify = "", true
		}
		res := p.Deliver(ctx, env, req, verify)
		for _, e := range events {
			if strings.Contains(e.Detail, "-----BEGIN") || strings.Contains(e.Detail, strings.TrimSpace(string(cert.KeyPEM))) {
				t.Errorf("event carries key material: %+v", e)
			}
			for _, name := range env.Secrets {
				if v := env.Credential[name]; v != "" && strings.Contains(e.Detail, v) {
					t.Errorf("event carries credential %s: %+v", name, e)
				}
			}
		}
		if strings.Contains(res.Detail, "-----BEGIN") {
			t.Errorf("detail carries a PEM block: %q", res.Detail)
		}
		return res, events
	}

	t.Run("validate", func(t *testing.T) {
		dev.Reset()
		if err := p.Validate(ctx, dev.Env()); err != nil {
			t.Fatalf("validate against a healthy device: %v", err)
		}
	})

	t.Run("delivers and the hub verifies", func(t *testing.T) {
		dev.Reset()
		cert := NewCert(t, "delivered")
		res, _ := deliver(t, cert, servedVerifier)
		if res.Outcome != agentinstall.OutcomeInstalledVerified || !res.Verified || !res.Installed {
			t.Fatalf("result %+v", res)
		}
		if dev.Served() != cert.Fingerprint {
			t.Fatal("device does not serve the delivered certificate")
		}
	})

	t.Run("verify mismatch rolls back", func(t *testing.T) {
		dev.Reset()
		before := dev.Served()
		res, _ := deliver(t, NewCert(t, "unverified"), stale())
		if res.Outcome != agentinstall.OutcomeVerifyFailed || res.Verified || !res.RolledBack {
			t.Fatalf("result %+v", res)
		}
		if dev.Served() != before {
			t.Fatal("RolledBack is true but the device does not serve the previous certificate")
		}
	})

	t.Run("failed rollback is reported as failed", func(t *testing.T) {
		dev.Reset()
		dev.FailNext("rollback")
		res, _ := deliver(t, NewCert(t, "stuck"), stale())
		if res.RolledBack || res.Outcome != agentinstall.OutcomeVerifyFailed || !strings.Contains(res.Detail, "ROLLBACK FAILED") {
			t.Fatalf("a failed rollback must never read as rolled back: %+v", res)
		}
	})

	for step, want := range map[string]string{"upload": abi.OutcomeWriteFailed, "bind": abi.OutcomeBindingFailed} {
		t.Run(step+" failure", func(t *testing.T) {
			dev.Reset()
			before := dev.Served()
			dev.FailNext(step)
			res, _ := deliver(t, NewCert(t, step), servedVerifier)
			if res.Outcome != want || res.Installed || res.Verified {
				t.Fatalf("result %+v, want outcome %s", res, want)
			}
			if dev.Served() != before {
				t.Fatal("a failed delivery changed what the device serves")
			}
		})
	}
}
