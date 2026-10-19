// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"kryptkeeper/internal/plugins/delivery"
)

// loadWithout loads the plugin in dir with its declared capabilities after
// narrow has removed some, as an operator approving less than it asks for.
func loadWithout(t testing.TB, rt *delivery.Runtime, dir string, narrow func(*abi.Capabilities)) *delivery.Plugin {
	t.Helper()
	wasm := Build(t, dir)
	manifest := PinManifest(t, dir, wasm)
	m, err := abi.ParseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	granted := m.Capabilities
	narrow(&granted)
	p, err := rt.Load(context.Background(), manifest, wasm, granted)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close(context.Background()) })
	return p
}

// verStore is the versioned-secret model shared by the secret-store mock
// devices (Vault, Azure Key Vault, GCP Secret Manager). Versions are
// 1-based. It implements the Device failure switches for readback plugins:
//
//	upload   the write of a NEW certificate fails
//	rollback the write of previously stored content (a restore) or a disable fails
//	bind     the plugin's own first read-back of the new version fails
//	verify   every later read-back of the newest version returns another certificate
type verStore struct {
	mu      sync.Mutex
	certs   []string // version-1 -> certificate PEM
	enabled []bool
	fail    failSet
	pending bool // newly uploaded version not yet read back by the plugin
	tamper  bool
	stale   string
	initial Cert
}

func newVerStore(t testing.TB, initial, stale Cert) *verStore {
	s := &verStore{initial: initial, stale: string(stale.CertPEM)}
	s.reset()
	return s
}

func (s *verStore) reset() {
	s.certs, s.enabled = []string{string(s.initial.CertPEM)}, []bool{true}
	s.fail, s.pending, s.tamper = failSet{}, false, false
}

func (s *verStore) latest() int { return len(s.certs) }

// servedLocked is the fingerprint of the newest enabled version.
func (s *verStore) servedLocked() string {
	for i := len(s.certs) - 1; i >= 0; i-- {
		if s.enabled[i] {
			return Fingerprint(s.certs[i])
		}
	}
	return ""
}

// write appends a version. Content equal to an existing version is a
// restore (the "rollback" step); anything else is the "upload" step.
func (s *verStore) writeLocked(certPEM string) (version int, ok bool) {
	restore := false
	for _, c := range s.certs {
		if Fingerprint(c) == Fingerprint(certPEM) {
			restore = true
		}
	}
	step := "upload"
	if restore {
		step = "rollback"
	}
	if s.fail.take(step) {
		return 0, false
	}
	s.certs, s.enabled = append(s.certs, certPEM), append(s.enabled, true)
	s.pending = !restore
	return len(s.certs), true
}

// disableLocked is the "rollback" step for providers that roll back by
// disabling a version.
func (s *verStore) disableLocked(n int) bool {
	if n < 1 || n > len(s.certs) || s.fail.take("rollback") {
		return false
	}
	s.enabled[n-1] = false
	return true
}

// readLocked returns the certificate of version n. ok is false for an
// unknown or disabled version, or when the "bind" failure is armed.
func (s *verStore) readLocked(n int) (pem string, ok bool) {
	if n < 1 || n > len(s.certs) || !s.enabled[n-1] {
		return "", false
	}
	if n == len(s.certs) {
		if s.pending {
			s.pending = false
			if s.fail.take("bind") {
				return "", false
			}
		} else if s.tamper {
			return s.stale, true
		}
	}
	return s.certs[n-1], true
}

func (s *verStore) failNext(step string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if step == "verify" {
		s.tamper = true
		return
	}
	s.fail[step] = true
}

// anyHostEnv is mockEnv with the TLS server name pinned to example.com, so
// the httptest certificate verifies whatever provider host name the plugin
// dials (the plugin's granted hosts are still enforced by the runtime).
func anyHostEnv(ts *httptest.Server, cred map[string]string, secrets []string, target map[string]string) delivery.Env {
	env := mockEnv(ts, cred, secrets, target)
	env.HTTPClient.Transport.(*http.Transport).TLSClientConfig.ServerName = "example.com"
	return env
}
