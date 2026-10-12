// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// blockingKeyStore stalls Insert/Revoke/TouchLastUsed until released or the
// caller's context ends, like a core DB behind a network partition.
type blockingKeyStore struct {
	mu      sync.Mutex
	gate    chan struct{} // nil: pass through; else writes wait for close
	entered chan struct{}
}

func newBlockingKeyStore() *blockingKeyStore {
	return &blockingKeyStore{entered: make(chan struct{}, 8)}
}

// stall makes every following write wait until unstall.
func (b *blockingKeyStore) stall() {
	b.mu.Lock()
	b.gate = make(chan struct{})
	b.mu.Unlock()
}

func (b *blockingKeyStore) unstall() {
	b.mu.Lock()
	close(b.gate)
	b.mu.Unlock()
}

func (b *blockingKeyStore) block(ctx context.Context, signal bool) error {
	b.mu.Lock()
	gate := b.gate
	b.mu.Unlock()
	if gate == nil {
		return nil
	}
	if signal {
		b.entered <- struct{}{}
	}
	select {
	case <-gate:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *blockingKeyStore) LoadActive(context.Context) ([]apiKeyRecord, error) { return nil, nil }
func (b *blockingKeyStore) Insert(ctx context.Context, _ apiKeyRecord) error {
	return b.block(ctx, true)
}
func (b *blockingKeyStore) Revoke(ctx context.Context, _ string, _ time.Time) error {
	return b.block(ctx, true)
}
func (b *blockingKeyStore) TouchLastUsed(ctx context.Context, _ string, _ time.Time) error {
	return b.block(ctx, false)
}

func authCompletesPromptly(t *testing.T, a *Authenticator, token string) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		_, err := a.AuthenticatePrincipalDetails(req, time.Now())
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("authentication failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("authentication blocked behind a stalled API key DB write (apiKeyMu held across DB I/O)")
	}
}

func TestMintingDoesNotBlockAuthenticationWhenDBStalls(t *testing.T) {
	a := newKeyAuth(t, nil, nil)
	_, token, err := a.CreateAPIKeyAs("alice@example.test", "ci", "svc", "service-account", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	store := newBlockingKeyStore()
	a.apiKeyMu.Lock()
	a.apiKeyStore = store
	a.persistedKids = map[string]bool{}
	a.apiKeyMu.Unlock()

	store.stall()
	mintDone := make(chan error, 1)
	go func() {
		_, _, err := a.CreateAPIKeyAs("alice@example.test", "second", "svc2", "service-account", nil, "", "", time.Now())
		mintDone <- err
	}()
	<-store.entered
	authCompletesPromptly(t, a, token)
	store.unstall()
	if err := <-mintDone; err != nil {
		t.Fatalf("mint after release: %v", err)
	}
}

func TestRevokeDoesNotBlockAuthenticationWhenDBStalls(t *testing.T) {
	store := newBlockingKeyStore()
	a := newKeyAuth(t, nil, nil)
	a.apiKeyMu.Lock()
	a.apiKeyStore = store
	a.persistedKids = map[string]bool{}
	a.apiKeyMu.Unlock()
	_, keep, err := a.CreateAPIKeyAs("alice@example.test", "keep", "svc", "service-account", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec, gone, err := a.CreateAPIKeyAs("alice@example.test", "gone", "svc2", "service-account", nil, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	store.stall()

	revokeDone := make(chan error, 1)
	go func() {
		_, err := a.RevokeAPIKey(rec.Kid)
		revokeDone <- err
	}()
	<-store.entered
	authCompletesPromptly(t, a, keep)
	if _, err := authStatus(a, gone); err == nil {
		t.Error("revoked key must be rejected in-process while the DB write is still stalled")
	}
	store.unstall()
	if err := <-revokeDone; err != nil {
		t.Fatalf("revoke after release: %v", err)
	}
}
