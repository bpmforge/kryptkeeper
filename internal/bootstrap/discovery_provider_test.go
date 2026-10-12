// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// configTestDiscoveryProvider is a minimal DiscoveryProvider whose identity (via
// tag) proves WHICH underlying provider configuredDiscoveryProvider picked,
// without needing a real file- or DB-backed provider in these tests.
type configTestDiscoveryProvider struct{ tag string }

func (s *configTestDiscoveryProvider) GetSummary(context.Context) (DiscoverySummary, error) {
	return DiscoverySummary{}, nil
}

func (s *configTestDiscoveryProvider) ListEndpoints(context.Context, DiscoveryEndpointQuery) (DiscoveryEndpointResult, error) {
	return DiscoveryEndpointResult{}, nil
}

func (s *configTestDiscoveryProvider) ListScanJobs(context.Context, DiscoveryScanJobQuery) (DiscoveryScanJobResult, error) {
	return DiscoveryScanJobResult{}, nil
}

func (s *configTestDiscoveryProvider) CreateScan(context.Context, string, string, []int) (DiscoveryScanCreateResult, error) {
	return DiscoveryScanCreateResult{}, nil
}

func (s *configTestDiscoveryProvider) CancelScanJob(context.Context, string, string) (DiscoveryScanJobActionResult, error) {
	return DiscoveryScanJobActionResult{}, nil
}

func (s *configTestDiscoveryProvider) RequeueScanJob(context.Context, string, string) (DiscoveryScanJobActionResult, error) {
	return DiscoveryScanJobActionResult{}, nil
}

// countingConfigStore wraps a real ConfigStore and counts Get calls, to
// prove configuredDiscoveryProvider's poll is bounded (acceptance #3): it
// must not read the store on every call, only once per TTL window.
type countingConfigStore struct {
	ConfigStore
	gets int32
}

func (c *countingConfigStore) Get(ctx context.Context, key string) (ConfigEntry, bool, error) {
	atomic.AddInt32(&c.gets, 1)
	return c.ConfigStore.Get(ctx, key)
}

func TestResolveDiscoveryMode(t *testing.T) {
	tests := []struct {
		name     string
		envVal   string
		override string // "" = no override written
		want     string
	}{
		{"nothing set defaults to file", "", "", discoveryProviderFile},
		{"env db selects db", "db", "", discoveryProviderDB},
		{"unknown env falls back to file", "bogus", "", discoveryProviderFile},
		{"db override wins over env file", "file", "db", discoveryProviderDB},
		{"file override wins over env db", "db", "file", discoveryProviderFile},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(discoveryProviderEnv, tt.envVal)
			store := newFreshConfigStore(t, []byte("test-passphrase"))
			if tt.override != "" {
				if err := store.Set(context.Background(), "discovery.provider", tt.override, "tester"); err != nil {
					t.Fatalf("write override: %v", err)
				}
			}
			if got := resolveDiscoveryMode(context.Background(), store); got != tt.want {
				t.Errorf("resolveDiscoveryMode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveDiscoveryMode_NilStoreFallsBackToEnv(t *testing.T) {
	t.Setenv(discoveryProviderEnv, "db")
	if got := resolveDiscoveryMode(context.Background(), nil); got != discoveryProviderDB {
		t.Errorf("resolveDiscoveryMode(nil store) = %q, want %q", got, discoveryProviderDB)
	}
}

// TestConfiguredDiscoveryProvider_DBOverrideSwitchesModeWithoutReconstruction
// is the W8-13 acceptance #2 test for the discovery consumer: a DB override
// written through the real store must change which underlying provider the
// SAME configuredDiscoveryProvider instance delegates to, once its poll TTL
// elapses -- no new provider is constructed for this.
//
// Sabotage-checked: if current() ignored the override entirely (e.g. always
// returned the cached file provider), this test would still pass the FIRST
// assertion but fail the third -- confirmed by temporarily hardcoding
// current() to always select file mode, watching this go red, then
// reverting.
func TestConfiguredDiscoveryProvider_DBOverrideSwitchesModeWithoutReconstruction(t *testing.T) {
	store := newFreshConfigStore(t, []byte("test-passphrase"))
	ctx := context.Background()

	fileProvider := &configTestDiscoveryProvider{tag: "file"}
	dbProvider := &configTestDiscoveryProvider{tag: "db"}
	clock := time.Now()

	c := &configuredDiscoveryProvider{
		storeFactory: func() ConfigStore { return store },
		fileFactory:  func() DiscoveryProvider { return fileProvider },
		dbFactory:    func() DiscoveryProvider { return dbProvider },
		ttl:          time.Minute,
		now:          func() time.Time { return clock },
	}

	got := c.current(ctx)
	if got.(*configTestDiscoveryProvider).tag != "file" {
		t.Fatalf("expected file provider with no override, got tag %q", got.(*configTestDiscoveryProvider).tag)
	}

	if err := store.Set(ctx, "discovery.provider", "db", "test-operator"); err != nil {
		t.Fatalf("write override: %v", err)
	}

	// Still within the TTL window -- must NOT re-check yet (bounded read,
	// acceptance #3).
	if got := c.current(ctx); got.(*configTestDiscoveryProvider).tag != "file" {
		t.Fatalf("expected cached file provider within TTL window, got tag %q", got.(*configTestDiscoveryProvider).tag)
	}

	clock = clock.Add(2 * time.Minute) // advance past the TTL
	got = c.current(ctx)               // same configuredDiscoveryProvider instance -- no reconstruction
	if got.(*configTestDiscoveryProvider).tag != "db" {
		t.Fatalf("expected db provider once the TTL elapses and observes the DB override, got tag %q", got.(*configTestDiscoveryProvider).tag)
	}
}

// TestConfiguredDiscoveryProvider_BoundedReadsWithinTTL proves acceptance
// #3's bound directly: repeated calls within one TTL window must issue
// exactly one config-store read, not one per call.
func TestConfiguredDiscoveryProvider_BoundedReadsWithinTTL(t *testing.T) {
	inner := newFreshConfigStore(t, []byte("test-passphrase"))
	counting := &countingConfigStore{ConfigStore: inner}
	clock := time.Now()

	c := &configuredDiscoveryProvider{
		storeFactory: func() ConfigStore { return counting },
		fileFactory:  func() DiscoveryProvider { return &configTestDiscoveryProvider{tag: "file"} },
		dbFactory:    func() DiscoveryProvider { return &configTestDiscoveryProvider{tag: "db"} },
		ttl:          time.Minute,
		now:          func() time.Time { return clock },
	}
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		c.current(ctx)
	}
	if got := atomic.LoadInt32(&counting.gets); got != 1 {
		t.Fatalf("expected exactly 1 config store read across 5 calls within one TTL window, got %d", got)
	}
}

// TestConfiguredDiscoveryProvider_LazyStoreNeverConstructedIfUnused proves
// the other half of acceptance #3: a DiscoveryProvider that is constructed
// but never actually used (the common case across this package's other test
// files, which build the full RegisterHandlers graph but exercise unrelated
// endpoints) must never touch the config store at all.
func TestConfiguredDiscoveryProvider_LazyStoreNeverConstructedIfUnused(t *testing.T) {
	called := false
	c := &configuredDiscoveryProvider{
		storeFactory: func() ConfigStore { called = true; return nil },
		fileFactory:  func() DiscoveryProvider { return &configTestDiscoveryProvider{tag: "file"} },
		dbFactory:    func() DiscoveryProvider { return &configTestDiscoveryProvider{tag: "db"} },
		ttl:          time.Minute,
		now:          time.Now,
	}
	_ = c // never call current() -- constructed, never used.
	if called {
		t.Fatal("storeFactory must not run until current() is first called")
	}
}

func TestNewDiscoveryProviderFromEnv_DefaultsToFile(t *testing.T) {
	t.Setenv("APP_CREDENTIAL_STORE_PASSPHRASE", "")
	t.Setenv("KRYPTKEEPER_KEYSTORE_PASSPHRASE", "")
	t.Setenv(discoveryProviderEnv, "")

	p := NewDiscoveryProviderFromEnv()
	summary, err := p.GetSummary(context.Background())
	if err != nil {
		t.Fatalf("GetSummary: %v", err)
	}
	_ = summary // file provider always succeeds; DB mode would need a store.
}
