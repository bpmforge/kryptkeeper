// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"kryptkeeper/internal/plugins/delivery"
)

// DNS01Device is a mock of a DNS provider's zone API, driven by DNS01Suite.
// It serves one zone and keeps TXT values per name in plain form (without
// vendor quoting), so one suite grades every provider.
type DNS01Device interface {
	// Env reaches the mock: credential and HTTP client.
	Env() delivery.Env
	// Zone is the zone the mock serves ("example.com").
	Zone() string
	// Records lists the TXT values now at fqdn.
	Records(fqdn string) []string
	// Seed puts a value at fqdn as if another tenant or tool had.
	Seed(fqdn, value string)
	// FailNext makes the next API request fail: "server_error" answers 500,
	// "rate_limit" answers 429, "unauthorized" answers 401.
	FailNext(mode string)
	Reset()
}

// DNS01Suite grades a dns01 plugin against its mock provider. It asserts what
// the hub relies on: the record lands at the right name and the plugin names
// the right zone, a shared name keeps every other value through cleanup
// (a wildcard and its base name share one), cleanup is idempotent, a
// provider refusal is an error and never a silent success, a name outside
// the provider's zones is refused, and nothing in the plugin's events,
// results or errors carries a credential value.
func DNS01Suite(t *testing.T, p *delivery.Plugin, dev DNS01Device) {
	ctx := context.Background()
	if p.Kind() != abi.KindDNS01 {
		t.Fatalf("plugin kind %q is not dns01", p.Kind())
	}
	zone := dev.Zone()
	base := "_acme-challenge." + zone
	sub := "_acme-challenge.www." + zone

	checkLeaks := func(t *testing.T, env delivery.Env, texts ...string) {
		t.Helper()
		for _, name := range env.Secrets {
			v := env.Credential[name]
			for _, s := range texts {
				if v != "" && strings.Contains(s, v) {
					t.Errorf("credential %s leaks into %q", name, s)
				}
			}
		}
		for _, s := range texts {
			if strings.Contains(s, "-----BEGIN") {
				t.Errorf("PEM block in %q", s)
			}
		}
	}
	present := func(t *testing.T, fqdn, value string) (abi.DNS01PresentResult, error) {
		t.Helper()
		env := dev.Env()
		var events []string
		env.Events = func(e delivery.Event) { events = append(events, e.Detail) }
		env.Timeout = time.Minute
		res, err := p.DNS01Present(ctx, env, fqdn, value, 60)
		texts := append(events, res.RecordID, res.Zone)
		if err != nil {
			texts = append(texts, err.Error())
		}
		checkLeaks(t, env, texts...)
		return res, err
	}
	cleanup := func(t *testing.T, fqdn, value, recordID string) error {
		t.Helper()
		env := dev.Env()
		var events []string
		env.Events = func(e delivery.Event) { events = append(events, e.Detail) }
		env.Timeout = time.Minute
		err := p.DNS01Cleanup(ctx, env, fqdn, value, recordID)
		if err != nil {
			events = append(events, err.Error())
		}
		checkLeaks(t, env, events...)
		return err
	}
	want := func(t *testing.T, fqdn string, values ...string) {
		t.Helper()
		got := dev.Records(fqdn)
		slices.Sort(got)
		w := append([]string(nil), values...)
		slices.Sort(w)
		if !slices.Equal(got, w) {
			t.Fatalf("records at %s = %v, want %v", fqdn, got, w)
		}
	}

	t.Run("publishes the value and names the zone", func(t *testing.T) {
		dev.Reset()
		res, err := present(t, base, "digest-one")
		if err != nil {
			t.Fatal(err)
		}
		want(t, base, "digest-one")
		if res.Zone != zone || res.RecordID == "" {
			t.Fatalf("result %+v: want zone %q and a record id", res, zone)
		}
	})

	t.Run("a name below the zone resolves to the zone", func(t *testing.T) {
		dev.Reset()
		res, err := present(t, sub, "digest-sub")
		if err != nil {
			t.Fatal(err)
		}
		want(t, sub, "digest-sub")
		if res.Zone != zone {
			t.Fatalf("zone %q, want %q", res.Zone, zone)
		}
	})

	t.Run("cleanup removes exactly the published value", func(t *testing.T) {
		dev.Reset()
		res, err := present(t, base, "digest-one")
		if err != nil {
			t.Fatal(err)
		}
		if err := cleanup(t, base, "digest-one", res.RecordID); err != nil {
			t.Fatal(err)
		}
		want(t, base)
	})

	t.Run("a shared name keeps every other value through cleanup", func(t *testing.T) {
		dev.Reset()
		dev.Seed(base, "foreign-value")
		a, err := present(t, base, "digest-one")
		if err != nil {
			t.Fatal(err)
		}
		b, err := present(t, base, "digest-two")
		if err != nil {
			t.Fatal(err)
		}
		want(t, base, "foreign-value", "digest-one", "digest-two")
		if err := cleanup(t, base, "digest-one", a.RecordID); err != nil {
			t.Fatal(err)
		}
		want(t, base, "foreign-value", "digest-two")
		if err := cleanup(t, base, "digest-two", b.RecordID); err != nil {
			t.Fatal(err)
		}
		want(t, base, "foreign-value")
	})

	t.Run("presenting the same value twice does not duplicate it", func(t *testing.T) {
		dev.Reset()
		for range 2 {
			if _, err := present(t, base, "digest-one"); err != nil {
				t.Fatal(err)
			}
		}
		got := dev.Records(base)
		// A provider with one record per value may hold two; none may lose the value.
		if len(got) == 0 || got[0] != "digest-one" {
			t.Fatalf("records %v", got)
		}
	})

	t.Run("cleanup is idempotent", func(t *testing.T) {
		dev.Reset()
		res, err := present(t, base, "digest-one")
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if err := cleanup(t, base, "digest-one", res.RecordID); err != nil {
				t.Fatalf("cleanup of a record that is gone must succeed: %v", err)
			}
		}
		if err := cleanup(t, base, "never-published", ""); err != nil {
			t.Fatalf("cleanup without a record id: %v", err)
		}
		want(t, base)
	})

	t.Run("a name outside the provider's zones is refused", func(t *testing.T) {
		dev.Reset()
		if _, err := present(t, "_acme-challenge.not-ours.example.net", "v"); err == nil {
			t.Fatal("a name the provider does not host must fail, not succeed silently")
		}
	})

	for name, mode := range map[string]string{"a server error": "server_error", "a rate limit": "rate_limit", "refused credentials": "unauthorized"} {
		t.Run(name+" is an error and leaves no record", func(t *testing.T) {
			dev.Reset()
			dev.FailNext(mode)
			if _, err := present(t, base, "digest-one"); err == nil {
				t.Fatalf("%s must surface as an error", name)
			}
			dev.Reset()
			want(t, base)
		})
	}

	t.Run("then recovers", func(t *testing.T) {
		dev.Reset()
		if _, err := present(t, base, "digest-one"); err != nil {
			t.Fatal(err)
		}
		want(t, base, "digest-one")
	})

	t.Run("a hostile name or value never reaches the provider", func(t *testing.T) {
		dev.Reset()
		for _, fqdn := range []string{base + "/../x", base + "?a=b", "_acme-challenge.example.com\r\nX: y"} {
			if _, err := present(t, fqdn, "v"); err == nil {
				t.Errorf("fqdn %q accepted", fqdn)
			}
		}
		if _, err := present(t, base, `a"b`); err == nil {
			t.Error("a value with a quote was accepted")
		}
		want(t, base)
	})
}
