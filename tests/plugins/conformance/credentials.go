// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"kryptkeeper/internal/plugins/delivery"
)

// CredentialsDevice is a mock of a credentials plugin's secret manager,
// driven by CredentialsSuite.
type CredentialsDevice interface {
	// Env reaches the mock: the source's own login and an HTTP client.
	Env() delivery.Env
	// Reference names the account the mock holds, as the plugin documents it.
	Reference() map[string]string
	// Expected is what a correct plugin returns for Reference.
	Expected() map[string]string
	// FailNext makes the next credential request fail: "missing" answers the
	// manager's not-found, "denied" its forbidden, "server_error" a 500.
	FailNext(mode string)
	// Unknown is a reference the mock does not hold.
	Unknown() map[string]string
}

// CredentialsSuite grades a credentials plugin against its mock manager. It
// asserts what the hub relies on: the fields the plugin returns are exactly
// the secret's, a missing or forbidden secret is an error and never empty or
// partial fields, a manager outage is an error, and neither the secret
// values nor the source's own login reach an event or an error text.
func CredentialsSuite(t *testing.T, p *delivery.Plugin, dev CredentialsDevice) {
	ctx := context.Background()
	if p.Kind() != abi.KindCredentials {
		t.Fatalf("plugin kind %q is not credentials", p.Kind())
	}
	if !p.Granted().ProvideCredentials {
		t.Fatal("a credentials plugin runs with provide_credentials granted")
	}
	get := func(t *testing.T, ref map[string]string) (abi.CredentialsGetResult, error) {
		env := dev.Env()
		var events []delivery.Event
		env.Events = func(e delivery.Event) { events = append(events, e) }
		env.Timeout = time.Minute
		res, err := p.CredentialsGet(ctx, env, ref)

		// What must never be said anywhere but in the result itself.
		var secrets []string
		for _, v := range dev.Expected() {
			secrets = append(secrets, v)
		}
		for _, name := range env.Secrets {
			secrets = append(secrets, env.Credential[name])
		}
		var said []string
		for _, e := range events {
			said = append(said, e.Detail)
		}
		if err != nil {
			said = append(said, err.Error())
		}
		for _, s := range said {
			for _, secret := range secrets {
				if len(secret) >= 4 && strings.Contains(s, secret) {
					t.Errorf("a secret value leaks into %q", s)
				}
			}
			if strings.Contains(s, "-----BEGIN") {
				t.Errorf("PEM block in %q", s)
			}
		}
		return res, err
	}

	t.Run("returns the secret's fields", func(t *testing.T) {
		res, err := get(t, dev.Reference())
		if err != nil {
			t.Fatal(err)
		}
		want := dev.Expected()
		for k, v := range want {
			if res.Fields[k] != v {
				t.Errorf("field %q = %q, want %q", k, res.Fields[k], v)
			}
		}
		if len(res.Fields) != len(want) {
			t.Errorf("got fields %v, want exactly %v", keys(res.Fields), keys(want))
		}
	})

	t.Run("a missing secret is an error without fields", func(t *testing.T) {
		dev.FailNext("missing")
		res, err := get(t, dev.Reference())
		if err == nil || len(res.Fields) != 0 {
			t.Fatalf("result %+v err %v: a missing secret must not look like a credential", res, err)
		}
		if res, err := get(t, dev.Unknown()); err == nil || len(res.Fields) != 0 {
			t.Fatalf("unknown reference: result %+v err %v", res, err)
		}
	})

	t.Run("a refusal is an error without fields", func(t *testing.T) {
		dev.FailNext("denied")
		res, err := get(t, dev.Reference())
		if err == nil || len(res.Fields) != 0 {
			t.Fatalf("result %+v err %v", res, err)
		}
	})

	t.Run("a server error is an error without fields", func(t *testing.T) {
		dev.FailNext("server_error")
		res, err := get(t, dev.Reference())
		if err == nil || len(res.Fields) != 0 {
			t.Fatalf("result %+v err %v", res, err)
		}
	})

	t.Run("a reference naming nothing is refused before the manager is asked", func(t *testing.T) {
		if res, err := get(t, map[string]string{}); err == nil || len(res.Fields) != 0 {
			t.Fatalf("result %+v err %v", res, err)
		}
	})

	t.Run("then recovers", func(t *testing.T) {
		if _, err := get(t, dev.Reference()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("a delivery operation is not defined for it", func(t *testing.T) {
		if err := p.Validate(ctx, dev.Env()); err == nil || !strings.Contains(err.Error(), "not defined for this plugin's kind") {
			t.Fatalf("validate on a credentials plugin: %v", err)
		}
	})
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
