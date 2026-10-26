// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
)

func dnsPlugin(kind string, result any, pluginErr string) (*Plugin, *[]string) {
	var ops []string
	p := &Plugin{manifest: abi.Manifest{Kind: kind}, granted: abi.Capabilities{}}
	p.invokeHook = func(_ context.Context, op string, _ []byte) ([]byte, error) {
		ops = append(ops, op)
		res, _ := json.Marshal(result)
		return json.Marshal(abi.Response{Result: res, Error: pluginErr})
	}
	return p, &ops
}

func TestDNS01RefusedOnOtherKinds(t *testing.T) {
	for _, kind := range []string{abi.KindDelivery, abi.KindNotify} {
		p, ops := dnsPlugin(kind, abi.DNS01PresentResult{}, "")
		if _, err := p.DNS01Present(context.Background(), Env{}, "_acme-challenge.example.com", "v", 60); !errors.Is(err, ErrOpNotForKind) {
			t.Errorf("%s present: %v", kind, err)
		}
		if err := p.DNS01Cleanup(context.Background(), Env{}, "_acme-challenge.example.com", "v", "id"); !errors.Is(err, ErrOpNotForKind) {
			t.Errorf("%s cleanup: %v", kind, err)
		}
		if len(*ops) != 0 {
			t.Errorf("%s: plugin ran %v", kind, *ops)
		}
	}
	// And a dns01 plugin is never asked to push.
	p, ops := dnsPlugin(abi.KindDNS01, abi.DNS01PresentResult{}, "")
	if err := p.Validate(context.Background(), Env{}); !errors.Is(err, ErrOpNotForKind) || len(*ops) != 0 {
		t.Fatalf("validate on dns01 plugin: %v %v", err, *ops)
	}
}

func TestDNS01PresentZoneMustContainTheName(t *testing.T) {
	const fqdn = "_acme-challenge.www.example.com"
	for zone, ok := range map[string]bool{
		"example.com":     true,
		"www.example.com": true,
		"EXAMPLE.COM.":    true,
		"evil.com":        false,
		"ample.com":       false, // a suffix of the text, not a parent name
		"":                false,
	} {
		p, _ := dnsPlugin(abi.KindDNS01, abi.DNS01PresentResult{RecordID: "r", Zone: zone}, "")
		res, err := p.DNS01Present(context.Background(), Env{}, fqdn, "v", 60)
		if (err == nil) != ok {
			t.Errorf("zone %q: err %v, want ok=%v", zone, err, ok)
		}
		if ok && strings.HasSuffix(res.Zone, ".") {
			t.Errorf("zone %q not normalised: %q", zone, res.Zone)
		}
	}
}

func TestDNS01ResultAndErrorsAreSanitised(t *testing.T) {
	secret := "vendor-api-token-value"
	env := Env{Credential: map[string]string{"api_token": secret}, Secrets: []string{"api_token"}}

	p, _ := dnsPlugin(abi.KindDNS01, abi.DNS01PresentResult{RecordID: "id\n" + secret + strings.Repeat("x", 400), Zone: "example.com"}, "")
	res, err := p.DNS01Present(context.Background(), env, "_acme-challenge.example.com", "v", 60)
	if err != nil || len(res.RecordID) > maxRecordID || strings.Contains(res.RecordID, secret) || strings.Contains(res.RecordID, "\n") {
		t.Fatalf("record id %q err %v", res.RecordID, err)
	}

	p, _ = dnsPlugin(abi.KindDNS01, nil, "provider said no for "+secret)
	_, err = p.DNS01Present(context.Background(), env, "_acme-challenge.example.com", "v", 60)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("plugin error must be returned without the credential: %v", err)
	}
}

func TestDNS01CleanupNeedsConfirmation(t *testing.T) {
	p, _ := dnsPlugin(abi.KindDNS01, abi.DNS01CleanupResult{Removed: true}, "")
	if err := p.DNS01Cleanup(context.Background(), Env{}, "_acme-challenge.example.com", "v", "id"); err != nil {
		t.Fatal(err)
	}
	p, _ = dnsPlugin(abi.KindDNS01, abi.DNS01CleanupResult{}, "")
	if err := p.DNS01Cleanup(context.Background(), Env{}, "_acme-challenge.example.com", "v", "id"); err == nil {
		t.Fatal("removed=false must be an error")
	}
}
