// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package abi

import (
	"strings"
	"testing"
)

const goodManifest = `{
  "api_version": "kryptkeeper.delivery/v1",
  "id": "community.example-device",
  "name": "Example device",
  "version": "1.0.0",
  "publisher": "Kryptkeeper Authors",
  "artifact": {"file": "plugin.wasm", "sha256": "` + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" + `"},
  "capabilities": {"receive_private_key": true, "network": {"hosts_from_credential": "base_url", "ports": [443]}, "tls_verify": true},
  "credential_schema": {"base_url": {"type": "url", "required": true}, "token": {"type": "string", "required": true, "secret": true}},
  "target_schema": {"binding": {"type": "string", "required": true}}
}`

func TestParseManifest(t *testing.T) {
	m, err := ParseManifest([]byte(goodManifest))
	if err != nil {
		t.Fatalf("good manifest: %v", err)
	}
	if !m.Capabilities.ReceivePrivateKey || m.Capabilities.Network.HostsFromCredential != "base_url" {
		t.Fatalf("parsed %+v", m.Capabilities)
	}

	for name, mutate := range map[string]func(string) string{
		"unknown capability": func(s string) string {
			return strings.Replace(s, `"tls_verify": true`, `"tls_verify": true, "raw_sockets": true`, 1)
		},
		"unknown api_version":   func(s string) string { return strings.Replace(s, "delivery/v1", "delivery/v9", 1) },
		"bad sha256":            func(s string) string { return strings.Replace(s, "0123456789abcdef0123", "XYZ", 1) },
		"artifact path":         func(s string) string { return strings.Replace(s, `"plugin.wasm"`, `"../plugin.wasm"`, 1) },
		"network host wildcard": func(s string) string { return strings.Replace(s, `"ports": [443]`, `"hosts": ["*.example.com"]`, 1) },
		"network field not url": func(s string) string {
			return strings.Replace(s, `"hosts_from_credential": "base_url"`, `"hosts_from_credential": "token"`, 1)
		},
		"secret target field": func(s string) string {
			return strings.Replace(s, `"binding": {"type": "string", "required": true}`, `"binding": {"type": "string", "secret": true}`, 1)
		},
		"elevated without remote": func(s string) string {
			return strings.Replace(s, `"tls_verify": true`, `"tls_verify": true, "elevated_exec": true`, 1)
		},
	} {
		if _, err := ParseManifest([]byte(mutate(goodManifest))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCapabilitiesWithin(t *testing.T) {
	declared := Capabilities{ReceivePrivateKey: true, Network: &Network{HostsFromCredential: "base_url", Ports: []int{443}}, FileWrite: []string{"/etc/ssl"}}
	if !declared.Within(declared) {
		t.Fatal("a manifest's own set must be within itself")
	}
	for name, c := range map[string]Capabilities{
		"extra elevated": {ElevatedExec: true},
		"extra host":     {Network: &Network{HostsFromCredential: "base_url", Hosts: []string{"evil.example"}}},
		"extra path":     {FileWrite: []string{"/etc"}},
		"extra port":     {Network: &Network{HostsFromCredential: "base_url", Ports: []int{8443}}},
	} {
		if c.Within(declared) {
			t.Errorf("%s: a grant wider than the manifest was accepted", name)
		}
	}
}

func TestCapabilitiesTier(t *testing.T) {
	// SUP-A08-1: a credential-named host is network access, so High.
	if got := (Capabilities{Network: &Network{HostsFromCredential: "base_url"}, TLSVerify: true}).Tier(); got != TierHigh {
		t.Errorf("hosts_from_credential only: tier %s, want high", got)
	}
	for want, c := range map[string]Capabilities{
		TierCritical: {ReceivePrivateKey: true, Network: &Network{HostsFromCredential: "base_url"}},
		TierHigh:     {Network: &Network{HostsFromCredential: "base_url", Hosts: []string{"api.cdn.example"}}},
		TierStandard: {TLSVerify: true, FileWrite: []string{"/etc/x"}},
	} {
		if got := c.Tier(); got != want {
			t.Errorf("%+v: tier %s, want %s", c, got, want)
		}
	}
	if (Capabilities{RemoteExec: true}).Tier() != TierHigh || (Capabilities{TrustStore: true, RemoteExec: true}).Tier() != TierCritical {
		t.Error("exec / trust store tiers wrong")
	}
}
