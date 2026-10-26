// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package abi

import (
	"strings"
	"testing"
)

const notifyManifest = `{
  "api_version": "kryptkeeper.delivery/v1",
  "kind": "notify",
  "id": "community.example-alerts",
  "name": "Example alerts",
  "version": "1.0.0",
  "publisher": "Kryptkeeper Authors",
  "artifact": {"file": "plugin.wasm", "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
  "capabilities": {"network": {"hosts_from_credential": "webhook_url"}},
  "credential_schema": {"webhook_url": {"type": "url", "required": true, "secret": true}}
}`

func TestManifestKindDefaultsToDelivery(t *testing.T) {
	m, err := ParseManifest([]byte(goodManifest))
	if err != nil {
		t.Fatal(err)
	}
	if m.Kind != KindDelivery {
		t.Fatalf("kind %q, want delivery", m.Kind)
	}
}

func TestManifestKinds(t *testing.T) {
	if m, err := ParseManifest([]byte(notifyManifest)); err != nil || m.Kind != KindNotify {
		t.Fatalf("notify manifest: kind %q err %v", m.Kind, err)
	}
	for name, tc := range map[string]struct{ from, to, want string }{
		"issuer is reserved":    {`"kind": "notify"`, `"kind": "issuer"`, "reserved"},
		"unknown kind":          {`"kind": "notify"`, `"kind": "teleport"`, "not supported"},
		"notify with key":       {`"network": {`, `"receive_private_key": true, "network": {`, "may not declare"},
		"notify with file":      {`"network": {`, `"file_write": ["/tmp"], "network": {`, "may not declare"},
		"notify without net":    {`"capabilities": {"network": {"hosts_from_credential": "webhook_url"}}`, `"capabilities": {}`, "needs a network grant"},
		"provide_credentials":   {`"network": {`, `"provide_credentials": true, "network": {`, "only for the credentials kind"},
		"api version unchanged": {`delivery/v1`, `delivery/v2`, "not supported"},
	} {
		_, err := ParseManifest([]byte(strings.Replace(notifyManifest, tc.from, tc.to, 1)))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want %q", name, err, tc.want)
		}
	}
}

func TestOpAllowedPerKind(t *testing.T) {
	cases := []struct {
		kind, op string
		want     bool
	}{
		{"", OpPush, true}, {KindDelivery, OpVerify, true}, {KindDelivery, OpNotifySend, false},
		{KindNotify, OpNotifySend, true}, {KindNotify, OpPush, false}, {KindDNS01, OpPush, false},
		{KindDNS01, OpDNS01Present, true}, {KindDNS01, OpDNS01Cleanup, true}, {KindDelivery, OpDNS01Present, false}, {KindNotify, OpDNS01Cleanup, false},
		{KindTicket, OpNotifySend, false}, {KindTicket, OpTicketCreate, true}, {KindTicket, OpTicketExists, true}, {KindTicket, OpTicketResolve, true}, {KindTicket, OpPush, false}, {KindNotify, OpTicketCreate, false},
	}
	for _, c := range cases {
		if got := OpAllowed(c.kind, c.op); got != c.want {
			t.Errorf("OpAllowed(%q,%q)=%v want %v", c.kind, c.op, got, c.want)
		}
	}
	if !Runnable(KindNotify) || !Runnable(KindTicket) || !Runnable(KindDNS01) || !Runnable(KindCredentials) || Runnable(KindInventory) {
		t.Error("delivery, notify, ticket, dns01 and credentials are runnable; inventory is not")
	}
	if !OpAllowed(KindCredentials, OpCredentialsGet) || OpAllowed(KindCredentials, OpPush) || OpAllowed(KindNotify, OpCredentialsGet) {
		t.Error("credentials.get belongs to the credentials kind alone")
	}
}

func TestProvideCredentialsIsCritical(t *testing.T) {
	c := Capabilities{ProvideCredentials: true}
	if c.Tier() != TierCritical {
		t.Fatalf("tier %s", c.Tier())
	}
	if c.Within(Capabilities{}) {
		t.Fatal("a grant of provide_credentials must not fit a manifest that did not declare it")
	}
}

const credentialsManifest = `{
  "api_version": "kryptkeeper.delivery/v1",
  "kind": "credentials",
  "id": "community.example-vault",
  "name": "Example credentials",
  "version": "1.0.0",
  "publisher": "Kryptkeeper Authors",
  "artifact": {"file": "plugin.wasm", "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
  "capabilities": {"provide_credentials": true, "network": {"hosts_from_credential": "base_url"}},
  "credential_schema": {"base_url": {"type": "url", "required": true}}
}`

func TestCredentialsKindNeedsProvideCredentials(t *testing.T) {
	m, err := ParseManifest([]byte(credentialsManifest))
	if err != nil || m.Kind != KindCredentials || m.Capabilities.Tier() != TierCritical {
		t.Fatalf("credentials manifest: %+v err %v", m, err)
	}
	_, err = ParseManifest([]byte(strings.Replace(credentialsManifest, `"provide_credentials": true, `, "", 1)))
	if err == nil || !strings.Contains(err.Error(), "must declare provide_credentials") {
		t.Fatalf("a credentials plugin without the capability must be refused: %v", err)
	}
	_, err = ParseManifest([]byte(strings.Replace(credentialsManifest, `"kind": "credentials"`, `"kind": "notify"`, 1)))
	if err == nil || !strings.Contains(err.Error(), "only for the credentials kind") {
		t.Fatalf("provide_credentials on another kind must be refused: %v", err)
	}
	_, err = ParseManifest([]byte(strings.Replace(credentialsManifest, `"provide_credentials": true, `, `"provide_credentials": true, "remote_exec": true, `, 1)))
	if err == nil || !strings.Contains(err.Error(), "may not declare") {
		t.Fatalf("a credentials plugin may not run commands on hosts: %v", err)
	}
}
