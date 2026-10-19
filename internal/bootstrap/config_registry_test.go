// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"testing"
)

func TestAgentlessPrivilegeModeRegistryKey(t *testing.T) {
	def, ok := lookupConfigKey("agentless.default_privilege_mode")
	if !ok || def.EnvVar != "KRYPTKEEPER_AGENTLESS_DEFAULT_PRIVILEGE_MODE" || def.Secret {
		t.Fatalf("registry entry: %+v ok=%v", def, ok)
	}
	if defaultAgentlessPrivilegeMode != "helper" {
		t.Fatalf("default must be helper (D-209), got %q", defaultAgentlessPrivilegeMode)
	}
	for _, v := range []string{"none", "nopasswd", "password", "helper", " helper "} {
		if err := validateConfigValue("agentless.default_privilege_mode", v); err != nil {
			t.Errorf("%q rejected: %v", v, err)
		}
	}
	for _, v := range []string{"", "root", "sudo", "HELPER"} {
		if err := validateConfigValue("agentless.default_privilege_mode", v); err == nil {
			t.Errorf("%q accepted", v)
		}
	}
}

func TestAgentlessPrivilegeModeEffectiveSource(t *testing.T) {
	t.Setenv("KRYPTKEEPER_AGENTLESS_DEFAULT_PRIVILEGE_MODE", "nopasswd")
	settings, err := EffectiveSettings(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range settings {
		if s.Key == "agentless.default_privilege_mode" {
			if s.Value != "nopasswd" || s.EffectiveSource != "env" || s.Category != "agentless" {
				t.Fatalf("setting: %+v", s)
			}
			return
		}
	}
	t.Fatal("key missing from EffectiveSettings")
}
