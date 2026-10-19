// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"strings"
	"testing"
)

func TestMultiTenancyExperimentalCheck(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		wantErr bool
	}{
		{"off", map[string]string{}, false},
		{"explicit false", map[string]string{"MULTI_TENANCY": "false"}, false},
		// Gate lifted in v0.10 (W22-03): no acknowledgement needed.
		{"on without ack", map[string]string{"MULTI_TENANCY": "on"}, false},
		{"true without ack", map[string]string{"MULTI_TENANCY": "true"}, false},
		{"on wrong ack", map[string]string{"MULTI_TENANCY": "on", MultiTenancyExperimentalEnv: "yes"}, false},
		{"on ack wrong case", map[string]string{"MULTI_TENANCY": "on", MultiTenancyExperimentalEnv: "Accept-Risk"}, false},
		{"on exact ack", map[string]string{"MULTI_TENANCY": "on", MultiTenancyExperimentalEnv: "accept-risk"}, false},
		{"off with ack", map[string]string{MultiTenancyExperimentalEnv: "accept-risk"}, false},
		// Re-enforced gate (rollback) behaves exactly like v0.9.
		{"on + gate=enforce, no ack", map[string]string{"MULTI_TENANCY": "on", MultiTenancyGateEnv: "enforce"}, true},
		{"on + gate=enforce, wrong-case ack", map[string]string{"MULTI_TENANCY": "on", MultiTenancyGateEnv: "enforce", MultiTenancyExperimentalEnv: "Accept-Risk"}, true},
		{"on + gate=enforce + exact ack", map[string]string{"MULTI_TENANCY": "on", MultiTenancyGateEnv: "enforce", MultiTenancyExperimentalEnv: "accept-risk"}, false},
		{"on + gate=Enforce (wrong case) is not enforce", map[string]string{"MULTI_TENANCY": "on", MultiTenancyGateEnv: "Enforce"}, false},
		{"gate=enforce, tenancy off", map[string]string{MultiTenancyGateEnv: "enforce"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := MultiTenancyExperimentalCheck(func(k string) string { return tc.env[k] })
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestMultiTenancyNoticeText(t *testing.T) {
	if strings.Contains(MultiTenancyExperimentalWarning, "EXPERIMENTAL") {
		t.Fatalf("notice still says EXPERIMENTAL: %q", MultiTenancyExperimentalWarning)
	}
}
