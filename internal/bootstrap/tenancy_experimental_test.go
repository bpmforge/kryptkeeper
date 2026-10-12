// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import "testing"

func TestMultiTenancyExperimentalCheck(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		wantErr bool
	}{
		{"off", map[string]string{}, false},
		{"explicit false", map[string]string{"MULTI_TENANCY": "false"}, false},
		{"on without ack", map[string]string{"MULTI_TENANCY": "on"}, true},
		{"true without ack", map[string]string{"MULTI_TENANCY": "true"}, true},
		{"on wrong ack", map[string]string{"MULTI_TENANCY": "on", MultiTenancyExperimentalEnv: "yes"}, true},
		{"on ack wrong case", map[string]string{"MULTI_TENANCY": "on", MultiTenancyExperimentalEnv: "Accept-Risk"}, true},
		{"on exact ack", map[string]string{"MULTI_TENANCY": "on", MultiTenancyExperimentalEnv: "accept-risk"}, false},
		{"off with ack", map[string]string{MultiTenancyExperimentalEnv: "accept-risk"}, false},
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
