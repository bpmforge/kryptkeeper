// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package agentinstall

import "testing"

func TestValidateIISRequestFields(t *testing.T) {
	ok := IISInstallRequest{IPPort: "0.0.0.0:443", AppID: "{4dc3e181-e14b-4a21-b022-59fc669b0914}", StoreName: "WebHosting"}
	if err := validateIISRequestFields(ok); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	if err := validateIISRequestFields(IISInstallRequest{IPPort: "[::]:8443"}); err != nil {
		t.Fatalf("IPv6 ipport rejected: %v", err)
	}
	bad := []IISInstallRequest{
		{IPPort: "0.0.0.0:443&calc"},
		{IPPort: "0.0.0.0:443 & calc"},
		{IPPort: "example.com:443"},
		{IPPort: "0.0.0.0:0"},
		{IPPort: "0.0.0.0:443", AppID: "{guid}&calc"},
		{IPPort: "0.0.0.0:443", StoreName: "My|calc"},
	}
	for _, r := range bad {
		if err := validateIISRequestFields(r); err == nil {
			t.Errorf("%+v: want rejection", r)
		}
	}
}
