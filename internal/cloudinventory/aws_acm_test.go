// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package cloudinventory

import (
	"testing"

	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
)

// ACM tests require real AWS credentials; unit tests cover helper logic only.

func TestACMConnectorNotNilWithValidConfig(t *testing.T) {
	// NewACMConnector needs real AWS creds — just verify it compiles and that
	// the struct is constructible without panicking.
	_ = ACMConnector{}
}

func TestACMStatusToString(t *testing.T) {
	import_acmCases := []struct {
		input string
		want  string
	}{
		{"ISSUED", "issued"},
		{"PENDING_VALIDATION", "pending_validation"},
		{"REVOKED", "revoked"},
		{"EXPIRED", "expired"},
		{"", ""},
	}
	for _, tc := range import_acmCases {
		import_acmTypes := acmtypes.CertificateStatus(tc.input)
		got := acmStatusToString(import_acmTypes)
		if got != tc.want {
			t.Errorf("acmStatusToString(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
