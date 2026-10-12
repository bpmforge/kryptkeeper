// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"strings"
	"testing"
)

func TestRenewalStatusVocabulary(t *testing.T) {
	for _, v := range renewalStatuses {
		if !validRenewalStatus(string(v)) {
			t.Errorf("%q not accepted", v)
		}
		if !strings.Contains(renewalStatusList(), string(v)) {
			t.Errorf("%q missing from the error-message list", v)
		}
	}
	for _, bad := range []string{"", "Active", "pending", "reissue-required"} {
		if validRenewalStatus(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
