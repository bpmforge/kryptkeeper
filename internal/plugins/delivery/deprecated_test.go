// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import "testing"

func TestDeprecatedOpsgenie(t *testing.T) {
	d, ok := Deprecated("kryptkeeper.opsgenie")
	if !ok || d.Removal != "2.0" || d.Reason == "" {
		t.Fatalf("opsgenie deprecation = %+v, %v", d, ok)
	}
	if _, ok := Deprecated("kryptkeeper.pagerduty"); ok {
		t.Fatal("pagerduty must not be deprecated")
	}
}
