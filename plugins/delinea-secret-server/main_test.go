// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

// The host import is only callable inside the sandbox, so the unit tests
// cover the argument checks that run before any call; the full exchange is
// graded by tests/plugins/conformance against a Secret Server mock.
func TestReferenceChecks(t *testing.T) {
	for _, id := range []string{"", "abc", "12 34", "1/../2", "12345678901"} {
		_, err := delinea{}.Get(delivery.NewHost(nil), abi.CredentialsGetRequest{Reference: map[string]string{"secret_id": id}})
		if err == nil || !strings.Contains(err.Error(), "numeric secret_id") {
			t.Errorf("secret_id %q: %v", id, err)
		}
	}
	_, err := delinea{}.Get(delivery.NewHost(nil), abi.CredentialsGetRequest{Reference: map[string]string{"secret_id": "4", "map": "bad"}})
	if err == nil || !strings.Contains(err.Error(), "SourceField:payload_field") {
		t.Errorf("bad map: %v", err)
	}
}

func TestSecretFailureNames(t *testing.T) {
	if secretFailure(404) != "no such secret" || !strings.Contains(secretFailure(403), "may not view") {
		t.Fatal("unexpected reasons")
	}
}
