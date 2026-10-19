// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"testing"
)

func TestRevertTransitionDetailIsValidJSON(t *testing.T) {
	got := revertTransitionDetail("managed", "discovered", "acme", "", "conn-\x01-é ")
	var out struct {
		From   string                    `json:"from"`
		To     string                    `json:"to"`
		Method struct{ From, To string } `json:"renewal_method"`
		Conn   struct{ From, To string } `json:"renewal_connector_id"`
	}
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("not valid JSON: %v: %s", err, got)
	}
	if out.Conn.From != "conn-\x01-é " || out.Method.From != "acme" || out.From != "managed" {
		t.Fatalf("round trip lost data: %+v", out)
	}
}
