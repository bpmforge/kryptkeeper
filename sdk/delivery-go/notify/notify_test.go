// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"encoding/json"
	"testing"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

type fake struct{}

func (fake) Send(_ *delivery.Host, req abi.NotifySendRequest) (abi.NotifySendResult, error) {
	return abi.NotifySendResult{Delivered: true, ProviderID: req.DedupeKey}, nil
}

func TestHandle(t *testing.T) {
	out, err := Handle(fake{}, delivery.NewHost(nil), abi.OpNotifySend, []byte(`{"dedupe_key":"k1"}`))
	if err != nil {
		t.Fatal(err)
	}
	var res abi.NotifySendResult
	if err := json.Unmarshal(out, &res); err != nil || !res.Delivered || res.ProviderID != "k1" {
		t.Fatalf("result %s err %v", out, err)
	}
	if _, err := Handle(fake{}, delivery.NewHost(nil), abi.OpPush, []byte(`{}`)); err == nil {
		t.Fatal("a notify plugin must refuse a delivery op")
	}
}

func TestTruncateKeepsRunes(t *testing.T) {
	if got := Truncate("héllo", 2); got != "h" {
		t.Fatalf("got %q", got)
	}
	if got := Truncate("abc", 10); got != "abc" {
		t.Fatalf("got %q", got)
	}
}
