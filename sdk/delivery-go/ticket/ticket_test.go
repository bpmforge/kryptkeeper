// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package ticket

import (
	"encoding/json"
	"testing"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

type fake struct{}

func (fake) Create(_ *delivery.Host, req abi.TicketCreateRequest) (abi.TicketCreateResult, error) {
	return abi.TicketCreateResult{Key: req.Event.ID}, nil
}
func (fake) Exists(_ *delivery.Host, req abi.TicketExistsRequest) (abi.TicketExistsResult, error) {
	return abi.TicketExistsResult{Exists: req.Key == "1"}, nil
}
func (fake) Resolve(_ *delivery.Host, _ abi.TicketResolveRequest) (abi.TicketResolveResult, error) {
	return abi.TicketResolveResult{}, nil
}

func TestHandleRoutesEveryOp(t *testing.T) {
	h := delivery.NewHost(nil)
	out, err := Handle(fake{}, h, abi.OpTicketCreate, []byte(`{"event":{"id":"e1"}}`))
	var c abi.TicketCreateResult
	if err != nil || json.Unmarshal(out, &c) != nil || c.Key != "e1" {
		t.Fatalf("create %s %v", out, err)
	}
	out, err = Handle(fake{}, h, abi.OpTicketExists, []byte(`{"key":"1"}`))
	var e abi.TicketExistsResult
	if err != nil || json.Unmarshal(out, &e) != nil || !e.Exists {
		t.Fatalf("exists %s %v", out, err)
	}
	if _, err := Handle(fake{}, h, abi.OpTicketResolve, []byte(`{"key":"1"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := Handle(fake{}, h, abi.OpPush, []byte(`{}`)); err == nil {
		t.Fatal("a ticket plugin must refuse a delivery op")
	}
}

func TestFailedClassifies(t *testing.T) {
	for status, want := range map[int]string{
		401: abi.FailurePermanent, 404: abi.FailurePermanent, 422: abi.FailurePermanent,
		408: abi.FailureTemporary, 429: abi.FailureTemporary, 500: abi.FailureTemporary, 503: abi.FailureTemporary,
	} {
		if got := Failed(abi.HTTPResponse{Status: status}, "x").Failure; got != want {
			t.Errorf("%d: %s want %s", status, got, want)
		}
	}
	f := Failed(abi.HTTPResponse{Status: 429, Headers: map[string]string{"retry-after": "9000"}}, "x")
	if f.RetryAfterSeconds != MaxRetryAfterSeconds {
		t.Fatalf("hint %d not capped", f.RetryAfterSeconds)
	}
}

func TestBaseURLRequiresHTTPS(t *testing.T) {
	if BaseURL("https://acme.zendesk.com/") != "https://acme.zendesk.com" || BaseURL("http://x.com") != "" || BaseURL("https://") != "" {
		t.Fatal("BaseURL")
	}
}
