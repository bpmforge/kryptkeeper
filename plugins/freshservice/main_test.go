// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

var cred = abi.Invocation{Credential: map[string]string{"base_url": "https://acme.freshservice.com", "api_key": "key", "requester_email": "kk@acme.example", "workspace_id": "3"}}

type seen struct {
	method, url, auth string
	body              map[string]any
}

func host(t *testing.T, status int, body string, log *[]seen) *delivery.Host {
	t.Helper()
	return delivery.NewHost(func(_ string, in []byte) ([]byte, error) {
		var hr abi.HTTPRequest
		_ = json.Unmarshal(in, &hr)
		s := seen{method: hr.Method, url: hr.URL, auth: hr.Headers["Authorization"]}
		_ = json.Unmarshal(hr.Body, &s.body)
		*log = append(*log, s)
		res, _ := json.Marshal(abi.HTTPResponse{Status: status, Body: []byte(body)})
		return json.Marshal(abi.HostReply{Result: res})
	})
}

func TestCreate(t *testing.T) {
	var log []seen
	res, err := fs{}.Create(host(t, 201, `{"ticket":{"id":77}}`, &log), abi.TicketCreateRequest{Invocation: cred,
		Event: abi.TicketEvent{ID: "ev1", Class: "renewal_failed", CN: "<b>shop</b>", Risk: "high", TicketType: "Incident"}})
	if err != nil || res.Key != "77" || res.URL != "https://acme.freshservice.com/a/tickets/77" {
		t.Fatalf("%+v %v", res, err)
	}
	s := log[0]
	if s.method != "POST" || s.url != "https://acme.freshservice.com/api/v2/tickets" || s.auth != "Basic "+base64.StdEncoding.EncodeToString([]byte("key:X")) {
		t.Fatalf("%+v", s)
	}
	if s.body["priority"] != float64(3) || s.body["status"] != float64(2) || s.body["email"] != "kk@acme.example" || s.body["type"] != "Incident" || s.body["workspace_id"] != float64(3) {
		t.Fatalf("body %+v", s.body)
	}
	if d := s.body["description"].(string); strings.Contains(d, "<b>") {
		t.Fatalf("certificate name not escaped: %s", d)
	}
}

func TestExists(t *testing.T) {
	for _, c := range []struct {
		status int
		body   string
		want   bool
	}{{200, `{"ticket":{"deleted":false}}`, true}, {200, `{"ticket":{"deleted":true}}`, false}, {404, ``, false}} {
		var log []seen
		res, err := fs{}.Exists(host(t, c.status, c.body, &log), abi.TicketExistsRequest{Invocation: cred, Key: "5"})
		if err != nil || res.Exists != c.want || res.Failure != "" {
			t.Fatalf("%+v: %+v %v", c, res, err)
		}
	}
	var log []seen
	if res, _ := (fs{}).Exists(host(t, 429, ``, &log), abi.TicketExistsRequest{Invocation: cred, Key: "5"}); res.Failure != abi.FailureTemporary {
		t.Fatalf("%+v", res)
	}
}

func TestResolveSetsStatusThenNotes(t *testing.T) {
	var log []seen
	res, err := fs{}.Resolve(host(t, 200, `{}`, &log), abi.TicketResolveRequest{Invocation: cred, Key: "5", Comment: "replaced"})
	if err != nil || res.Failure != "" || len(log) != 2 {
		t.Fatalf("%+v %v %d calls", res, err, len(log))
	}
	if log[0].method != "PUT" || log[0].body["status"] != float64(4) || log[1].url != "https://acme.freshservice.com/api/v2/tickets/5/notes" || log[1].body["private"] != true {
		t.Fatalf("%+v", log)
	}
}

func TestBadWorkspaceRefused(t *testing.T) {
	var log []seen
	bad := abi.Invocation{Credential: map[string]string{"base_url": "https://a.freshservice.com", "api_key": "k", "requester_email": "e", "workspace_id": "x1"}}
	if _, err := (fs{}).Create(host(t, 201, `{}`, &log), abi.TicketCreateRequest{Invocation: bad}); err == nil || len(log) != 0 {
		t.Fatal("must refuse a non-numeric workspace_id before sending")
	}
}
