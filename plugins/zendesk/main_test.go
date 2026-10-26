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

var cred = abi.Invocation{Credential: map[string]string{"base_url": "https://acme.zendesk.com/", "email": "a@b.c", "api_token": "tok"}}

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
	res, err := zd{}.Create(host(t, 201, `{"ticket":{"id":35436}}`, &log), abi.TicketCreateRequest{Invocation: cred,
		Event: abi.TicketEvent{ID: "ev1", Class: "renewal_failed", CN: "shop.example.com", Risk: "critical", TicketType: "incident"}})
	if err != nil || res.Key != "35436" || res.URL != "https://acme.zendesk.com/agent/tickets/35436" {
		t.Fatalf("%+v %v", res, err)
	}
	s := log[0]
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("a@b.c/token:tok"))
	if s.method != "POST" || s.url != "https://acme.zendesk.com/api/v2/tickets.json" || s.auth != want {
		t.Fatalf("%+v", s)
	}
	tk := s.body["ticket"].(map[string]any)
	if tk["priority"] != "urgent" || tk["external_id"] != "ev1" || tk["type"] != "incident" || !strings.Contains(tk["subject"].(string), "shop.example.com") {
		t.Fatalf("ticket %+v", tk)
	}
}

func TestExists(t *testing.T) {
	for _, c := range []struct {
		status int
		body   string
		want   bool
	}{{200, `{"ticket":{"status":"open"}}`, true}, {200, `{"ticket":{"status":"deleted"}}`, false}, {404, ``, false}} {
		var log []seen
		res, err := zd{}.Exists(host(t, c.status, c.body, &log), abi.TicketExistsRequest{Invocation: cred, Key: "12"})
		if err != nil || res.Exists != c.want || res.Failure != "" || log[0].url != "https://acme.zendesk.com/api/v2/tickets/12.json" {
			t.Fatalf("%+v: %+v %v", c, res, err)
		}
	}
	var log []seen
	if res, _ := (zd{}).Exists(host(t, 401, ``, &log), abi.TicketExistsRequest{Invocation: cred, Key: "0"}); res.Failure != abi.FailurePermanent {
		t.Fatalf("a refused credential must be a permanent failure: %+v", res)
	}
	if res, _ := (zd{}).Exists(host(t, 200, `{}`, &log), abi.TicketExistsRequest{Invocation: cred, Key: "../../users"}); res.Exists || len(log) != 1 {
		t.Fatal("a non-numeric key must not reach the service")
	}
}

func TestResolveSolvesWithInternalNote(t *testing.T) {
	var log []seen
	res, err := zd{}.Resolve(host(t, 200, `{}`, &log), abi.TicketResolveRequest{Invocation: cred, Key: "9", Comment: "done"})
	tk := log[0].body["ticket"].(map[string]any)
	if err != nil || res.Failure != "" || log[0].method != "PUT" || tk["status"] != "solved" || tk["comment"].(map[string]any)["public"] != false {
		t.Fatalf("%+v %v %+v", res, err, log[0])
	}
	if res, _ = (zd{}).Resolve(host(t, 503, ``, &log), abi.TicketResolveRequest{Invocation: cred, Key: "9"}); res.Failure != abi.FailureTemporary {
		t.Fatalf("%+v", res)
	}
}

func TestRejectsPlainHTTPCredential(t *testing.T) {
	var log []seen
	bad := abi.Invocation{Credential: map[string]string{"base_url": "http://acme.zendesk.com", "email": "a", "api_token": "t"}}
	if _, err := (zd{}).Create(host(t, 201, `{}`, &log), abi.TicketCreateRequest{Invocation: bad}); err == nil || len(log) != 0 {
		t.Fatal("must refuse before sending the token")
	}
}
