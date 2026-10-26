// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

type sent struct {
	url  string
	auth string
	body map[string]any
}

// run drives Send against a scripted host and returns what it posted.
func run(t *testing.T, r abi.NotifySendRequest, status int) (sent, abi.NotifySendResult) {
	t.Helper()
	var s sent
	h := delivery.NewHost(func(op string, in []byte) ([]byte, error) {
		var hr abi.HTTPRequest
		_ = json.Unmarshal(in, &hr)
		s.url, s.auth = hr.URL, hr.Headers["Authorization"]
		_ = json.Unmarshal(hr.Body, &s.body)
		res, _ := json.Marshal(abi.HTTPResponse{Status: status, Body: []byte(`{"requestId":"req-1"}`)})
		return json.Marshal(abi.HostReply{Result: res})
	})
	res, err := og{}.Send(h, r)
	if err != nil {
		t.Fatal(err)
	}
	return s, res
}

func request(class string) abi.NotifySendRequest {
	return abi.NotifySendRequest{
		Invocation: abi.Invocation{Credential: map[string]string{"api_base": "https://api.opsgenie.com/", "api_key": "k"}},
		EventClass: class, Severity: abi.SeverityCritical, Title: "T", Body: "B", DedupeKey: "exp/1 2", DeepLink: "https://kk.example.com/c/1",
		Fields: map[string]string{"cn": "a.example.com"},
	}
}

func TestCreate(t *testing.T) {
	s, res := run(t, request("certificate.expiry"), 202)
	if s.url != "https://api.opsgenie.com/v2/alerts" || s.auth != "GenieKey k" {
		t.Fatalf("%+v", s)
	}
	if s.body["priority"] != "P1" || s.body["alias"] != "exp/1 2" || !strings.Contains(s.body["description"].(string), "kk.example.com") {
		t.Fatalf("body %+v", s.body)
	}
	if !res.Delivered || res.ProviderID != "req-1" {
		t.Fatalf("%+v", res)
	}
}

func TestCloseEscapesTheAlias(t *testing.T) {
	s, res := run(t, request("certificate.expiry.resolved"), 202)
	if s.url != "https://api.opsgenie.com/v2/alerts/exp%2F1%202/close?identifierType=alias" || !res.Delivered {
		t.Fatalf("%+v %+v", s, res)
	}
}

func TestLimitsAndRefusals(t *testing.T) {
	r := request("x")
	r.Title = strings.Repeat("é", 200)
	s, _ := run(t, r, 202)
	if len(s.body["message"].(string)) > maxMessage {
		t.Fatalf("message %d bytes", len(s.body["message"].(string)))
	}
	if _, res := run(t, request("x"), 403); res.Delivered || !strings.Contains(res.Detail, "403") {
		t.Fatalf("%+v", res)
	}
	big := map[string]string{}
	for i := range 50 {
		big[strings.Repeat("k", 3)+string(rune('a'+i%26))+string(rune('A'+i/26))] = strings.Repeat("v", 400)
	}
	total := 0
	for k, v := range details(big) {
		total += len(k) + len(v)
	}
	if total > maxDetails {
		t.Fatalf("details %d characters", total)
	}
}
