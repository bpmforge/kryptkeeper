// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"testing"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/delivery"
)

func req(class string) abi.NotifySendRequest {
	return abi.NotifySendRequest{
		Invocation: abi.Invocation{Credential: map[string]string{"webhook_url": "https://flow.example.com/hook?sig=s"}},
		EventClass: class, Severity: abi.SeverityCritical, Title: "Expiring", Body: "5 days", DedupeKey: "k",
		Fields: map[string]string{"b": "2", "a": "1"}, DeepLink: "https://kk.example.com/c/1",
	}
}

// TestWorkflowsPayload pins the documented envelope: type "message" and one
// adaptive-card attachment with a null contentUrl.
func TestWorkflowsPayload(t *testing.T) {
	var posted map[string]any
	h := delivery.NewHost(func(_ string, in []byte) ([]byte, error) {
		var hr abi.HTTPRequest
		_ = json.Unmarshal(in, &hr)
		_ = json.Unmarshal(hr.Body, &posted)
		res, _ := json.Marshal(abi.HTTPResponse{Status: 202})
		return json.Marshal(abi.HostReply{Result: res})
	})
	res, err := teams{}.Send(h, req("certificate.expiry"))
	if err != nil || !res.Delivered {
		t.Fatalf("%+v %v", res, err)
	}
	if posted["type"] != "message" {
		t.Fatalf("type %v", posted["type"])
	}
	att := posted["attachments"].([]any)[0].(map[string]any)
	if att["contentType"] != "application/vnd.microsoft.card.adaptive" {
		t.Fatalf("contentType %v", att["contentType"])
	}
	if v, present := att["contentUrl"]; !present || v != nil {
		t.Fatalf("contentUrl must be present and null, got %v (present=%v)", v, present)
	}
	c := att["content"].(map[string]any)
	if c["type"] != "AdaptiveCard" || c["version"] != "1.2" || c["actions"] == nil {
		t.Fatalf("card %+v", c)
	}
	body := c["body"].([]any)
	facts := body[len(body)-1].(map[string]any)["facts"].([]any)
	if facts[0].(map[string]any)["title"] != "a" {
		t.Fatalf("facts must be sorted by name: %+v", facts)
	}
}

func TestResolvedAndColor(t *testing.T) {
	c := card(req("certificate.expiry.resolved"))
	first := c["body"].([]map[string]any)[0]
	if first["text"] != "Resolved: Expiring" || first["color"] != "Good" {
		t.Fatalf("%+v", first)
	}
	if got := color(abi.SeverityMedium, false); got != "Warning" {
		t.Fatal(got)
	}
}
