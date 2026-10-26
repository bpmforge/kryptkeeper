// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
)

// scripted answers requests in order and records them.
type scripted struct {
	replies []abi.HTTPResponse
	seen    []abi.HTTPRequest
}

func (s *scripted) do(r abi.HTTPRequest) (abi.HTTPResponse, error) {
	s.seen = append(s.seen, r)
	resp := s.replies[0]
	s.replies = s.replies[1:]
	return resp, nil
}

func TestPresentShape(t *testing.T) {
	s := &scripted{replies: []abi.HTTPResponse{
		{Status: 404}, // _acme-challenge.www.example.com is not a domain... parent www.example.com is not either
		{Status: 200},
		{Status: 201, Body: []byte(`{"domain_record":{"id":28448429,"type":"TXT"}}`)},
	}}
	c := &client{token: "tok-secret", send: s.do}
	res, err := c.present(abi.DNS01PresentRequest{FQDN: "_acme-challenge.www.example.com", Value: "digest", TTLSeconds: 5})
	if err != nil {
		t.Fatal(err)
	}
	if res.Zone != "example.com" || res.RecordID != "example.com/28448429" {
		t.Fatalf("result %+v", res)
	}
	if len(s.seen) != 3 || s.seen[0].URL != "https://api.digitalocean.com/v2/domains/www.example.com" || s.seen[1].URL != "https://api.digitalocean.com/v2/domains/example.com" {
		t.Fatalf("zone discovery %+v", s.seen)
	}
	post := s.seen[2]
	var body map[string]any
	_ = json.Unmarshal(post.Body, &body)
	if post.Method != "POST" || post.URL != "https://api.digitalocean.com/v2/domains/example.com/records" ||
		post.Headers["Authorization"] != "Bearer tok-secret" ||
		body["type"] != "TXT" || body["name"] != "_acme-challenge.www" || body["data"] != "digest" || body["ttl"] != float64(minTTL) {
		t.Fatalf("create request %s %s %v", post.Method, post.URL, body)
	}
}

func TestCleanupByIDAndBySearch(t *testing.T) {
	s := &scripted{replies: []abi.HTTPResponse{{Status: 204}}}
	c := &client{token: "t", send: s.do}
	if _, err := c.cleanup(abi.DNS01CleanupRequest{FQDN: "_acme-challenge.example.com", Value: "v", RecordID: "example.com/42"}); err != nil {
		t.Fatal(err)
	}
	if s.seen[0].Method != "DELETE" || !strings.HasSuffix(s.seen[0].URL, "/v2/domains/example.com/records/42") {
		t.Fatalf("%+v", s.seen[0])
	}

	// Without a usable id the plugin searches, and deletes only the record
	// holding this value.
	s = &scripted{replies: []abi.HTTPResponse{
		{Status: 200}, // zone
		{Status: 200, Body: []byte(`{"domain_records":[{"id":1,"data":"other"},{"id":2,"data":"v"}]}`)},
		{Status: 204},
	}}
	c = &client{token: "t", send: s.do}
	if _, err := c.cleanup(abi.DNS01CleanupRequest{FQDN: "_acme-challenge.example.com", Value: "v"}); err != nil {
		t.Fatal(err)
	}
	if len(s.seen) != 3 || !strings.HasSuffix(s.seen[2].URL, "/records/2") || !strings.Contains(s.seen[1].URL, "name=_acme-challenge.example.com") {
		t.Fatalf("%+v", s.seen)
	}

	s = &scripted{replies: []abi.HTTPResponse{{Status: 404}}}
	c = &client{token: "t", send: s.do}
	if res, err := c.cleanup(abi.DNS01CleanupRequest{FQDN: "_acme-challenge.example.com", Value: "v", RecordID: "example.com/9"}); err != nil || !res.Removed {
		t.Fatalf("a record that is already gone is success: %+v %v", res, err)
	}
}

func TestAuthFailureNamesTheCauseNotTheToken(t *testing.T) {
	s := &scripted{replies: []abi.HTTPResponse{{Status: 401, Body: []byte(`reflected tok-secret`)}}}
	c := &client{token: "tok-secret", send: s.do}
	_, err := c.present(abi.DNS01PresentRequest{FQDN: "_acme-challenge.example.com", Value: "v", TTLSeconds: 60})
	if err == nil || !strings.Contains(err.Error(), "token was refused") || strings.Contains(err.Error(), "tok-secret") {
		t.Fatalf("err %v", err)
	}
}

func TestParseID(t *testing.T) {
	for in, ok := range map[string]bool{"example.com/42": true, "": false, "example.com": false, "example.com/x": false, "/42": false, "example.com/0": false} {
		if _, _, got := parseID(in); got != ok {
			t.Errorf("parseID(%q)=%v", in, got)
		}
	}
}
