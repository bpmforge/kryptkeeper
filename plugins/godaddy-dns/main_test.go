// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/abi"
	"github.com/bpmforge/kryptkeeper/sdk/delivery-go/dns01"
)

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

func TestFirstValueIsAppendedWithTheMinimumTTL(t *testing.T) {
	s := &scripted{replies: []abi.HTTPResponse{
		{Status: 404}, // www.example.com: not a domain
		{Status: 200}, // example.com
		{Status: 404}, // no TXT yet
		{Status: 204}, // PATCH
	}}
	b := &backend{auth: "sso-key k:s", ttl: max(60, minTTL), send: s.do}
	res, err := dns01.PresentRRSet(b, "_acme-challenge.www.example.com", "digest")
	if err != nil || res.Zone != "example.com" {
		t.Fatalf("%+v %v", res, err)
	}
	patch := s.seen[3]
	var body []map[string]any
	_ = json.Unmarshal(patch.Body, &body)
	if patch.Method != "PATCH" || patch.URL != "https://api.godaddy.com/v1/domains/example.com/records" || patch.Headers["Authorization"] != "sso-key k:s" ||
		len(body) != 1 || body[0]["type"] != "TXT" || body[0]["name"] != "_acme-challenge.www" || body[0]["data"] != "digest" || body[0]["ttl"] != float64(600) {
		t.Fatalf("%s %s %v", patch.Method, patch.URL, body)
	}
}

func TestCleanupNeverDeletesTheWholeSetWhileOthersRemain(t *testing.T) {
	s := &scripted{replies: []abi.HTTPResponse{
		{Status: 200, Body: []byte(`[{"data":"ours"},{"data":"theirs"}]`)},
		{Status: 204},
	}}
	b := &backend{auth: "x", ttl: 600, send: s.do}
	if _, err := dns01.CleanupRRSet(b, "_acme-challenge.example.com", "ours", "example.com"); err != nil {
		t.Fatal(err)
	}
	put := s.seen[1]
	var body []map[string]any
	_ = json.Unmarshal(put.Body, &body)
	if put.Method != "PUT" || len(body) != 1 || body[0]["data"] != "theirs" {
		t.Fatalf("expected a PUT of the remaining value, got %s %s", put.Method, put.Body)
	}

	s = &scripted{replies: []abi.HTTPResponse{{Status: 200, Body: []byte(`[{"data":"ours"}]`)}, {Status: 204}}}
	b = &backend{auth: "x", ttl: 600, send: s.do}
	if _, err := dns01.CleanupRRSet(b, "_acme-challenge.example.com", "ours", "example.com"); err != nil || s.seen[1].Method != "DELETE" {
		t.Fatalf("an empty set is deleted: %v %+v", err, s.seen)
	}
}

func TestRejectedKeyDoesNotEchoTheBody(t *testing.T) {
	s := &scripted{replies: []abi.HTTPResponse{{Status: 401, Body: []byte(`you sent sso-key k:topsecret`)}}}
	b := &backend{auth: "sso-key k:topsecret", send: s.do}
	_, err := b.Zone("_acme-challenge.example.com")
	if err == nil || !strings.Contains(err.Error(), "key was refused") || strings.Contains(err.Error(), "topsecret") {
		t.Fatalf("err %v", err)
	}
}
