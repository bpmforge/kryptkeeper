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

func TestCreateThenUpdateKeepsForeignAnswers(t *testing.T) {
	s := &scripted{replies: []abi.HTTPResponse{
		{Status: 200}, // zone
		{Status: 404}, // no record yet
		{Status: 200}, // PUT
	}}
	b := &backend{key: "k", ttl: 60, send: s.do}
	if _, err := dns01.PresentRRSet(b, "_acme-challenge.example.com", "one"); err != nil {
		t.Fatal(err)
	}
	put := s.seen[2]
	var body map[string]any
	_ = json.Unmarshal(put.Body, &body)
	if put.Method != "PUT" || put.URL != "https://api.nsone.net/v1/zones/example.com/_acme-challenge.example.com/TXT" ||
		put.Headers["X-NSONE-Key"] != "k" || body["type"] != "TXT" || body["domain"] != "_acme-challenge.example.com" || body["ttl"] != float64(60) {
		t.Fatalf("create %s %s %s", put.Method, put.URL, put.Body)
	}

	// A second value (wildcard + base) and a foreign answer split in two
	// strings: both must survive an update unchanged.
	s = &scripted{replies: []abi.HTTPResponse{
		{Status: 200},
		{Status: 200, Body: []byte(`{"answers":[{"answer":["foreign-a","foreign-b"]},{"answer":["one"]}]}`)},
		{Status: 200},
	}}
	b = &backend{key: "k", ttl: 60, send: s.do}
	if _, err := dns01.PresentRRSet(b, "_acme-challenge.example.com", "two"); err != nil {
		t.Fatal(err)
	}
	post := s.seen[2]
	if post.Method != "POST" || !strings.Contains(string(post.Body), `{"answer":["foreign-a","foreign-b"]},{"answer":["one"]},{"answer":["two"]}`) {
		t.Fatalf("update %s %s", post.Method, post.Body)
	}
}

func TestCleanupDeletesOnlyWhenNothingElseRemains(t *testing.T) {
	s := &scripted{replies: []abi.HTTPResponse{
		{Status: 200, Body: []byte(`{"answers":[{"answer":["ours"]},{"answer":["theirs"]}]}`)},
		{Status: 200},
	}}
	b := &backend{key: "k", send: s.do}
	if _, err := dns01.CleanupRRSet(b, "_acme-challenge.example.com", "ours", "example.com"); err != nil {
		t.Fatal(err)
	}
	if s.seen[1].Method != "POST" || strings.Contains(string(s.seen[1].Body), "ours") || !strings.Contains(string(s.seen[1].Body), "theirs") {
		t.Fatalf("%s %s", s.seen[1].Method, s.seen[1].Body)
	}
	s = &scripted{replies: []abi.HTTPResponse{{Status: 200, Body: []byte(`{"answers":[{"answer":["ours"]}]}`)}, {Status: 200}}}
	b = &backend{key: "k", send: s.do}
	if _, err := dns01.CleanupRRSet(b, "_acme-challenge.example.com", "ours", "example.com"); err != nil || s.seen[1].Method != "DELETE" {
		t.Fatalf("%v %+v", err, s.seen)
	}
}

func TestRejectedKeyDoesNotEchoTheBody(t *testing.T) {
	s := &scripted{replies: []abi.HTTPResponse{{Status: 401, Body: []byte(`bad key topsecret`)}}}
	b := &backend{key: "topsecret", send: s.do}
	_, err := b.Zone("_acme-challenge.example.com")
	if err == nil || !strings.Contains(err.Error(), "key was refused") || strings.Contains(err.Error(), "topsecret") {
		t.Fatalf("err %v", err)
	}
}
